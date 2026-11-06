"""Server-owned, killable MCP tool execution with bounded process admission.

Only registered fixed tools in the five server modules can be dispatched. This
is not a Python execution API. A deadline can race a durable commit: callers must
inspect status/replay the same idempotency key, never infer rollback from timeout.
"""
from __future__ import annotations

import atexit
from contextlib import contextmanager
from functools import wraps
import importlib
import inspect
import json
import logging
import os
from queue import Empty, Queue
import selectors
import signal
import subprocess
import sys
from threading import Lock, Thread
import time
from types import SimpleNamespace
import uuid

import anyio
from mcp.server.mcpserver.exceptions import ToolError
from pydantic_core import to_jsonable_python
from .postgres_execution_policy import (
    TOOL_SECONDS, TERMINATION_SECONDS, PROCESSES_PER_LISTENER,
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, DEADLINE_CODE, CAPACITY_CODE, FAILURE_CODE,
    CONTROL_PROCESSES_PER_LISTENER, AUTHENTICATION_SECONDS, STARTUP_SECONDS,
    WEB_PROCESSES_PER_LISTENER,
)
from .postgres_execution_scope import tool_execution_scope, ToolDeadlineExpired, current_deadline
from .postgres_mcp_fair_admission import AdmissionRejected, FairAdmissionScheduler
from .postgres_verified_principal import (
    VerifiedPrincipal, bind_verified_principal, current_verified_principal,
    deserialize_verified_principal, validate_principal_configuration,
    verified_principal_from_claims,
)
MODULES = frozenset({
    'platform_postgres_mcp_server', 'platform_postgres_router_mcp_server',
    'platform_postgres_workspace_mcp_server', 'platform_postgres_platform_mcp_server',
    'platform_postgres_reset_mcp_server',
})
WEB_MODULE = 'platform_postgres_web_http'
PLATFORM_WEB_MODULE = 'platform_postgres_platform_browser_http'
WEB_MODULES = frozenset((WEB_MODULE, PLATFORM_WEB_MODULE))
EXECUTION_MODULES = MODULES | WEB_MODULES
LOG = logging.getLogger(__name__)


_fair_admission = FairAdmissionScheduler()


@contextmanager
def verified_mcp_request(principal: VerifiedPrincipal):
    """Bind one control-worker-verified identity to its ASGI request."""
    if not isinstance(principal, VerifiedPrincipal):
        raise ValueError('Verified MCP principal is invalid')
    with bind_verified_principal(principal):
        yield


def _admission_application(module: str, values: dict) -> tuple[str, str, str]:
    """Derive a bounded scheduler key from fixed listener scope or typed route."""
    if module == 'platform_postgres_router_mcp_server':
        workspace = values.get('workspace_id')
        application = values.get('application_id')
        if (isinstance(workspace, str) and 1 <= len(workspace) <= 200
                and isinstance(application, str) and 1 <= len(application) <= 200):
            return ('application', workspace, application)
        return ('listener', module, 'discovery')
    if module == 'platform_postgres_mcp_server':
        workspace = os.environ.get('EPM_PG_WORKSPACE_ID', '')
        application = os.environ.get('EPM_PG_APPLICATION_ID', '')
        if not workspace or not application:
            raise ToolError('MCP_APPLICATION_SCOPE_NOT_CONFIGURED')
        return ('application', workspace, application)
    return ('listener', module, 'fixed')


async def fair_admission_snapshot() -> dict:
    """Internal fixed-cardinality metrics; never returns issuer or subject."""
    return await _fair_admission.snapshot()


def _remaining(deadline):
    return max(0., deadline - time.monotonic())


def _process_pool_size(module, plane):
    if plane == 'control':
        return CONTROL_PROCESSES_PER_LISTENER
    if module in WEB_MODULES:
        return WEB_PROCESSES_PER_LISTENER
    return PROCESSES_PER_LISTENER


class _Worker:
    def __init__(self, module, *, command=None, plane='tools'):
        self.module = module
        self.command = command
        self.plane = plane
        self.process = None
        self.quarantined = False

    def stop(self):
        process = self.process
        if process is None:
            return
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=TERMINATION_SECONDS)
        except subprocess.TimeoutExpired:
            # Do not reuse or replace a process whose death is unconfirmed.
            self.quarantined = True
            return
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                stream.close()
        self.process = None
        self.quarantined = False

    def call(self, request, deadline):
        if self.quarantined:
            self.stop()
            if self.quarantined:
                raise ToolError(CAPACITY_CODE)
        if self.process is None or self.process.poll() is not None:
            self.stop()
            command = self.command or [sys.executable, '-m',
                'epm_core.postgres_mcp_execution', self.module, str(os.getpid()), self.plane]
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=None, bufsize=0, start_new_session=True)
            os.set_blocking(self.process.stdin.fileno(), False)
            os.set_blocking(self.process.stdout.fileno(), False)
        try:
            payload = json.dumps(request, ensure_ascii=False,
                separators=(',', ':'), allow_nan=False).encode() + b'\n'
        except (ValueError, TypeError):
            raise ToolError('MCP_TOOL_REQUEST_INVALID_NOT_DISPATCHED') from None
        if len(payload) > MAX_REQUEST_BYTES:
            raise ToolError('MCP_TOOL_REQUEST_TOO_LARGE_NOT_DISPATCHED')
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(self.process.stdin, selectors.EVENT_WRITE)
                position = 0
                while position < len(payload):
                    if _remaining(deadline) <= 0:
                        raise TimeoutError()
                    if not selector.select(_remaining(deadline)):
                        raise TimeoutError()
                    position += os.write(self.process.stdin.fileno(), payload[position:position+65536])
                selector.unregister(self.process.stdin)
                selector.register(self.process.stdout, selectors.EVENT_READ)
                output = bytearray()
                while True:
                    if _remaining(deadline) <= 0:
                        raise TimeoutError()
                    if not selector.select(_remaining(deadline)):
                        raise TimeoutError()
                    chunk = os.read(self.process.stdout.fileno(), 65536)
                    if not chunk:
                        raise EOFError()
                    output.extend(chunk)
                    if len(output) > MAX_RESPONSE_BYTES:
                        raise ValueError('Response bound exceeded')
                    if output.endswith(b'\n'):
                        break
                response = json.loads(output)
                if (not isinstance(response, dict) or response.get('id') != request['id']
                        or type(response.get('ok')) is not bool):
                    raise ValueError('Invalid response identity')
                fields = {'id', 'ok', 'result'} if response['ok'] else {'id', 'ok', 'error'}
                if set(response) != fields or (not response['ok'] and not isinstance(response['error'], str)):
                    raise ValueError('Invalid response fields')
        except (TimeoutError, OSError, EOFError, ValueError) as error:
            returncode = self.process.poll() if self.process is not None else None
            LOG.warning('MCP child transport failure module=%s plane=%s '
                'error=%s returncode=%s', self.module, self.plane,
                type(error).__name__, returncode)
            self.stop()
            code = DEADLINE_CODE if isinstance(error, TimeoutError) else FAILURE_CODE
            raise ToolError(code + '; inspect durable status and reuse the same request key') from None
        if not response['ok']:
            raise ToolError(response['error'])
        return response['result']


class _Pool:
    def __init__(self, module, *, size=PROCESSES_PER_LISTENER, worker_factory=_Worker):
        self.workers = [worker_factory(module) for _ in range(size)]
        self.available = Queue(maxsize=size)
        for worker in self.workers:
            self.available.put_nowait(worker)

    def call(self, request, deadline):
        remaining = _remaining(deadline)
        if remaining <= 0:
            raise ToolError(CAPACITY_CODE)
        try:
            worker = self.available.get(timeout=remaining)
        except Empty:
            raise ToolError(CAPACITY_CODE) from None
        try:
            if _remaining(deadline) <= 0:
                raise ToolError(CAPACITY_CODE)
            return worker.call(request, deadline)
        finally:
            self.available.put_nowait(worker)

    def close(self):
        for worker in self.workers:
            worker.stop()


_pools = {}
_pool_lock = Lock()


def close_pools():
    with _pool_lock:
        for pool in _pools.values():
            pool.close()
        _pools.clear()


atexit.register(close_pools)


def _dispatch_request(module, request, deadline, *, plane):
    if module not in EXECUTION_MODULES:
        raise ToolError('MCP_TOOL_TARGET_INVALID')
    with _pool_lock:
        key = (module, plane)
        pool = _pools.get(key)
        if pool is None:
            size = _process_pool_size(module, plane)
            pool = _pools[key] = _Pool(module, size=size,
                worker_factory=lambda bound: _Worker(bound, plane=plane))
    return pool.call(request, deadline)


def dispatch(module, name, arguments, headers, deadline):
    request = {'id': uuid.uuid4().hex, 'kind': 'tool', 'tool': name,
        'arguments': arguments, 'headers': headers, 'deadline': deadline}
    verified_principal = current_verified_principal()
    if verified_principal is not None:
        if not isinstance(verified_principal, VerifiedPrincipal):
            raise ToolError('MCP_VERIFIED_PRINCIPAL_INVALID_NOT_DISPATCHED')
        request['verifiedPrincipal'] = verified_principal.serialized()
    return _dispatch_request(module, request, deadline, plane='tools')


def dispatch_control(module, operation, arguments, deadline):
    if operation not in ('authenticate', 'startup'):
        raise ToolError('MCP_CONTROL_OPERATION_INVALID')
    request = {'id': uuid.uuid4().hex, 'kind': 'control', 'operation': operation,
        'arguments': arguments, 'deadline': deadline}
    return _dispatch_request(module, request, deadline, plane='control')


async def execute_web_request(arguments, headers):
    deadline=time.monotonic()+TOOL_SECONDS
    inherited=current_deadline()
    if inherited is not None:deadline=min(deadline,inherited)
    return await anyio.to_thread.run_sync(lambda:dispatch(
        WEB_MODULE,'_web_request',arguments,headers,deadline),abandon_on_cancel=False)


async def execute_platform_web_request(arguments, headers):
    deadline=time.monotonic()+TOOL_SECONDS
    inherited=current_deadline()
    if inherited is not None:deadline=min(deadline,inherited)
    return await anyio.to_thread.run_sync(lambda:dispatch(
        PLATFORM_WEB_MODULE,'_web_request',arguments,headers,deadline),
        abandon_on_cancel=False)


_control_threads = anyio.CapacityLimiter(CONTROL_PROCESSES_PER_LISTENER)


async def authenticate_http(module, headers):
    from .postgres_auth import AuthError
    deadline = time.monotonic()+AUTHENTICATION_SECONDS
    inherited = current_deadline()
    if inherited is not None:
        deadline = min(deadline, inherited)
    try:
        result = await anyio.to_thread.run_sync(lambda: dispatch_control(
            module, 'authenticate', {'headers':headers}, deadline),
            abandon_on_cancel=False, limiter=_control_threads)
        if (not isinstance(result, dict) or type(result.get('authenticated')) is not bool):
            raise ToolError('Invalid authentication response')
        if result['authenticated']:
            if set(result) != {'authenticated', 'verifiedPrincipal'}:
                raise ToolError('Invalid authentication response')
            try:
                principal = deserialize_verified_principal(
                    result['verifiedPrincipal'])
                validate_principal_configuration(principal)
            except ValueError:
                raise ToolError('Invalid authentication response') from None
            expected_kind = 'web' if module in WEB_MODULES else 'mcp'
            if principal.audience_kind != expected_kind:
                raise ToolError('Invalid authentication response')
            return principal
        if (set(result) != {'authenticated','error','status'}
                or not isinstance(result['error'],str) or type(result['status']) is not int
                or not 400 <= result['status'] <= 599):
            raise ToolError('Invalid authentication response')
        if result['status'] == 503:
            # Keep the public response deliberately generic, but retain the
            # bounded internal reason for operators.  Authentication workers
            # never return tokens or identity claims in this field.
            LOG.warning('HTTP authentication unavailable: %s', result['error'])
            raise AuthError('HTTP_AUTHENTICATION_UNAVAILABLE_RETRY', 503)
        raise AuthError(result['error'], result['status'])
    except ToolError:
        raise AuthError('HTTP_AUTHENTICATION_UNAVAILABLE_RETRY', 503) from None


def check_startup(module):
    try:
        result = dispatch_control(module, 'startup', {}, time.monotonic()+STARTUP_SECONDS)
    except ToolError:
        raise RuntimeError('STARTUP_ROLE_CHECK_UNAVAILABLE') from None
    if not isinstance(result, dict) or result != {'ready':True}:
        reason = result.get('error') if isinstance(result,dict) else None
        raise RuntimeError(reason if isinstance(reason,str) else 'STARTUP_ROLE_CHECK_FAILED')


def execute_control(module, operation, arguments):
    if operation == 'authenticate':
        from .postgres_auth import AuthError, access_token, verify_access_jwt
        if set(arguments) != {'headers'} or not isinstance(arguments['headers'],dict):
            raise ToolError('MCP_CONTROL_REQUEST_INVALID')
        try:
            principal = verify_access_jwt(access_token(arguments['headers']),
                'web' if getattr(module,'__name__',None) in WEB_MODULES else 'mcp')
        except AuthError as error:
            return {'authenticated':False, 'status':error.status, 'error':str(error)}
        sealed = verified_principal_from_claims(principal,
            'web' if getattr(module,'__name__',None) in WEB_MODULES else 'mcp')
        return {'authenticated':True, 'verifiedPrincipal':sealed.serialized()}
    if operation == 'startup' and arguments == {}:
        try:
            module._startup_role_check()
        except (ValueError, RuntimeError) as error:
            return {'ready':False, 'error':str(error)}
        return {'ready':True}
    raise ToolError('MCP_CONTROL_OPERATION_INVALID')


def bounded_tool(server):
    """Register an async isolated endpoint; retain the direct fixed function."""
    def register(function):
        if function.__module__ not in MODULES:
            raise ValueError('Only fixed EPM server modules may register tools')
        signature = inspect.signature(function, eval_str=True)
        function._epm_fixed_tool = True

        @wraps(function)
        async def isolated(*args, **kwargs):
            deadline = time.monotonic() + TOOL_SECONDS
            inherited = current_deadline()
            if inherited is not None:
                deadline = min(deadline, inherited)
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            values = dict(bound.arguments)
            context = values.pop('ctx')
            try:
                source = context.headers or {}
            except (AttributeError, ValueError):
                source = {}
            headers = {str(k).lower(): v for k, v in source.items()
                if str(k).lower() == 'authorization'}
            principal = current_verified_principal()
            if principal is None:
                raise ToolError('MCP_VERIFIED_PRINCIPAL_REQUIRED_NOT_DISPATCHED')
            application_key = _admission_application(function.__module__, values)
            try:
                permit = await _fair_admission.acquire(
                    application_key, (principal.issuer, principal.subject),
                    deadline=deadline)
            except AdmissionRejected as error:
                raise ToolError(error.code) from None
            # Keep the thread tracked until the child exits or is killed. Client
            # disconnect does not turn its still-running write into rollback.
            async with permit:
                return await anyio.to_thread.run_sync(lambda: dispatch(
                    function.__module__, function.__name__, values, headers, deadline),
                    abandon_on_cancel=False)

        isolated.__signature__ = signature
        isolated.__annotations__ = inspect.get_annotations(function, eval_str=True)
        server.tool()(isolated)
        return function
    return register


def _execute(module, request, *, plane='tools'):
    if plane == 'control':
        if request.get('kind') != 'control' or not isinstance(request.get('arguments'),dict):
            raise ToolError('MCP_CONTROL_REQUEST_INVALID')
        with tool_execution_scope(request['deadline']):
            return execute_control(module, request.get('operation'), request['arguments'])
    if request.get('kind','tool') != 'tool':
        raise ToolError('MCP_TOOL_REQUEST_INVALID')
    name = request.get('tool')
    if getattr(module,'__name__',None) in WEB_MODULES:
        if (name!='_web_request' or set(request)!={
                'id','kind','tool','arguments','headers','deadline',
                'verifiedPrincipal'}
                or not isinstance(request.get('arguments'),dict)
                or not isinstance(request.get('headers'),dict)):
            raise ToolError('WEB_OPERATION_INVALID')
        try:
            principal=deserialize_verified_principal(request['verifiedPrincipal'])
            validate_principal_configuration(principal)
        except ValueError:
            raise ToolError('WEB_VERIFIED_PRINCIPAL_INVALID') from None
        if principal.audience_kind!='web':
            raise ToolError('WEB_VERIFIED_PRINCIPAL_INVALID')
        with tool_execution_scope(request['deadline']), bind_verified_principal(principal):
            return module._web_request(request['arguments'],request['headers'])
    target = getattr(module, name, None) if isinstance(name, str) else None
    if not callable(target) or not getattr(target, '_epm_fixed_tool', False):
        raise ToolError('MCP_TOOL_TARGET_INVALID')
    arguments = request.get('arguments')
    headers = request.get('headers')
    if (set(request) != {'id','kind','tool','arguments','headers','deadline',
                         'verifiedPrincipal'}
            or not isinstance(arguments, dict)
            or any(name in arguments for name in ('ctx', 'verifiedPrincipal'))
            or not isinstance(headers, dict)):
        raise ToolError('MCP_TOOL_REQUEST_INVALID')
    try:
        principal = deserialize_verified_principal(request['verifiedPrincipal'])
        validate_principal_configuration(principal)
    except ValueError:
        raise ToolError('MCP_VERIFIED_PRINCIPAL_INVALID') from None
    if principal.audience_kind != 'mcp':
        raise ToolError('MCP_VERIFIED_PRINCIPAL_INVALID')
    with tool_execution_scope(request['deadline']), bind_verified_principal(principal):
        return target(**arguments, ctx=SimpleNamespace(headers=headers))


def main():
    if (len(sys.argv) != 4 or sys.argv[1] not in EXECUTION_MODULES
            or sys.argv[3] not in ('tools','control')):
        raise SystemExit('Fixed MCP worker module required')
    parent_pid = int(sys.argv[2])
    if os.getppid() != parent_pid:
        return 1
    if sys.platform == 'linux':
        # PR_SET_PDEATHSIG is tied to the specific parent *thread*.  These
        # reusable children are spawned from AnyIO worker threads, so that
        # mechanism can SIGKILL a healthy child when an idle thread retires.
        # A pidfd observes the owning service process instead and remains
        # correct across thread-pool churn.
        try:
            parent_fd = os.pidfd_open(parent_pid)
        except (AttributeError, OSError) as error:
            raise SystemExit('Cannot bind worker lifetime to service') from error

        def watch_parent():
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(parent_fd, selectors.EVENT_READ)
                    selector.select()
            finally:
                os.close(parent_fd)
            os.killpg(os.getpgrp(), signal.SIGKILL)
        Thread(target=watch_parent, daemon=True).start()
    else:
        def watch_parent():
            while True:
                time.sleep(.2)
                if os.getppid() != parent_pid:
                    os.killpg(os.getpgrp(), signal.SIGKILL)
        Thread(target=watch_parent, daemon=True).start()
    module = importlib.import_module(sys.argv[1])
    while line := sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1):
        if len(line) > MAX_REQUEST_BYTES or not line.endswith(b'\n'):
            return 1
        request = json.loads(line)
        try:
            result = _execute(module, request, plane=sys.argv[3])
            response = {'id': request['id'], 'ok': True, 'result': result}
        except ToolError as error:
            response = {'id': request['id'], 'ok': False, 'error': str(error)}
        except ToolDeadlineExpired:
            response = {'id': request['id'], 'ok': False, 'error': DEADLINE_CODE}
        except Exception:
            LOG.exception('Fixed MCP worker operation failed')
            response = {'id': request['id'], 'ok': False, 'error': FAILURE_CODE}
        encoded = json.dumps(to_jsonable_python(response), ensure_ascii=False,
            separators=(',', ':'), allow_nan=False).encode() + b'\n'
        if len(encoded) > MAX_RESPONSE_BYTES:
            return 1
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()
        request = response = result = encoded = None
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
