"""Fixed deployment-owner CLI execution with bounded, non-replayed outcomes.

This is not a business-operation or MCP endpoint. Only migration and initial
trust/service-role bootstrap commands are supported. A timeout may follow commit.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

DEFAULT_SECONDS=900
MAX_SECONDS=86400
TERMINATION_SECONDS=1
OPERATIONS={'migrate','service-roles','operator'}
MAX_FRAME=1_048_576

class AdminOutcomeUnknown(RuntimeError):
    pass


def add_budget_argument(parser):
    import argparse
    def budget(value):
        try:number=int(value)
        except ValueError:raise argparse.ArgumentTypeError('Use whole seconds') from None
        if not 1<=number<=MAX_SECONDS:
            raise argparse.ArgumentTypeError(f'Use 1 through {MAX_SECONDS} seconds')
        return number
    parser.add_argument('--timeout-seconds',type=budget,default=DEFAULT_SECONDS,
        help='Total command budget (default 900, maximum 86400); expiry can follow commit')


def run_admin_cli(parser,operation,arguments,seconds):
    try:return execute_admin(operation,arguments,seconds=seconds)
    except (AdminOutcomeUnknown,ValueError) as error:
        if operation=='migrate':
            from .observability import record_operational_signal
            record_operational_signal('migration_failure')
        parser.exit(2,str(error)+'; inspect migration/bootstrap state before retry; '
            'previously committed stages are not rolled back\n')


def execute_admin(operation,arguments,*,seconds=DEFAULT_SECONDS):
    if (operation not in OPERATIONS or not isinstance(arguments,dict)
            or type(seconds) is not int or not 1<=seconds<=MAX_SECONDS):
        raise ValueError('ADMIN_COMMAND_OR_BUDGET_INVALID')
    deadline=time.monotonic()+seconds
    payload=json.dumps({'arguments':arguments,'deadline':deadline},allow_nan=False).encode()
    if len(payload)>MAX_FRAME:raise ValueError('ADMIN_COMMAND_CONFIGURATION_TOO_LARGE')
    try:
        child=subprocess.Popen([sys.executable,'-m','epm_core.postgres_admin_execution',
            operation,str(os.getpid())],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,start_new_session=True)
    except OSError:
        raise AdminOutcomeUnknown('ADMIN_COMMAND_UNAVAILABLE_NOT_DISPATCHED') from None
    try:
        try:output,_=child.communicate(payload,timeout=max(.001,deadline-time.monotonic()))
        except subprocess.TimeoutExpired:
            raise AdminOutcomeUnknown('ADMIN_COMMAND_DEADLINE_OUTCOME_UNKNOWN') from None
        except KeyboardInterrupt:
            raise AdminOutcomeUnknown('ADMIN_COMMAND_INTERRUPTED_OUTCOME_UNKNOWN') from None
        except OSError:
            raise AdminOutcomeUnknown('ADMIN_COMMAND_TRANSPORT_OUTCOME_UNKNOWN') from None
        if child.returncode!=0 or len(output)>MAX_FRAME:
            raise AdminOutcomeUnknown('ADMIN_COMMAND_TRANSPORT_OUTCOME_UNKNOWN')
        try:result=json.loads(output)
        except (ValueError,UnicodeError):
            raise AdminOutcomeUnknown('ADMIN_COMMAND_TRANSPORT_OUTCOME_UNKNOWN') from None
        if not isinstance(result,dict):
            raise AdminOutcomeUnknown('ADMIN_COMMAND_TRANSPORT_OUTCOME_UNKNOWN')
        if (set(result)=={'ok','result'} and result['ok'] is True
                and _valid_result(operation,result['result'])):return result['result']
        if set(result)=={'ok','validation'} and result['ok'] is False and isinstance(result['validation'],str):
            raise ValueError(result['validation'])
        raise AdminOutcomeUnknown('ADMIN_COMMAND_FAILED_OUTCOME_UNKNOWN')
    finally:
        if child.poll() is None:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        try:child.wait(timeout=TERMINATION_SECONDS)
        except subprocess.TimeoutExpired:
            raise AdminOutcomeUnknown('ADMIN_COMMAND_TERMINATION_UNCONFIRMED') from None
        for stream in (child.stdin,child.stdout):
            if stream is not None:stream.close()


def _valid_result(operation,result):
    if operation=='migrate':
        return isinstance(result,list) and bool(result) and all(isinstance(row,str) for row in result)
    if operation=='operator':return result in ('verified','enrolled')
    from scripts.bootstrap_postgres_service_roles import ROLES
    return (isinstance(result,dict) and set(result)=={row[0] for row in ROLES}
        and all(value in ('created','verified') for value in result.values()))


def _execute(operation,arguments):
    if operation=='migrate' and set(arguments) in (
            {'dsn','directory'},{'dsn','directory','forecastBoundaryMap'},
            {'dsn','directory','freshBaselineManifest','forecastBoundaryMap'}):
        from scripts.apply_postgres_migrations import apply_migrations
        path=arguments.get('forecastBoundaryMap')
        if path is not None and type(path) is not str:
            raise ValueError('ADMIN_COMMAND_ARGUMENTS_INVALID')
        baseline=arguments.get('freshBaselineManifest')
        if baseline is not None and type(baseline) is not str:
            raise ValueError('ADMIN_COMMAND_ARGUMENTS_INVALID')
        return apply_migrations(arguments['dsn'],Path(arguments['directory']),
            forecast_boundary_map=None if path is None else Path(path),
            fresh_baseline_manifest=None if baseline is None else Path(baseline))
    if operation=='service-roles' and set(arguments)=={'dsn','passwords'}:
        from scripts.bootstrap_postgres_service_roles import bootstrap_service_roles
        return bootstrap_service_roles(arguments['dsn'],arguments['passwords'])
    if operation=='operator' and set(arguments)=={'dsn','issuer','subjectId'}:
        from scripts.bootstrap_postgres_operator import bootstrap_operator
        return bootstrap_operator(arguments['dsn'],arguments['issuer'],arguments['subjectId'])
    raise ValueError('ADMIN_COMMAND_ARGUMENTS_INVALID')


def main():
    if len(sys.argv)!=3 or sys.argv[1] not in OPERATIONS:return 1
    parent=int(sys.argv[2])
    if sys.platform=='linux':
        import ctypes
        if ctypes.CDLL(None).prctl(1,signal.SIGKILL,0,0,0)!=0:return 1
    if os.getppid()!=parent:return 1
    if sys.platform!='linux':
        from threading import Thread
        def watch():
            while True:
                time.sleep(.2)
                if os.getppid()!=parent:os.killpg(os.getpgrp(),signal.SIGKILL)
        Thread(target=watch,daemon=True).start()
    raw=sys.stdin.buffer.read(MAX_FRAME+1)
    try:
        request=json.loads(raw)
        if (len(raw)>MAX_FRAME or not isinstance(request,dict)
                or set(request)!={'arguments','deadline'}
                or not isinstance(request['arguments'],dict)):return 1
        from .postgres_execution_scope import tool_execution_scope
        with tool_execution_scope(request['deadline']):
            result={'ok':True,'result':_execute(sys.argv[1],request['arguments'])}
    except ValueError as error:result={'ok':False,'validation':str(error)}
    except Exception:result={'ok':False,'failed':True}
    sys.stdout.write(json.dumps(result,allow_nan=False))
    return 0

if __name__=='__main__':raise SystemExit(main())
