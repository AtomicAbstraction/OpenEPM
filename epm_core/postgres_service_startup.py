"""SDK-independent, read-only worker startup/readiness in a bounded process.

Only fixed worker/runtime role checks and readiness reads run. Credentials travel
over stdin, never command arguments. No jobs can be claimed by this helper.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time

STARTUP_SECONDS = 30
HEALTH_SECONDS = 3
TERMINATION_SECONDS = 1


class StartupCancelled(RuntimeError):
    pass


class StartupRoleRejected(ValueError):
    """Preserve the fixed worker's configuration-validation error contract."""


def worker_roles(worker_dsn, runtime_dsn):
    from .postgres_access import assert_nonowner_role
    assert_nonowner_role(worker_dsn,'epm_worker',
        ('job','operation_receipt','expression_rule_sequence',
         'full_aggregate_sequence','worker_workspace_dispatch',
         'cube_aggregate_query','python_program_build',
         'application_rule_workflow','application_schedule_occurrence'))
    assert_nonowner_role(runtime_dsn,'epm_runtime',
        ('application','coordinate','numeric_cell_current','source_batch','generic_fact_table'))


def worker_health(worker_dsn, runtime_dsn):
    from .postgres_connection import connect_postgres
    worker_roles(worker_dsn,runtime_dsn)
    for dsn,query in ((worker_dsn,
            """SELECT
              has_function_privilege(current_user,
                'epm.cube_aggregate_worker_claim(text,integer,integer,integer,integer)','EXECUTE')
              AND has_function_privilege(current_user,
                'epm.cube_aggregate_worker_unexpected(text,text,text,bigint,text)','EXECUTE')
              AND has_function_privilege(current_user,
                'epm.cube_aggregate_worker_expire(integer,integer)','EXECUTE')
              AND has_function_privilege(current_user,
                'epm.python_build_worker_claim(text,integer,integer,integer,integer)','EXECUTE')
              AND has_function_privilege(current_user,
                'epm.application_rule_worker_claim(text,integer,integer,integer,integer)','EXECUTE')
              AND has_function_privilege(current_user,
                'epm.application_schedule_worker_claim(text,integer,integer,integer,integer)','EXECUTE')
              AND has_function_privilege(current_user,
                'epm.application_schedule_occurrence_worker_claim(text,integer,integer,integer,integer)','EXECUTE')
              """),
            (runtime_dsn,'SELECT 1 FROM epm.application_state LIMIT 1')):
        with connect_postgres(dsn) as db:
            db.execute('SET TRANSACTION READ ONLY')
            result=db.execute(query).fetchone()
            if dsn==worker_dsn and result!=(True,):
                raise ValueError('WORKER_HEALTH_PRIVILEGE_MISSING')


def assert_worker_startup(worker_dsn, runtime_dsn, *, stop=None):
    return _check_service(worker_dsn,runtime_dsn,stop=stop,
        operation='worker',seconds=STARTUP_SECONDS)


def assert_worker_health(worker_dsn, runtime_dsn):
    return _check_service(worker_dsn,runtime_dsn,stop=None,
        operation='worker-health',seconds=HEALTH_SECONDS)


def _check_service(worker_dsn, runtime_dsn, *, stop, operation, seconds):
    if operation not in ('worker','worker-health'):
        raise ValueError('WORKER_CHECK_OPERATION_INVALID')
    if stop is not None and stop.is_set():
        raise StartupCancelled('WORKER_STARTUP_CANCELLED')
    deadline=time.monotonic()+seconds
    prefix='WORKER_STARTUP' if operation=='worker' else 'WORKER_HEALTH'
    payload=json.dumps({'workerDsn':worker_dsn,'runtimeDsn':runtime_dsn,
        'deadline':deadline},allow_nan=False).encode()
    if len(payload)>16384:
        raise ValueError(prefix+'_CONFIGURATION_TOO_LARGE')
    try:
        process=subprocess.Popen([sys.executable,'-m','epm_core.postgres_service_startup',
            operation,str(os.getpid())],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,start_new_session=True)
    except OSError:
        raise RuntimeError(prefix+'_UNAVAILABLE_NOT_CLAIMED') from None
    first=True
    try:
        while True:
            if stop is not None and stop.is_set():
                raise StartupCancelled('WORKER_STARTUP_CANCELLED')
            remaining=deadline-time.monotonic()
            if remaining<=0:
                raise RuntimeError(prefix+'_DEADLINE_NOT_CLAIMED')
            try:
                output,_=process.communicate(input=payload if first else None,
                    timeout=min(remaining,.2))
                break
            except subprocess.TimeoutExpired:
                first=False
        if process.returncode!=0 or len(output)>16384:
            raise RuntimeError(prefix+'_UNAVAILABLE_NOT_CLAIMED')
        result=json.loads(output)
        if result!={'ready':True}:
            reason=result.get('error') if isinstance(result,dict) else None
            if (isinstance(result,dict) and result.get('invalidConfiguration') is True
                    and isinstance(reason,str)):
                raise StartupRoleRejected(reason)
            raise RuntimeError(reason if isinstance(reason,str) else prefix+'_UNAVAILABLE_NOT_CLAIMED')
    except StartupRoleRejected:
        raise
    except (OSError,ValueError):
        raise RuntimeError(prefix+'_UNAVAILABLE_NOT_CLAIMED') from None
    finally:
        if process.poll() is None:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        try:process.wait(timeout=TERMINATION_SECONDS)
        except subprocess.TimeoutExpired:
            raise RuntimeError(prefix+'_TERMINATION_UNCONFIRMED') from None
        for stream in (process.stdin,process.stdout):
            if stream is not None:stream.close()


def main():
    if len(sys.argv)!=3 or sys.argv[1] not in ('worker','worker-health'):
        return 1
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
    raw=sys.stdin.buffer.read(16385)
    try:
        request=json.loads(raw)
        if len(raw)>16384 or set(request)!={'workerDsn','runtimeDsn','deadline'}:
            return 1
        from .postgres_execution_scope import tool_execution_scope
        with tool_execution_scope(request['deadline']):
            check=worker_roles if sys.argv[1]=='worker' else worker_health
            check(request['workerDsn'],request['runtimeDsn'])
        result={'ready':True}
    except ValueError as error:
        result={'ready':False,'error':str(error),'invalidConfiguration':True}
    except Exception:
        prefix='WORKER_STARTUP' if sys.argv[1]=='worker' else 'WORKER_HEALTH'
        result={'ready':False,'error':prefix+'_UNAVAILABLE_NOT_CLAIMED'}
    sys.stdout.write(json.dumps(result))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
