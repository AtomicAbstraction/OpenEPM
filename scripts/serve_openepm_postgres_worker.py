"""Launch the fixed PostgreSQL job worker in a managed process.

No application business data is modified outside the fixed publishers.
"""
from __future__ import annotations

import logging
import os
import signal
import threading
from pathlib import Path

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from epm_core.postgres_worker_service import PostgresWorkerService
from epm_core.python_build_deployment import read_secret_text
from epm_core.python_build_startup import create_python_build_worker


class _LazyPythonBuildWorker:
    """Construct credentialed adapters only after bounded worker attestation."""
    def __init__(self, environment):
        self.environment=environment;self.instance=None;self.worker_id=None
    def bind_worker_id(self,worker_id):
        if (type(worker_id) is not str or not worker_id
                or self.instance is not None or self.worker_id is not None):
            raise ValueError('PYTHON_BUILD_WORKER_CONFIGURATION_INVALID')
        self.worker_id=worker_id
    def run_claim(self,*args,**kwargs):
        if self.instance is None:
            if self.worker_id is None:
                raise ValueError('PYTHON_BUILD_WORKER_CONFIGURATION_INVALID')
            self.instance=create_python_build_worker(
                self.environment,worker_id=self.worker_id)
        return self.instance.run_claim(*args,**kwargs)


def _configuration(environment):
    if environment.get('EPM_PG_WORKER_DSN_FILE'):
        worker_dsn=read_secret_text(environment,'EPM_PG_WORKER_DSN_FILE')
        runtime_dsn=read_secret_text(environment,'EPM_PG_RUNTIME_DSN_FILE')
        preview_value=read_secret_text(environment,'EPM_PG_PREVIEW_SECRET_FILE',
                                       maximum=4096)
        try: preview_secret=bytes.fromhex(preview_value)
        except ValueError: preview_secret=preview_value.encode('utf-8')
        build_worker=_LazyPythonBuildWorker(environment)
        return worker_dsn,runtime_dsn,preview_secret,build_worker
    return (environment.get('EPM_PG_WORKER_DSN',''),
            environment.get('EPM_PG_RUNTIME_DSN',''),
            bytes.fromhex(environment.get('EPM_PG_PREVIEW_SECRET_HEX','')),
            None)


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(name)s %(message)s')
    stop=threading.Event()
    for signum in (signal.SIGINT,signal.SIGTERM):
        signal.signal(signum,lambda _signum,_frame:stop.set())
    worker_dsn,runtime_dsn,preview_secret,build_worker=_configuration(os.environ)
    heartbeat_path=Path(os.environ.get(
        'EPM_WORKER_HEARTBEAT_FILE','/tmp/openepm-worker-heartbeat'))
    if (not heartbeat_path.is_absolute() or heartbeat_path.parent!=Path('/tmp')
            or heartbeat_path.is_symlink()):
        raise ValueError('WORKER_HEARTBEAT_PATH_INVALID')
    def heartbeat():
        heartbeat_path.touch(mode=0o600,exist_ok=True)
        heartbeat_path.chmod(0o600)
    service=PostgresWorkerService(
        worker_dsn=worker_dsn,runtime_dsn=runtime_dsn,
        preview_secret=preview_secret,python_build_worker=build_worker,
        heartbeat=heartbeat,
        capacity_limits=(
            int(os.environ.get('EPM_PG_MAX_RUNNING_GLOBAL','32')),
            int(os.environ.get('EPM_PG_MAX_RUNNING_WORKSPACE','8')),
            int(os.environ.get('EPM_PG_MAX_RUNNING_APPLICATION','2'))))
    service.run(stop)


if __name__=='__main__':
    main()
