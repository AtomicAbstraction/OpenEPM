"""Container readiness probe for the fixed PostgreSQL V2 worker."""
from __future__ import annotations

import os
import time

import sys
from pathlib import Path

# Support both the packaged module command and direct deployment-owner CLI.
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from epm_core.postgres_service_startup import assert_worker_health
from epm_core.deployment_secrets import configured_hex_bytes, configured_text


def observe() -> str:
    try:
        worker=configured_text(os.environ,'EPM_PG_WORKER_DSN',
                               'EPM_PG_WORKER_DSN_FILE')
        runtime=configured_text(os.environ,'EPM_PG_RUNTIME_DSN',
                                'EPM_PG_RUNTIME_DSN_FILE')
        configured_hex_bytes(os.environ,'EPM_PG_PREVIEW_SECRET_HEX',
                             'EPM_PG_PREVIEW_SECRET_FILE')
    except (OSError,ValueError,RuntimeError):
        return 'configuration-unavailable'
    heartbeat=os.environ.get('EPM_WORKER_HEARTBEAT_FILE')
    if heartbeat:
        try:
            path=Path(heartbeat)
            if not path.is_file() or path.is_symlink():
                return 'loop-marker-unavailable'
            age=time.time()-path.stat().st_mtime
            if age<0:
                return 'loop-marker-unavailable'
            if age>15:
                return 'loop-marker-stale'
        except OSError:
            return 'loop-marker-unavailable'
    try:
        assert_worker_health(worker,runtime)
    except (OSError,ValueError,RuntimeError):
        return 'database-role-check-unavailable'
    return 'ready' if heartbeat else 'loop-check-not-configured'


def main(*, report: bool = False) -> int:
    result=observe()
    if report:
        # Docker retains health output. Only fixed codes cross this boundary.
        print(f'openepm-worker-health-v1:{result}')
    return 0 if result in ('ready','loop-check-not-configured') else 1


if __name__ == '__main__':
    raise SystemExit(main(report=True))
