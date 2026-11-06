"""Serve the private, capability-only Python build input broker."""
from __future__ import annotations

import os

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from epm_core.python_build_startup import create_python_build_broker


def main() -> None:
    import uvicorn
    port = os.environ.get('EPM_PYTHON_BUILD_BROKER_PORT', '5198')
    if not port.isdecimal() or not 1024 <= int(port) <= 65535:
        raise ValueError('EPM_PYTHON_BUILD_BROKER_PORT_INVALID')
    uvicorn.run(create_python_build_broker(os.environ), host='0.0.0.0',
                port=int(port), log_level='info', access_log=False,
                limit_concurrency=32, backlog=64, timeout_keep_alive=5)


if __name__ == '__main__': main()
