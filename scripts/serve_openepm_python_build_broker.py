"""Serve the private, capability-only Python build input broker."""
from __future__ import annotations

import argparse
from contextlib import closing
from http.client import HTTPConnection, HTTPException
import os

from psycopg import Error as PostgresError

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from epm_core.python_build_startup import create_python_build_broker


def check_health(port: int) -> str:
    # Use the existing inert HTTP response so the probe never requests build input.
    expected = b'{"error":"NOT_FOUND"}'
    try:
        with closing(HTTPConnection('127.0.0.1', port, timeout=1)) as connection:
            connection.request('GET', '/')
            response = connection.getresponse()
            if response.status != 404 or response.read(len(expected) + 1) != expected:
                return 'listener-unavailable'
    except (OSError, HTTPException):
        return 'listener-unavailable'
    try:
        create_python_build_broker(os.environ)
    except (OSError, ValueError, RuntimeError, PostgresError):
        return 'configuration-or-database-roles-unavailable'
    return 'ready'


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--healthcheck', action='store_true')
    args = parser.parse_args(argv)
    port = os.environ.get('EPM_PYTHON_BUILD_BROKER_PORT', '5198')
    if not port.isdecimal() or not 1024 <= int(port) <= 65535:
        if args.healthcheck:
            print('configuration-or-database-roles-unavailable')
            return 1
        raise ValueError('EPM_PYTHON_BUILD_BROKER_PORT_INVALID')
    if args.healthcheck:
        result = check_health(int(port))
        print(result)
        return 0 if result == 'ready' else 1

    import uvicorn
    uvicorn.run(create_python_build_broker(os.environ), host='0.0.0.0',
                port=int(port), log_level='info', access_log=False,
                limit_concurrency=32, backlog=64, timeout_keep_alive=5)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
