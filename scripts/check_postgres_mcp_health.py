"""Container readiness probe for the authenticated PostgreSQL MCP listeners."""
from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request

from epm_core.postgres_auth import assert_oidc_readiness
from epm_core.postgres_listener_readiness import assert_listener_database_readiness


def _listener_status(port: int, path: str) -> int | None:
    request = urllib.request.Request(
        f'http://127.0.0.1:{port}{path}',
        data=b'{}',
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=3) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except (OSError, TimeoutError):
        return None


def main(arguments=None) -> int:
    arguments = sys.argv[1:] if arguments is None else list(arguments)
    if len(arguments) > 1 or (arguments and arguments[0] not in
                              ('liveness', 'unsigned-denial', 'readiness')):
        return 1
    mode = arguments[0] if arguments else 'readiness'
    try:
        port = int(os.environ['EPM_PG_HEALTH_PORT'])
    except (KeyError, ValueError):
        return 1
    if not 1 <= port <= 65535:
        return 1
    path = os.environ.get('EPM_PG_HEALTH_PATH', '/mcp')
    if path not in ('/mcp', '/'):
        return 1
    status = _listener_status(port, path)
    if mode == 'liveness':
        return 0 if status is not None else 1
    if status != 401:
        return 1
    if mode == 'unsigned-denial':
        return 0
    try:
        audiences = tuple(
            audience for audience, key in (
                ('mcp', 'EPM_OIDC_AUD_MCP'), ('web', 'EPM_OIDC_AUD_WEB'))
            if os.environ.get(key, '').strip())
        assert_oidc_readiness(audiences)
        assert_listener_database_readiness()
    except Exception:
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
