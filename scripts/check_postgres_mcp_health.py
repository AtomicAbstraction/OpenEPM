"""Container readiness probe for the authenticated PostgreSQL MCP listeners."""
from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request

from epm_core.postgres_auth import assert_oidc_readiness
from epm_core.postgres_listener_readiness import assert_listener_database_readiness


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _listener_status(port: int, path: str) -> int | None:
    request = urllib.request.Request(
        f'http://127.0.0.1:{port}{path}',
        data=b'{}',
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
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

    def not_ready(reason: str) -> int:
        if mode == 'readiness':
            print(reason, file=sys.stderr)
        return 1

    try:
        port = int(os.environ['EPM_PG_HEALTH_PORT'])
    except (KeyError, ValueError):
        return not_ready('LISTENER_CONFIGURATION_NOT_READY')
    if not 1 <= port <= 65535:
        return not_ready('LISTENER_CONFIGURATION_NOT_READY')
    path = os.environ.get('EPM_PG_HEALTH_PATH', '/mcp')
    if path not in ('/mcp', '/'):
        return not_ready('LISTENER_CONFIGURATION_NOT_READY')
    status = _listener_status(port, path)
    if mode == 'liveness':
        return 0 if status is not None else 1
    if status is None:
        return not_ready('LISTENER_NOT_REACHABLE')
    if status != 401:
        return not_ready('UNSIGNED_DENIAL_NOT_CONFIRMED')
    if mode == 'unsigned-denial':
        return 0
    audiences = tuple(
        audience for audience, key in (
            ('mcp', 'EPM_OIDC_AUD_MCP'), ('web', 'EPM_OIDC_AUD_WEB'))
        if os.environ.get(key, '').strip())
    try:
        assert_oidc_readiness(audiences)
    except Exception:
        return not_ready('OIDC_DEPENDENCY_NOT_READY')
    try:
        assert_listener_database_readiness()
    except Exception:
        return not_ready('DATABASE_DEPENDENCY_NOT_READY')
    print('ready')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
