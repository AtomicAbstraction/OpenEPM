"""Strict deployment-declared endpoint inventory for reset preparation.

This is review evidence, not proof that every external proxy or legacy listener
has been discovered. An apply operation must independently verify retirement.
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit


_KINDS = {'platform_mcp', 'workspace_mcp', 'application_mcp',
          'router_mcp', 'web_inspector'}


def parse_endpoint_inventory(raw: str | None, workspace_id: str) -> dict:
    if not isinstance(workspace_id, str) or not workspace_id:
        raise ValueError('RESET_ENDPOINT_WORKSPACE_REQUIRED')
    if not raw:
        return {'source': 'not_configured', 'endpoints': [],
                'coverage': 'unknown'}
    if not isinstance(raw, str) or len(raw.encode('utf-8')) > 16_384:
        raise ValueError('RESET_ENDPOINT_INVENTORY_INVALID')
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('RESET_ENDPOINT_INVENTORY_INVALID') from error
    if (not isinstance(value, dict) or set(value) != {'endpoints'} or
            not isinstance(value['endpoints'], list) or
            len(value['endpoints']) > 100):
        raise ValueError('RESET_ENDPOINT_INVENTORY_INVALID')
    endpoints = []
    seen = set()
    for item in value['endpoints']:
        if (not isinstance(item, dict) or
                set(item) != {'kind', 'url', 'workspaceId', 'applicationId'} or
                not isinstance(item['kind'], str) or
                item['kind'] not in _KINDS or
                not isinstance(item['url'], str) or
                not isinstance(item['workspaceId'], str) or
                not isinstance(item['applicationId'], str) or
                len(item['url']) > 1024 or
                item['url'] != item['url'].strip() or
                any(ord(character) < 32 for character in item['url']) or
                len(item['workspaceId']) > 200 or
                len(item['applicationId']) > 200):
            raise ValueError('RESET_ENDPOINT_INVENTORY_INVALID')
        kind, url = item['kind'], item['url']
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError as error:
            raise ValueError('RESET_ENDPOINT_URL_INVALID') from error
        if (parts.scheme not in ('https', 'http') or not parts.hostname or
                (port is not None and port < 1) or
                parts.username or parts.password or parts.query or parts.fragment or
                (parts.scheme == 'http' and parts.hostname not in
                 ('127.0.0.1', 'localhost', '::1'))):
            raise ValueError('RESET_ENDPOINT_URL_INVALID')
        if (kind == 'workspace_mcp' and
                (item['workspaceId'] != workspace_id or
                 item['applicationId'])):
            raise ValueError('RESET_ENDPOINT_SCOPE_INVALID')
        if (kind == 'application_mcp' and
                (item['workspaceId'] != workspace_id or
                 not item['applicationId'])):
            raise ValueError('RESET_ENDPOINT_SCOPE_INVALID')
        if (kind not in ('workspace_mcp', 'application_mcp') and
                (item['workspaceId'] or item['applicationId'])):
            raise ValueError('RESET_ENDPOINT_SCOPE_INVALID')
        if url in seen:
            raise ValueError('RESET_ENDPOINT_DUPLICATE')
        seen.add(url)
        endpoints.append(dict(item))
    endpoints.sort(key=lambda item: (
        item['kind'], item['workspaceId'], item['applicationId'], item['url']))
    return {'source': 'deployment_config', 'endpoints': endpoints,
            'coverage': 'declared_not_independently_verified'}
