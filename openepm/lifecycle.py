"""Exact application retirement through an authenticated workspace MCP."""
from __future__ import annotations
from typing import Any, Mapping
from .client import Transport


class ApplicationPurge:
    """Bound to the workspace listener; current workspace administration required."""
    def __init__(self, workspace_transport: Transport):
        self.transport=workspace_transport

    def _call(self, action: str, arguments: dict, request_key: str | None) -> Mapping[str, Any]:
        return self.transport.call('execute_v2_application_purge', {
            'program': {'languageVersion': 2, 'function': 'workspace.application.purge.'+action,
                        'arguments': arguments}, 'idempotency_key': request_key})

    def prepare(self, application_id: str) -> Mapping[str, Any]:
        return self._call('prepare', {'applicationId': application_id}, None)

    def quiesce(self, application_id: str, *, created_at: str,
                manifest_digest: str, request_key: str) -> Mapping[str, Any]:
        return self._call('quiesce', {'applicationId': application_id,
            'createdAt': created_at, 'manifestDigest': manifest_digest}, request_key)

    def apply(self, application_id: str, *, created_at: str,
              request_key: str) -> Mapping[str, Any]:
        return self._call('apply', {'applicationId': application_id,
            'createdAt': created_at}, request_key)
