"""JupyterHub spawner using only the narrow trusted notebook launcher socket.

The host launcher is intentionally a separate release gate.  This client has
no Docker API, image arguments, mounts, environment variables or host paths.
"""
from __future__ import annotations

import asyncio
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import secrets
import struct
import time

from jupyterhub.spawner import Spawner

from managed_notebook_contract import (assignment_for_hub_username,
                                        policy_from_environment)


MAX_MESSAGE = 64 * 1024


class ManagedNotebookSpawner(Spawner):
    async def _call(self, action: str) -> dict:
        policy = policy_from_environment(os.environ)
        assignment = assignment_for_hub_username(policy, self.user.name)
        key_path = Path(os.environ["EPM_NOTEBOOK_CONTROL_KEY_FILE"])
        if not key_path.is_file() or key_path.is_symlink():
            raise RuntimeError("MANAGED_NOTEBOOK_CONTROL_KEY_UNAVAILABLE")
        key = key_path.read_bytes()
        if len(key) < 32 or len(key) > 4096:
            raise RuntimeError("MANAGED_NOTEBOOK_CONTROL_KEY_INVALID")
        hub_environment = self.get_env() if action == "start" else {}
        allowed = ("JUPYTERHUB_API_TOKEN", "JUPYTERHUB_CLIENT_ID",
                   "JUPYTERHUB_API_URL", "JUPYTERHUB_ACTIVITY_URL",
                   "JUPYTERHUB_BASE_URL", "JUPYTERHUB_SERVICE_PREFIX",
                   "JUPYTERHUB_SERVICE_URL",
                   "JUPYTERHUB_OAUTH_CALLBACK_URL", "JUPYTERHUB_OAUTH_SCOPES",
                   "JUPYTERHUB_OAUTH_ACCESS_SCOPES",
                   "JUPYTERHUB_OAUTH_CLIENT_ALLOWED_SCOPES",
                   "JUPYTERHUB_USER", "JUPYTERHUB_SERVER_NAME",
                   "JUPYTERHUB_COOKIE_NAME", "JUPYTERHUB_COOKIE_OPTIONS",
                   "JUPYTERHUB_COOKIE_HOST_PREFIX_ENABLED",
                   "JUPYTERHUB_DEFAULT_URL", "JUPYTERHUB_DISABLE_USER_CONFIG",
                   "JUPYTERHUB_ROOT_DIR", "JUPYTERHUB_HOST",
                   "JUPYTERHUB_PUBLIC_URL", "JUPYTERHUB_PUBLIC_HUB_URL")
        authentication = {name: hub_environment[name] for name in allowed
                          if name in hub_environment}
        last_activity = getattr(self.user, "last_activity", None)
        activity_at = int(last_activity.timestamp()) if last_activity else int(time.time())
        payload = {"version": 1, "action": action,
                   "issuedAt": int(time.time()), "nonce": secrets.token_hex(16),
                   "activityAt": activity_at, "assignment": assignment,
                   "authentication": authentication}
        unsigned = json.dumps(payload, sort_keys=True,
                              separators=(",", ":")).encode()
        payload["signature"] = hmac.new(key, unsigned, sha256).hexdigest()
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        if len(raw) > MAX_MESSAGE:
            raise RuntimeError("MANAGED_NOTEBOOK_REQUEST_LIMIT")
        reader, writer = await asyncio.open_unix_connection(policy.control_socket)
        try:
            writer.write(struct.pack("!I", len(raw)) + raw)
            await writer.drain()
            length = struct.unpack("!I", await reader.readexactly(4))[0]
            if not 2 <= length <= MAX_MESSAGE:
                raise RuntimeError("MANAGED_NOTEBOOK_RESPONSE_INVALID")
            result = json.loads(await reader.readexactly(length))
        finally:
            writer.close()
            await writer.wait_closed()
        if type(result) is not dict or result.get("ok") is not True:
            raise RuntimeError("MANAGED_NOTEBOOK_LAUNCHER_DENIED")
        return result

    async def start(self):
        result = await self._call("start")
        if set(result) != {"ok", "url"} or not isinstance(result["url"], str):
            raise RuntimeError("MANAGED_NOTEBOOK_RESPONSE_INVALID")
        return result["url"]

    async def poll(self):
        result = await self._call("poll")
        if set(result) != {"ok", "running"} or type(result["running"]) is not bool:
            raise RuntimeError("MANAGED_NOTEBOOK_RESPONSE_INVALID")
        return None if result["running"] else 1

    async def stop(self, now=False):
        del now
        await self._call("stop")
