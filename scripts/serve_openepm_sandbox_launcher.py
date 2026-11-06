"""Host-level trusted launcher; install with root-owned config and Unix socket."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import threading

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from epm_core.python_sandbox_control import SandboxControlProtocol, serve_connection
from epm_core.python_sandbox_launcher import (ApprovedSandboxEnvironment,
                                               GVisorDockerSandboxLauncher)


_EVENT_LOCK = threading.Lock()


def _read(path: str, maximum: int) -> bytes:
    target = Path(path)
    if not target.is_file() or target.is_symlink():
        raise ValueError("PYTHON_SANDBOX_HOST_CONFIGURATION_INVALID")
    value = target.read_bytes()
    if not value or len(value) > maximum:
        raise ValueError("PYTHON_SANDBOX_HOST_CONFIGURATION_INVALID")
    return value


def create(environment):
    key = _read(environment["EPM_SANDBOX_CONTROL_KEY_FILE"], 4096)
    raw = json.loads(_read(environment["EPM_PYTHON_BUILDER_PROFILES_FILE"],
                           1024 * 1024))
    if type(raw) is not dict or set(raw) != {"profiles"}:
        raise ValueError("PYTHON_SANDBOX_HOST_CONFIGURATION_INVALID")
    profiles = []
    for item in raw["profiles"]:
        if (type(item) is not dict
                or not {"environmentId", "environmentVersion", "image",
                        "network"}.issubset(item)
                or not set(item).issubset({"environmentId",
                    "environmentVersion", "image", "network",
                    "compilerVersions"})
                or type(item.get("compilerVersions", [])) is not list):
            raise ValueError("PYTHON_SANDBOX_HOST_CONFIGURATION_INVALID")
        profiles.append(ApprovedSandboxEnvironment(item["environmentId"],
            item["environmentVersion"], item["image"], item["network"],
            tuple(item.get("compilerVersions", []))))
    broker_url = environment.get("EPM_PYTHON_BUILD_BROKER_URL",
        "http://python-build-broker:5198/internal/python-build/read")
    return SandboxControlProtocol(key, GVisorDockerSandboxLauncher(
        profiles, broker_url=broker_url, event_sink=_emit_event))


def _emit_event(event):
    """Write one bounded credential-free launcher record to the journal."""
    with _EVENT_LOCK:
        print(json.dumps(event, sort_keys=True, separators=(",", ":")), flush=True)


def main() -> None:
    path = os.environ.get("EPM_SANDBOX_CONTROL_SOCKET",
                          "/run/openepm-sandbox/sandbox-launcher.sock")
    if not path.startswith("/run/openepm-sandbox/"):
        raise ValueError("PYTHON_SANDBOX_HOST_CONFIGURATION_INVALID")
    protocol = create(os.environ)  # verifies runsc before binding
    gid_value = os.environ.get("EPM_SANDBOX_CONTROL_GID", "10001")
    if not gid_value.isdecimal() or not 1 <= int(gid_value) <= 2**31-1:
        raise ValueError("PYTHON_SANDBOX_HOST_CONFIGURATION_INVALID")
    target = Path(path)
    target.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if target.exists():
        if not target.is_socket():
            raise ValueError("PYTHON_SANDBOX_HOST_CONFIGURATION_INVALID")
        target.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(path); os.chown(path, -1, int(gid_value)); os.chmod(path, 0o660)
        server.listen(16)
        capacity = threading.BoundedSemaphore(16)
        def handle(connection):
            try:
                with connection: serve_connection(connection, protocol)
            finally:
                capacity.release()
        while True:
            connection, _ = server.accept()
            if not capacity.acquire(blocking=False):
                connection.close()
                continue
            threading.Thread(target=handle, args=(connection,), daemon=True).start()


if __name__ == "__main__": main()
