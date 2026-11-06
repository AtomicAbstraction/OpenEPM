#!/usr/bin/env python3
"""Serve the trusted notebook launcher on a root-owned Unix socket."""
from __future__ import annotations
import json
import os
from pathlib import Path
import socket
import struct
import threading

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from deploy.notebook.notebook_launcher import MAX_MESSAGE, NotebookLauncher, NotebookProfile


def _read(path, maximum):
    target = Path(path)
    if not target.is_file() or target.is_symlink():
        raise ValueError("MANAGED_NOTEBOOK_CONFIGURATION_INVALID")
    value = target.read_bytes()
    if not value or len(value) > maximum:
        raise ValueError("MANAGED_NOTEBOOK_CONFIGURATION_INVALID")
    return value


def create(environment, **kwargs):
    raw = json.loads(_read(environment["EPM_NOTEBOOK_PROFILE_FILE"], 65536))
    if type(raw) is not dict or set(raw) != {"profileId", "image", "network",
            "baseDomain", "maximumActive", "idleSeconds", "storageRoot"}:
        raise ValueError("MANAGED_NOTEBOOK_CONFIGURATION_INVALID")
    return NotebookLauncher(_read(environment["EPM_NOTEBOOK_CONTROL_KEY_FILE"], 4096),
        NotebookProfile(raw["profileId"], raw["image"], raw["network"],
            raw["baseDomain"], raw["maximumActive"], raw["idleSeconds"],
            raw["storageRoot"]), **kwargs)


def _serve(connection, launcher):
    header = bytearray()
    while len(header) < 4:
        part = connection.recv(4 - len(header))
        if not part: raise ValueError("MANAGED_NOTEBOOK_REQUEST_INVALID")
        header.extend(part)
    length = struct.unpack("!I", header)[0]
    if not 2 <= length <= MAX_MESSAGE:
        raise ValueError("MANAGED_NOTEBOOK_REQUEST_INVALID")
    chunks = bytearray()
    while len(chunks) < length:
        part = connection.recv(length - len(chunks))
        if not part: raise ValueError("MANAGED_NOTEBOOK_REQUEST_INVALID")
        chunks.extend(part)
    try: response = launcher.handle(json.loads(chunks))
    except (ValueError, json.JSONDecodeError): response = {"ok": False}
    raw = json.dumps(response, sort_keys=True, separators=(",", ":")).encode()
    connection.sendall(struct.pack("!I", len(raw)) + raw)


def _reap_idle(launcher, stop, interval):
    """Run independently of request traffic; stop is injectable for tests."""
    while not stop.wait(interval):
        launcher.expire_idle()


def _emit_event(event):
    """Emit one bounded machine-readable record for the system journal."""
    print(json.dumps(event, sort_keys=True, separators=(",", ":")), flush=True)


def main():
    environment = os.environ
    path = environment.get("EPM_NOTEBOOK_CONTROL_SOCKET",
                           "/run/openepm/notebook-launcher.sock")
    if not path.startswith("/run/openepm/"):
        raise ValueError("MANAGED_NOTEBOOK_CONFIGURATION_INVALID")
    launcher = create(environment, event_sink=_emit_event)
    stop = threading.Event()
    interval = max(1, min(60, launcher.profile.idle_seconds // 10))
    threading.Thread(target=_reap_idle, args=(launcher, stop, interval),
                     daemon=True, name="openepm-notebook-idle-reaper").start()
    target = Path(path); target.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if target.exists():
        if not target.is_socket(): raise ValueError("MANAGED_NOTEBOOK_CONFIGURATION_INVALID")
        target.unlink()
    gid = int(environment.get("EPM_NOTEBOOK_CONTROL_GID", "10001"))
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(path); os.chown(path, -1, gid); os.chmod(path, 0o660); server.listen(16)
        while True:
            connection, _ = server.accept()
            def handle(client=connection):
                with client: _serve(client, launcher)
            threading.Thread(target=handle, daemon=True).start()


if __name__ == "__main__": main()
