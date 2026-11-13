#!/usr/bin/env python3
"""Install or remove one marker-owned sandbox launcher inside Colima."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PROJECT = re.compile(r"openepm-[a-z0-9][a-z0-9-]{2,59}\Z")


class SandboxLauncherError(RuntimeError):
    pass


def _fail(code: str) -> None:
    raise SandboxLauncherError(code)


def _write_once(path: Path, value: dict) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def render(project: str, broker_ip: str) -> dict[str, str]:
    if (not PROJECT.fullmatch(project) or project.startswith("openepm-owner-")
            or not re.fullmatch(r"172\.30\.25[3-9]\.[2-9]", broker_ip)):
        _fail("SANDBOX_IDENTITY_INVALID")
    unit_name = project + "-sandbox-launcher.service"
    library = "/usr/lib/openepm/qualification/" + project
    config = "/etc/openepm/qualification/" + project
    socket_dir = "/run/openepm-sandbox/" + project
    environment = "\n".join((
        f"EPM_SANDBOX_CONTROL_KEY_FILE={config}/control-key",
        f"EPM_PYTHON_BUILDER_PROFILES_FILE={config}/profiles.json",
        f"EPM_SANDBOX_CONTROL_SOCKET={socket_dir}/sandbox-launcher.sock",
        "EPM_SANDBOX_CONTROL_GID=10001",
        f"EPM_PYTHON_BUILD_BROKER_URL=http://{broker_ip}:5198/"
        "internal/python-build/read", ""))
    unit = "\n".join(("[Unit]",
        "Description=Open EPM marker-owned qualification sandbox launcher",
        "Requires=docker.service",
        "After=docker.service network-online.target", "", "[Service]",
        "Type=simple", "User=root", "Group=root",
        f"EnvironmentFile={config}/launcher.env",
        f"ExecStart=/usr/bin/python3 {library}/sandbox-launcher.pyz",
        "Restart=on-failure", "RestartSec=5s", "UMask=0077",
        "NoNewPrivileges=true", "PrivateTmp=true", "ProtectHome=true",
        "ProtectSystem=strict", f"ReadWritePaths={socket_dir}",
        "RestrictAddressFamilies=AF_UNIX",
        "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER",
        "LockPersonality=true", "MemoryDenyWriteExecute=true", ""))
    return {"unitName": unit_name, "libraryDirectory": library,
        "configDirectory": config, "socketDirectory": socket_dir,
        "socketPath": socket_dir + "/sandbox-launcher.sock",
        "environment": environment, "unit": unit}


class Colima:
    def run(self, arguments: list[str], *, data: bytes | None = None,
            output: bool = False) -> str:
        completed = subprocess.run(["colima", "ssh", "--", *arguments],
            input=data, stdout=subprocess.PIPE if output else subprocess.DEVNULL,
            stderr=subprocess.PIPE, timeout=60, check=False)
        if completed.returncode:
            _fail("SANDBOX_COLIMA_COMMAND_FAILED")
        return completed.stdout.decode().strip() if output else ""

    def put(self, path: str, data: bytes, mode: str) -> None:
        self.run(["sudo", "tee", path], data=data)
        self.run(["sudo", "chown", "root:root", path])
        self.run(["sudo", "chmod", mode, path])

    def test(self, arguments: list[str]) -> bool:
        completed = subprocess.run(["colima", "ssh", "--", *arguments],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=30, check=False)
        return completed.returncode == 0


def _owner_state(colima: Colima) -> dict:
    return {"unit": "openepm-sandbox-launcher.service",
        "mainPid": colima.run(["systemctl", "show", "--property=MainPID",
            "--value", "openepm-sandbox-launcher.service"], output=True),
        "socketInode": colima.run(["sudo", "stat", "-c", "%i",
            "/run/openepm-sandbox/sandbox-launcher.sock"], output=True),
        "profileSha256": colima.run(["sudo", "sha256sum",
            "/etc/openepm/secrets/epm_python_builder_profiles.json"],
            output=True).split()[0]}


def install(manifest_path: Path, colima: Colima | None = None) -> dict:
    colima = colima or Colima()
    manifest_path = manifest_path.resolve(strict=True)
    if (manifest_path.is_symlink() or manifest_path.stat().st_mode & 0o077):
        _fail("SANDBOX_MANIFEST_INVALID")
    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    if value.get("format") != "openepm-compose-runtime-v1":
        _fail("SANDBOX_MANIFEST_INVALID")
    project = value.get("project")
    material = render(project, value.get("sandboxBrokerIp"))
    runtime = manifest_path.parent / "python-build"
    pyz = runtime / "sandbox-launcher.pyz"
    profiles = runtime / "epm_python_builder_profiles.json"
    key = runtime / "epm_sandbox_control_key"
    for path in (pyz, profiles, key):
        if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
            _fail("SANDBOX_MATERIAL_INVALID")
    before = _owner_state(colima)
    colima.run(["sudo", "install", "-d", "-o", "root", "-g", "root",
        "-m", "0755", material["libraryDirectory"],
        material["configDirectory"]])
    colima.run(["sudo", "install", "-d", "-o", "root", "-g", "10001",
        "-m", "0750", material["socketDirectory"]])
    colima.put(material["libraryDirectory"] + "/sandbox-launcher.pyz",
               pyz.read_bytes(), "0555")
    colima.put(material["configDirectory"] + "/profiles.json",
               profiles.read_bytes(), "0444")
    colima.put(material["configDirectory"] + "/control-key",
               key.read_bytes(), "0400")
    colima.put(material["configDirectory"] + "/launcher.env",
               material["environment"].encode(), "0444")
    unit_path = "/etc/systemd/system/" + material["unitName"]
    colima.put(unit_path, material["unit"].encode(), "0444")
    colima.run(["sudo", "systemctl", "daemon-reload"])
    colima.run(["sudo", "systemctl", "start", material["unitName"]])
    deadline = time.monotonic() + 15
    while True:
        active = colima.run(["systemctl", "is-active", material["unitName"]],
                            output=True)
        socket_ready = colima.test(
            ["sudo", "test", "-S", material["socketPath"]])
        if active == "active" and socket_ready:
            break
        if time.monotonic() >= deadline:
            _fail("SANDBOX_START_TIMEOUT")
        time.sleep(0.2)
    after = _owner_state(colima)
    if before != after:
        _fail("SANDBOX_OWNER_RUNTIME_CHANGED")
    result = {"format": "openepm-sandbox-launcher-v1",
        "project": project, "unitName": material["unitName"],
        "sandboxBrokerIp": value["sandboxBrokerIp"],
        "socketDirectory": material["socketDirectory"],
        "socketPath": material["socketPath"],
        "launcherSha256": sha256(pyz.read_bytes()).hexdigest(),
        "profilesSha256": sha256(profiles.read_bytes()).hexdigest(),
        "ownerBefore": before, "ownerAfter": after,
        "ownerRuntimeChanged": False, "status": "ready"}
    _write_once(manifest_path.parent / "sandbox-launcher-manifest.json", result)
    return result


def remove(manifest_path: Path, colima: Colima | None = None) -> dict:
    colima = colima or Colima()
    value = json.loads(manifest_path.resolve(strict=True).read_text())
    project = value.get("project")
    # Manifests written before the broker identity was retained still contain
    # all marker-owned path identities.  The broker address affects only the
    # installed environment file, not removal targets; use the qualified
    # default solely to reconstruct those exact paths.
    material = render(project, value.get("sandboxBrokerIp",
                                         "172.30.253.2"))
    before = _owner_state(colima)
    colima.run(["sudo", "systemctl", "stop", material["unitName"]])
    colima.run(["sudo", "rm", "-f",
        "/etc/systemd/system/" + material["unitName"]])
    colima.run(["sudo", "rm", "-rf", material["libraryDirectory"],
                material["configDirectory"], material["socketDirectory"]])
    colima.run(["sudo", "systemctl", "daemon-reload"])
    after = _owner_state(colima)
    if before != after:
        _fail("SANDBOX_OWNER_RUNTIME_CHANGED")
    return {"project": project, "removed": True,
            "ownerRuntimeChanged": False, "ownerBefore": before,
            "ownerAfter": after}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "remove"))
    parser.add_argument("--manifest", type=Path, required=True)
    arguments = parser.parse_args()
    result = (install(arguments.manifest) if arguments.action == "install"
              else remove(arguments.manifest))
    print(json.dumps({"status": "ready" if arguments.action == "install"
        else "removed", "project": result["project"],
        "ownerRuntimeChanged": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
