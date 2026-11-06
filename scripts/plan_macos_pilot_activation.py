#!/usr/bin/env python3
"""Seal a non-executing blue/green activation contract for the Mac pilot."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile


IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{2,62}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")


class ActivationPlanError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _object(path: Path) -> dict:
    if not path.is_absolute():
        raise ActivationPlanError("readiness path must be absolute")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ActivationPlanError(f"invalid readiness evidence: {error}") from error
    if not isinstance(value, dict):
        raise ActivationPlanError("readiness evidence must be one JSON object")
    return value


def _name(value: str, label: str) -> str:
    if NAME.fullmatch(value) is None:
        raise ActivationPlanError(f"{label} is not a safe fixed identifier")
    return value


def build(readiness: dict, *, blue_project: str, green_project: str,
          blue_volume: str, green_volume: str, sandbox_network: str,
          private_ports: tuple[int,...] | list[int] | None = None) -> dict:
    if readiness.get("format") != "openepm-macos-pilot-upgrade-readiness-v1" \
            or readiness.get("readyForOperatorControlledUpgradePreparation") is not True \
            or readiness.get("readyForSharedActivation") is not False \
            or readiness.get("liveMutationSupportedByThisArtifact") is not False \
            or readiness.get("replacementProjectAndVolumeRequired") is not True:
        raise ActivationPlanError("qualified non-live readiness evidence is required")
    current, candidate, rollback = (readiness.get(key) for key in
                                    ("current", "candidate", "rollback"))
    if not all(isinstance(item, dict) for item in (current, candidate, rollback)):
        raise ActivationPlanError("readiness image and rollback bindings are incomplete")
    old_image, new_image = current.get("applicationImage"), candidate.get("applicationImage")
    database = candidate.get("databaseImage")
    if not all(isinstance(item, str) and IMAGE.fullmatch(item)
               for item in (old_image, new_image, database)) \
            or old_image == new_image \
            or rollback.get("applicationImage") != old_image \
            or current.get("databaseImage") != database \
            or rollback.get("databaseImage") != database:
        raise ActivationPlanError("readiness does not bind distinct exact images")
    backup = readiness.get("protectedBackup")
    if not isinstance(backup, dict) \
            or not isinstance(backup.get("sha256"), str) \
            or DIGEST.fullmatch(backup["sha256"]) is None \
            or not isinstance(backup.get("aclEntries"), int) \
            or isinstance(backup.get("aclEntries"), bool) \
            or backup["aclEntries"] <= 0:
        raise ActivationPlanError("ACL-preserving protected backup binding is missing")
    values = {
        "blueProject": _name(blue_project, "blue project"),
        "greenProject": _name(green_project, "green project"),
        "blueDatabaseVolume": _name(blue_volume, "blue database volume"),
        "greenDatabaseVolume": _name(green_volume, "green database volume"),
        "sandboxNetwork": _name(sandbox_network, "sandbox network"),
    }
    if values["blueProject"] == values["greenProject"] \
            or values["blueDatabaseVolume"] == values["greenDatabaseVolume"]:
        raise ActivationPlanError("blue and green projects/volumes must be distinct")
    port_binding=None
    if private_ports is not None:
        names=("web","platform","workspace","application")
        if not isinstance(private_ports,(tuple,list)) or len(private_ports)!=4 \
                or any(not isinstance(port,int) or isinstance(port,bool)
                       or port<1024 or port>65535 for port in private_ports) \
                or len(set(private_ports))!=4:
            raise ActivationPlanError("private port binding is invalid")
        port_binding=dict(zip(names,private_ports))
    body = {
        "format": "openepm-macos-pilot-activation-plan-v1",
        "readinessSha256": digest(readiness),
        "blue": {"slot": "blue", "project": values["blueProject"],
                 "databaseVolume": values["blueDatabaseVolume"],
                 "applicationImage": old_image, "databaseImage": database,
                 "schema": current.get("schema")},
        "green": {"slot": "green", "project": values["greenProject"],
                  "databaseVolume": values["greenDatabaseVolume"],
                  "applicationImage": new_image, "databaseImage": database,
                  "schema": candidate.get("targetSchema")},
        "sandboxNetwork": values["sandboxNetwork"],
        **({"privatePorts":port_binding} if port_binding is not None else {}),
        "protectedBackup": backup,
        "commands": ["prepare", "activate-read-only", "rollback", "commit"],
        "constraints": {
            "publicIngressStoppedUntilCommit": True,
            "writesDeniedUntilCommit": True,
            "bluePreservedUntilCommit": True,
            "rollbackPermittedAfterCommit": False,
            "commitIsPointOfNoReturn": True,
            "dockerExecutionIncluded": False,
            "sharedPilotMutationIncluded": False,
        },
    }
    return {**body, "planSha256": digest(body)}


def atomic_write(path: Path, value: dict) -> None:
    if not path.is_absolute():
        raise ActivationPlanError("output path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=".activation-plan-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readiness", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--blue-project", default="openepm-macos-pilot")
    parser.add_argument("--green-project", default="openepm-macos-pilot-green")
    parser.add_argument("--blue-volume", default="openepm-macos-pilot_postgres_data")
    parser.add_argument("--green-volume", default="openepm-macos-pilot-green_postgres_data")
    parser.add_argument("--sandbox-network", default="openepm-pilot-sandbox")
    parser.add_argument("--private-web-port", type=int, default=6201)
    parser.add_argument("--private-platform-port", type=int, default=6202)
    parser.add_argument("--private-workspace-port", type=int, default=6203)
    parser.add_argument("--private-application-port", type=int, default=6204)
    args = parser.parse_args()
    result = build(_object(args.readiness), blue_project=args.blue_project,
                   green_project=args.green_project, blue_volume=args.blue_volume,
                   green_volume=args.green_volume, sandbox_network=args.sandbox_network,
                   private_ports=(args.private_web_port,args.private_platform_port,
                     args.private_workspace_port,args.private_application_port))
    atomic_write(args.output, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
