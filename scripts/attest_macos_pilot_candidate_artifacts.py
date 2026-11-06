#!/usr/bin/env python3
"""Attest exact Mac-pilot candidate images without activating them."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_ID = re.compile(r"^[0-9a-f]{40}$")
OPT_IN = "EPM_PILOT_ARTIFACT_ATTESTATION"


class AttestationError(ValueError):
    pass


def validate(application_image: str, database_image: str,
             output: Path) -> dict[str, object]:
    if IMAGE.fullmatch(application_image) is None:
        raise AttestationError(
            "application image must be an exact sha256 identity")
    if IMAGE.fullmatch(database_image) is None:
        raise AttestationError(
            "database image must be an exact sha256 identity")
    if not output.is_absolute():
        raise AttestationError("attestation output must be absolute")
    return {
        "format": "openepm-macos-pilot-artifact-attestation-plan-v1",
        "applicationImage": application_image,
        "databaseImage": database_image,
        "architecture": "linux/arm64",
        "output": str(output),
        "sharedPilotMutation": False,
    }


def system_run(arguments: list[str], timeout: int = 300) -> str:
    completed = subprocess.run(
        arguments, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=timeout)
    if completed.returncode:
        raise AttestationError("candidate artifact check failed")
    return completed.stdout.strip()


def inspect_image(image: str, *, run: Callable[[list[str], int], str]) -> dict:
    try:
        value = json.loads(run(["docker", "image", "inspect", image], 30))
        record = value[0]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise AttestationError("candidate image inspection is invalid") from error
    if record.get("Id") != image:
        raise AttestationError("candidate image identity differs from input")
    if record.get("Os") != "linux" or record.get("Architecture") != "arm64":
        raise AttestationError("candidate image must be native linux/arm64")
    config = record.get("Config")
    if not isinstance(config, dict):
        raise AttestationError("candidate image configuration is invalid")
    labels = config.get("Labels") or {}
    if not isinstance(labels, dict):
        raise AttestationError("candidate image labels are invalid")
    return {"id": image, "labels": labels}


def retirement_check(image: str, kind: str, *,
                     run: Callable[[list[str], int], str]) -> None:
    script = ROOT / "scripts/check_delivered_runtime.py"
    try:
        value = json.loads(run(
            [sys.executable, str(script), image, kind], 300))
    except json.JSONDecodeError as error:
        raise AttestationError("runtime-retirement result is invalid") from error
    if (not isinstance(value, dict) or value.get("imageId") != image
            or value.get("kind") != kind
            or value.get("architecture") != "linux/arm64"
            or value.get("serverPdfParserPresent") is not False):
        raise AttestationError("runtime-retirement result is not exact")


def attest(plan: dict[str, object], *,
           run: Callable[[list[str], int], str] = system_run) -> dict[str, object]:
    if os.environ.get(OPT_IN) != "1":
        raise AttestationError("candidate artifact attestation opt-in is required")
    application = str(plan["applicationImage"])
    database = str(plan["databaseImage"])
    app_record = inspect_image(application, run=run)
    inspect_image(database, run=run)
    labels = app_record["labels"]
    commit = labels.get("org.openepm.source.commit")
    tree = labels.get("org.openepm.source.tree")
    if (labels.get("org.openepm.qualification") != "schema163-public-parity"
            or not isinstance(commit, str) or GIT_ID.fullmatch(commit) is None
            or not isinstance(tree, str) or GIT_ID.fullmatch(tree) is None):
        raise AttestationError("application source labels are not exact")
    retirement_check(application, "app", run=run)
    retirement_check(database, "db", run=run)
    return {
        "format": "openepm-macos-pilot-artifact-attestation-v1",
        "passed": True,
        "applicationImage": application,
        "databaseImage": database,
        "architecture": "linux/arm64",
        "qualification": "schema163-public-parity",
        "sourceCommit": commit,
        "sourceTree": tree,
        "applicationSourceLabelsMatch": True,
        "runtimeRetirementChecksPassed": True,
        "sharedPilotMutation": False,
    }


def atomic_write(path: Path, value: dict[str, object]) -> None:
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise AttestationError("attestation output directory is unavailable")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=path.parent,
                prefix="." + path.name + ".", suffix=".tmp",
                delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--application-image", required=True)
    parser.add_argument("--database-image", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        plan = validate(arguments.application_image, arguments.database_image,
                        arguments.output)
        if not arguments.execute:
            print(json.dumps(plan, sort_keys=True))
            return 0
        result = attest(plan)
        atomic_write(arguments.output, result)
    except (AttestationError, OSError, subprocess.TimeoutExpired) as error:
        parser.error(str(error))
    print(json.dumps({"passed": True, "output": str(arguments.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
