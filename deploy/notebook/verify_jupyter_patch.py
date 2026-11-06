#!/usr/bin/env python3
"""Verify and apply the exact maintained Jupyter Server source adaptation."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parent
CONTRACT = ROOT / "compatibility-contract.json"
MARKER = "sql" + "ite"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def _safe_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    result = []
    for member in archive.getmembers():
        path = Path(member.name)
        if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk():
            raise ValueError("JUPYTER_SOURCE_ARCHIVE_UNSAFE")
        result.append(member)
    return result


def verify_and_patch(source: Path, destination: Path, *, component_name: str = "jupyter_server",
                     contract: dict | None = None, patch_file: Path | None = None) -> dict[str, str]:
    contract = contract or json.loads(CONTRACT.read_text())
    component = contract["components"][component_name]
    patch_file = patch_file or ROOT / component["requiredAdaptation"]
    if digest(source) != component["sourceSha256"]:
        raise ValueError("JUPYTER_SOURCE_DIGEST_MISMATCH")
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(source, "r:gz") as archive:
        members = _safe_members(archive)
        roots = {Path(member.name).parts[0] for member in members if Path(member.name).parts}
        if len(roots) != 1:
            raise ValueError("JUPYTER_SOURCE_LAYOUT_INVALID")
        archive.extractall(destination, members=members, filter="data")
    source_root = destination / roots.pop()
    targets = component.get("targets") or [{
        "path": component["targetPath"], "before": component["targetSha256Before"],
        "after": component["targetSha256After"]}]
    for item in targets:
        target = source_root / item["path"]
        if not target.is_file() or digest(target) != item["before"]:
            raise ValueError("JUPYTER_PATCH_TARGET_MISMATCH: " + item["path"])
    applied = subprocess.run(
        ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(patch_file)],
        cwd=source_root, text=True, capture_output=True, check=False)
    if applied.returncode != 0:
        detail = "\n".join(value for value in (applied.stdout.strip(), applied.stderr.strip()) if value)
        raise ValueError("JUPYTER_PATCH_APPLICATION_FAILED: " + detail)
    output = {}
    for item in targets:
        target = source_root / item["path"]
        if digest(target) != item["after"]:
            raise ValueError("JUPYTER_PATCHED_TARGET_MISMATCH: " + item["path"])
        lowered = target.read_bytes().lower()
        if MARKER.encode() in lowered or b":memory:" in lowered:
            raise ValueError("JUPYTER_PATCHED_TARGET_RETAINS_BACKEND: " + item["path"])
        output[item["path"]] = item["after"]
    return {"component": component_name, "sourceSha256": digest(source),
            "targets": output, "sourceRoot": str(source_root)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("component", choices=("jupyter_server", "nbformat", "jupyterhub"))
    parser.add_argument("source", type=Path)
    parser.add_argument("--destination", type=Path)
    arguments = parser.parse_args(argv)
    if arguments.destination:
        print(json.dumps(verify_and_patch(arguments.source, arguments.destination,
                                          component_name=arguments.component), sort_keys=True))
    else:
        with tempfile.TemporaryDirectory(prefix="openepm-jupyter-patch-") as directory:
            print(json.dumps(verify_and_patch(arguments.source, Path(directory) / "source",
                                               component_name=arguments.component),
                             sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
