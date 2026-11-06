#!/usr/bin/env python3
"""Fail-closed retirement audit for Hub, notebook and builder images.

This scanner is intentionally independent of the EPM database.  It can audit
an extracted image filesystem and, when executed inside an image, probe the
current interpreter and native loader.  A memory-backed use of the retired
engine is still a finding; changing a filename or connection URL is not an
acceptable workaround.
"""
from __future__ import annotations

import argparse
from ctypes.util import find_library
import importlib.util
import json
from pathlib import Path
import sys


MARKER = "sql" + "ite"
FORBIDDEN_BYTES = tuple(value.encode() for value in (
    MARKER, MARKER + "3", ":" + "memory:", MARKER + "://", "jdbc:" + MARKER))
ARCHIVE_SUFFIXES = frozenset((".egg", ".gz", ".tar", ".tgz", ".whl", ".zip"))
LIVE_VIRTUAL_ROOTS = frozenset(("dev", "proc", "run", "sys"))


class RetirementFinding(ValueError):
    pass


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _contains_forbidden(path: Path) -> bool:
    overlap = max(map(len, FORBIDDEN_BYTES)) - 1
    tail = b""
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            payload = (tail + chunk).lower()
            if any(marker in payload for marker in FORBIDDEN_BYTES):
                return True
            tail = payload[-overlap:]
    return False


def audit_tree(root: Path) -> dict[str, object]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise RetirementFinding("NOTEBOOK_RETIREMENT_ROOT_INVALID")
    findings: list[dict[str, str]] = []
    files = 0
    for path in sorted(root.rglob("*")):
        relative = _relative(root, path)
        # Container build mounts are not part of the image layer.  Inspecting
        # device and procfs pseudo-files can return EINVAL and says nothing
        # about the filesystem that will be copied into the final image.
        if root == Path("/") and relative.split("/", 1)[0] in LIVE_VIRTUAL_ROOTS:
            continue
        if path.is_symlink():
            try:
                target = path.resolve(strict=True)
            except (FileNotFoundError, RuntimeError):
                findings.append({"path": _relative(root, path), "kind": "unsafe_symlink"})
                continue
            if not target.is_relative_to(root):
                findings.append({"path": _relative(root, path), "kind": "external_symlink"})
            continue
        if not path.is_file():
            continue
        files += 1
        if MARKER in relative.lower():
            findings.append({"path": relative, "kind": "forbidden_name"})
            continue
        # Compressed package/cache payloads cannot be proven clean by a raw byte
        # search. They are not needed in a final runtime and therefore fail.
        if path.suffix.lower() in ARCHIVE_SUFFIXES:
            findings.append({"path": relative, "kind": "uninspectable_archive"})
            continue
        try:
            contains_forbidden = _contains_forbidden(path)
        except OSError:
            # A full-tree qualification is meaningful only when every regular
            # file can be inspected.  Runtime users may legitimately lack
            # access to root-owned account locks, but that must be reported as
            # an explicit failed audit rather than an unhandled traceback.
            findings.append({"path": relative, "kind": "unreadable_file"})
            continue
        if contains_forbidden:
            findings.append({"path": relative, "kind": "forbidden_content"})
    if findings:
        raise RetirementFinding(json.dumps({"code": "NOTEBOOK_RUNTIME_RETIRED_ENGINE_PRESENT",
                                             "findings": findings}, sort_keys=True))
    return {"root": str(root), "filesVisited": files, "findings": 0}


def probe_current_runtime() -> dict[str, object]:
    modules = [MARKER + "3", "_" + MARKER + "3", "dbm." + MARKER + "3"]
    available = [name for name in modules if importlib.util.find_spec(name) is not None]
    library = find_library(MARKER + "3")
    if available or library:
        raise RetirementFinding(json.dumps({
            "code": "NOTEBOOK_RUNTIME_RETIRED_ENGINE_RESOLVES",
            "modules": available, "nativeLibrary": library}, sort_keys=True))
    return {"modulesProbed": len(modules), "nativeLibrary": None}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--probe-current-runtime", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        result = {"tree": audit_tree(arguments.root)}
        if arguments.probe_current_runtime:
            result["runtime"] = probe_current_runtime()
    except RetirementFinding as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
