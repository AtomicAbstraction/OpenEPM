#!/usr/bin/env python3
"""Build a bound runner config for a clean-Linux release bundle."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


class ConfigError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ConfigError(f"invalid {label}: {error}") from error
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be an object")
    return value


def bundle_child(root: Path, relative: str, label: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute() \
            or ".." in Path(relative).parts:
        raise ConfigError(f"invalid {label} path")
    candidate = root / relative
    if candidate.is_symlink():
        raise ConfigError(f"{label} must not be symbolic")
    path = candidate.resolve()
    if root not in path.parents or not path.is_file():
        raise ConfigError(f"{label} is outside or missing from bundle")
    return path


def build(plan_path: Path, root: Path, *, bundle_manifest: str,
          release_manifest: str, phase_harness: str, context: str) -> dict:
    plan = load(plan_path, "qualification plan")
    phases = plan.get("phases")
    if not isinstance(phases, list) or not phases or len(phases) != len(set(phases)) \
            or any(not isinstance(item, str) or not item for item in phases):
        raise ConfigError("qualification plan phases are invalid")
    root = root.resolve()
    if not root.is_dir():
        raise ConfigError("bundle root is not a directory")
    paths = {"bundle manifest": bundle_child(root, bundle_manifest, "bundle manifest"),
        "release manifest": bundle_child(root, release_manifest, "release manifest"),
        "phase harness": bundle_child(root, phase_harness, "phase harness"),
        "context": bundle_child(root, context, "context")}
    bundle = load(paths["bundle manifest"], "bundle manifest")
    items = bundle.get("files")
    if not isinstance(items, list):
        raise ConfigError("bundle manifest file records are absent")
    records = {}
    for item in items:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"} \
                or not isinstance(item["path"], str) or item["path"] in records:
            raise ConfigError("bundle manifest file records are invalid or duplicated")
        records[item["path"]] = item["sha256"]
    for relative, label in ((phase_harness, "phase harness"), (context, "context"),
                            (release_manifest, "release manifest")):
        if records.get(relative) != sha(paths[label]):
            raise ConfigError(f"{label} is not bundle-manifest bound")
    executable = {"path": phase_harness, "sha256": sha(paths["phase harness"])}
    return {"format": "openepm-clean-linux-runner-config-v1",
        "planSha256": hashlib.sha256(canonical(plan)).hexdigest(),
        # The runner rebases this relative root against the config file.  Never
        # bind the assembly host's temporary absolute path into a bundle that
        # must be copied to two independent clean hosts.
        "bundleRoot": ".",
        "releaseManifest": {"path": release_manifest,
            "sha256": sha(paths["release manifest"])},
        "bundleManifest": {"path": bundle_manifest,
            "sha256": sha(paths["bundle manifest"])},
        "phaseExecutables": {phase: executable for phase in phases},
        "commands": {phase: [phase_harness, "--phase", phase,
                              "--context", context] for phase in phases}}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--bundle-manifest", required=True)
    parser.add_argument("--release-manifest", required=True)
    parser.add_argument("--phase-harness", required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.output.exists():
        parser.error("output already exists")
    try:
        result = build(arguments.plan.resolve(), arguments.bundle_root,
            bundle_manifest=arguments.bundle_manifest,
            release_manifest=arguments.release_manifest,
            phase_harness=arguments.phase_harness, context=arguments.context)
    except ConfigError as error:
        parser.error(str(error))
    arguments.output.write_bytes(canonical(result) + b"\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
