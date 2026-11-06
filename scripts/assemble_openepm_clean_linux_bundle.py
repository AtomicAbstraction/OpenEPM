#!/usr/bin/env python3
"""Assemble clean-Linux qualification tooling without claiming execution."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import urllib.parse

from build_openepm_clean_linux_runner_config import build as build_runner_config
from build_openepm_clean_linux_profiles import (publication_contract,
    qualification_source_digest, QUALIFICATION_SOURCE)


class BundleError(ValueError):
    pass


COMPONENTS = {"application", "database", "operations", "builder",
              "notebook", "hub", "identity", "proxy", "browser_gateway",
              "browser_session_store"}
CONTEXT_ARTIFACTS = {
    "bundleManifest": "qualification-bundle-manifest.json",
    "releaseManifest": "release-manifest.json",
    "epmctl": "epmctl",
    "browserProbeExecutable": "browser-probe",
    "browserProbeConfig": "browser-probe.json",
    "pythonBuildProbeExecutable": "python-build-publication-probe",
    "pythonBuildProbeConfig": "python-build-publication-probe.json",
    "headlessRunscProfile": "headless-runsc-profile.json",
    "notebookRunscProfile": "notebook-runsc-profile.json",
    "populatedVerifier": "populated-verifier",
    "restoredPopulatedVerifier": "restored-populated-verifier",
    "mcpRequest": "mcp-request.json",
    "sourceAttestationModule": "create_openepm_source_backup_attestation.py",
}


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
FIXED = {
    "openepm_clean_linux_phase.py": (SCRIPT_DIR / "openepm_clean_linux_phase.py", 0o555),
    "run_openepm_clean_linux_qualification.py": (SCRIPT_DIR / "run_openepm_clean_linux_qualification.py", 0o555),
    "build_openepm_clean_linux_runner_config.py": (SCRIPT_DIR / "build_openepm_clean_linux_runner_config.py", 0o555),
    "qualify_openepm_clean_linux_release.py": (SCRIPT_DIR / "qualify_openepm_clean_linux_release.py", 0o444),
    "openepm_release_inventory.py": (SCRIPT_DIR / "openepm_release_inventory.py", 0o444),
    "create_openepm_source_backup_attestation.py": (SCRIPT_DIR / "create_openepm_source_backup_attestation.py", 0o444),
    "browser-probe": (SCRIPT_DIR / "openepm_browser_probe.py", 0o555),
    "python-build-publication-probe": (
        SCRIPT_DIR / "openepm_python_build_publication_probe.py", 0o555),
    "python-publication-program.py": (QUALIFICATION_SOURCE, 0o444),
    "notebook-kernel-debug-probe.py": (
        SCRIPT_DIR / "openepm_notebook_kernel_debug_probe.py", 0o444),
    "epmctl": (ROOT / "deploy/release/epmctl", 0o555),
}
SUPPLIED = {
    "release-manifest.json": "release_manifest",
    "qualification-context.json": "context",
    "browser-probe.json": "browser_config",
    "python-build-publication-probe.json": "python_build_config",
    "headless-runsc-profile.json": "headless_profile",
    "notebook-runsc-profile.json": "notebook_profile",
    "populated-verifier": "populated_verifier",
    "restored-populated-verifier": "restored_verifier",
    "mcp-request.json": "mcp_request",
}
EXECUTABLES = {"openepm_clean_linux_phase.py", "run_openepm_clean_linux_qualification.py",
               "build_openepm_clean_linux_runner_config.py", "epmctl", "browser-probe",
               "python-build-publication-probe",
               "populated-verifier", "restored-populated-verifier"}


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source(path: Path, label: str) -> Path:
    if path.is_symlink():
        raise BundleError(f"{label} is missing or symbolic")
    path = path.resolve()
    if not path.is_file():
        raise BundleError(f"{label} is missing or symbolic")
    return path


def portable_context(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BundleError(f"invalid qualification context: {error}") from error
    if not isinstance(value, dict) or value.get("bundleRoot") != ".":
        raise BundleError(
            "qualification context bundleRoot must be '.' for portable execution")
    if any(value.get(field) != expected
           for field, expected in CONTEXT_ARTIFACTS.items()):
        raise BundleError("qualification context bundle artifacts are invalid")
    if value.get("cleanHost") is not True:
        raise BundleError("qualification context must require a clean host")
    for field in ("mcpTokenFile", "browserIdentitySecretsDirectory",
                  "pythonBuildTokenFile",
                  "notebookHubApiTokenFile", "notebookLauncherProfileFile",
                  "sourceBackupAttestation", "sourceAttestationKeyFile",
                  "backupExportRoot"):
        item = value.get(field)
        if not isinstance(item, str) or not item or not Path(item).is_absolute() \
                or ".." in Path(item).parts:
            raise BundleError(f"qualification context {field} must be an absolute host path")
    for field in ("databaseContainer", "databaseUser", "databaseName",
                  "restoreTargetProject"):
        item = value.get(field)
        if not isinstance(item, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", item):
            raise BundleError(f"qualification context {field} is invalid")
    endpoint = value.get("mcpEndpoint")
    try:
        parsed = urllib.parse.urlsplit(endpoint) if isinstance(endpoint, str) else None
        port = parsed.port if parsed is not None else None
    except ValueError as error:
        raise BundleError("qualification context mcpEndpoint is invalid") from error
    if parsed is None or parsed.scheme != "https" or not parsed.hostname \
            or parsed.username is not None or parsed.password is not None \
            or parsed.fragment or port == 0:
        raise BundleError("qualification context mcpEndpoint must be credential-free HTTPS")
    hub_endpoint = value.get("notebookHubApiEndpoint")
    try:
        hub = urllib.parse.urlsplit(hub_endpoint) \
            if isinstance(hub_endpoint, str) else None
        hub_port = hub.port if hub is not None else None
    except ValueError as error:
        raise BundleError("qualification context notebook Hub endpoint is invalid") from error
    if hub is None or hub.scheme != "https" or not hub.hostname \
            or hub.username is not None or hub.password is not None \
            or hub.fragment or hub.query or hub_port == 0 \
            or hub.path.rstrip("/") != "/hub/api":
        raise BundleError(
            "qualification context notebook Hub endpoint must be credential-free HTTPS /hub/api")
    if not re.fullmatch(r"u-[a-f0-9]{32}",
                        value.get("notebookQualificationUsername", "")):
        raise BundleError("qualification context notebook qualification username is invalid")
    if value.get("notebookLauncherJournalUnit") != \
            "openepm-notebook-launcher.service":
        raise BundleError("qualification context notebook launcher journal unit is invalid")
    if value.get("sandboxLauncherJournalUnit") != \
            "openepm-sandbox-launcher.service":
        raise BundleError("qualification context sandbox launcher journal unit is invalid")
    maximum = value.get("backupMaximumBytes")
    if type(maximum) is not int or not 1 <= maximum <= 1024 ** 4:
        raise BundleError("qualification context backupMaximumBytes is invalid")
    return value


def json_object(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BundleError(f"invalid {label}: {error}") from error
    if not isinstance(value, dict):
        raise BundleError(f"{label} must be an object")
    return value


def validate_plan_bindings(plan_path: Path, incoming: dict[str, Path],
                           context: dict) -> None:
    plan = json_object(plan_path, "qualification plan")
    images = plan.get("nativeImageDigests")
    if not isinstance(images, dict) or set(images) != COMPONENTS \
            or any(not isinstance(value, str) or not value.startswith("sha256:")
                   or len(value) != 71
                   or any(character not in "0123456789abcdef"
                          for character in value[7:]) for value in images.values()):
        raise BundleError("qualification plan image bindings are incomplete")
    if context.get("images") != images:
        raise BundleError("qualification context images differ from the plan")
    expected_release = plan.get("releaseManifestSha256")
    if not isinstance(expected_release, str) or sha(
            incoming["release-manifest.json"]) != expected_release:
        raise BundleError("release manifest differs from the qualification plan")
    profiles = (("headless-runsc-profile.json", "image", "builder"),
                ("notebook-runsc-profile.json", "image", "notebook"),
                ("python-build-publication-probe.json", "builderImage", "builder"))
    for name, field, component in profiles:
        value = json_object(incoming[name], name)
        if value.get(field) != images[component]:
            raise BundleError(f"{name} does not bind the planned {component} image")
        if name == "python-build-publication-probe.json":
            if value.get("format") != "openepm-python-build-publication-probe-v2":
                raise BundleError("Python build/publication probe format is invalid")
            try:
                publication_contract({key: item for key, item in value.items()
                                      if key not in {"format", "builderImage",
                                                     "expectedSourceDigest"}})
            except ValueError as error:
                raise BundleError(str(error)) from error
            if value.get("expectedSourceDigest") != qualification_source_digest():
                raise BundleError("Python qualification source digest differs")
    maximum = context.get("proxyRetirementMaximumBytes")
    if type(maximum) is not int or not 1024 <= maximum <= 1024 * 1024 * 1024:
        raise BundleError("proxy retirement bound is absent or invalid")


def assemble(*, output: Path, plan: Path, supplied: dict[str, Path]) -> dict:
    if output.exists() or output.is_symlink():
        raise BundleError("output directory already exists")
    plan = source(plan, "qualification plan")
    if set(supplied) != set(SUPPLIED.values()):
        raise BundleError("all supplied qualification artifacts are required")
    incoming = {name: source(supplied[key], name)
                for name, key in SUPPLIED.items()}
    context = portable_context(incoming["qualification-context.json"])
    validate_plan_bindings(plan, incoming, context)
    output.mkdir(mode=0o755)
    try:
        for name, (path, mode) in FIXED.items():
            shutil.copyfile(path, output / name)
            (output / name).chmod(mode)
        for name, path in incoming.items():
            shutil.copyfile(path, output / name)
            (output / name).chmod(0o555 if name in EXECUTABLES else 0o444)
        records = [{"path": path.name, "sha256": sha(path)}
                   for path in sorted(output.iterdir())]
        plan_value = json.loads(plan.read_text(encoding="utf-8"))
        inner = {"format": "openepm-clean-linux-bundle-manifest-v1",
            "sourceCommit": plan_value["sourceCommit"],
            "schemaMigration": plan_value["schemaMigration"],
            "sourceTreeSha256": hashlib.sha256(canonical(records)).hexdigest(),
            "files": records}
        inner_path = output / "qualification-bundle-manifest.json"
        inner_path.write_bytes(canonical(inner) + b"\n")
        inner_path.chmod(0o444)
        config = build_runner_config(plan, output,
            bundle_manifest=inner_path.name,
            release_manifest="release-manifest.json",
            phase_harness="openepm_clean_linux_phase.py",
            context="qualification-context.json")
        config_path = output / "qualification-runner-config.json"
        config_path.write_bytes(canonical(config) + b"\n")
        config_path.chmod(0o444)
        outer_records = [{"path": path.name, "sha256": sha(path),
                          "executable": path.name in EXECUTABLES}
                         for path in sorted(output.iterdir())]
        index = {"format": "openepm-clean-linux-bundle-index-v1",
            "status": "execution-required", "qualificationClaimed": False,
            "files": outer_records}
        index_path = output / "qualification-bundle-index.json"
        index_path.write_bytes(canonical(index) + b"\n")
        index_path.chmod(0o444)
        return index
    except Exception:
        if output.exists():
            shutil.rmtree(output)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    for key in SUPPLIED.values():
        parser.add_argument("--" + key.replace("_", "-"), type=Path, required=True)
    args = parser.parse_args()
    try:
        value = assemble(output=args.output.resolve(), plan=args.plan.resolve(),
                         supplied={key: getattr(args, key) for key in SUPPLIED.values()})
    except (BundleError, KeyError, ValueError, OSError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
