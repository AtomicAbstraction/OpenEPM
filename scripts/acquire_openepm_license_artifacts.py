#!/usr/bin/env python3
"""Plan, acquire, and verify wheel license evidence without installing it."""
from __future__ import annotations

import argparse
from email.parser import Parser
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit, urlunsplit
import zipfile

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
# Some release helpers import through the repository-level ``scripts``
# namespace.  Keep the documented executable form (``python scripts/...``)
# equivalent to ``python -m scripts...`` instead of depending on caller
# PYTHONPATH state.
sys.path.insert(0, str(SCRIPT_DIR.parent))
from build_openepm_source_archive import ROOT, SourcePackageError, canonical  # noqa: E402
from build_openepm_source_compliance import LOCKS, locked_dependencies, normalized  # noqa: E402


TARGETS = {
    # pip's explicit selector does not infer older compatible manylinux tags.
    # Admit both wheel baselines used by the locks; both are below the Ubuntu
    # 24.04 glibc 2.39 reference host.
    "linux-amd64-cp314": {"platforms":
        ["manylinux_2_28_x86_64", "manylinux2014_x86_64"], "arch": "linux/amd64"},
    "linux-arm64-cp314": {"platforms":
        ["manylinux_2_28_aarch64", "manylinux2014_aarch64"], "arch": "linux/arm64"},
}
WHEEL = re.compile(r"^[A-Za-z0-9_.]+-[A-Za-z0-9_.!+]+-.+\.whl$")
LICENSE_FILE = re.compile(r"^(license|licence|copying|copyright|authors|notice)(\.|$)", re.I)


def outside_source(root: Path, destination: Path) -> Path:
    root, destination = root.resolve(), destination.resolve()
    if destination == root or root in destination.parents:
        raise SourcePackageError("license artifacts must stay outside the source tree")
    return destination


def plan(*, root: Path, acquisition_root: Path) -> dict:
    dependencies = locked_dependencies(root)
    acquisition_root = outside_source(root, acquisition_root)
    commands = []
    for target, profile in TARGETS.items():
        destination = acquisition_root / "downloads" / target
        for ordinal, relative in enumerate(LOCKS, 1):
            argv = [sys.executable, "-m", "pip", "download",
                    "--disable-pip-version-check", "--require-hashes",
                    "--only-binary=:all:", "--no-deps"]
            for platform in profile["platforms"]:
                argv += ["--platform", platform]
            argv += ["--implementation", "cp",
                    "--python-version", "3.14", "--abi", "cp314",
                    "--dest", str(destination), "--log",
                    str(acquisition_root / "logs" /
                        f"{target}-{ordinal:02d}.pip.log"),
                    "--requirement", str((root / relative).resolve())]
            commands.append({"target": target, "lock": relative, "argv": argv})
    return {"format": "openepm-license-acquisition-plan-v1",
        "status": "network-not-executed", "installPackages": False,
        "sdistsAllowed": [], "targets": TARGETS,
        "lockedPackageCount": len(dependencies), "commands": commands,
        "lockSha256": {relative: hashlib.sha256(
            (root / relative).read_bytes()).hexdigest() for relative in LOCKS}}


def safe_url(value: str) -> str:
    parsed = urlsplit(value.rstrip("),]"))
    if parsed.scheme not in {"https", "http"} or not parsed.netloc \
            or parsed.username or parsed.password:
        raise SourcePackageError("download provenance URL is unsafe")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def urls(log_paths: list[Path]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for log in log_paths:
        if not log.is_file() or log.is_symlink():
            raise SourcePackageError(f"pip acquisition log is missing: {log}")
        for raw in re.findall(r"https?://[^\s]+", log.read_text(
                encoding="utf-8", errors="strict")):
            value = safe_url(raw)
            filename = Path(unquote(urlsplit(value).path)).name
            if filename.endswith(".whl"):
                result.setdefault(filename, set()).add(value)
    return result


def verify(*, root: Path, acquisition_root: Path, plan_value: dict) -> dict:
    acquisition_root = outside_source(root, acquisition_root)
    if plan_value != plan(root=root, acquisition_root=acquisition_root):
        raise SourcePackageError("acquisition plan differs from current exact plan")
    if (plan_value.get("format") != "openepm-license-acquisition-plan-v1"
            or plan_value.get("sdistsAllowed") != []
            or plan_value.get("installPackages") is not False):
        raise SourcePackageError("acquisition plan permits unsupported behavior")
    dependencies = locked_dependencies(root)
    expected_lock_hashes = {relative: hashlib.sha256(
        (root / relative).read_bytes()).hexdigest() for relative in LOCKS}
    if plan_value.get("lockSha256") != expected_lock_hashes:
        raise SourcePackageError("lock identities changed after acquisition planning")
    log_paths = [Path(item["argv"][item["argv"].index("--log") + 1])
                 for item in plan_value["commands"]]
    provenance_urls = urls(log_paths)
    artifacts = []
    proposal_roots = []
    for target in TARGETS:
        directory = acquisition_root / "downloads" / target
        if not directory.is_dir() or directory.is_symlink():
            raise SourcePackageError(f"target download directory is missing: {target}")
        unexpected = sorted(path.name for path in directory.iterdir()
                            if path.is_file() and path.suffix != ".whl")
        if unexpected:
            raise SourcePackageError(f"sdists/unsupported artifacts rejected: {unexpected}")
        seen = set()
        metadata_root = acquisition_root / "verified-metadata" / target
        metadata_root.mkdir(parents=True, exist_ok=True)
        for wheel in sorted(directory.glob("*.whl")):
            if wheel.is_symlink() or not WHEEL.fullmatch(wheel.name):
                raise SourcePackageError(f"invalid wheel artifact: {wheel.name}")
            digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            with zipfile.ZipFile(wheel) as archive:
                names = archive.namelist()
                metadata_names = [name for name in names
                                  if name.count("/") == 1
                                  and name.endswith(".dist-info/METADATA")]
                if len(metadata_names) != 1:
                    raise SourcePackageError(f"wheel METADATA is ambiguous: {wheel.name}")
                metadata_name = metadata_names[0]
                metadata_parent = Path(metadata_name).parent
                if (not re.fullmatch(r"[A-Za-z0-9_.-]+\.dist-info",
                                     metadata_parent.name)
                        or any(part in ("", ".", "..")
                               for part in metadata_parent.parts)):
                    raise SourcePackageError(
                        f"unsafe wheel metadata path: {metadata_name}")
                metadata_bytes = archive.read(metadata_name)
                message = Parser().parsestr(metadata_bytes.decode("utf-8"))
                package, version = normalized(message.get("Name", "")), message.get("Version")
                expected = dependencies.get(package)
                if not expected or version != expected["version"] or digest not in expected["hashes"]:
                    raise SourcePackageError(f"wheel is not admitted by exact locks: {wheel.name}")
                if package in seen:
                    raise SourcePackageError(f"duplicate wheel for target/package: {target}/{package}")
                seen.add(package)
                urls_for_wheel = sorted(provenance_urls.get(wheel.name, ()))
                if len(urls_for_wheel) != 1:
                    raise SourcePackageError(f"wheel URL provenance is missing/ambiguous: {wheel.name}")
                dist_info = metadata_root / Path(metadata_name).parent.name
                dist_info.mkdir(parents=True, exist_ok=False)
                (dist_info / "METADATA").write_bytes(metadata_bytes)
                license_records = []
                for name in sorted(names):
                    path = Path(name)
                    if (path.parts and path.parts[0] == Path(metadata_name).parts[0]
                            and LICENSE_FILE.match(path.name) and not name.endswith("/")):
                        if path.is_absolute() or any(part in ("", ".", "..")
                                                     for part in path.parts):
                            raise SourcePackageError(
                                f"unsafe wheel license path: {name}")
                        payload = archive.read(name)
                        relative = Path(*path.parts[1:])
                        destination = dist_info / relative
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_bytes(payload)
                        license_records.append({"path":
                            destination.relative_to(metadata_root).as_posix(),
                            "sha256": hashlib.sha256(payload).hexdigest()})
            artifacts.append({"target": target, "architecture": TARGETS[target]["arch"],
                "package": package, "version": version, "filename": wheel.name,
                "sha256": digest, "url": urls_for_wheel[0],
                "lockPaths": expected["locks"],
                "metadataPath": (dist_info / "METADATA").relative_to(
                    metadata_root).as_posix(),
                "metadataSha256": hashlib.sha256(metadata_bytes).hexdigest(),
                "licenseFiles": license_records})
        missing = sorted(set(dependencies) - seen)
        if missing:
            raise SourcePackageError(f"platform wheel coverage gap {target}: {missing}")
        proposal_roots.append(str(metadata_root))
    return {"format": "openepm-license-artifact-provenance-v1",
        "status": "verified-unapproved", "packagesInstalled": False,
        "networkExecutionRecorded": True, "targets": TARGETS,
        "lockedPackageCount": len(dependencies), "artifacts": artifacts,
        "proposalMetadataRoots": proposal_roots,
        "lockSha256": expected_lock_hashes}


def execute(plan_value: dict, acquisition_root: Path, *, root: Path = ROOT) -> None:
    if os.environ.get("EPM_LICENSE_ACQUISITION_NETWORK") != "1":
        raise SourcePackageError("network acquisition opt-in is required")
    if plan_value != plan(root=root, acquisition_root=acquisition_root):
        raise SourcePackageError("acquisition plan differs from current exact plan")
    acquisition_root.mkdir(parents=True, exist_ok=False)
    (acquisition_root / "logs").mkdir()
    for target in TARGETS:
        (acquisition_root / "downloads" / target).mkdir(parents=True)
    for item in plan_value["commands"]:
        subprocess.run(item["argv"], check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("plan", "execute", "verify"))
    parser.add_argument("--acquisition-root", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "plan":
            value = plan(root=ROOT, acquisition_root=args.acquisition_root)
            if args.plan.exists():
                raise SourcePackageError("plan output already exists")
            args.plan.write_bytes(canonical(value) + b"\n")
        else:
            value = json.loads(args.plan.read_text(encoding="utf-8"))
            if args.mode == "execute":
                execute(value, args.acquisition_root.resolve(), root=ROOT)
            else:
                if not args.output or args.output.exists():
                    raise SourcePackageError("new provenance output is required")
                result = verify(root=ROOT,
                    acquisition_root=args.acquisition_root.resolve(), plan_value=value)
                args.output.write_bytes(canonical(result) + b"\n")
                value = result
    except (SourcePackageError, OSError, json.JSONDecodeError,
            subprocess.CalledProcessError) as error:
        parser.error(str(error))
    print(json.dumps({"format": value["format"],
                      "status": value["status"]}, sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
