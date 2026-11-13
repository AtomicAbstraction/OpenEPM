#!/usr/bin/env python3
"""Build the deterministic, sanitized tree used for Open EPM's public root."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.build_openepm_source_archive import (
    GitFile,
    SourcePackageError,
    canonical,
    forbidden,
    load_manifest,
    normalize_path,
    selected_git_files,
    validate_coverage,
)


DEFAULT_MANIFEST = ROOT / "deploy/release/public-repository.manifest.json"
ARCHIVE_ROOT = "openepm-public-root"
CI_REQUIRED_PATHS = frozenset({
    "Makefile",
    "requirements-dev.txt",
    "requirements-postgres-dev.txt",
    "requirements-postgres.txt",
})


def load_public_manifest(
        path: Path) -> tuple[dict, Path, list[str], list[str], dict[str, str]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SourcePackageError(f"cannot read public-root manifest: {error}") from error
    if value.get("format") != "openepm-public-repository-v1":
        raise SourcePackageError("unsupported public-root manifest format")
    source_manifest = normalize_path(value.get("sourcePackageManifest"))
    repository_paths = value.get("repositoryPaths")
    required_absent = value.get("requiredAbsent")
    raw_overlays = value.get("repositoryOverlays", {})
    if not isinstance(repository_paths, list) or not repository_paths:
        raise SourcePackageError("repositoryPaths must be a nonempty array")
    if not isinstance(required_absent, list) or not required_absent:
        raise SourcePackageError("requiredAbsent must be a nonempty array")
    if not isinstance(raw_overlays, dict):
        raise SourcePackageError("repositoryOverlays must be an object")
    repository_paths = [normalize_path(item) for item in repository_paths]
    required_absent = [normalize_path(item) for item in required_absent]
    overlays = {normalize_path(destination): normalize_path(source)
                for destination, source in raw_overlays.items()}
    if len(repository_paths) != len(set(repository_paths)):
        raise SourcePackageError("repositoryPaths contains duplicates")
    if len(required_absent) != len(set(required_absent)):
        raise SourcePackageError("requiredAbsent contains duplicates")
    for item in repository_paths:
        if forbidden(item):
            raise SourcePackageError(f"private path requested for public root: {item}")
    for destination, source in overlays.items():
        if forbidden(destination) or forbidden(source):
            raise SourcePackageError(
                f"private overlay requested for public root: {destination}")
        if source not in repository_paths:
            raise SourcePackageError(
                f"overlay source is not a repository path: {source}")
    return (value, ROOT / source_manifest, repository_paths, required_absent,
            overlays)


def selected_files(root: Path, manifest_path: Path) -> tuple[dict, list[GitFile]]:
    public, source_manifest_path, repository_paths, required_absent, overlays = (
        load_public_manifest(manifest_path))
    _, source_paths = load_manifest(source_manifest_path)
    validate_coverage(root, source_paths)
    files = selected_git_files(root, source_paths + repository_paths)
    by_path = {item.path: item for item in files}
    for destination, source in overlays.items():
        item = by_path[source]
        by_path[destination] = GitFile(destination, item.mode, item.data)
    files = sorted(by_path.values(), key=lambda item: item.path.encode("utf-8"))
    selected = {item.path for item in files}
    if ".github/workflows/ci.yml" in selected:
        missing_ci_paths = sorted(CI_REQUIRED_PATHS - selected)
        if missing_ci_paths:
            raise SourcePackageError(
                "public CI workflow dependencies are absent: "
                f"{missing_ci_paths}")
    leaked = sorted(path for path in selected if any(
        path == excluded or path.startswith(excluded + "/")
        for excluded in required_absent))
    if leaked:
        raise SourcePackageError(f"private paths entered public root: {leaked}")
    return public, files


def build(root: Path, manifest_path: Path, output: Path,
          source_date_epoch: int) -> dict:
    if source_date_epoch < 0:
        raise SourcePackageError("source-date-epoch must be nonnegative")
    manifest, files = selected_files(root, manifest_path)
    commit = __import__("subprocess").run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True,
        stdout=__import__("subprocess").PIPE, text=True).stdout.strip()
    descriptor = {
        "format": "openepm-public-root-candidate-v1",
        "sourceCommit": commit,
        "sourceDateEpoch": source_date_epoch,
        "publicManifestSha256": hashlib.sha256(canonical(manifest)).hexdigest(),
        "files": [{"path": item.path, "mode": oct(item.mode),
                   "sha256": hashlib.sha256(item.data).hexdigest()}
                  for item in files],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        payload = canonical(descriptor) + b"\n"
        info = tarfile.TarInfo(f"{ARCHIVE_ROOT}/PUBLIC_ROOT.json")
        info.size = len(payload); info.mode = 0o444; info.mtime = source_date_epoch
        info.uid = info.gid = 0; info.uname = info.gname = "root"
        archive.addfile(info, io.BytesIO(payload))
        for item in files:
            info = tarfile.TarInfo(f"{ARCHIVE_ROOT}/{item.path}")
            info.size = len(item.data); info.mode = item.mode & 0o777
            info.mtime = source_date_epoch; info.uid = info.gid = 0
            info.uname = info.gname = "root"
            archive.addfile(info, io.BytesIO(item.data))
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                           mtime=0, compresslevel=9) as compressed:
            compressed.write(buffer.getvalue())
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    return {**descriptor, "archive": output.name,
            "archiveSha256": digest, "archiveSize": output.stat().st_size}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    arguments = parser.parse_args()
    try:
        result = build(ROOT, arguments.manifest.resolve(),
                       arguments.output.resolve(), arguments.source_date_epoch)
    except SourcePackageError as error:
        raise SystemExit(f"public root rejected: {error}") from error
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
