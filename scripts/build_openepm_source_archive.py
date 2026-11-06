#!/usr/bin/env python3
"""Build a deterministic, manifest-bounded Open EPM source archive."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import fnmatch
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shlex
import subprocess
import tarfile


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "deploy/release/source-package.manifest.json"
ARCHIVE_ROOT = "openepm-source"
RELEASE_CONTRACTS = {
    "deploy/release/openepm.env.example",
    "deploy/release/source-package.manifest.json",
    "deploy/release/release-manifest.schema.json",
    "deploy/release/release-manifest.example.json",
    "deploy/release/epm_python_builder_profiles.example.json",
}
FORBIDDEN_COMPONENTS = {
    ".git", ".entire", ".codex", ".agents", ".aws", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", "node_modules",
    "pgdata", "wal_archive", "base_backups", "notebook-user-data",
    "agent-transcripts",
}
_RETIRED_DB_SUFFIX = "." + "sql" + "ite"
FORBIDDEN_SUFFIXES = {".pyc", ".pyo", ".pem", ".key", _RETIRED_DB_SUFFIX, _RETIRED_DB_SUFFIX + "3"}


class SourcePackageError(RuntimeError):
    pass


@dataclass(frozen=True)
class GitFile:
    path: str
    mode: int
    data: bytes


def git(*arguments: str, root: Path = ROOT, binary: bool = False):
    result = subprocess.run(["git", *arguments], cwd=root,
        check=True, stdout=subprocess.PIPE,
        text=not binary)
    return result.stdout


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def normalize_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise SourcePackageError(f"invalid required path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise SourcePackageError(f"unsafe required path: {value}")
    normalized = path.as_posix()
    if normalized != value.rstrip("/"):
        raise SourcePackageError(f"non-canonical required path: {value}")
    return normalized


def forbidden(path: str) -> bool:
    value = PurePosixPath(path)
    lowered = {part.lower() for part in value.parts}
    if lowered & FORBIDDEN_COMPONENTS or value.suffix.lower() in FORBIDDEN_SUFFIXES:
        return True
    name = value.name.lower()
    return (name in {"id_rsa", "id_ed25519", ".env"}
            or name.endswith(".secret") or name.endswith(".credentials"))


def load_manifest(path: Path) -> tuple[dict, list[str]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SourcePackageError(f"cannot read source manifest: {error}") from error
    if value.get("format") != "openepm-source-package-v1":
        raise SourcePackageError("unsupported source manifest format")
    raw = value.get("requiredPaths")
    if not isinstance(raw, list) or not raw:
        raise SourcePackageError("requiredPaths must be a nonempty array")
    paths = [normalize_path(item) for item in raw]
    if len(paths) != len(set(paths)):
        raise SourcePackageError("requiredPaths contains duplicates")
    for required in paths:
        if forbidden(required):
            raise SourcePackageError(f"excluded private/runtime class: {required}")
    return value, paths


def covered(path: str, required: list[str]) -> bool:
    return any(path == item or path.startswith(item + "/") for item in required)


def docker_copy_sources(root: Path, required: list[str]) -> set[str]:
    sources: set[str] = set()
    tracked = set(git("ls-files", root=root).splitlines())
    for dockerfile in sorted(root.glob("deploy/**/Dockerfile*")):
        relative = dockerfile.relative_to(root).as_posix()
        # A source archive is closed over the build recipes it actually ships.
        # Internal qualification recipes may deliberately consume test/evidence
        # material that is not part of the portable production source package.
        if not covered(relative, required):
            continue
        logical: list[str] = []
        pending = ""
        for line in dockerfile.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            pending += stripped[:-1] + " " if stripped.endswith("\\") else stripped
            if stripped.endswith("\\"):
                continue
            if pending.startswith("COPY "):
                logical.append(pending)
            pending = ""
        for instruction in logical:
            tokens = shlex.split(instruction)[1:]
            if any(token.startswith("--from=") for token in tokens):
                continue
            tokens = [token for token in tokens if not token.startswith("--")]
            for source in tokens[:-1]:
                source = source.rstrip("/")
                matches = {item for item in tracked
                           if item == source or item.startswith(source + "/")
                           or fnmatch.fnmatchcase(item, source)}
                if not matches:
                    raise SourcePackageError(
                        f"Docker COPY source resolves to no tracked path: {source}")
                sources.update(matches)
    return sources


def selected_git_files(root: Path, required: list[str]) -> list[GitFile]:
    stage = git("ls-files", "-s", "--", *required, root=root).splitlines()
    if not stage:
        raise SourcePackageError("manifest selected no tracked files")
    files: list[GitFile] = []
    seen: set[str] = set()
    for row in stage:
        metadata, path = row.split("\t", 1)
        mode_text, object_id, stage_number = metadata.split()
        if stage_number != "0":
            raise SourcePackageError(f"unmerged required path: {path}")
        if path in seen:
            continue
        seen.add(path)
        if mode_text == "120000":
            raise SourcePackageError(f"symlink is forbidden in source package: {path}")
        if mode_text not in ("100644", "100755"):
            raise SourcePackageError(f"unsupported Git mode {mode_text}: {path}")
        if forbidden(path):
            raise SourcePackageError(f"excluded private/runtime class: {path}")
        files.append(GitFile(path, int(mode_text, 8),
                             git("cat-file", "blob", object_id,
                                 root=root, binary=True)))
    missing = [item for item in required if not any(
        file.path == item or file.path.startswith(item + "/") for file in files)]
    if missing:
        raise SourcePackageError(f"missing or untracked required paths: {missing}")
    untracked = git("ls-files", "--others", "--exclude-standard", "--",
                    *required, root=root).splitlines()
    untracked_runtime = [item for item in untracked if not forbidden(item)]
    if untracked_runtime:
        raise SourcePackageError(
            f"untracked files under required runtime paths: {untracked_runtime}")
    dirty = git("status", "--porcelain=v1", "--untracked-files=all", "--",
                *required, root=root).splitlines()
    if dirty:
        raise SourcePackageError(f"dirty required source inputs: {dirty}")
    return sorted(files, key=lambda item: item.path.encode("utf-8"))


def validate_coverage(root: Path, required: list[str]) -> None:
    entrypoints = {path.relative_to(root).as_posix()
                   for path in root.glob("platform_postgres*.py")}
    explicit = set(required)
    omitted = sorted((entrypoints | RELEASE_CONTRACTS) - explicit)
    if omitted:
        raise SourcePackageError(f"required entrypoints/contracts omitted: {omitted}")
    copied = docker_copy_sources(root, required)
    uncovered = sorted(path for path in copied if not covered(path, required))
    if uncovered:
        raise SourcePackageError(f"Docker COPY source not packaged: {uncovered}")


def build(root: Path, manifest_path: Path, output: Path,
          source_date_epoch: int) -> dict:
    if source_date_epoch < 0:
        raise SourcePackageError("source-date-epoch must be nonnegative")
    manifest, required = load_manifest(manifest_path)
    validate_coverage(root, required)
    files = selected_git_files(root, required)
    commit = git("rev-parse", "HEAD", root=root).strip()
    if len(commit) != 40:
        raise SourcePackageError("full source commit identity is unavailable")
    package = {"format": "openepm-source-archive-v1", "sourceCommit": commit,
        "sourceDateEpoch": source_date_epoch,
        "sourceManifestSha256": hashlib.sha256(canonical(manifest)).hexdigest(),
        "files": [{"path": item.path, "mode": oct(item.mode),
                   "sha256": hashlib.sha256(item.data).hexdigest()}
                  for item in files]}
    output.parent.mkdir(parents=True, exist_ok=True)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        payload = canonical(package) + b"\n"
        info = tarfile.TarInfo(f"{ARCHIVE_ROOT}/SOURCE_PACKAGE.json")
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
    sidecar = output.with_name(output.name + ".sha256")
    sidecar.write_text(f"{digest}  {output.name}\n", encoding="ascii")
    return {**package, "archive": output.name, "archiveSha256": digest,
            "archiveSize": output.stat().st_size,
            "digestFile": sidecar.name}


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
        raise SystemExit(f"source package rejected: {error}") from error
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
