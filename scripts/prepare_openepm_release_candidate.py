#!/usr/bin/env python3
"""Prepare deterministic source artifacts for a candidate Open EPM release.

This stage does not create or qualify a final release manifest.  It produces a
strict fragment and source-SBOM interface that the final release assembler must
bind alongside image, configuration, qualification, and full SBOM evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from build_openepm_source_archive import (  # noqa: E402
    DEFAULT_MANIFEST, ROOT, SourcePackageError, build, canonical, git,
)


RELEASE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def artifact(path: Path) -> dict:
    return {"path": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def write_json(path: Path, value: object) -> None:
    path.write_bytes(canonical(value) + b"\n")


def prepare(*, root: Path, manifest: Path, output: Path, release: str,
            source_date_epoch: int) -> dict:
    if not RELEASE.fullmatch(release):
        raise SourcePackageError("release identifier is invalid")
    if output.is_symlink():
        raise SourcePackageError("candidate output directory cannot be a symlink")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise SourcePackageError("candidate output directory must be empty")
    archive_path = output / f"openepm-source-{release}.tar.gz"
    built = build(root, manifest, archive_path, source_date_epoch)
    migration_names = sorted(path for path in git(
        "ls-files", "schema/postgres/*.sql", root=root).splitlines())
    if not migration_names:
        raise SourcePackageError("no tracked PostgreSQL migrations found")
    final_migration = Path(migration_names[-1]).name
    files_digest = hashlib.sha256(canonical(built["files"])).hexdigest()
    source_sbom = {
        "format": "openepm-source-sbom-binding-v1",
        "status": "candidate-unqualified",
        "sourceCommit": built["sourceCommit"],
        "sourceManifestSha256": built["sourceManifestSha256"],
        "sourceArchive": artifact(archive_path),
        "fileCount": len(built["files"]),
        "filesDigest": files_digest,
    }
    sbom_path = output / "openepm-source-sbom-binding.json"
    write_json(sbom_path, source_sbom)
    binding = {
        "format": "openepm-release-source-binding-v1",
        "status": "candidate-unqualified",
        "release": release,
        "sourceDateEpoch": source_date_epoch,
        "releaseManifestFragment": {
            "sourceCommit": built["sourceCommit"],
            "schemaMigration": final_migration,
            "source": artifact(archive_path),
        },
        "sourceArchiveDigestFile": artifact(
            archive_path.with_name(archive_path.name + ".sha256")),
        "sourceSbom": artifact(sbom_path),
        "sourceManifestSha256": built["sourceManifestSha256"],
        "filesDigest": files_digest,
    }
    binding_path = output / "openepm-release-source-binding.json"
    write_json(binding_path, binding)
    checksummed = sorted((archive_path,
        archive_path.with_name(archive_path.name + ".sha256"), sbom_path,
        binding_path), key=lambda path: path.name)
    checksums_path = output / "SOURCE_SHA256SUMS"
    checksums_path.write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        for path in checksummed), encoding="ascii")
    return {"format": "openepm-release-source-candidate-v1",
        "status": "candidate-unqualified", "release": release,
        "sourceCommit": built["sourceCommit"],
        "schemaMigration": final_migration,
        "source": artifact(archive_path), "sourceSbom": artifact(sbom_path),
        "binding": artifact(binding_path), "checksums": artifact(checksums_path)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    arguments = parser.parse_args()
    try:
        result = prepare(root=ROOT, manifest=arguments.manifest.resolve(),
            output=arguments.output_directory.resolve(), release=arguments.release,
            source_date_epoch=arguments.source_date_epoch)
    except SourcePackageError as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
