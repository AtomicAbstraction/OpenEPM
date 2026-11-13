#!/usr/bin/env python3
"""Create deterministic source-only SPDX and license notices.

Image and base-operating-system packages are intentionally out of scope.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from build_openepm_source_archive import (  # noqa: E402
    DEFAULT_MANIFEST, ROOT, SourcePackageError, canonical, git, load_manifest,
    selected_git_files,
)
from assemble_openepm_release_candidate import child, load_json  # noqa: E402


LOCKS = ("requirements-postgres.lock",)
PIN = re.compile(
    r"^([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?==([^ ;\\]+)(?:\s*\\)?$")
SPDX_EXPRESSION = re.compile(r"^[A-Za-z0-9.+() -]+$")


def normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def locked_dependencies(root: Path) -> dict[str, dict]:
    dependencies: dict[str, dict] = {}
    for relative in LOCKS:
        data = (root / relative).read_text(encoding="utf-8")
        lines = data.splitlines()
        positions = [index for index, line in enumerate(lines) if PIN.fullmatch(line)]
        for ordinal, index in enumerate(positions):
            match = PIN.fullmatch(lines[index]); assert match is not None
            name, version = normalized(match.group(1)), match.group(2)
            end = positions[ordinal + 1] if ordinal + 1 < len(positions) else len(lines)
            block = "\n".join(lines[index:end])
            hashes = sorted(set(re.findall(r"--hash=sha256:([a-f0-9]{64})", block)))
            if not hashes:
                raise SourcePackageError(f"unpinned or unhashed dependency: {name}")
            existing = dependencies.get(name)
            if existing and existing["version"] != version:
                raise SourcePackageError(f"dependency version conflict: {name}")
            record = dependencies.setdefault(name, {"version": version,
                "hashes": set(), "locks": set()})
            record["hashes"].update(hashes); record["locks"].add(relative)
        # Any active requirement without an exact == pin is forbidden.
        for line in lines:
            stripped = line.strip()
            if (stripped and not stripped.startswith(("#", "--hash=", "\\"))
                    and not line.startswith((" ", "\t"))
                    and not PIN.fullmatch(line)):
                raise SourcePackageError(f"unpinned dependency syntax in {relative}: {line}")
    return {name: {"version": value["version"],
            "hashes": sorted(value["hashes"]), "locks": sorted(value["locks"])}
            for name, value in sorted(dependencies.items())}


def policy(path: Path, dependencies: dict[str, dict]) -> dict:
    value = load_json(path, "source license policy")
    if (value.get("format") != "openepm-source-license-policy-v1"
            or set(value) != {"format", "project", "dependencies"}
            or not isinstance(value["dependencies"], dict)):
        raise SourcePackageError("source license policy fields are invalid")
    if set(value["dependencies"]) != set(dependencies):
        missing = sorted(set(dependencies) - set(value["dependencies"]))
        extra = sorted(set(value["dependencies"]) - set(dependencies))
        raise SourcePackageError(f"license metadata coverage mismatch missing={missing} extra={extra}")
    for name, record in [("openepm-source", value["project"]),
                         *sorted(value["dependencies"].items())]:
        if not isinstance(record, dict) or set(record) != {
                "licenseExpression", "copyrightText", "noticeText"}:
            raise SourcePackageError(f"license metadata is invalid: {name}")
        if (not all(isinstance(record[key], str) and record[key].strip()
                    for key in record)
                or record["licenseExpression"] in {"NOASSERTION", "NONE", "UNKNOWN"}
                or not SPDX_EXPRESSION.fullmatch(record["licenseExpression"])):
            raise SourcePackageError(f"unknown license or missing notice text: {name}")
    return value


def source_index(archive: Path) -> dict:
    with tarfile.open(archive, "r:gz") as stream:
        try:
            member = stream.getmember("openepm-source/SOURCE_PACKAGE.json")
            extracted = stream.extractfile(member)
            if extracted is None:
                raise KeyError
            value = json.load(extracted)
        except (KeyError, json.JSONDecodeError) as error:
            raise SourcePackageError("source archive lacks a valid package index") from error
    if value.get("format") != "openepm-source-archive-v1":
        raise SourcePackageError("source archive package index format is invalid")
    return value


def build(*, root: Path, manifest: Path, binding_path: Path,
          binding_sha256: str, policy_path: Path, output: Path) -> dict:
    actual_binding = hashlib.sha256(binding_path.read_bytes()).hexdigest()
    if actual_binding != binding_sha256:
        raise SourcePackageError("source binding digest mismatch")
    binding = load_json(binding_path, "source binding")
    fragment = binding.get("releaseManifestFragment", {})
    commit = git("rev-parse", "HEAD", root=root).strip()
    migrations = sorted(git("ls-files", "schema/postgres/*.sql", root=root).splitlines())
    if (fragment.get("sourceCommit") != commit or not migrations
            or fragment.get("schemaMigration") != Path(migrations[-1]).name):
        raise SourcePackageError("source commit/schema differs from binding")
    _, required = load_manifest(manifest)
    selected_git_files(root, required)  # includes dirty/untracked rejection
    try:
        policy_relative = policy_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise SourcePackageError("license policy must be tracked inside the source tree") from error
    try:
        tracked_policy = git("ls-files", "--error-unmatch", "--",
                             policy_relative, root=root).strip()
    except subprocess.CalledProcessError as error:
        raise SourcePackageError("license policy must be tracked and clean") from error
    if (tracked_policy != policy_relative or git("status", "--porcelain=v1",
            "--", policy_relative, root=root).strip()):
        raise SourcePackageError("license policy must be tracked and clean")
    directory = binding_path.resolve().parent
    archive = child(directory, fragment.get("source"), "source archive")
    index = source_index(archive)
    if (index.get("sourceCommit") != commit
            or index.get("sourceManifestSha256") != binding.get("sourceManifestSha256")):
        raise SourcePackageError("source archive identity differs from binding")
    dependencies = locked_dependencies(root)
    licenses = policy(policy_path, dependencies)
    if output.exists() and (output.is_symlink() or not output.is_dir()
                            or any(output.iterdir())):
        raise SourcePackageError("source compliance output must be a new empty directory")
    output.mkdir(parents=True, exist_ok=True)
    epoch = binding.get("sourceDateEpoch")
    if not isinstance(epoch, int) or epoch < 0:
        raise SourcePackageError("source binding epoch is invalid")
    created = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    packages = [{"SPDXID": "SPDXRef-Package-OpenEPM", "name": "openepm-source",
        "versionInfo": commit, "downloadLocation": "NOASSERTION",
        "licenseConcluded": licenses["project"]["licenseExpression"],
        "licenseDeclared": licenses["project"]["licenseExpression"],
        "copyrightText": licenses["project"]["copyrightText"],
        "checksums": [{"algorithm": "SHA256", "checksumValue":
            fragment["source"]["sha256"]}]}]
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES", "relatedSpdxElement":
        "SPDXRef-Package-OpenEPM"}]
    for ordinal, (name, dependency) in enumerate(dependencies.items(), 1):
        metadata = licenses["dependencies"][name]
        spdx_id = f"SPDXRef-Package-{ordinal:04d}"
        packages.append({"SPDXID": spdx_id, "name": name,
            "versionInfo": dependency["version"],
            "downloadLocation": f"https://pypi.org/project/{name}/{dependency['version']}/",
            "licenseConcluded": metadata["licenseExpression"],
            "licenseDeclared": metadata["licenseExpression"],
            "copyrightText": metadata["copyrightText"],
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl", "referenceLocator":
                f"pkg:pypi/{name}@{dependency['version']}"}],
            "annotations": [{"annotationType": "OTHER", "annotator":
                "Tool: openepm-source-compliance", "annotationDate": created,
                "comment": "Pinned artifact hashes: " + ",".join(dependency["hashes"])}]})
        relationships.append({"spdxElementId": "SPDXRef-Package-OpenEPM",
            "relationshipType": "DEPENDS_ON", "relatedSpdxElement": spdx_id})
    spdx = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT", "name": "Open EPM source candidate",
        "documentNamespace": "urn:openepm:source:" + binding_sha256,
        "creationInfo": {"created": created,
            "creators": ["Tool: openepm-source-compliance"]},
        "documentDescribes": ["SPDXRef-Package-OpenEPM"],
        "packages": packages, "relationships": relationships,
        "comment": "Source archive and Python lock scope only; image/base OS coverage is excluded."}
    spdx_path = output / "openepm-source.spdx.json"
    spdx_path.write_bytes(canonical(spdx) + b"\n")
    notice = ["OPEN EPM SOURCE RELEASE NOTICES", "",
        "Scope: source archive and pinned Python locks only; not container images.", "",
        "Open EPM source", licenses["project"]["noticeText"].strip(), ""]
    for name, dependency in dependencies.items():
        metadata = licenses["dependencies"][name]
        notice += [f"{name} {dependency['version']}",
                   f"License: {metadata['licenseExpression']}",
                   metadata["noticeText"].strip(), ""]
    notices_path = output / "OPEN_SOURCE_NOTICES.txt"
    notices_path.write_text("\n".join(notice).rstrip() + "\n", encoding="utf-8")
    artifact = lambda path: {"path": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    compliance = {"format": "openepm-source-compliance-binding-v1",
        "status": "candidate-unqualified", "imageCoverage": False,
        "sourceCommit": commit, "schemaMigration": fragment["schemaMigration"],
        "sourceBindingSha256": binding_sha256,
        "dependencyLocks": {relative: hashlib.sha256(
            (root / relative).read_bytes()).hexdigest() for relative in LOCKS},
        "licensePolicySha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        "spdx": artifact(spdx_path), "licenseNotices": artifact(notices_path)}
    binding_output = output / "openepm-source-compliance-binding.json"
    binding_output.write_bytes(canonical(compliance) + b"\n")
    return compliance


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--source-binding", type=Path, required=True)
    parser.add_argument("--source-binding-sha256", required=True)
    parser.add_argument("--license-policy", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build(root=ROOT, manifest=args.manifest.resolve(),
            binding_path=args.source_binding.resolve(),
            binding_sha256=args.source_binding_sha256,
            policy_path=args.license_policy.resolve(),
            output=args.output_directory.resolve())
    except SourcePackageError as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
