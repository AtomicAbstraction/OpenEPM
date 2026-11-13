#!/usr/bin/env python3
"""Verify and assemble candidate source artifacts into a release manifest.

The output is deliberately not accepted by the final release verifier.  It is
an input to final assembly after image, SPDX, licensing, and qualification
artifacts exist.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from build_openepm_source_archive import (  # noqa: E402
    ROOT, SourcePackageError, canonical, git,
)
from build_openepm_sdk_release import (  # noqa: E402
    CHECKSUMS as SDK_CHECKSUMS,
    MANIFEST as SDK_MANIFEST,
    SIGNATURE as SDK_SIGNATURE,
    verify_release as verify_sdk_release,
)
from validate_release_manifest import validate_execution_evidence  # noqa: E402
from openepm_release_inventory import resolve as resolve_release_inventory  # noqa: E402

from openepm_release_policy_contract import validate as validate_policy_inventory


SHA256 = re.compile(r"^[a-f0-9]{64}$")
COMMIT = re.compile(r"^[a-f0-9]{40}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
ARCHITECTURES = {"linux/amd64", "linux/arm64"}
COMPONENTS = {"application", "database", "operations", "builder",
              "identity", "proxy", "browser_gateway",
              "browser_session_store", "telemetry_collector"}
FINAL_ARTIFACTS = {"configuration", "inventory", "sbom", "licenses",
                   "checksums", "signature", "provenance"}
RESOLVED_POLICY = "openepm-resolved-release-policy.json"
DECISION_PACKET = Path("deploy/release/owner-decision-packet.json")


def load_json(path: Path, label: str) -> dict:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise SourcePackageError(f"duplicate JSON key in {label}: {key}")
            value[key] = item
        return value
    try:
        value = json.loads(path.read_text(encoding="utf-8"),
                           object_pairs_hook=unique)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SourcePackageError(f"invalid {label}: {error}") from error
    if not isinstance(value, dict):
        raise SourcePackageError(f"{label} must be a JSON object")
    return value


def registry_reference(value: object, component: str) -> str:
    if not isinstance(value, str) or "@" in value or value.startswith("sha256:"):
        raise SourcePackageError(f"{component} image reference is not a registry repository")
    first, _, last = value.partition("/")
    if not last or not ("." in first or ":" in first) or ":" in value.rsplit("/", 1)[-1]:
        raise SourcePackageError(f"{component} image reference must not be a tag or local name")
    return value


def final_artifact(directory: Path, record: object, label: str) -> dict:
    path = child(directory, record, label)
    return {"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def artifact(path: Path) -> dict:
    return {"path": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def validate_resolved_policy(root: Path, policy: dict,
                             artifact_root: Path) -> None:
    """Bind the resolved choices to the exact decision inventory being shipped."""
    try:
        validate_policy_inventory(policy, root / DECISION_PACKET,
                                  artifact_root=artifact_root)
    except (OSError, ValueError) as error:
        raise SourcePackageError(str(error)) from error


def sdk_release(directory: Path, record: object,
                source_commit: str) -> dict:
    """Verify and bind one signed public SDK envelope without choosing policy."""
    if not isinstance(record, dict) or set(record) != {"directory", "publicKey"}:
        raise SourcePackageError("invalid signed SDK release record")
    relative = record["directory"]
    parsed = PurePosixPath(relative) if isinstance(relative, str) else None
    if (parsed is None or parsed.is_absolute() or len(parsed.parts) != 1
            or parsed.parts[0] in ("", ".", "..")):
        raise SourcePackageError("signed SDK directory must be one bundle-relative name")
    sdk_directory = directory / parsed.parts[0]
    if not sdk_directory.is_dir() or sdk_directory.is_symlink():
        raise SourcePackageError("signed SDK directory is missing or symbolic")
    public_key = child(directory, record["publicKey"], "SDK public key")
    try:
        manifest = verify_sdk_release(sdk_directory, public_key=public_key)
    except (OSError, ValueError) as error:
        raise SourcePackageError(f"signed SDK release verification failed: {error}") from error
    if manifest.get("source", {}).get("declaredCommit") != source_commit:
        raise SourcePackageError("signed SDK source commit differs from release source")
    package = manifest.get("package")
    signing = manifest.get("signing")
    if (not isinstance(package, dict) or package.get("name") != "openepm-sdk"
            or not isinstance(signing, dict)
            or signing.get("algorithm") != "Ed25519"):
        raise SourcePackageError("signed SDK identity is invalid")
    wheel_name = package.get("filename")
    if (not isinstance(wheel_name, str) or PurePosixPath(wheel_name).name != wheel_name
            or wheel_name in (SDK_MANIFEST, SDK_SIGNATURE, SDK_CHECKSUMS)):
        raise SourcePackageError("signed SDK wheel filename is invalid")
    names = {
        "wheel": wheel_name,
        "manifest": SDK_MANIFEST,
        "signature": SDK_SIGNATURE,
        "checksums": SDK_CHECKSUMS,
    }
    artifacts = {}
    for label, name in names.items():
        path = sdk_directory / name
        if not path.is_file() or path.is_symlink():
            raise SourcePackageError(f"signed SDK {label} is missing or symbolic")
        artifacts[label] = {
            "path": f"{parsed.parts[0]}/{name}",
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    return {
        "package": package,
        "source": manifest["source"],
        "signing": signing,
        "artifacts": artifacts,
        "publicKey": final_artifact(directory, record["publicKey"],
                                    "SDK public key"),
    }


def child(root: Path, record: object, label: str) -> Path:
    if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
        raise SourcePackageError(f"invalid {label} artifact record")
    relative, expected = record["path"], record["sha256"]
    if not isinstance(relative, str) or not isinstance(expected, str) \
            or not SHA256.fullmatch(expected):
        raise SourcePackageError(f"invalid {label} artifact identity")
    parsed = PurePosixPath(relative)
    if parsed.is_absolute() or ".." in parsed.parts or len(parsed.parts) != 1:
        raise SourcePackageError(f"{label} must be a sibling artifact")
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise SourcePackageError(f"missing or symbolic {label}: {relative}")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise SourcePackageError(f"{label} digest mismatch")
    return path


def assemble(*, root: Path, binding_path: Path, expected_binding_sha256: str,
             output: Path) -> dict:
    if not SHA256.fullmatch(expected_binding_sha256):
        raise SourcePackageError("expected binding digest is invalid")
    binding_path = binding_path.resolve()
    if not binding_path.is_file() or binding_path.is_symlink():
        raise SourcePackageError("source binding is missing or symbolic")
    actual_binding = hashlib.sha256(binding_path.read_bytes()).hexdigest()
    if actual_binding != expected_binding_sha256:
        raise SourcePackageError("source binding digest mismatch")
    binding = load_json(binding_path, "source binding")
    if (binding.get("format") != "openepm-release-source-binding-v1"
            or binding.get("status") != "candidate-unqualified"):
        raise SourcePackageError("source binding is not an unqualified candidate")
    fragment = binding.get("releaseManifestFragment")
    if not isinstance(fragment, dict) or set(fragment) != {
            "sourceCommit", "schemaMigration", "source"}:
        raise SourcePackageError("source binding release fragment is invalid")
    current_commit = git("rev-parse", "HEAD", root=root).strip()
    if (not isinstance(fragment["sourceCommit"], str)
            or not COMMIT.fullmatch(fragment["sourceCommit"])
            or fragment["sourceCommit"] != current_commit):
        raise SourcePackageError("source commit identity differs from current checkout")
    migrations = sorted(git("ls-files", "schema/postgres/*.sql",
                            root=root).splitlines())
    if (not isinstance(fragment["schemaMigration"], str) or not migrations
            or fragment["schemaMigration"] != Path(migrations[-1]).name):
        raise SourcePackageError("schema migration identity differs from current checkout")
    directory = binding_path.parent
    source = child(directory, fragment["source"], "source archive")
    sidecar = child(directory, binding.get("sourceArchiveDigestFile"),
                    "source archive digest file")
    expected_sidecar = f"{fragment['source']['sha256']}  {source.name}\n"
    if sidecar.read_text(encoding="ascii") != expected_sidecar:
        raise SourcePackageError("source archive digest sidecar content mismatch")
    sbom_path = child(directory, binding.get("sourceSbom"),
                      "source SBOM binding")
    sbom = load_json(sbom_path, "source SBOM binding")
    if (sbom.get("format") != "openepm-source-sbom-binding-v1"
            or sbom.get("status") != "candidate-unqualified"
            or sbom.get("sourceCommit") != current_commit
            or sbom.get("sourceArchive") != fragment["source"]
            or sbom.get("sourceManifestSha256") !=
                binding.get("sourceManifestSha256")
            or sbom.get("filesDigest") != binding.get("filesDigest")):
        raise SourcePackageError("source SBOM identities diverge from source binding")
    if output.exists():
        raise SourcePackageError("candidate manifest output already exists")
    resolved_policy_path = directory / RESOLVED_POLICY
    if not resolved_policy_path.is_file() or resolved_policy_path.is_symlink():
        raise SourcePackageError("explicit resolved release policy is required")
    resolved_policy = load_json(resolved_policy_path, "resolved release policy")
    validate_resolved_policy(root, resolved_policy, directory)
    resolved_policy_record = artifact(resolved_policy_path)
    result = {
        "format": "openepm-release-candidate-manifest-v1",
        "status": "candidate-unqualified",
        "release": binding.get("release"),
        "sourceDateEpoch": binding.get("sourceDateEpoch"),
        "sourceCommit": current_commit,
        "schemaMigration": fragment["schemaMigration"],
        "source": fragment["source"],
        "sourceArchiveDigestFile": binding["sourceArchiveDigestFile"],
        "sourceBinding": {"path": binding_path.name,
                          "sha256": actual_binding},
        "sourceSbom": binding["sourceSbom"],
        "resolvedReleasePolicy": resolved_policy_record,
        "finalArtifactsRequired": ["complete-runtime-image-digest-manifest",
            "SPDX-SBOM", "license-notices", "configuration",
            "SHA256SUMS", "qualification-summary"],
    }
    output.write_bytes(canonical(result) + b"\n")
    return result


def assemble_final(*, root: Path, candidate_path: Path,
                   materials_path: Path, output: Path) -> dict:
    candidate = load_json(candidate_path, "candidate manifest")
    if (candidate.get("format") != "openepm-release-candidate-manifest-v1"
            or candidate.get("status") != "candidate-unqualified"):
        raise SourcePackageError("finalization requires an unqualified candidate manifest")
    materials = load_json(materials_path, "final materials")
    if (materials.get("format") != "openepm-final-materials-v1"
            or set(materials) != {"format", "release", "architectures",
                                  "images", "artifacts", "sourceCompliance",
                                  "qualificationSummary", "sdk"}):
        raise SourcePackageError("final materials fields do not match the contract")
    if materials["release"] != candidate.get("release"):
        raise SourcePackageError("final materials release identity mismatch")
    architectures = materials["architectures"]
    if (not isinstance(architectures, list) or not architectures
            or len(architectures) != len(set(architectures))
            or not set(architectures).issubset(ARCHITECTURES)):
        raise SourcePackageError("advertised architectures are invalid or duplicated")
    images = materials["images"]
    if not isinstance(images, dict) or set(images) != COMPONENTS:
        raise SourcePackageError("the complete runtime image inventory is required")
    verified_images = {}
    image_identities = set()
    for component in sorted(COMPONENTS):
        image = images[component]
        if not isinstance(image, dict) or set(image) != {"reference", "digests"}:
            raise SourcePackageError(f"invalid component image identity: {component}")
        reference = registry_reference(image["reference"], component)
        digests = image["digests"]
        if (not isinstance(digests, dict) or set(digests) != set(architectures)
                or any(not isinstance(value, str) or not DIGEST.fullmatch(value)
                       for value in digests.values())
                or len(set(digests.values())) != len(digests)):
            raise SourcePackageError(
                f"{component} image architecture digests are incomplete or mismatched")
        verified_images[component] = {"reference": reference,
            "digests": {arch: digests[arch] for arch in architectures}}
        identity = (reference, tuple(digests[arch] for arch in architectures))
        if identity in image_identities:
            raise SourcePackageError("duplicate component image identities are forbidden")
        image_identities.add(identity)
    directory = materials_path.resolve().parent
    resolved_policy_record = final_artifact(directory,
        candidate.get("resolvedReleasePolicy"), "resolved release policy")
    resolved_policy = load_json(directory / resolved_policy_record["path"],
                                "resolved release policy")
    validate_resolved_policy(root, resolved_policy, directory)
    verified_sdk = sdk_release(directory, materials["sdk"],
                               candidate["sourceCommit"])
    artifacts = materials["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != FINAL_ARTIFACTS:
        raise SourcePackageError("all final artifact identities are required")
    verified_artifacts = {name: final_artifact(directory, artifacts[name], name)
                          for name in sorted(FINAL_ARTIFACTS)}
    inventory_path = directory / verified_artifacts["inventory"]["path"]
    try:
        resolve_release_inventory(inventory_path)
    except ValueError as error:
        raise SourcePackageError("release inventory contract is invalid") from error
    qualification_record = final_artifact(directory,
        materials["qualificationSummary"], "qualification summary")
    source_compliance_record = final_artifact(directory,
        materials["sourceCompliance"], "source compliance binding")
    source_compliance = load_json(directory / source_compliance_record["path"],
                                  "source compliance binding")
    if (source_compliance.get("format") != "openepm-source-compliance-binding-v1"
            or source_compliance.get("status") != "candidate-unqualified"
            or source_compliance.get("imageCoverage") is not False
            or source_compliance.get("sourceBindingSha256") !=
                candidate["sourceBinding"]["sha256"]):
        raise SourcePackageError("source compliance identity differs from candidate")
    source_spdx = final_artifact(directory, source_compliance.get("spdx"),
                                 "source SPDX")
    source_notices = final_artifact(directory,
        source_compliance.get("licenseNotices"), "source license notices")
    if (verified_artifacts["sbom"] == source_spdx
            or verified_artifacts["licenses"] == source_notices):
        raise SourcePackageError("source-only compliance cannot substitute for image coverage")
    qualification_path = directory / qualification_record["path"]
    qualification = load_json(qualification_path, "qualification summary")
    execution = qualification.get("executionEvidence")
    expected_qualification = {
        "format": "openepm-exact-artifact-qualification-v1",
        "status": "passed",
        "release": candidate["release"],
        "sourceCommit": candidate["sourceCommit"],
        "schemaMigration": candidate["schemaMigration"],
        "sourceBindingSha256": candidate["sourceBinding"]["sha256"],
        "resolvedReleasePolicySha256": resolved_policy_record["sha256"],
        "architectures": architectures,
        "images": verified_images,
        "sdk": verified_sdk,
        "artifacts": verified_artifacts,
        "sourceComplianceSha256": source_compliance_record["sha256"],
        "executionEvidence": execution,
    }
    if qualification != expected_qualification:
        raise SourcePackageError(
            "qualification summary does not bind the exact release artifacts")
    validate_execution_evidence(execution, architectures=architectures,
        source_commit=candidate["sourceCommit"],
        schema_migration=candidate["schemaMigration"], images=verified_images,
        configuration_profile_sha256=verified_artifacts["configuration"]["sha256"],
        artifact_loader=lambda record, label: child(directory, record, label),
        json_loader=load_json, error_type=SourcePackageError)
    if output.exists():
        raise SourcePackageError("final manifest output already exists")
    result = {
        "format": "openepm-release-manifest-v3",
        "status": "final-qualified",
        "release": candidate["release"],
        "sourceCommit": candidate["sourceCommit"],
        "schemaMigration": candidate["schemaMigration"],
        "architectures": architectures,
        "images": verified_images,
        "sdk": verified_sdk,
        "source": candidate["source"],
        "sourceBinding": candidate["sourceBinding"],
        "sourceSbom": candidate["sourceSbom"],
        "resolvedReleasePolicy": resolved_policy_record,
        "sourceCompliance": source_compliance_record,
        "artifacts": verified_artifacts,
        "qualificationSummary": qualification_record,
    }
    output.write_bytes(canonical(result) + b"\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-binding", type=Path)
    parser.add_argument("--source-binding-sha256")
    parser.add_argument("--candidate-manifest", type=Path)
    parser.add_argument("--final-materials", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        if arguments.final_materials or arguments.candidate_manifest:
            if (not arguments.final_materials or not arguments.candidate_manifest
                    or arguments.source_binding or arguments.source_binding_sha256):
                parser.error("final mode requires candidate-manifest and final-materials only")
            result = assemble_final(root=ROOT,
                candidate_path=arguments.candidate_manifest.resolve(),
                materials_path=arguments.final_materials.resolve(),
                output=arguments.output.resolve())
        else:
            if not arguments.source_binding or not arguments.source_binding_sha256:
                parser.error("candidate mode requires source-binding and its sha256")
            result = assemble(root=ROOT, binding_path=arguments.source_binding,
                expected_binding_sha256=arguments.source_binding_sha256,
                output=arguments.output.resolve())
    except SourcePackageError as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
