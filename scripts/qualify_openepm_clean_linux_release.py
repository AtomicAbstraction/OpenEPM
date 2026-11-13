#!/usr/bin/env python3
"""Plan and verify exact clean-Ubuntu release qualification evidence.

This tool does not claim or simulate a host run. It emits a digest-bound plan
and accepts only complete evidence returned by a separate trusted host runner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from scripts.openepm_release_inventory import (
        InventoryError, resolve as resolve_release_inventory)
except ModuleNotFoundError:  # bundled tools are copied into one directory
    from openepm_release_inventory import (  # type: ignore[no-redef]
        InventoryError, resolve as resolve_release_inventory)

try:
    from openepm_release_policy_contract import validate as validate_policy
except ImportError:
    from scripts.openepm_release_policy_contract import validate as validate_policy


class QualificationError(ValueError):
    pass


COMPONENTS = {"application", "database", "operations", "builder",
              "identity", "proxy", "browser_gateway",
              "browser_session_store", "telemetry_collector"}
ARCHES = {"linux/amd64", "linux/arm64"}


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QualificationError(f"invalid {label}: {error}") from error
    if not isinstance(value, dict):
        raise QualificationError(f"{label} must be an object")
    return value


def sibling(root: Path, record: object, label: str) -> Path:
    if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
        raise QualificationError(f"invalid {label} identity")
    parsed = PurePosixPath(record["path"])
    if parsed.is_absolute() or ".." in parsed.parts or len(parsed.parts) != 1:
        raise QualificationError(f"unsafe {label} path")
    path = root / parsed.as_posix()
    if not path.is_file() or path.is_symlink() or sha(path) != record["sha256"]:
        raise QualificationError(f"{label} digest mismatch")
    return path


def plan(manifest_path: Path, *, architecture: str) -> dict:
    manifest = load(manifest_path, "final manifest")
    if (manifest.get("format") != "openepm-release-manifest-v3"
            or manifest.get("status") != "final-qualified"):
        raise QualificationError("clean-host qualification requires final manifest v3")
    if architecture not in ARCHES or architecture not in manifest.get("architectures", []):
        raise QualificationError("host architecture is not advertised by final manifest")
    images = manifest.get("images")
    if not isinstance(images, dict) or set(images) != COMPONENTS:
        raise QualificationError("final manifest does not bind the complete runtime image inventory")
    image_digests = {}
    for component, value in images.items():
        digests = value.get("digests") if isinstance(value, dict) else None
        digest = digests.get(architecture) if isinstance(digests, dict) else None
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise QualificationError(f"missing native image digest: {component}")
        image_digests[component] = digest
    root = manifest_path.resolve().parent
    policy_path = sibling(root, manifest.get("resolvedReleasePolicy"),
                          "resolved release policy")
    policy = load(policy_path, "resolved release policy")
    try:
        validate_policy(policy, artifact_root=policy_path.parent)
    except (OSError, ValueError) as error:
        raise QualificationError("resolved release policy is incomplete") from error
    artifacts = manifest.get("artifacts")
    inventory_path = sibling(root,
        artifacts.get("inventory") if isinstance(artifacts, dict) else None,
        "release inventory")
    try:
        release_inventory = resolve_release_inventory(inventory_path)
    except InventoryError as error:
        raise QualificationError("release inventory contract is invalid") from error
    return {"format": "openepm-clean-linux-qualification-plan-v2",
        "status": "execution-required", "qualificationClaimed": False,
        "releaseManifestSha256": sha(manifest_path),
        "resolvedReleasePolicySha256": sha(policy_path),
        "releaseInventorySha256": sha(inventory_path),
        "releaseInventory": release_inventory,
        "release": manifest["release"], "sourceCommit": manifest["sourceCommit"],
        "schemaMigration": manifest["schemaMigration"],
        "host": {"osId": "ubuntu", "osVersion": "24.04",
                 "architecture": architecture, "requiredRuntime": "runsc",
                 "mustBeCleanHost": True},
        "nativeImageDigests": {key: image_digests[key] for key in sorted(image_digests)},
        "phases": ["host-attestation", "bundle-integrity", "epmctl-doctor",
            "epmctl-install", "authenticated-mcp", "authenticated-browser",
            "runsc-headless-python",
            "runsc-python-build-publication", "database-version-read",
            "service-restart", "populated-backup", "independent-host-restore",
            "storage-retirement", "native-architecture-proof"]}


def verify(plan_value: dict, evidence: dict) -> dict:
    if (plan_value.get("format") != "openepm-clean-linux-qualification-plan-v2"
            or plan_value.get("status") != "execution-required"
            or plan_value.get("qualificationClaimed") is not False):
        raise QualificationError("invalid qualification plan")
    if (evidence.get("format") != "openepm-clean-linux-qualification-evidence-v2"
            or evidence.get("status") != "passed"
            or evidence.get("planSha256") != hashlib.sha256(
                canonical(plan_value)).hexdigest()):
        raise QualificationError("evidence does not bind the exact plan")
    host = evidence.get("host", {})
    expected_host = plan_value["host"]
    if (host.get("osId") != "ubuntu" or host.get("osVersion") != "24.04"
            or host.get("architecture") != expected_host["architecture"]
            or host.get("cleanHost") is not True
            or host.get("runscVersion") in (None, "")
            or host.get("dockerRunscRegistered") is not True
            or host.get("developmentMacPathsPresent") is not False):
        raise QualificationError("clean Ubuntu/runsc host proof is incomplete")
    host_identity = host.get("hostIdentity")
    if (not isinstance(host_identity, str) or len(host_identity) != 64
            or any(character not in "0123456789abcdef"
                   for character in host_identity)):
        raise QualificationError("clean-host identity proof is incomplete")
    if (evidence.get("releaseManifestSha256") !=
            plan_value["releaseManifestSha256"]
            or evidence.get("resolvedReleasePolicySha256") !=
            plan_value["resolvedReleasePolicySha256"]
            or evidence.get("releaseInventorySha256") !=
                plan_value.get("releaseInventorySha256")
            or evidence.get("releaseInventory") !=
                plan_value.get("releaseInventory")
            or evidence.get("sourceCommit") != plan_value["sourceCommit"]
            or evidence.get("schemaMigration") != plan_value["schemaMigration"]):
        raise QualificationError("source/policy/schema identity mismatch")
    if evidence.get("nativeImageDigests") != plan_value["nativeImageDigests"]:
        raise QualificationError("native image identities differ from final manifest")
    commands = evidence.get("commands", {})
    if commands.get("doctorExitCode") != 0 or commands.get("installExitCode") != 0:
        raise QualificationError("doctor/install did not pass")
    workflows = evidence.get("workflows", {})
    required_workflows = ("authenticatedMcp", "authenticatedBrowser",
        "runscHeadlessPython",
        "runscPythonBuildPublication",
        "restartPassed")
    if any(workflows.get(key) is not True for key in required_workflows):
        raise QualificationError("required authenticated/runtime workflow is incomplete")
    attestations = evidence.get("runtimeAttestations", {})
    authenticated_mcp = attestations.get("authenticatedMcp", {})
    if (authenticated_mcp.get("verified") is not True
            or authenticated_mcp.get("unsignedDenied") is not True
            or not isinstance(authenticated_mcp.get("responseSha256"), str)
            or len(authenticated_mcp["responseSha256"]) != 64
            or any(character not in "0123456789abcdef"
                   for character in authenticated_mcp["responseSha256"])):
        raise QualificationError("authenticated MCP runtime proof is incomplete")
    restart = attestations.get("restart", {})
    if (restart.get("verified") is not True
            or restart.get("authenticatedWorkflowClaimed") is not True
            or restart.get("unsignedDenied") is not True
            or not isinstance(restart.get("responseSha256"), str)
            or len(restart["responseSha256"]) != 64
            or any(character not in "0123456789abcdef"
                   for character in restart["responseSha256"])
            or restart["responseSha256"] != authenticated_mcp["responseSha256"]):
        raise QualificationError("authenticated post-restart MCP proof is incomplete")
    headless = attestations.get("runscHeadlessPython", {})
    if (headless.get("verified") is not True
            or headless.get("runtime") != "runsc"
            or headless.get("image") != plan_value["nativeImageDigests"]["builder"]
            or type(headless.get("uid")) is not int or headless["uid"] == 0
            or headless.get("rootReadOnly") is not True
            or headless.get("networkBlocked") is not True
            or headless.get("tmpWritable") is not True
            or headless.get("negativeExitCode") != 23
            or not isinstance(headless.get("positiveOutputSha256"), str)
            or len(headless["positiveOutputSha256"]) != 64
            or any(character not in "0123456789abcdef"
                   for character in headless["positiveOutputSha256"])):
        raise QualificationError("runsc headless runtime proof is incomplete")
    publication = attestations.get("runscPythonBuildPublication", {})
    publication_digests = ("artifactSha256", "planSha256", "receiptSha256",
        "lineageSha256", "denialRevisionBefore", "denialRevisionAfter",
        "outputSha256")
    if (publication.get("verified") is not True
            or publication.get("runtime") != "runsc"
            or publication.get("builderImage") !=
                plan_value["nativeImageDigests"]["builder"]
            or not isinstance(publication.get("profileImage"), str)
            or not publication["profileImage"].endswith(
                "@" + publication["builderImage"])
            or publication.get("rootReadOnly") is not True
            or publication.get("capabilitiesDropped") is not True
            or publication.get("noNewPrivileges") is not True
            or publication.get("pidsLimit") != 128
            or publication.get("cpuLimit") != 1
            or publication.get("memoryMiB") != 512
            or publication.get("journalUnit") !=
                "openepm-sandbox-launcher.service"
            or not isinstance(publication.get("launcherEventSha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}",
                                publication["launcherEventSha256"])
            or publication.get("publicSdkOnly") is not True
            or publication.get("publicMcpHttps") is not True
            or not isinstance(publication.get("buildId"), str)
            or not re.fullmatch(r"[a-f0-9]{32}", publication["buildId"])
            or not isinstance(publication.get("workflowId"), str)
            or not re.fullmatch(r"[a-f0-9]{32}", publication["workflowId"])
            or publication.get("buildAttempts") != 1
            or publication.get("buildClaimGeneration") != 1
            or publication.get("buildReplaySame") is not True
            or publication.get("capabilityActionCount") != 2
            or publication.get("capabilityGenerationBound") is not True
            or publication.get("sourceExecutionCount") != 1
            or publication.get("sealedRunWithoutRebuild") is not True
            or not isinstance(publication.get("result"), str)
            or not publication["result"]
            or publication.get("denialZeroEffect") is not True
            or publication.get("denialRevisionBefore") !=
                publication.get("denialRevisionAfter")
            or any(publication.get(field) is not False for field in
                   ("databaseCredentialsPresent", "trustedCorePresent",
                    "dockerSocketPresent", "sourceMounted"))
            or any(not isinstance(publication.get(field), str)
                   or len(publication[field]) != 64
                   or any(character not in "0123456789abcdef"
                          for character in publication[field])
                   for field in publication_digests)):
        raise QualificationError(
            "runsc Python build/publication runtime proof is incomplete")
    browser = attestations.get("authenticatedBrowser", {})
    if (browser.get("verified") is not True
            or browser.get("engine") != "Playwright"
            or browser.get("browser") != "Google Chrome"
            or not isinstance(browser.get("browserVersion"), str)
            or not browser["browserVersion"]
            or browser.get("headless") is not True
            or browser.get("unauthenticatedProtected") is not True
            or browser.get("sameContext") is not True
            or browser.get("presentationBundleLoaded") is not True
            or browser.get("nativeLogin") is not True
            or browser.get("firstPasswordReplacement") is not True
            or browser.get("opaqueSessionCookie") is not True
            or browser.get("browserTokenStorage") is not False
            or browser.get("runOwnedInitialAdministrator") is not True
            or browser.get("qualificationCleanupRequired") is not True
            or browser.get("workspaceCreated") is not True
            or browser.get("applicationCreated") is not True
            or browser.get("metadataMemberCount") != 8
            or browser.get("authorizedWrite") is not True
            or browser.get("exactReadback") is not True
            or browser.get("readbackAmount") != "17.25000000"
            or type(browser.get("applicationCount")) is not int
            or browser["applicationCount"] < 0
            or browser.get("debuggerClaimed") is not False
            or browser.get("persistenceClaimed") is not False
            or not isinstance(browser.get("outputSha256"), str)
            or len(browser["outputSha256"]) != 64
            or any(character not in "0123456789abcdef"
                   for character in browser["outputSha256"])):
        raise QualificationError("authenticated browser runtime proof is incomplete")
    versions = evidence.get("databaseVersions", {})
    if (not isinstance(versions.get("postgresql"), str)
            or not versions["postgresql"].strip()
            or not isinstance(versions.get("pgDuckdb"), str)
            or not versions["pgDuckdb"].strip()
            or versions.get("readFromRunningDatabase") is not True):
        raise QualificationError("actual PostgreSQL/pg_duckdb versions are absent")
    backup = evidence.get("backup", {})
    backup_signature = backup.get("preBackupPopulatedSignature")
    if (not isinstance(backup.get("bundle"), str)
            or not backup["bundle"]
            or not isinstance(backup.get("sourceHostIdentity"), str)
            or len(backup["sourceHostIdentity"]) != 64
            or any(character not in "0123456789abcdef"
                   for character in backup["sourceHostIdentity"])
            or not isinstance(backup_signature, str)
            or len(backup_signature) != 64
            or any(character not in "0123456789abcdef"
                   for character in backup_signature)
            or any(not isinstance(backup.get(field), str)
                   or len(backup[field]) != 64
                   or any(character not in "0123456789abcdef"
                          for character in backup[field])
                   for field in ("manifestSha256", "encryptedArtifactSha256"))
            or type(backup.get("encryptedPayloadCount")) is not int
            or backup["encryptedPayloadCount"] < 1
            or type(backup.get("totalBytes")) is not int
            or backup["totalBytes"] < 1):
        raise QualificationError("populated encrypted backup proof is incomplete")
    restore = evidence.get("restore", {})
    if (restore.get("populated") is not True
            or restore.get("independentHost") is not True
            or restore.get("encryptedTransfer") is not True
            or restore.get("sourceHostIdentity") == restore.get("targetHostIdentity")
            or not restore.get("sourceHostIdentity")
            or restore.get("sourceHostIdentity") != backup["sourceHostIdentity"]
            or restore.get("targetHostIdentity") != host_identity
            or restore.get("beforeSignature") != backup_signature
            or restore.get("afterSignature") != backup_signature
            or restore.get("activationVerified") is not True
            or restore.get("bundle") != backup.get("bundle")
            or not isinstance(restore.get("targetProject"), str)
            or not restore["targetProject"]
            or not isinstance(restore.get("priorProject"), str)
            or not restore["priorProject"]
            or restore["targetProject"] == restore["priorProject"]):
        raise QualificationError("independent populated restore proof is incomplete")
    retirement = evidence.get("storageRetirement", {})
    if (set(retirement.get("scannedImages", [])) != COMPONENTS
            or retirement.get("prohibitedMatches") != 0
            or retirement.get("scannerExitCode") != 0
            or retirement.get("proxyScratchFiles") != 2
            or any(not isinstance(retirement.get(field), str)
                   or len(retirement[field]) != 64
                   or any(character not in "0123456789abcdef"
                          for character in retirement[field])
                   for field in ("proxyBinarySha256",
                                 "proxyCertificateSha256"))):
        raise QualificationError("storage-retirement proof is incomplete")
    phases = evidence.get("completedPhases")
    if phases != plan_value["phases"]:
        raise QualificationError("qualification phases are missing or reordered")
    return {"format": "openepm-clean-linux-qualification-certificate-v2",
        "status": "passed", "release": plan_value["release"],
        "architecture": expected_host["architecture"],
        "releaseManifestSha256": plan_value["releaseManifestSha256"],
        "resolvedReleasePolicySha256": plan_value["resolvedReleasePolicySha256"],
        "evidenceSha256": hashlib.sha256(canonical(evidence)).hexdigest(),
        "externalHostExecutionRequired": True}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--final-manifest", type=Path, required=True)
    parser.add_argument("--architecture", choices=sorted(ARCHES), required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    try:
        value = plan(args.final_manifest.resolve(), architecture=args.architecture)
        if args.evidence:
            value = verify(value, load(args.evidence.resolve(), "qualification evidence"))
    except QualificationError as error:
        parser.error(str(error))
    args.output.write_bytes(canonical(value) + b"\n")
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
