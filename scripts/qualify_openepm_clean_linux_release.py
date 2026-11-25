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
    from openepm_release_inventory import (  # type: ignore[no-redef]
        InventoryError, resolve as resolve_release_inventory)
except ModuleNotFoundError:  # Repository imports can resolve through the package.
    from scripts.openepm_release_inventory import (
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
SHA256 = re.compile(r"[a-f0-9]{64}")
MCP_IDENTITY_TOOL = "read_v2_session_identity"
PHASES = ("host-attestation", "bundle-integrity", "epmctl-doctor",
          "epmctl-install", "authenticated-mcp", "authenticated-browser",
          "runsc-headless-python", "runsc-python-build-publication",
          "database-version-read", "service-restart", "populated-backup",
          "independent-host-restore", "storage-retirement", "native-architecture-proof")


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
        "phases": list(PHASES)}


def verify_mcp_identity_request(request: object) -> None:
    if (not isinstance(request, dict)
            or set(request) != {"jsonrpc", "id", "method", "params"}
            or request.get("jsonrpc") != "2.0"
            or type(request.get("id")) not in (int, str)
            or request.get("method") != "tools/call"
            or request.get("params") != {"name": MCP_IDENTITY_TOOL, "arguments": {}}):
        raise QualificationError("MCP request must call read_v2_session_identity without arguments")


def verify_mcp_identity_evidence(observation: object, *, before: dict | None = None) -> None:
    fields = ("requestSha256", "responseSha256")
    if (not isinstance(observation, dict)
            or observation.get("verified") is not True
            or observation.get("unsignedDenied") is not True
            or observation.get("tool") != MCP_IDENTITY_TOOL
            or any(not isinstance(observation.get(field), str)
                   or not SHA256.fullmatch(observation[field]) for field in fields)):
        label = "authenticated post-restart MCP" if before is not None else "authenticated MCP runtime"
        raise QualificationError(f"{label} identity proof is incomplete")
    if before is not None and (observation.get("authenticatedWorkflowClaimed") is not True
            or any(observation[field] != before[field] for field in fields)):
        raise QualificationError("authenticated post-restart MCP request or identity changed")


def verify_restart_transition(before: dict[str, str], started: dict[str, str]) -> None:
    if before["continuitySha256"] != started["continuitySha256"]:
        raise QualificationError("release configuration, service identities or database volumes changed on restart")
    if before["runningSha256"] == started["runningSha256"]:
        raise QualificationError("release restart did not change the observed running generation")


def verify_restart_continuity(evidence: object) -> None:
    steps = ("beforeStop", "afterStart", "afterReadback")
    fields = ("continuitySha256", "runningSha256")
    if (not isinstance(evidence, dict) or set(evidence) != set(steps)
            or any(not isinstance(row, dict) or set(row) != set(fields)
                   or any(not isinstance(row[field], str) or not SHA256.fullmatch(row[field])
                          for field in fields) for row in evidence.values())):
        raise QualificationError("restart continuity evidence is incomplete")
    before, started, readback = (evidence[step] for step in steps)
    verify_restart_transition(before, started)
    if started != readback:
        raise QualificationError("release changed during authenticated post-restart readback")


def verify_database_versions(versions: object) -> None:
    if (not isinstance(versions, dict) or versions.get("readFromRunningDatabase") is not True
            or not isinstance(versions.get("postgresql"), str)
            or not re.fullmatch(r"PostgreSQL [1-9][0-9]*(?:\.[0-9]+)+(?: [^\r\n]+)?", versions["postgresql"])
            or not isinstance(versions.get("pgDuckdb"), str)
            or not re.fullmatch(r"pg_duckdb [0-9]+(?:\.[0-9]+)+(?:[-+._a-zA-Z0-9]*)", versions["pgDuckdb"])):
        raise QualificationError("actual PostgreSQL server and pg_duckdb versions are required")


def verify_restored_public_readback(readback: object, *, target: str,
                                    runtime: str, expected: object) -> None:
    """Require both public clients to read the attested source projection on the restored target."""
    if (not isinstance(expected, str) or SHA256.fullmatch(expected) is None
            or not isinstance(readback, dict)
            or set(readback) != {"targetProject", "activatedRuntimeSha256", "browser", "mcp"}
            or readback.get("targetProject") != target
            or readback.get("activatedRuntimeSha256") != runtime):
        raise QualificationError("restored public readback does not bind the source and activated target")
    for surface in ("browser", "mcp"):
        result = readback[surface]
        if (not isinstance(result, dict)
                or set(result) != {"authenticated", "unsignedDenied", "signature", "responseSha256"}
                or result.get("authenticated") is not True
                or result.get("unsignedDenied") is not True
                or result.get("signature") != expected
                or not isinstance(result.get("responseSha256"), str)
                or SHA256.fullmatch(result["responseSha256"]) is None):
            raise QualificationError(f"restored {surface} public readback differs from the attested source or lacks authority proof")


def verify_restored_evidence(restore: object, backup: dict, host_identity: str) -> None:
    """Bind the encrypted source, imported population and verified serving cutover."""
    if not isinstance(restore, dict):
        raise QualificationError("independent populated restore proof is incomplete")
    population = backup["preBackupPopulatedSignature"]
    runtime = restore.get("activatedRuntimeSha256")
    projects = (restore.get("priorProject"), restore.get("targetProject"))
    if (restore.get("populated") is not True
            or restore.get("independentHost") is not True
            or restore.get("encryptedTransfer") is not True
            or restore.get("activationVerified") is not True
            or restore.get("sourceHostIdentity") != backup["sourceHostIdentity"]
            or restore.get("sourceHostIdentity") == host_identity
            or restore.get("targetHostIdentity") != host_identity
            or any(restore.get(field) != backup[field]
                   for field in ("bundle", "manifestSha256", "encryptedArtifactSha256"))
            or any(restore.get(field) != backup["manifestSha256"]
                   for field in ("restoredManifestSha256", "activatedManifestSha256"))
            or any(restore.get(field) != population for field in (
                "beforeSignature", "restoredSignatureBeforeActivation", "afterSignature"))
            or any(not isinstance(project, str) or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project) is None
                   for project in projects)
            or projects[0] == projects[1]
            or not isinstance(runtime, str) or re.fullmatch(r"[a-f0-9]{64}", runtime) is None):
        raise QualificationError("independent populated restore proof is incomplete")
    verify_restored_public_readback(restore.get("publicReadback"), target=projects[1],
                                    runtime=runtime, expected=backup.get("preBackupPublicReadSignature"))


def verify_serving_release(observation: object, release_binding: dict) -> str:
    """Check the base installation against the live, signed operator projection."""
    if not isinstance(observation, dict):
        raise QualificationError("serving release observation is missing")
    for observed, expected in (("releaseManifestSha256", "releaseManifestSha256"),
                               ("inventorySha256", "releaseInventorySha256")):
        digest = release_binding.get(expected)
        if (not isinstance(digest, str) or not SHA256.fullmatch(digest)
                or observation.get(observed) != digest):
            raise QualificationError("serving release differs from the bound manifest or inventory")
    project = observation.get("project")
    launcher = observation.get("launcher")
    compose = observation.get("composeObservation")
    if (observation.get("format") != "openepm-operator-status-v1"
            or not isinstance(project, str) or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project) is None
            or observation.get("releaseImageCheck") != "matched"
            or observation.get("componentChecksPassed") is not True
            or not isinstance(launcher, dict) or launcher.get("status") != "active"
            or not isinstance(compose, dict) or compose.get("status") != "observed"
            or observation.get("observedOptionalProfiles") != []
            or type(observation.get("unclassifiedContainerCount")) is not int
            or observation["unclassifiedContainerCount"] != 0):
        raise QualificationError("serving release did not match the ready base installation")
    inventory = release_binding.get("releaseInventory")
    services = inventory.get("services") if isinstance(inventory, dict) else None
    components = observation.get("components")
    if (not isinstance(services, list) or not services
            or any(not isinstance(service, str) or not service for service in services)
            or not isinstance(components, list) or len(components) != len(services)):
        raise QualificationError("serving release has incomplete component coverage")
    remaining = set(services)
    for component in components:
        service = component.get("service") if isinstance(component, dict) else None
        if (not isinstance(service, str) or service not in remaining
                or component.get("readiness") != "checks-passed"
                or component.get("releaseImageCheck") != "matched"):
            raise QualificationError("serving release contains an unexpected or unverified component")
        remaining.remove(service)
        instances = component.get("instances")
        if not isinstance(instances, list) or len(instances) != 1:
            raise QualificationError("serving release must have one instance per component")
        instance = instances[0]
        if (not isinstance(instance, dict)
                or instance.get("state") != "running"
                or instance.get("instanceObservation") != "container-inspect"
                or instance.get("releaseImageCheck") != "matched"
                or instance.get("oneOff") is not False):
            raise QualificationError("serving release lacks one inspected matching instance per component")
    return project


def verify_host_attestation(host: object, expected_host: object) -> None:
    """Require an eligible Ubuntu/runsc target and an authenticated distinct source."""
    if (not isinstance(host, dict) or not isinstance(expected_host, dict)
            or not isinstance(expected_host.get("architecture"), str)
            or expected_host["architecture"] not in ARCHES
            or host.get("osId") != "ubuntu" or host.get("osVersion") != "24.04"
            or host.get("architecture") != expected_host["architecture"]
            or host.get("cleanHost") is not True
            or not isinstance(host.get("runscVersion"), str) or not host["runscVersion"].strip()
            or host.get("dockerRunscRegistered") is not True
            or host.get("developmentMacPathsPresent") is not False):
        raise QualificationError("clean Ubuntu/runsc host proof is incomplete")
    host_identity = host.get("hostIdentity")
    if not isinstance(host_identity, str) or not SHA256.fullmatch(host_identity):
        raise QualificationError("clean-host identity proof is incomplete")
    source = host.get("sourceHostIdentity")
    if not isinstance(source, str) or not SHA256.fullmatch(source):
        raise QualificationError("source backup host identity was not authenticated before installation")
    if source == host_identity:
        raise QualificationError("qualification target is not independent from source host")


def verify(plan_value: dict, evidence: dict) -> dict:
    if (plan_value.get("format") != "openepm-clean-linux-qualification-plan-v2"
            or plan_value.get("status") != "execution-required"
            or plan_value.get("qualificationClaimed") is not False
            or plan_value.get("phases") != list(PHASES)):
        raise QualificationError("invalid qualification plan")
    if (evidence.get("format") != "openepm-clean-linux-qualification-evidence-v2"
            or evidence.get("status") != "passed"
            or evidence.get("planSha256") != hashlib.sha256(
                canonical(plan_value)).hexdigest()):
        raise QualificationError("evidence does not bind the exact plan")
    host = evidence.get("host")
    expected_host = plan_value.get("host")
    verify_host_attestation(host, expected_host)
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
    if not isinstance(attestations, dict):
        raise QualificationError("serving release attestations are invalid")
    install_project = verify_serving_release(attestations.get("installedRelease"), plan_value)
    authenticated_mcp = attestations.get("authenticatedMcp", {})
    verify_mcp_identity_evidence(authenticated_mcp)
    restart = attestations.get("restart", {})
    verify_mcp_identity_evidence(restart, before=authenticated_mcp)
    verify_restart_continuity(restart.get("restartContinuity"))
    if verify_serving_release(restart.get("servingRelease"), plan_value) != install_project:
        raise QualificationError("serving release project changed on restart")
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
    verify_database_versions(evidence.get("databaseVersions"))
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
    if backup.get("sourceHostIdentity") != host["sourceHostIdentity"]:
        raise QualificationError("backup source differs from the pre-install host attestation")
    verify_restored_evidence(restore, backup, host["hostIdentity"])
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
        "releaseInventorySha256": evidence["releaseInventorySha256"],
        "activatedRestoreRuntimeSha256": restore["activatedRuntimeSha256"],
        "restoredBackupManifestSha256": restore["activatedManifestSha256"],
        "restoredPublicReadSignature": backup["preBackupPublicReadSignature"],
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
