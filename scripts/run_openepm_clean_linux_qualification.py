#!/usr/bin/env python3
"""Run a clean-Linux qualification plan on a trusted external host.

The runner deliberately knows no product credentials or deployment shortcuts.
An operator supplies one argv vector per plan phase.  Each command must emit a
small JSON attestation; stdout/stderr are hashed, not copied into evidence.
Injected executors are supported for deterministic validation, but only an
exact (not subclassed) SubprocessExecutor may emit ``status: passed``.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Protocol

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from qualify_openepm_clean_linux_release import (  # noqa: E402
    QualificationError, verify as verify_qualification,
)


class RunnerError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_object(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RunnerError(f"invalid {label}: {error}") from error
    if not isinstance(value, dict):
        raise RunnerError(f"{label} must be an object")
    return value


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class Executor(Protocol):
    def run(self, argv: tuple[str, ...]) -> CommandResult: ...


class SubprocessExecutor:
    def run(self, argv: tuple[str, ...]) -> CommandResult:
        completed = subprocess.run(argv, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        return CommandResult(completed.returncode, completed.stdout,
                             completed.stderr)


def _command(value: object, phase: str) -> tuple[str, ...]:
    if (not isinstance(value, list) or not value
            or any(not isinstance(item, str) or not item or "\x00" in item
                   for item in value)):
        raise RunnerError(f"phase {phase} requires a nonempty argv array")
    return tuple(value)


def _phase_payload(result: CommandResult, phase: str) -> dict:
    if result.returncode != 0:
        raise RunnerError(f"phase {phase} failed with exit {result.returncode}")
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RunnerError(f"phase {phase} did not emit one JSON object") from error
    if not isinstance(payload, dict) or payload.get("phase") != phase \
            or payload.get("status") != "passed":
        raise RunnerError(f"phase {phase} attestation is incomplete")
    return payload


def _artifact(root: Path, record: object, label: str) -> Path:
    if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
        raise RunnerError(f"invalid {label} binding")
    parsed = PurePosixPath(record["path"])
    if parsed.is_absolute() or ".." in parsed.parts:
        raise RunnerError(f"unsafe {label} path")
    candidate = root / parsed.as_posix()
    if candidate.is_symlink():
        raise RunnerError(f"{label} must not be a symlink")
    path = candidate.resolve()
    if root not in path.parents or not path.is_file():
        raise RunnerError(f"missing {label}")
    if digest_bytes(path.read_bytes()) != record["sha256"]:
        raise RunnerError(f"{label} digest mismatch")
    return path


def run(plan: dict, config: dict, executor: Executor, *, authorized: bool,
        config_root: Path | None = None) -> dict:
    if (plan.get("format") != "openepm-clean-linux-qualification-plan-v2"
            or plan.get("status") != "execution-required"
            or plan.get("qualificationClaimed") is not False):
        raise RunnerError("invalid clean-Linux qualification plan")
    phases = plan.get("phases")
    if not isinstance(phases, list) or len(phases) != len(set(phases)):
        raise RunnerError("plan phases are invalid")
    commands = config.get("commands")
    executables = config.get("phaseExecutables")
    if (config.get("format") != "openepm-clean-linux-runner-config-v2"
            or not isinstance(commands, dict)
            or set(commands) != set(phases)
            or not isinstance(executables, dict)
            or set(executables) != set(phases)):
        raise RunnerError("runner config must bind every exact plan phase")
    plan_sha = digest_bytes(canonical(plan))
    if config.get("planSha256") != plan_sha:
        raise RunnerError("runner config does not bind the exact plan")
    configured_root = Path(config.get("bundleRoot", ""))
    if not configured_root.is_absolute():
        base = (config_root if config_root is not None else Path.cwd()).resolve()
        configured_root = base / configured_root
    if configured_root.is_symlink():
        raise RunnerError("bundle root must not be a symlink")
    bundle_root = configured_root.resolve()
    if not bundle_root.is_dir():
        raise RunnerError("bundle root must be a real directory")
    manifest = _artifact(bundle_root, config.get("releaseManifest"),
                         "release manifest")
    bundle_manifest = _artifact(bundle_root, config.get("bundleManifest"),
                                "bundle manifest")
    if digest_bytes(manifest.read_bytes()) != plan["releaseManifestSha256"]:
        raise RunnerError("release manifest differs from qualification plan")
    bound_executables = {phase: _artifact(bundle_root, executables[phase],
        f"{phase} executable") for phase in phases}
    if any(not os.access(path, os.X_OK) for path in bound_executables.values()):
        raise RunnerError("every bound phase executable must be executable")
    phase_commands = {phase: _command(commands[phase], phase)
                      for phase in phases}
    for phase in phases:
        argv = list(phase_commands[phase])
        invoked = Path(argv[0])
        if not invoked.is_absolute():
            invoked = bundle_root / invoked
            argv[0] = str(invoked)
        # The generated phase command binds its context by a relative bundle
        # path. Rebase that exact argument without interpreting arbitrary
        # shell syntax or changing any other operator-supplied argument.
        if len(argv) == 5 and argv[1:4] == ["--phase", phase, "--context"]:
            context = Path(argv[4])
            if not context.is_absolute():
                argv[4] = str(bundle_root / context)
        phase_commands[phase] = tuple(argv)
        if invoked.is_symlink() or invoked.resolve() != bound_executables[phase]:
            raise RunnerError(f"phase {phase} command is not its bound executable")
    if not authorized:
        return {"format": "openepm-clean-linux-runner-result-v2",
            "status": "prepared-not-run", "qualificationClaimed": False,
            "externalHostExecutionRequired": True,
            "planSha256": plan_sha,
            "reason": "explicit external-host execution authorization required"}

    payloads: dict[str, dict] = {}
    command_evidence: dict[str, dict] = {}
    for phase in phases:
        argv = phase_commands[phase]
        result = executor.run(argv)
        payloads[phase] = _phase_payload(result, phase)
        command_evidence[phase] = {"argvSha256": digest_bytes(canonical(argv)),
            "executableSha256": digest_bytes(bound_executables[phase].read_bytes()),
            "exitCode": result.returncode,
            "stdoutSha256": digest_bytes(result.stdout),
            "stderrSha256": digest_bytes(result.stderr)}

    host = payloads["host-attestation"].get("host")
    bundle = payloads["bundle-integrity"].get("bundle")
    native = payloads["native-architecture-proof"].get("native")
    if not isinstance(host, dict) or not isinstance(bundle, dict) \
            or not isinstance(native, dict):
        raise RunnerError("host, bundle or native attestation is missing")
    host_identity = host.get("hostIdentity")
    if (not isinstance(host_identity, str) or len(host_identity) != 64
            or any(character not in "0123456789abcdef"
                   for character in host_identity)):
        raise RunnerError("clean-host identity attestation is missing")
    expected_bundle = {"releaseManifestSha256": plan["releaseManifestSha256"],
        "bundleManifestSha256": digest_bytes(bundle_manifest.read_bytes()),
        "sourceCommit": plan["sourceCommit"],
        "schemaMigration": plan["schemaMigration"]}
    if any(bundle.get(key) != value for key, value in expected_bundle.items()) \
            or not isinstance(bundle.get("sourceTreeSha256"), str) \
            or len(bundle["sourceTreeSha256"]) != 64:
        raise RunnerError("bundle/source/schema attestation differs from plan")
    if (native.get("architecture") != plan["host"]["architecture"]
            or native.get("sourceTreeSha256") != bundle["sourceTreeSha256"]
            or native.get("imageDigests") != plan["nativeImageDigests"]):
        raise RunnerError("native architecture/image/source proof differs from plan")

    backup = payloads["populated-backup"].get("backup", {})
    if (not isinstance(backup, dict)
            or not isinstance(backup.get("bundle"), str)
            or not backup["bundle"]
            or not isinstance(backup.get("sourceHostIdentity"), str)
            or len(backup["sourceHostIdentity"]) != 64
            or any(character not in "0123456789abcdef"
                   for character in backup["sourceHostIdentity"])
            or not isinstance(backup.get("preBackupPopulatedSignature"), str)
            or len(backup["preBackupPopulatedSignature"]) != 64
            or any(character not in "0123456789abcdef"
                   for character in backup["preBackupPopulatedSignature"])
            or not isinstance(backup.get("manifestSha256"), str)
            or len(backup["manifestSha256"]) != 64
            or any(character not in "0123456789abcdef"
                   for character in backup["manifestSha256"])
            or not isinstance(backup.get("encryptedArtifactSha256"), str)
            or len(backup["encryptedArtifactSha256"]) != 64
            or any(character not in "0123456789abcdef"
                   for character in backup["encryptedArtifactSha256"])
            or type(backup.get("encryptedPayloadCount")) is not int
            or backup["encryptedPayloadCount"] < 1
            or type(backup.get("totalBytes")) is not int
            or backup["totalBytes"] < 1):
        raise RunnerError("populated encrypted backup attestation is incomplete")
    restore = payloads["independent-host-restore"].get("restore", {})
    if (restore.get("independentHost") is not True
            or not restore.get("sourceHostIdentity")
            or restore.get("sourceHostIdentity") != backup["sourceHostIdentity"]
            or restore.get("sourceHostIdentity") == restore.get("targetHostIdentity")
            or restore.get("targetHostIdentity") != host_identity
            or restore.get("encryptedTransfer") is not True
            or restore.get("populated") is not True
            or restore.get("beforeSignature")
                != backup["preBackupPopulatedSignature"]
            or restore.get("afterSignature")
                != backup["preBackupPopulatedSignature"]):
        raise RunnerError("independent encrypted restore attestation is incomplete")
    if (restore.get("activationVerified") is not True
            or restore.get("bundle") != backup["bundle"]
            or not isinstance(restore.get("targetProject"), str)
            or not restore["targetProject"]
            or not isinstance(restore.get("priorProject"), str)
            or not restore["priorProject"]
            or restore["targetProject"] == restore["priorProject"]):
        raise RunnerError("restored-target activation attestation is incomplete")
    retirement = payloads["storage-retirement"].get("storageRetirement", {})
    if (set(retirement.get("scannedImages", [])) != set(plan["nativeImageDigests"])
            or retirement.get("prohibitedMatches") != 0
            or retirement.get("scannerExitCode") != 0
            or retirement.get("proxyScratchFiles") != 2
            or any(not isinstance(retirement.get(field), str)
                   or len(retirement[field]) != 64
                   or any(character not in "0123456789abcdef"
                          for character in retirement[field])
                   for field in ("proxyBinarySha256",
                                 "proxyCertificateSha256"))):
        raise RunnerError("final-image storage-retirement attestation is incomplete")

    workflow_map = {"authenticated-mcp": "authenticatedMcp",
        "authenticated-browser": "authenticatedBrowser",
        "runsc-headless-python": "runscHeadlessPython",
        "runsc-python-build-publication": "runscPythonBuildPublication",
        "service-restart": "restartPassed"}
    workflows = {target: payloads[source].get("verified") is True
                 for source, target in workflow_map.items()}
    authenticated_mcp = payloads["authenticated-mcp"]
    if (authenticated_mcp.get("verified") is not True
            or authenticated_mcp.get("unsignedDenied") is not True
            or not isinstance(authenticated_mcp.get("responseSha256"), str)
            or len(authenticated_mcp["responseSha256"]) != 64
            or any(character not in "0123456789abcdef"
                   for character in authenticated_mcp["responseSha256"])):
        raise RunnerError("authenticated MCP attestation is incomplete")
    restart = payloads["service-restart"]
    if (restart.get("verified") is not True
            or restart.get("authenticatedWorkflowClaimed") is not True
            or restart.get("unsignedDenied") is not True
            or not isinstance(restart.get("responseSha256"), str)
            or len(restart["responseSha256"]) != 64
            or any(character not in "0123456789abcdef"
                   for character in restart["responseSha256"])
            or restart["responseSha256"] != authenticated_mcp["responseSha256"]):
        raise RunnerError("authenticated post-restart MCP attestation is incomplete")
    headless = payloads["runsc-headless-python"]
    if (headless.get("verified") is not True
            or headless.get("runtime") != "runsc"
            or headless.get("image") != plan["nativeImageDigests"]["builder"]
            or type(headless.get("uid")) is not int or headless["uid"] == 0
            or headless.get("rootReadOnly") is not True
            or headless.get("networkBlocked") is not True
            or headless.get("tmpWritable") is not True
            or headless.get("negativeExitCode") != 23
            or not isinstance(headless.get("positiveOutputSha256"), str)
            or len(headless["positiveOutputSha256"]) != 64
            or any(character not in "0123456789abcdef"
                   for character in headless["positiveOutputSha256"])):
        raise RunnerError("runsc headless attestation is incomplete")
    publication = payloads["runsc-python-build-publication"]
    publication_digests = ("artifactSha256", "planSha256", "receiptSha256",
        "lineageSha256", "denialRevisionBefore", "denialRevisionAfter",
        "outputSha256")
    if (publication.get("verified") is not True
            or publication.get("runtime") != "runsc"
            or publication.get("builderImage") != plan["nativeImageDigests"]["builder"]
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
        raise RunnerError("runsc Python build/publication attestation is incomplete")
    browser = payloads["authenticated-browser"]
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
        raise RunnerError("authenticated browser attestation is incomplete")
    database_versions = payloads["database-version-read"].get(
        "databaseVersions", {})
    evidence = {"format": "openepm-clean-linux-qualification-evidence-v2",
        "status": "validation-only", "qualificationClaimed": False,
        "externalHostExecutionRequired": True,
        "planSha256": plan_sha,
        "releaseManifestSha256": plan["releaseManifestSha256"],
        "resolvedReleasePolicySha256": plan["resolvedReleasePolicySha256"],
        "sourceCommit": plan["sourceCommit"],
        "schemaMigration": plan["schemaMigration"],
        "sourceTreeSha256": bundle["sourceTreeSha256"],
        "bundleManifestSha256": expected_bundle["bundleManifestSha256"],
        "nativeImageDigests": plan["nativeImageDigests"], "host": host,
        "commands": {"doctorExitCode": command_evidence["epmctl-doctor"]["exitCode"],
                     "installExitCode": command_evidence["epmctl-install"]["exitCode"],
                     "evidence": command_evidence},
        "workflows": workflows, "databaseVersions": database_versions,
        "backup": backup, "restore": restore, "storageRetirement": retirement,
        "runtimeAttestations": {"authenticatedMcp": authenticated_mcp,
                                "restart": restart,
                                "authenticatedBrowser": browser,
                                "runscHeadlessPython": headless,
                                "runscPythonBuildPublication": publication},
        "completedPhases": phases}
    if type(executor) is not SubprocessExecutor:
        return evidence
    evidence["status"] = "passed"
    evidence["qualificationClaimed"] = True
    try:
        verify_qualification(plan, evidence)
    except QualificationError as error:
        raise RunnerError(f"existing clean-Linux verifier rejected evidence: {error}") \
            from error
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    authorized = args.run and os.environ.get("EPM_CLEAN_LINUX_RUN") == \
        "EXTERNAL_HOST_EXECUTION_AUTHORIZED"
    try:
        config_path = args.config.resolve()
        result = run(load_object(args.plan.resolve(), "plan"),
            load_object(config_path, "runner config"),
            SubprocessExecutor(), authorized=authorized,
            config_root=config_path.parent)
    except RunnerError as error:
        parser.error(str(error))
    args.output.write_bytes(canonical(result) + b"\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
