#!/usr/bin/env python3
"""Fail closed unless the current enterprise/UAT-readiness register is complete."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
REGISTER = ROOT / "docs" / "enterprise-readiness-acceptance-register.json"
EXPECTED_PACKAGES = [f"W{number}" for number in range(11)]
EXPECTED_GATES = {
    "zeroUnresolvedCriticalOrHighDefects", "cleanLinuxAmd64", "cleanLinuxArm64",
    "sustained300SessionsTenNotebooks", "activatedArtifactMatchesQualifiedRelease",
    "cleanupVerified", "ownerUatReady",
}
EXPECTED_BINDING_FIELDS = {
    "candidateDigest", "sourceTreeDigest", "migrationChainDigest",
    "schemaFingerprint", "configurationProfileDigest", "imageDigests",
    "architectures", "hostFingerprint", "executedScenarios", "executedAt",
}
HEX_DIGEST = re.compile(r"[0-9a-f]{64}")
IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
EXECUTED_AT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


def _verify_qualification_binding(name: str, value: object) -> dict:
    if not isinstance(value, dict) or set(value) != EXPECTED_BINDING_FIELDS:
        raise ValueError(f"RELEASE_GATE_BINDING_INVALID:{name}")
    for field in (
            "candidateDigest", "sourceTreeDigest", "migrationChainDigest",
            "schemaFingerprint", "configurationProfileDigest",
            "hostFingerprint"):
        if not isinstance(value.get(field), str) or not HEX_DIGEST.fullmatch(
                value[field]):
            raise ValueError(f"RELEASE_GATE_BINDING_INVALID:{name}:{field}")
    images = value.get("imageDigests")
    if (not isinstance(images, dict) or not images
            or any(not isinstance(image, str) or not image
                   or not isinstance(digest, str)
                   or not IMAGE_DIGEST.fullmatch(digest)
                   for image, digest in images.items())):
        raise ValueError(f"RELEASE_GATE_BINDING_INVALID:{name}:imageDigests")
    architectures = value.get("architectures")
    if (not isinstance(architectures, list) or not architectures
            or len(set(architectures)) != len(architectures)
            or any(architecture not in {"amd64", "arm64"}
                   for architecture in architectures)):
        raise ValueError(f"RELEASE_GATE_BINDING_INVALID:{name}:architectures")
    scenarios = value.get("executedScenarios")
    if (not isinstance(scenarios, list) or not scenarios
            or len(set(scenarios)) != len(scenarios)
            or any(not isinstance(scenario, str) or not scenario.strip()
                   for scenario in scenarios)):
        raise ValueError(
            f"RELEASE_GATE_BINDING_INVALID:{name}:executedScenarios")
    if (not isinstance(value.get("executedAt"), str)
            or not EXECUTED_AT.fullmatch(value["executedAt"])):
        raise ValueError(f"RELEASE_GATE_BINDING_INVALID:{name}:executedAt")
    required_architecture = {
        "cleanLinuxAmd64": "amd64",
        "cleanLinuxArm64": "arm64",
    }.get(name)
    if required_architecture and required_architecture not in architectures:
        raise ValueError(
            f"RELEASE_GATE_ARCHITECTURE_MISMATCH:{name}:{required_architecture}")
    return value


def verify_gate_evidence(name: str, value: object) -> dict:
    if not isinstance(value, dict) or set(value) != {
            "artifactPath", "artifactSha256", "evidenceFormat"}:
        raise ValueError(f"RELEASE_GATE_EVIDENCE_INVALID:{name}")
    relative = value.get("artifactPath")
    digest = value.get("artifactSha256")
    evidence_format = value.get("evidenceFormat")
    if (not isinstance(relative, str) or not relative
            or not isinstance(digest, str) or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not isinstance(evidence_format, str) or not evidence_format):
        raise ValueError(f"RELEASE_GATE_EVIDENCE_INVALID:{name}")
    candidate = ROOT / relative
    try:
        resolved = candidate.resolve(strict=True)
        qualifications = (ROOT / "docs" / "qualifications").resolve(strict=True)
    except OSError as error:
        raise ValueError(f"RELEASE_GATE_EVIDENCE_UNAVAILABLE:{name}") from error
    if (candidate.is_symlink() or not resolved.is_file()
            or resolved == qualifications or qualifications not in resolved.parents):
        raise ValueError(f"RELEASE_GATE_EVIDENCE_PATH_INVALID:{name}")
    payload = resolved.read_bytes()
    if hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError(f"RELEASE_GATE_EVIDENCE_DIGEST_MISMATCH:{name}")
    try:
        evidence = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"RELEASE_GATE_EVIDENCE_INVALID:{name}") from error
    if (not isinstance(evidence, dict)
            or evidence.get("format") != evidence_format
            or evidence.get("releaseGate") != name
            or evidence.get("passed") is not True):
        raise ValueError(f"RELEASE_GATE_EVIDENCE_ASSERTION_INVALID:{name}")
    return _verify_qualification_binding(name, evidence.get("qualificationBinding"))


def verify_work_package_evidence(package: str, values: object,
                                 *, verified: bool) -> None:
    if (not isinstance(values, list) or not values
            or len(set(values)) != len(values)
            or any(not isinstance(value, str) or not value for value in values)):
        raise ValueError(f"WORK_PACKAGE_EVIDENCE_INVALID:{package}")
    qualification_seen = False
    root = ROOT.resolve(strict=True)
    qualifications = (ROOT / "docs" / "qualifications").resolve(strict=True)
    for relative in values:
        candidate = ROOT / relative
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise ValueError(
                f"WORK_PACKAGE_EVIDENCE_UNAVAILABLE:{package}:{relative}") from error
        if (Path(relative).is_absolute() or candidate.is_symlink()
                or not resolved.is_file() or root not in resolved.parents):
            raise ValueError(
                f"WORK_PACKAGE_EVIDENCE_PATH_INVALID:{package}:{relative}")
        if qualifications in resolved.parents and resolved.suffix == ".json":
            try:
                qualification = json.loads(resolved.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise ValueError(
                    f"WORK_PACKAGE_QUALIFICATION_INVALID:{package}:{relative}") \
                    from error
            if not isinstance(qualification, dict):
                raise ValueError(
                    f"WORK_PACKAGE_QUALIFICATION_INVALID:{package}:{relative}")
            if qualification.get("format"):
                qualification_seen = True
            elif verified:
                raise ValueError(
                    f"WORK_PACKAGE_QUALIFICATION_INVALID:{package}:{relative}")
    if verified and not qualification_seen:
        raise ValueError(f"VERIFIED_PACKAGE_REQUIRES_QUALIFICATION:{package}")


def evaluate(value: object) -> dict:
    if not isinstance(value, dict) or value.get("format") != "openepm-enterprise-readiness-v1":
        raise ValueError("REGISTER_FORMAT_UNSUPPORTED")
    packages = value.get("workPackages")
    if not isinstance(packages, list) or [row.get("id") for row in packages if isinstance(row, dict)] != EXPECTED_PACKAGES:
        raise ValueError("WORK_PACKAGE_INVENTORY_INVALID")
    statuses = value.get("statusValues")
    if statuses != ["not_started", "in_progress", "verified", "deferred"]:
        raise ValueError("STATUS_VOCABULARY_INVALID")
    for row in packages:
        if row.get("status") not in statuses or not isinstance(row.get("evidence"), list):
            raise ValueError("WORK_PACKAGE_INVALID")
        if row.get("status") == "verified" and not row["evidence"]:
            raise ValueError("VERIFIED_PACKAGE_REQUIRES_EVIDENCE")
        if row["evidence"]:
            verify_work_package_evidence(
                row["id"], row["evidence"],
                verified=row["status"] == "verified")
    gates = value.get("releaseGates")
    if not isinstance(gates, dict) or set(gates) != EXPECTED_GATES or any(type(result) is not bool for result in gates.values()):
        raise ValueError("RELEASE_GATES_INVALID")
    gate_evidence = value.get("releaseGateEvidence")
    if not isinstance(gate_evidence, dict) or set(gate_evidence) != EXPECTED_GATES:
        raise ValueError("RELEASE_GATE_EVIDENCE_INVENTORY_INVALID")
    passed_bindings = []
    for name, passed in gates.items():
        if passed:
            passed_bindings.append((name, verify_gate_evidence(
                name, gate_evidence[name])))
        elif gate_evidence[name] is not None:
            raise ValueError(f"UNPASSED_RELEASE_GATE_HAS_EVIDENCE:{name}")
    if passed_bindings:
        identity_fields = (
            "candidateDigest", "sourceTreeDigest", "migrationChainDigest",
            "schemaFingerprint", "configurationProfileDigest",
        )
        first_name, first = passed_bindings[0]
        for name, binding in passed_bindings[1:]:
            if any(binding[field] != first[field] for field in identity_fields):
                raise ValueError(
                    f"RELEASE_GATE_CANDIDATE_MISMATCH:{first_name}:{name}")
    deferred = value.get("deferred")
    if not isinstance(deferred, list) or not deferred or any(not isinstance(row, dict) or row.get("mustNotBeReportedAsPassed") is not True for row in deferred):
        raise ValueError("DEFERRED_INVENTORY_INVALID")
    unresolved = [row["id"] for row in packages if row["status"] != "verified"]
    unmet = [name for name, result in gates.items() if not result]
    complete = not unresolved and not unmet
    if gates["ownerUatReady"] and (unresolved or any(name != "ownerUatReady" for name in unmet)):
        raise ValueError("OWNER_UAT_READINESS_CONTRADICTED")
    return {"format": "openepm-enterprise-readiness-check-v1", "complete": complete,
        "unresolvedWorkPackages": unresolved, "unmetReleaseGates": unmet,
        "deferredRequirements": [row["requirement"] for row in deferred]}


def main() -> int:
    try:
        result = evaluate(json.loads(REGISTER.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"format": "openepm-enterprise-readiness-check-v1", "complete": False, "error": str(error)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
