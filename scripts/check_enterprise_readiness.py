#!/usr/bin/env python3
"""Fail closed unless the current enterprise/UAT-readiness register is complete."""
from __future__ import annotations

import argparse
from datetime import datetime
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
    "sustained300Sessions", "activatedArtifactMatchesQualifiedRelease",
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
    if (not _nonempty_strings(architectures)
            or any(architecture not in {"amd64", "arm64"}
                   for architecture in architectures)):
        raise ValueError(f"RELEASE_GATE_BINDING_INVALID:{name}:architectures")
    scenarios = value.get("executedScenarios")
    if not _nonempty_strings(scenarios):
        raise ValueError(
            f"RELEASE_GATE_BINDING_INVALID:{name}:executedScenarios")
    if (not isinstance(value.get("executedAt"), str)
            or not EXECUTED_AT.fullmatch(value["executedAt"])):
        raise ValueError(f"RELEASE_GATE_BINDING_INVALID:{name}:executedAt")
    try:
        datetime.strptime(value["executedAt"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ValueError(f"RELEASE_GATE_BINDING_INVALID:{name}:executedAt") from error
    required_architecture = {
        "cleanLinuxAmd64": "amd64",
        "cleanLinuxArm64": "arm64",
    }.get(name)
    if required_architecture and required_architecture not in architectures:
        raise ValueError(
            f"RELEASE_GATE_ARCHITECTURE_MISMATCH:{name}:{required_architecture}")
    return value


def _read_bound_evidence(name: str, value: object) -> dict:
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
    if (Path(relative).is_absolute() or candidate.is_symlink() or not resolved.is_file()
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
            or evidence.get("passed") is not True):
        raise ValueError(f"RELEASE_GATE_EVIDENCE_ASSERTION_INVALID:{name}")
    return evidence


def verify_gate_evidence(name: str, value: object) -> dict:
    evidence = _read_bound_evidence(name, value)
    if evidence.get("releaseGate") != name:
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



LAPTOP_PACKAGES = [f"L{number:02}" for number in range(16)]
LAPTOP_OBLIGATIONS = [f"F{number:02}" for number in range(1, 65)]
LAPTOP_STATUSES = ["pending", "in_progress", "verified", "blocked"]
LAPTOP_DEPENDENCIES = {
    "L00": [], "L01": ["L00"], "L02": ["L00", "L01"],
    "L03": ["L02"], "L04": ["L02"],
    "L05": ["L02", "L03", "L04"], "L06": ["L02", "L04"],
    "L07": ["L03", "L04", "L06"],
    "L08": ["L02", "L04", "L05", "L06", "L07"],
    "L09": ["L04", "L05", "L07", "L08"],
    "L10": ["L04", "L05", "L06", "L07", "L08", "L09"],
    "L11": ["L08", "L09", "L10"], "L12": ["L11"],
    "L13": ["L12"], "L14": ["L13"], "L15": ["L14"],
}
LAPTOP_OWNERS = {
    **{f"F{i:02}": "L02" for i in range(1, 6)},
    **{f"F{i:02}": "L03" for i in range(6, 10)},
    **{f"F{i:02}": "L04" for i in range(10, 19)},
    **{f"F{i:02}": "L05" for i in range(19, 25)},
    **{f"F{i:02}": "L06" for i in range(25, 36)},
    **{f"F{i:02}": "L07" for i in (*range(36, 40), *range(44, 48))},
    **{f"F{i:02}": "L09" for i in (*range(40, 44), 52, 53)},
    **{f"F{i:02}": "L08" for i in range(48, 52)},
    **{f"F{i:02}": "L01" for i in range(54, 57)},
    "F57": "L13", "F58": "L12", "F59": "L12", "F60": "L13",
    "F61": "L14", "F62": "L15", "F63": "L15", "F64": "L15",
}
LAPTOP_DEFERRED_CAMPAIGNS = [
    "concurrency_and_contention", "crash_takeover_and_recovery",
    "load_performance_and_storage_scale", "portable_distribution",
    "rust_migration", "acceleration", "formal_backup_retention",
]
LAPTOP_CLAIMS = {
    "laptopFunctionalComplete", "historyCleanupComplete", "planComplete",
}
LAPTOP_IDENTITY_FIELDS = (
    "candidateDigest", "sourceTreeDigest", "migrationChainDigest",
    "schemaFingerprint", "configurationProfileDigest",
)


def _nonempty_strings(value: object) -> bool:
    return (isinstance(value, list) and bool(value)
            and all(isinstance(item, str) and item.strip() for item in value)
            and len(set(value)) == len(value))


def _verify_laptop_evidence(subject: str, reference: object) -> dict:
    evidence = _read_bound_evidence(subject, reference)
    subjects = evidence.get("subjects")
    owner_subjects = {"L14", "F61"}
    known_subjects = set(LAPTOP_PACKAGES) | set(LAPTOP_OBLIGATIONS)
    if (not _nonempty_strings(subjects) or subject not in subjects
            or not set(subjects) <= known_subjects or "subject" in evidence):
        raise ValueError(f"LAPTOP_EVIDENCE_SUBJECT_INVALID:{subject}")
    owner_acceptance = bool(set(subjects) & owner_subjects)
    expected_format = ("openepm-laptop-owner-acceptance-v1" if owner_acceptance
                       else "openepm-laptop-functional-evidence-v1")
    if (evidence.get("format") != expected_format
            or evidence.get("acceptanceGroup") != "laptopFunctionalAcceptance"
            or (owner_acceptance and not set(subjects) <= owner_subjects)):
        raise ValueError(f"LAPTOP_EVIDENCE_SUBJECT_INVALID:{subject}")
    binding = _verify_qualification_binding(
        subject, evidence.get("qualificationBinding"))
    if not set(subjects).issubset(binding["executedScenarios"]):
        raise ValueError(f"LAPTOP_EVIDENCE_SCENARIO_MISSING:{subject}")
    context = evidence.get("functionalContext")
    if not isinstance(context, dict) or set(context) != {
            "scope", "runtimeContractDigest", "clientContractDigest",
            "principalIds", "applicationIds", "commands", "outcome"}:
        raise ValueError(f"LAPTOP_EVIDENCE_CONTEXT_INVALID:{subject}")
    for field in ("runtimeContractDigest", "clientContractDigest"):
        if (not isinstance(context[field], str)
                or not HEX_DIGEST.fullmatch(context[field])):
            raise ValueError(f"LAPTOP_EVIDENCE_CONTEXT_INVALID:{subject}:{field}")
    for field in ("principalIds", "applicationIds", "commands"):
        if not _nonempty_strings(context[field]):
            raise ValueError(f"LAPTOP_EVIDENCE_CONTEXT_INVALID:{subject}:{field}")
    scope = context["scope"]
    if (not isinstance(scope, str) or scope not in {"source_contract", "isolated_functional",
                      "installed_laptop", "owner_acceptance", "history_cleanup"}
            or context["outcome"] != "passed"):
        raise ValueError(f"LAPTOP_EVIDENCE_CONTEXT_INVALID:{subject}")
    # A current proof may serve several rows. Validate every claimed subject,
    # including those not yet referenced by a register row, under one binding.
    for claimed_subject in subjects:
        required_scope = {
            "L11": "isolated_functional", "L12": "installed_laptop",
            "L13": "installed_laptop", "L14": "owner_acceptance",
            "L15": "history_cleanup", "F58": "installed_laptop",
            "F59": "installed_laptop", "F60": "installed_laptop",
            "F61": "owner_acceptance", "F62": "history_cleanup",
            "F63": "history_cleanup", "F64": "history_cleanup",
        }.get(claimed_subject)
        if required_scope and scope != required_scope:
            raise ValueError(f"LAPTOP_EVIDENCE_SCOPE_INVALID:{claimed_subject}")
        if claimed_subject in {"L09", "L11", "L12", "L14", "F40", "F61"} and (
                len(context["principalIds"]) != 5 or len(context["applicationIds"]) < 2):
            raise ValueError(f"LAPTOP_FIVE_USER_SCOPE_REQUIRED:{claimed_subject}")
        required_scenarios = {
            "L11": {f"F{i:02}" for i in range(1, 57)},
            "L12": {f"F{i:02}" for i in (*range(1, 54), 58, 59, 60)},
            "L13": {f"F{i:02}" for i in (*range(19, 25), 57, 60)},
        }.get(claimed_subject, set())
        if not required_scenarios.issubset(binding["executedScenarios"]):
            raise ValueError(f"LAPTOP_INTEGRATED_COVERAGE_MISSING:{claimed_subject}")
    if owner_acceptance:
        confirmation = evidence.get("ownerAcceptance")
        if (not isinstance(confirmation, dict) or set(confirmation) != {
                "decision", "acceptedBy", "confirmationReference", "statement"}
                or confirmation.get("decision") != "accepted"
                or any(not isinstance(confirmation.get(field), str)
                       or not confirmation[field].strip()
                       for field in ("acceptedBy", "confirmationReference", "statement"))):
            raise ValueError(f"LAPTOP_OWNER_ACCEPTANCE_REQUIRED:{subject}")
    return {"binding": binding, "context": context}


def _verify_laptop_scoped_evidence(subject: str, reference: object) -> None:
    """Validate informative implementation evidence without accepting a row."""
    if not isinstance(reference, str) or not reference.strip():
        raise ValueError(f"LAPTOP_SCOPED_EVIDENCE_INVALID:{subject}")
    candidate = ROOT / reference
    try:
        resolved = candidate.resolve(strict=True)
        qualifications = (ROOT / "docs" / "qualifications").resolve(strict=True)
    except OSError as error:
        raise ValueError(
            f"LAPTOP_SCOPED_EVIDENCE_UNAVAILABLE:{subject}:{reference}") from error
    if (Path(reference).is_absolute() or candidate.is_symlink()
            or not resolved.is_file() or resolved.suffix != ".json"
            or qualifications not in resolved.parents):
        raise ValueError(f"LAPTOP_SCOPED_EVIDENCE_PATH_INVALID:{subject}")
    try:
        evidence = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"LAPTOP_SCOPED_EVIDENCE_INVALID:{subject}") from error
    if (not isinstance(evidence, dict)
            or not isinstance(evidence.get("format"), str)
            or not evidence["format"].strip()):
        raise ValueError(f"LAPTOP_SCOPED_EVIDENCE_INVALID:{subject}")


def evaluate_laptop(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != {
            "format", "authority", "population", "statusValues", "workPackages",
            "obligations", "acceptanceClaims", "deferredCampaigns"} or value.get(
                "format") != "openepm-laptop-functional-acceptance-v1":
        raise ValueError("LAPTOP_GROUP_INVALID")
    if value["authority"] != "docs/laptop-core-architecture-and-business-semantics-plan-2026-11-11.md":
        raise ValueError("LAPTOP_AUTHORITY_INVALID")
    if value["population"] != {"distinctUsers": 5, "minimumApplications": 2}:
        raise ValueError("LAPTOP_POPULATION_INVALID")
    if value["statusValues"] != LAPTOP_STATUSES:
        raise ValueError("LAPTOP_STATUS_VOCABULARY_INVALID")
    rows_by_id = {}
    verified_evidence = {}
    for collection, expected, fields in (
            ("workPackages", LAPTOP_PACKAGES,
             {"id", "title", "accountable", "dependsOn", "contributesTo", "status", "evidence"}),
            ("obligations", LAPTOP_OBLIGATIONS,
             {"id", "scenario", "requiredProof", "acceptanceOwner", "status", "evidence"})):
        rows = value[collection]
        if (not isinstance(rows, list)
                or any(not isinstance(row, dict) for row in rows)
                or [row.get("id") for row in rows] != expected):
            raise ValueError(f"LAPTOP_INVENTORY_INVALID:{collection}")
        for row in rows:
            subject = row["id"]
            if (set(row) != fields or row.get("status") not in LAPTOP_STATUSES
                    or not isinstance(row.get("evidence"), list)):
                raise ValueError(f"LAPTOP_ROW_INVALID:{subject}")
            text_fields = (("title", "accountable") if collection == "workPackages"
                           else ("scenario", "requiredProof"))
            if any(not isinstance(row[field], str) or not row[field].strip()
                   for field in text_fields):
                raise ValueError(f"LAPTOP_ROW_INVALID:{subject}")
            if collection == "workPackages":
                if row["dependsOn"] != LAPTOP_DEPENDENCIES[subject]:
                    raise ValueError(f"LAPTOP_DEPENDENCIES_INVALID:{subject}")
                contributes = row["contributesTo"]
                if (not isinstance(contributes, list)
                        or any(not isinstance(item, str) or item not in LAPTOP_OBLIGATIONS
                               for item in contributes)
                        or len(set(contributes)) != len(contributes)):
                    raise ValueError(f"LAPTOP_CONTRIBUTIONS_INVALID:{subject}")
            elif row["acceptanceOwner"] != LAPTOP_OWNERS[subject]:
                raise ValueError(f"LAPTOP_ACCEPTANCE_OWNER_INVALID:{subject}")
            if row["status"] == "verified":
                proofs = [
                    _verify_laptop_evidence(subject, item)
                    for item in row["evidence"]
                ]
                if len(proofs) != 1:
                    raise ValueError(f"LAPTOP_VERIFIED_REQUIRES_ONE_CURRENT_PROOF:{subject}")
                verified_evidence[subject] = proofs[0]
            else:
                scoped = [item for item in row["evidence"]
                          if isinstance(item, str)]
                if len(set(scoped)) != len(scoped):
                    raise ValueError(f"LAPTOP_SCOPED_EVIDENCE_DUPLICATE:{subject}")
                for item in row["evidence"]:
                    if isinstance(item, str):
                        _verify_laptop_scoped_evidence(subject, item)
                    else:
                        # A valid formal artifact may survive a status rollback,
                        # but it never counts as acceptance unless status is verified.
                        _verify_laptop_evidence(subject, item)
            rows_by_id[subject] = row
    for subject, row in rows_by_id.items():
        if row["status"] != "verified":
            continue
        dependencies = (row["dependsOn"] if subject.startswith("L")
                        else [row["acceptanceOwner"]])
        if any(rows_by_id[item]["status"] != "verified" for item in dependencies):
            raise ValueError(f"LAPTOP_DEPENDENCY_NOT_VERIFIED:{subject}")
    if rows_by_id["L14"]["status"] == "verified" and any(
            rows_by_id[f"F{i:02}"]["status"] != "verified" for i in range(1, 61)):
        raise ValueError("LAPTOP_OWNER_REVIEW_PREMATURE")
    if rows_by_id["L15"]["status"] == "verified" and rows_by_id["F61"]["status"] != "verified":
        raise ValueError("LAPTOP_HISTORY_RESET_PREMATURE")
    # Early package proofs are scoped contributions. Only final integration,
    # installation and owner acceptance must describe the same accepted tree.
    final_subjects = [item for item in ("L11", "L12", "L13", "L14", "F61")
                      if item in verified_evidence]
    if final_subjects:
        first = verified_evidence[final_subjects[0]]
        for subject in final_subjects[1:]:
            proof = verified_evidence[subject]
            if (any(proof["binding"][field] != first["binding"][field]
                    for field in LAPTOP_IDENTITY_FIELDS)
                    or any(proof["context"][field] != first["context"][field]
                           for field in ("runtimeContractDigest", "clientContractDigest"))):
                raise ValueError(f"LAPTOP_ACCEPTED_CANDIDATE_MISMATCH:{subject}")
    installed_subjects = [item for item in ("L12", "L13", "L14", "F61")
                          if item in verified_evidence]
    if installed_subjects:
        installed = verified_evidence[installed_subjects[0]]
        for subject in installed_subjects[1:]:
            proof = verified_evidence[subject]
            if (any(proof["binding"][field] != installed["binding"][field]
                    for field in ("hostFingerprint", "imageDigests"))
                    or any(set(proof["context"][field]) != set(installed["context"][field])
                           for field in ("principalIds", "applicationIds"))):
                raise ValueError(f"LAPTOP_INSTALLED_SCOPE_MISMATCH:{subject}")
    if "F61" in verified_evidence:
        accepted = verified_evidence["F61"]
        for subject in ("L15", "F62", "F63", "F64"):
            if subject not in verified_evidence:
                continue
            proof = verified_evidence[subject]
            # A rewritten root may change the candidate identifier, but cannot
            # substitute different accepted content, schema or runtime contracts.
            if (any(proof["binding"][field] != accepted["binding"][field]
                    for field in LAPTOP_IDENTITY_FIELDS if field != "candidateDigest")
                    or any(proof["context"][field] != accepted["context"][field]
                           for field in ("runtimeContractDigest", "clientContractDigest"))):
                raise ValueError(f"LAPTOP_HISTORY_CONTENT_MISMATCH:{subject}")
    campaigns = value["deferredCampaigns"]
    if (not isinstance(campaigns, list)
            or any(not isinstance(row, dict) or set(row) != {"id", "status", "reason"}
                   or row.get("status") != "deferred"
                   or not isinstance(row.get("reason"), str) or not row["reason"].strip()
                   for row in campaigns)
            or [row["id"] for row in campaigns] != LAPTOP_DEFERRED_CAMPAIGNS):
        raise ValueError("LAPTOP_DEFERRED_CAMPAIGNS_INVALID")
    unresolved_packages = [item for item in LAPTOP_PACKAGES if rows_by_id[item]["status"] != "verified"]
    unresolved_obligations = [item for item in LAPTOP_OBLIGATIONS if rows_by_id[item]["status"] != "verified"]
    functional = (not any(item in unresolved_packages for item in LAPTOP_PACKAGES[:15])
                  and not any(item in unresolved_obligations for item in LAPTOP_OBLIGATIONS[:61]))
    history = ("L15" not in unresolved_packages
               and not any(item in unresolved_obligations for item in LAPTOP_OBLIGATIONS[61:]))
    computed = {"laptopFunctionalComplete": functional,
                "historyCleanupComplete": history, "planComplete": functional and history}
    claims = value["acceptanceClaims"]
    if (not isinstance(claims, dict) or set(claims) != LAPTOP_CLAIMS
            or any(type(result) is not bool for result in claims.values())):
        raise ValueError("LAPTOP_ACCEPTANCE_CLAIMS_INVALID")
    for claim, asserted in claims.items():
        if asserted and not computed[claim]:
            raise ValueError(f"LAPTOP_ACCEPTANCE_CLAIM_UNSUPPORTED:{claim}")
    return {**computed, "unresolvedWorkPackages": unresolved_packages,
            "unresolvedObligations": unresolved_obligations,
            "deferredCampaigns": LAPTOP_DEFERRED_CAMPAIGNS}


def evaluate(value: object) -> dict:
    if not isinstance(value, dict) or value.get("format") != "openepm-enterprise-readiness-v1":
        raise ValueError("REGISTER_FORMAT_UNSUPPORTED")
    laptop = evaluate_laptop(value.get("laptopFunctionalAcceptance"))
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
        "deferredRequirements": [row["requirement"] for row in deferred],
        "laptopFunctionalAcceptance": laptop}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", choices=("enterprise", "laptop", "laptop-plan"),
                        default="enterprise")
    args = parser.parse_args(argv)
    try:
        result = evaluate(json.loads(REGISTER.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"format": "openepm-enterprise-readiness-check-v1", "complete": False, "error": str(error)}, sort_keys=True))
        return 2
    result["evaluatedScope"] = args.scope
    scoped_complete = (result["complete"] if args.scope == "enterprise" else
                       result["laptopFunctionalAcceptance"][
                           "laptopFunctionalComplete" if args.scope == "laptop" else "planComplete"])
    result["scopeComplete"] = scoped_complete
    print(json.dumps(result, sort_keys=True))
    return 0 if scoped_complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
