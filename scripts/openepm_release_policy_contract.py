"""Bind a resolved release policy to the shipped, authoritative decision packet."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re

CATEGORIES = ("legalReviewRequired", "ownerProductDecisions",
              "ownerSecurityOperationsDecisions")
POLICY_FIELDS = {"format", "status", "allDecisionsExplicit",
                 "decisionPacketSha256", "selectionsSha256", "decisionCount",
                 "legalAttestationCount", "decisions"}
DECISION_FIELDS = {"decisionId", "optionId", "effect", "parameters"}
LEGAL_FIELDS = DECISION_FIELDS | {"legalAttestation", "legalResolution"}
LEGAL_RESOLUTION_FIELDS = {"licenseExpression", "fileScopes",
                           "attributionAndNoticeObligations"}
LEGAL_ATTESTATION_FIELDS = {"path", "sha256", "reviewerReference",
                            "reviewedAt", "evidenceSha256"}
SHA256 = re.compile(r"^[a-f0-9]{64}$")
REVIEWED_AT = re.compile(
    r"^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))?$"
)


def default_packet() -> Path:
    bundled = Path(__file__).with_name("owner-decision-packet.json")
    return bundled if bundled.is_file() else (
        Path(__file__).parents[1] / "deploy/release/owner-decision-packet.json")


def _present(value: object) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return bool(value) and all(_present(item) for item in value)
    if isinstance(value, dict):
        return bool(value) and all(isinstance(key, str) and key.strip()
                                   and _present(item)
                                   for key, item in value.items())
    return isinstance(value, (bool, int, float))


def _packet_decisions(packet: dict) -> tuple[list[dict], set[str]]:
    if (packet.get("format") != "openepm-owner-decision-packet-v1"
            or packet.get("status") != "decisions-pending"
            or packet.get("approvalsRecorded") is not False
            or any(not isinstance(packet.get(name), list) for name in CATEGORIES)):
        raise ValueError("owner decision packet contract is invalid")
    decisions = [item for name in CATEGORIES for item in packet[name]]
    legal = {item.get("id") for item in packet["legalReviewRequired"]
             if isinstance(item, dict)}
    identities = [item.get("id") for item in decisions
                  if isinstance(item, dict)]
    if (len(identities) != len(decisions)
            or any(not isinstance(identity, str) or not identity
                   for identity in identities)
            or len(identities) != len(set(identities))):
        raise ValueError("owner decision packet identities are invalid")
    for decision in decisions:
        options = decision.get("options")
        required = decision.get("requiredParameters", [])
        if (not isinstance(options, list) or not options
                or any(not isinstance(option, dict)
                       or not isinstance(option.get("id"), str)
                       or not option["id"]
                       or not isinstance(option.get("effect"), str)
                       or not option["effect"] for option in options)
                or len({option["id"] for option in options}) != len(options)
                or not isinstance(required, list)
                or any(not isinstance(name, str) or not name.strip()
                       for name in required)
                or len(required) != len(set(required))):
            raise ValueError("owner decision packet choices are invalid")
    return decisions, legal


def validate(policy: dict, packet_path: Path | None = None,
             *, artifact_root: Path | None = None) -> None:
    path = packet_path or default_packet()
    raw = path.read_bytes()
    packet = json.loads(raw)
    if not isinstance(packet, dict):
        raise ValueError("owner decision packet contract is invalid")
    decisions, legal = _packet_decisions(packet)
    expected = {item["id"]: item for item in decisions}
    resolved = policy.get("decisions") if isinstance(policy, dict) else None
    if (not isinstance(policy, dict) or set(policy) != POLICY_FIELDS
            or policy.get("format") != "openepm-resolved-release-policy-v1"
            or policy.get("status") != "resolved-explicit"
            or policy.get("allDecisionsExplicit") is not True
            or policy.get("decisionPacketSha256") != hashlib.sha256(raw).hexdigest()
            or not isinstance(policy.get("selectionsSha256"), str)
            or SHA256.fullmatch(policy["selectionsSha256"]) is None
            or policy.get("decisionCount") != len(expected)
            or policy.get("legalAttestationCount") != len(legal)
            or not isinstance(resolved, list)):
        raise ValueError("resolved release policy differs from the shipped decision inventory")
    ids = [item.get("decisionId") for item in resolved
           if isinstance(item, dict)]
    if (len(ids) != len(resolved) or len(ids) != len(set(ids))
            or set(ids) != set(expected)):
        raise ValueError("resolved release policy differs from the shipped decision inventory")

    for record in resolved:
        decision_id = record["decisionId"]
        decision = expected[decision_id]
        is_legal = decision_id in legal
        if set(record) != (LEGAL_FIELDS if is_legal else DECISION_FIELDS):
            raise ValueError(f"resolved decision fields are invalid: {decision_id}")
        options = {option["id"]: option for option in decision["options"]}
        option_id = record.get("optionId")
        if (option_id not in options
                or record.get("effect") != options[option_id]["effect"]):
            raise ValueError(f"resolved decision choice is invalid: {decision_id}")
        parameters = record.get("parameters")
        required = decision.get("requiredParameters", [])
        if not isinstance(parameters, dict):
            raise ValueError(f"resolved decision parameters are invalid: {decision_id}")
        if required:
            if (set(parameters) != set(required)
                    or any(not _present(parameters[name]) for name in required)):
                raise ValueError(
                    f"resolved decision parameters are incomplete: {decision_id}")
        elif any(not isinstance(name, str) or not name.strip()
                 or not _present(value) for name, value in parameters.items()):
            raise ValueError(f"resolved decision parameters are invalid: {decision_id}")
        if not is_legal:
            continue
        if option_id == "replace-or-exclude":
            raise ValueError(
                "dependency replacement requires regenerated locks, evidence, "
                f"and decision packet: {decision_id}")
        attestation = record["legalAttestation"]
        parsed = (PurePosixPath(attestation.get("path"))
                  if isinstance(attestation, dict)
                  and isinstance(attestation.get("path"), str) else None)
        expected_evidence = decision.get("evidence", {}).get(
            "rawLicenseEvidenceSha256")
        if (not isinstance(attestation, dict)
                or set(attestation) != LEGAL_ATTESTATION_FIELDS
                or parsed is None or parsed.is_absolute()
                or len(parsed.parts) != 1 or parsed.name in ("", ".", "..")
                or not isinstance(attestation.get("sha256"), str)
                or SHA256.fullmatch(attestation["sha256"]) is None
                or not isinstance(attestation.get("reviewerReference"), str)
                or not attestation["reviewerReference"].strip()
                or not isinstance(attestation.get("reviewedAt"), str)
                or REVIEWED_AT.fullmatch(attestation["reviewedAt"]) is None
                or not isinstance(expected_evidence, list)
                or not expected_evidence
                or any(not isinstance(item, str) or SHA256.fullmatch(item) is None
                       for item in expected_evidence)
                or attestation.get("evidenceSha256") != expected_evidence):
            raise ValueError(f"legal attestation reference is invalid: {decision_id}")
        if artifact_root is None:
            raise ValueError("legal attestation artifact root is required")
        attestation_path = artifact_root / parsed.as_posix()
        if (not attestation_path.is_file() or attestation_path.is_symlink()
                or hashlib.sha256(attestation_path.read_bytes()).hexdigest()
                != attestation["sha256"]):
            raise ValueError(f"legal attestation artifact is invalid: {decision_id}")
        resolution = record["legalResolution"]
        if (not isinstance(resolution, dict)
                or set(resolution) != LEGAL_RESOLUTION_FIELDS
                or any(not _present(resolution[name])
                       for name in LEGAL_RESOLUTION_FIELDS)):
            raise ValueError(f"legal resolution is incomplete: {decision_id}")
