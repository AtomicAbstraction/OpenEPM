"""Bind a resolved release policy to the shipped, authoritative decision packet."""
from __future__ import annotations

from datetime import datetime
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
REVIEW_FIELDS = ("reviewerReference", "reviewedAt", "evidenceSha256")
ATTESTATION_FIELDS = set(REVIEW_FIELDS) | {
    "format", "decisionPacketSha256", "decisionId", "optionId", "resolution"}
SHA256 = re.compile(r"^[a-f0-9]{64}$")
REVIEWED_AT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]+)?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9]))?"
)


def default_packet() -> Path:
    bundled = Path(__file__).with_name("owner-decision-packet.json")
    return bundled if bundled.is_file() else (
        Path(__file__).parents[1] / "deploy/release/owner-decision-packet.json")


def parameter_present(value: object) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return bool(value) and all(parameter_present(item) for item in value)
    if isinstance(value, dict):
        return bool(value) and all(isinstance(key, str) and key.strip()
                                   and parameter_present(item)
                                   for key, item in value.items())
    return isinstance(value, (bool, int, float))


def _review_date_valid(value: object) -> bool:
    if not isinstance(value, str) or REVIEWED_AT.fullmatch(value) is None:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _review_text(value: object) -> bool:
    """Scopes and notices may group textual findings by file or obligation."""
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return bool(value) and all(_review_text(entry) for entry in value)
    if isinstance(value, dict):
        return bool(value) and all(key.strip() and _review_text(entry)
                                   for key, entry in value.items())
    return False


def _legal_resolution_valid(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != LEGAL_RESOLUTION_FIELDS:
        return False
    expression = value["licenseExpression"]
    return (isinstance(expression, str) and any(letter.isalpha() for letter in expression)
            and expression.strip().upper() not in {"NONE", "UNKNOWN", "NOASSERTION"}
            and _review_text(value["fileScopes"])
            and _review_text(value["attributionAndNoticeObligations"]))


def parse_json_object(raw: bytes, label: str) -> dict:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    def invalid_number(number):
        raise ValueError(f"invalid JSON number: {number}")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                           parse_constant=invalid_number)
    except ValueError as error:
        raise ValueError(f"invalid {label}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def resolve_legal_attestation(root: Path, reference: object, *, packet_sha256: str,
                              decision: dict, option_id: str) -> tuple[dict, dict]:
    """Derive the policy's review and resolution from the digest-checked bytes."""
    decision_id = decision["id"]
    if (not isinstance(reference, dict) or set(reference) != {"path", "sha256"}
            or not isinstance(reference["path"], str)
            or not isinstance(reference["sha256"], str)
            or SHA256.fullmatch(reference["sha256"]) is None):
        raise ValueError(f"legal attestation reference is invalid: {decision_id}")
    name = PurePosixPath(reference["path"])
    if name.is_absolute() or len(name.parts) != 1 or name.name == "..":
        raise ValueError(f"legal attestation reference is invalid: {decision_id}")
    path = root / name
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"legal attestation artifact is invalid: {decision_id}")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != reference["sha256"]:
        raise ValueError(f"legal attestation identity mismatch: {decision_id}")
    envelope = parse_json_object(raw, f"legal attestation {decision_id}")
    evidence = decision.get("evidence", {}).get("rawLicenseEvidenceSha256")
    resolution = envelope.get("resolution")
    if (set(envelope) != ATTESTATION_FIELDS
            or envelope["format"] != "openepm-external-legal-review-attestation-v1"
            or envelope["decisionPacketSha256"] != packet_sha256
            or envelope["decisionId"] != decision_id or envelope["optionId"] != option_id
            or not isinstance(evidence, list) or not evidence
            or any(not isinstance(item, str) or SHA256.fullmatch(item) is None
                   for item in evidence)
            or envelope["evidenceSha256"] != evidence
            or not isinstance(envelope["reviewerReference"], str)
            or not envelope["reviewerReference"].strip()
            or not _review_date_valid(envelope["reviewedAt"])
            or not _legal_resolution_valid(resolution)):
        raise ValueError(f"legal attestation is forged or incomplete: {decision_id}")
    review = {key: envelope[key] for key in REVIEW_FIELDS}
    return {"path": path.name, "sha256": reference["sha256"], **review}, resolution


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
    packet = parse_json_object(raw, "owner decision packet")
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
                    or any(not parameter_present(parameters[name]) for name in required)):
                raise ValueError(
                    f"resolved decision parameters are incomplete: {decision_id}")
        elif any(not isinstance(name, str) or not name.strip()
                 or not parameter_present(value) for name, value in parameters.items()):
            raise ValueError(f"resolved decision parameters are invalid: {decision_id}")
        if not is_legal:
            continue
        if option_id == "replace-or-exclude":
            raise ValueError(
                "dependency replacement requires regenerated locks, evidence, "
                f"and decision packet: {decision_id}")
        attestation = record["legalAttestation"]
        if not isinstance(attestation, dict):
            raise ValueError(f"legal attestation reference is invalid: {decision_id}")
        if artifact_root is None:
            raise ValueError("legal attestation artifact root is required")
        reference = {"path": attestation.get("path"), "sha256": attestation.get("sha256")}
        review, resolution = resolve_legal_attestation(
            artifact_root, reference, packet_sha256=policy["decisionPacketSha256"],
            decision=decision, option_id=option_id)
        if attestation != review:
            raise ValueError(f"legal attestation reference is invalid: {decision_id}")
        if record["legalResolution"] != resolution:
            raise ValueError(f"legal resolution differs from its attestation: {decision_id}")
