"""Pure, non-activating review contract for a schema-163 baseline packet.

The validator deliberately cannot authorize or apply a baseline.  It binds all
inputs and independent reviews needed before an owner may create a separate
production activation manifest.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any


FORMAT = "openepm-schema163-baseline-activation-review-v1"
EVIDENCE_KINDS = (
    "semanticReference", "populatedPreservation", "artifactConstruction",
    "injectionRollback", "reset", "recovery", "functionalParity", "upgradePath",
)
REVIEW_ROLES = ("artifact", "security", "recovery")
INJECTION_POINTS = ("after-artifact", "after-fingerprint", "after-audit")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")


def _fail(code: str) -> None:
    raise ValueError(code)


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def _time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("BASELINE_ACTIVATION_REVIEW_TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail("BASELINE_ACTIVATION_REVIEW_TIME_INVALID")
    if parsed.tzinfo != timezone.utc:
        _fail("BASELINE_ACTIVATION_REVIEW_TIME_INVALID")
    return parsed


def validate_activation_review(packet: dict[str, Any], *, artifact_bytes: bytes,
        expected_source_commit: str, expected_source_tree: str,
        expected_generator_guard_commit: str, expected_generator_guard_tree: str,
        expected_postgres_profile: str, expected_extension_profile: str,
        expected_semantic_pins: list[dict[str, Any]],
        expected_evidence_digests: dict[str, str], expected_parity: dict[str, Any],
        now: datetime) -> dict[str, Any]:
    """Validate exact review bindings; always returns activationAuthorized false."""
    required = {"format", "activationAuthorized", "baselineId", "validFrom",
        "expiresAt", "revokedAt", "producerIdentity", "intendedSource",
        "artifact", "semanticPins", "generatorGuard", "profile", "parity",
        "evidence", "injection", "gates", "reviewers", "contractDigest"}
    if not isinstance(packet, dict) or set(packet) != required:
        _fail("BASELINE_ACTIVATION_REVIEW_SHAPE_INVALID")
    if packet["format"] != FORMAT or packet["activationAuthorized"] is not False:
        _fail("BASELINE_ACTIVATION_REVIEW_BOUNDARY_INVALID")
    if packet["revokedAt"] is not None:
        _fail("BASELINE_ACTIVATION_REVIEW_REVOKED")
    if now.tzinfo != timezone.utc:
        _fail("BASELINE_ACTIVATION_REVIEW_NOW_INVALID")
    valid_from, expires = _time(packet["validFrom"]), _time(packet["expiresAt"])
    if not valid_from <= now < expires:
        _fail("BASELINE_ACTIVATION_REVIEW_EXPIRED_OR_NOT_YET_VALID")
    if not isinstance(packet["baselineId"], str) or not packet["baselineId"]:
        _fail("BASELINE_ACTIVATION_REVIEW_IDENTITY_INVALID")

    source = packet["intendedSource"]
    if (not isinstance(source, dict) or set(source) != {"commit", "tree"}
            or source != {"commit": expected_source_commit,
                          "tree": expected_source_tree}
            or not _COMMIT.fullmatch(source["commit"])
            or not _COMMIT.fullmatch(source["tree"])):
        _fail("BASELINE_ACTIVATION_REVIEW_SOURCE_MISMATCH")
    artifact = packet["artifact"]
    artifact_sha = hashlib.sha256(artifact_bytes).hexdigest()
    try:
        artifact_payload = json.loads(artifact_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("BASELINE_ACTIVATION_REVIEW_ARTIFACT_MISMATCH")
    if (not isinstance(artifact, dict)
            or set(artifact) != {"format", "sha256", "statementCount"}
            or artifact["format"] != "openepm-sql-statements-v1"
            or artifact["sha256"] != artifact_sha
            or type(artifact["statementCount"]) is not int
            or artifact["statementCount"] <= 0
            or not isinstance(artifact_payload, dict)
            or set(artifact_payload) != {"format", "statements"}
            or artifact_payload["format"] != artifact["format"]
            or not isinstance(artifact_payload["statements"], list)
            or len(artifact_payload["statements"]) != artifact["statementCount"]):
        _fail("BASELINE_ACTIVATION_REVIEW_ARTIFACT_MISMATCH")

    if (packet["semanticPins"] != expected_semantic_pins
            or not isinstance(expected_semantic_pins, list)
            or len(expected_semantic_pins) != 20
            or [row.get("version") for row in expected_semantic_pins]
                != list(range(144, 164))
            or any(not isinstance(row, dict)
              or set(row) != {"version", "sourceSha256", "statementSha256"}
              or not _DIGEST.fullmatch(str(row["sourceSha256"]))
              or not _DIGEST.fullmatch(str(row["statementSha256"]))
              for row in expected_semantic_pins)):
        _fail("BASELINE_ACTIVATION_REVIEW_SEMANTIC_PINS_MISMATCH")

    guard = packet["generatorGuard"]
    if (not isinstance(guard, dict)
            or set(guard) != {"commit", "tree", "reviewedArtifactSha256"}
            or guard != {"commit": expected_generator_guard_commit,
                         "tree": expected_generator_guard_tree,
                         "reviewedArtifactSha256": artifact_sha}
            or not _COMMIT.fullmatch(guard["commit"])
            or not _COMMIT.fullmatch(guard["tree"])):
        _fail("BASELINE_ACTIVATION_REVIEW_GENERATOR_GUARD_MISMATCH")
    profile = packet["profile"]
    if profile != {"postgres": expected_postgres_profile,
                   "extensions": expected_extension_profile}:
        _fail("BASELINE_ACTIVATION_REVIEW_PROFILE_MISMATCH")

    parity = packet["parity"]
    parity_fields = {"referenceObjectCount", "materializedObjectCount",
        "referenceObjectDigest", "materializedObjectDigest",
        "referenceFingerprint", "materializedFingerprint", "mismatchCount",
        "migrationLedgerCount", "migrationLedgerDigest"}
    if (not isinstance(parity, dict) or set(parity) != parity_fields
            or parity != expected_parity
            or type(parity["referenceObjectCount"]) is not int
            or parity["referenceObjectCount"] <= 0
            or parity["referenceObjectCount"] != parity["materializedObjectCount"]
            or parity["referenceObjectDigest"] != parity["materializedObjectDigest"]
            or parity["referenceFingerprint"] != parity["materializedFingerprint"]
            or any(not _DIGEST.fullmatch(str(parity[name])) for name in
              ("referenceObjectDigest", "materializedObjectDigest",
               "referenceFingerprint", "materializedFingerprint",
               "migrationLedgerDigest"))
            or parity["mismatchCount"] != 0
            or parity["migrationLedgerCount"] != 163):
        _fail("BASELINE_ACTIVATION_REVIEW_PARITY_INVALID")

    evidence = packet["evidence"]
    if (not isinstance(evidence, dict) or tuple(evidence) != EVIDENCE_KINDS
            or set(expected_evidence_digests) != set(EVIDENCE_KINDS)):
        _fail("BASELINE_ACTIVATION_REVIEW_EVIDENCE_INCOMPLETE")
    evidence_ids, evidence_hashes = set(), set()
    for kind in EVIDENCE_KINDS:
        row = evidence[kind]
        if (not isinstance(row, dict) or set(row) != {"evidenceId", "sha256",
              "status", "sourceCommit", "sourceTree", "supersededBy",
              "expiresAt", "revokedAt", "producerIdentity"}
                or row["sha256"] != expected_evidence_digests[kind]
                or not _DIGEST.fullmatch(str(row["sha256"]))
                or row["status"] != "verified" or row["supersededBy"] is not None
                or row["revokedAt"] is not None or _time(row["expiresAt"]) < expires
                or not _COMMIT.fullmatch(str(row["sourceCommit"]))
                or not _COMMIT.fullmatch(str(row["sourceTree"]))
                or not isinstance(row["evidenceId"], str) or not row["evidenceId"]
                or not isinstance(row["producerIdentity"], str)
                or not row["producerIdentity"]):
            _fail("BASELINE_ACTIVATION_REVIEW_EVIDENCE_STALE_OR_INVALID")
        evidence_ids.add(row["evidenceId"]); evidence_hashes.add(row["sha256"])
    if len(evidence_ids) != len(EVIDENCE_KINDS) or len(evidence_hashes) != len(EVIDENCE_KINDS):
        _fail("BASELINE_ACTIVATION_REVIEW_EVIDENCE_REUSED")

    injection = packet["injection"]
    if (not isinstance(injection, list) or len(injection) != 3
            or [row.get("point") for row in injection] != list(INJECTION_POINTS)
            or any(set(row) != {"point", "passed", "pristineAfterFailure"}
                   or row["passed"] is not True
                   or row["pristineAfterFailure"] is not True for row in injection)):
        _fail("BASELINE_ACTIVATION_REVIEW_INJECTION_INCOMPLETE")
    gates = packet["gates"]
    if (not isinstance(gates, dict) or tuple(gates) != EVIDENCE_KINDS
            or any(gates[kind] is not True for kind in EVIDENCE_KINDS)):
        _fail("BASELINE_ACTIVATION_REVIEW_GATE_INCOMPLETE")

    producer = packet["producerIdentity"]
    reviewers = packet["reviewers"]
    if (not isinstance(producer, str) or not producer
            or not isinstance(reviewers, list) or len(reviewers) != 3
            or [row.get("role") for row in reviewers] != list(REVIEW_ROLES)):
        _fail("BASELINE_ACTIVATION_REVIEW_REVIEWERS_INVALID")
    identities = []
    for row in reviewers:
        if (set(row) != {"role", "identity", "decision", "reviewedArtifactSha256",
                        "reviewedSourceCommit"}
                or row["decision"] != "approve"
                or row["reviewedArtifactSha256"] != artifact_sha
                or row["reviewedSourceCommit"] != source["commit"]
                or not isinstance(row["identity"], str) or not row["identity"]):
            _fail("BASELINE_ACTIVATION_REVIEW_REVIEWERS_INVALID")
        identities.append(row["identity"])
    evidence_producers = {evidence[kind]["producerIdentity"] for kind in EVIDENCE_KINDS}
    if (producer in identities or len(set(identities)) != 3
            or set(identities) & evidence_producers):
        _fail("BASELINE_ACTIVATION_REVIEW_SELF_REVIEW_FORBIDDEN")

    canonical = {key: packet[key] for key in required - {"contractDigest"}}
    if (not _DIGEST.fullmatch(str(packet["contractDigest"]))
            or packet["contractDigest"] != _digest(canonical)):
        _fail("BASELINE_ACTIVATION_REVIEW_DIGEST_MISMATCH")
    return {"validated": True, "activationAuthorized": False,
        "baselineId": packet["baselineId"], "artifactSha256": artifact_sha,
        "contractDigest": packet["contractDigest"], "expiresAt": packet["expiresAt"]}
