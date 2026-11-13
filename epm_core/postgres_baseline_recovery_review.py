"""Fail-closed recovery review contract for an exact schema-164 baseline install.

This module neither performs recovery nor authorizes activation.  It validates
evidence bindings produced by disposable, independently owned recovery runs.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any


FORMAT = "openepm-schema164-baseline-recovery-review-v1"
EVIDENCE_KINDS = ("backupExport", "independentRestore", "pitrBoundary",
                  "restart", "signedPublicReadback")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_SECRET_KEY = re.compile(
    r"(?:password|passwd|secret|private.?key|access.?key|refresh.?token|dsn|credential)",
    re.I)


def _fail(code: str) -> None:
    raise ValueError(code)


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def _time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("BASELINE_RECOVERY_REVIEW_TIME_INVALID")
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail("BASELINE_RECOVERY_REVIEW_TIME_INVALID")
    if result.tzinfo != timezone.utc:
        _fail("BASELINE_RECOVERY_REVIEW_TIME_INVALID")
    return result


def _reject_secrets(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if _SECRET_KEY.search(str(key)):
                _fail("BASELINE_RECOVERY_REVIEW_SECRET_FIELD_FORBIDDEN")
            _reject_secrets(child)
    elif isinstance(value, list):
        for child in value: _reject_secrets(child)
    elif isinstance(value, str) and re.search(
            r"(?:postgres(?:ql)?://[^\s@]+@|-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16})",
            value):
        _fail("BASELINE_RECOVERY_REVIEW_SECRET_VALUE_FORBIDDEN")


def validate_recovery_review(packet: dict[str, Any], *,
        expected_source: dict[str, Any], expected_profile: dict[str, str],
        expected_parity: dict[str, Any], expected_pitr: dict[str, Any],
        expected_evidence_digests: dict[str, str], now: datetime) -> dict[str, Any]:
    """Validate an exact recovery packet; activation always remains false."""
    _reject_secrets(packet)
    required = {"format", "activationAuthorized", "recoveryId", "validFrom",
        "expiresAt", "revokedAt", "producerIdentity", "reviewerIdentity",
        "source", "backupExport", "restore", "profile", "parity", "pitr",
        "restart", "publicReadback", "evidence", "contractDigest"}
    if not isinstance(packet, dict) or set(packet) != required:
        _fail("BASELINE_RECOVERY_REVIEW_SHAPE_INVALID")
    if packet["format"] != FORMAT or packet["activationAuthorized"] is not False:
        _fail("BASELINE_RECOVERY_REVIEW_BOUNDARY_INVALID")
    if packet["revokedAt"] is not None:
        _fail("BASELINE_RECOVERY_REVIEW_REVOKED")
    if now.tzinfo != timezone.utc:
        _fail("BASELINE_RECOVERY_REVIEW_NOW_INVALID")
    valid_from, expires = _time(packet["validFrom"]), _time(packet["expiresAt"])
    if not valid_from <= now < expires:
        _fail("BASELINE_RECOVERY_REVIEW_EXPIRED_OR_NOT_YET_VALID")
    for name in ("recoveryId", "producerIdentity", "reviewerIdentity"):
        if not isinstance(packet[name], str) or not packet[name]:
            _fail("BASELINE_RECOVERY_REVIEW_IDENTITY_INVALID")
    if packet["producerIdentity"] == packet["reviewerIdentity"]:
        _fail("BASELINE_RECOVERY_REVIEW_SELF_REVIEW_FORBIDDEN")

    source_fields = {"deploymentId", "hostId", "projectId", "databaseId",
        "volumeId", "sourceCommit", "sourceTree", "artifactSha256"}
    source = packet["source"]
    if (not isinstance(source, dict) or set(source) != source_fields
            or source != expected_source or not _COMMIT.fullmatch(source["sourceCommit"])
            or not _COMMIT.fullmatch(source["sourceTree"])
            or not _DIGEST.fullmatch(source["artifactSha256"])):
        _fail("BASELINE_RECOVERY_REVIEW_SOURCE_MISMATCH")
    export = packet["backupExport"]
    if (not isinstance(export, dict) or set(export) != {"backupId", "sha256",
          "byteCount", "encrypted", "createdAt", "destinationProvider",
          "destinationLocationId", "destinationStorageIdentity",
          "independentFailureDomain"}
            or not _DIGEST.fullmatch(str(export["sha256"]))
            or type(export["byteCount"]) is not int or export["byteCount"] <= 0
            or export["encrypted"] is not True
            or export["independentFailureDomain"] is not True
            or _time(export["createdAt"]) > now
            or any(not isinstance(export[name], str) or not export[name] for name in
              ("backupId", "destinationProvider", "destinationLocationId",
               "destinationStorageIdentity"))):
        _fail("BASELINE_RECOVERY_REVIEW_EXPORT_INVALID")
    restore = packet["restore"]
    restore_fields = {"deploymentId", "hostId", "projectId", "databaseId",
        "volumeId", "restoredAt", "ownedDisposableTarget"}
    if (not isinstance(restore, dict) or set(restore) != restore_fields
            or restore["ownedDisposableTarget"] is not True
            or _time(restore["restoredAt"]) > now
            or any(not isinstance(restore[name], str) or not restore[name]
              for name in restore_fields - {"restoredAt", "ownedDisposableTarget"})):
        _fail("BASELINE_RECOVERY_REVIEW_RESTORE_INVALID")
    for identity in ("deploymentId", "hostId", "projectId", "databaseId", "volumeId"):
        if restore[identity] == source[identity]:
            _fail("BASELINE_RECOVERY_REVIEW_TARGET_NOT_INDEPENDENT")
    if export["destinationStorageIdentity"] in {source["volumeId"], restore["volumeId"]}:
        _fail("BASELINE_RECOVERY_REVIEW_SAME_VOLUME_ONLY_FORBIDDEN")

    if packet["profile"] != expected_profile:
        _fail("BASELINE_RECOVERY_REVIEW_PROFILE_MISMATCH")
    parity = packet["parity"]
    fields = {"migrationLedgerCount", "sourceLedgerDigest", "restoreLedgerDigest",
        "sourceAuditCount", "restoreAuditCount", "sourceAuditDigest", "restoreAuditDigest", "sourceArtifactSha256",
        "restoreArtifactSha256", "sourceCommit", "restoreSourceCommit",
        "sourceProfileDigest", "restoreProfileDigest", "sourceObjectCount",
        "restoreObjectCount", "sourceObjectDigest", "restoreObjectDigest",
        "sourceFingerprint", "restoreFingerprint", "sourceFactDigest",
        "restoreFactDigest", "sourceFactCount", "restoreFactCount",
        "sourceProgramDigest", "restoreProgramDigest", "sourceProgramCount",
        "restoreProgramCount"}
    pairs = (("sourceLedgerDigest", "restoreLedgerDigest"),
      ("sourceAuditDigest", "restoreAuditDigest"),
      ("sourceAuditCount", "restoreAuditCount"),
      ("sourceArtifactSha256", "restoreArtifactSha256"),
      ("sourceCommit", "restoreSourceCommit"),
      ("sourceProfileDigest", "restoreProfileDigest"),
      ("sourceObjectCount", "restoreObjectCount"),
      ("sourceObjectDigest", "restoreObjectDigest"),
      ("sourceFingerprint", "restoreFingerprint"),
      ("sourceFactDigest", "restoreFactDigest"),
      ("sourceFactCount", "restoreFactCount"),
      ("sourceProgramDigest", "restoreProgramDigest"),
      ("sourceProgramCount", "restoreProgramCount"))
    digest_fields = {name for pair in pairs for name in pair if "Digest" in name
                     or "Sha256" in name or "Fingerprint" in name}
    if (not isinstance(parity, dict) or set(parity) != fields
            or parity != expected_parity or parity["migrationLedgerCount"] != 164
            or parity["sourceAuditCount"] != 1
            or any(parity[left] != parity[right] for left, right in pairs)
            or any(not _DIGEST.fullmatch(str(parity[name])) for name in digest_fields)
            or parity["sourceArtifactSha256"] != source["artifactSha256"]
            or parity["sourceCommit"] != source["sourceCommit"]
            or any(type(parity[name]) is not int or parity[name] <= 0 for name in
              ("sourceAuditCount", "restoreAuditCount", "sourceObjectCount",
               "restoreObjectCount", "sourceFactCount", "restoreFactCount",
               "sourceProgramCount", "restoreProgramCount"))):
        _fail("BASELINE_RECOVERY_REVIEW_PARITY_INVALID")

    pitr = packet["pitr"]
    if (not isinstance(pitr, dict) or pitr != expected_pitr
            or set(pitr) != {"targetBoundary", "restoreReachedBoundary",
                             "beforeBoundaryMarkerPresent",
                             "afterBoundaryMarkerAbsent", "sourceTimeline",
                             "restoreTimeline"}
            or pitr["restoreReachedBoundary"] is not True
            or pitr["beforeBoundaryMarkerPresent"] is not True
            or pitr["afterBoundaryMarkerAbsent"] is not True
            or not isinstance(pitr["sourceTimeline"], str)
            or not isinstance(pitr["restoreTimeline"], str)
            or pitr["sourceTimeline"] == pitr["restoreTimeline"]
            or _time(pitr["targetBoundary"]) > now):
        _fail("BASELINE_RECOVERY_REVIEW_PITR_INVALID")
    restart = packet["restart"]
    if (not isinstance(restart, dict) or set(restart) != {"restartCount",
          "objectDigestBefore", "objectDigestAfter", "factDigestBefore",
          "factDigestAfter", "programDigestBefore", "programDigestAfter"}
            or type(restart["restartCount"]) is not int or restart["restartCount"] < 1
            or any(restart[left] != restart[right] for left, right in
              (("objectDigestBefore", "objectDigestAfter"),
               ("factDigestBefore", "factDigestAfter"),
               ("programDigestBefore", "programDigestAfter")))):
        _fail("BASELINE_RECOVERY_REVIEW_RESTART_INVALID")
    readback = packet["publicReadback"]
    if (not isinstance(readback, dict) or set(readback) != {"signed",
          "freshTokenAfterRestart", "authorizedIdentity", "outsiderDenied",
          "factDigest", "programDigest", "receiptDigest"}
            or readback["signed"] is not True
            or readback["freshTokenAfterRestart"] is not True
            or readback["outsiderDenied"] is not True
            or not isinstance(readback["authorizedIdentity"], str)
            or not readback["authorizedIdentity"]
            or any(not _DIGEST.fullmatch(str(readback[name])) for name in
              ("factDigest", "programDigest", "receiptDigest"))
            or readback["factDigest"] != parity["restoreFactDigest"]
            or readback["programDigest"] != parity["restoreProgramDigest"]):
        _fail("BASELINE_RECOVERY_REVIEW_PUBLIC_READBACK_INVALID")

    evidence = packet["evidence"]
    if (not isinstance(evidence, dict) or tuple(evidence) != EVIDENCE_KINDS
            or set(expected_evidence_digests) != set(EVIDENCE_KINDS)):
        _fail("BASELINE_RECOVERY_REVIEW_EVIDENCE_INCOMPLETE")
    ids, digests = set(), set()
    for kind in EVIDENCE_KINDS:
        row = evidence[kind]
        if (not isinstance(row, dict) or set(row) != {"evidenceId", "sha256",
              "status", "expiresAt", "revokedAt", "supersededBy",
              "producerIdentity"}
                or row["sha256"] != expected_evidence_digests[kind]
                or not _DIGEST.fullmatch(str(row["sha256"]))
                or row["status"] != "verified" or row["revokedAt"] is not None
                or row["supersededBy"] is not None or _time(row["expiresAt"]) < expires
                or not isinstance(row["evidenceId"], str) or not row["evidenceId"]
                or not isinstance(row["producerIdentity"], str)
                or not row["producerIdentity"]):
            _fail("BASELINE_RECOVERY_REVIEW_EVIDENCE_INVALID")
        ids.add(row["evidenceId"]); digests.add(row["sha256"])
    if len(ids) != len(EVIDENCE_KINDS) or len(digests) != len(EVIDENCE_KINDS):
        _fail("BASELINE_RECOVERY_REVIEW_EVIDENCE_REUSED")
    if packet["reviewerIdentity"] in {row["producerIdentity"] for row in evidence.values()}:
        _fail("BASELINE_RECOVERY_REVIEW_SELF_REVIEW_FORBIDDEN")

    canonical = {key: packet[key] for key in required - {"contractDigest"}}
    if (not _DIGEST.fullmatch(str(packet["contractDigest"]))
            or packet["contractDigest"] != _digest(canonical)):
        _fail("BASELINE_RECOVERY_REVIEW_DIGEST_MISMATCH")
    return {"validated": True, "activationAuthorized": False,
        "recoveryId": packet["recoveryId"], "contractDigest": packet["contractDigest"],
        "expiresAt": packet["expiresAt"]}
