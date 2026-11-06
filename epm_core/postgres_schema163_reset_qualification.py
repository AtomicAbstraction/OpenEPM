"""One-use authorization for disposable schema-163 reset qualification.

This is not a production activation manifest.  It only permits the reset
qualification harness to operate an exact owned disposable database after the
baseline framework has independently qualified the bound artifact.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import time
from typing import Any


FORMAT = "openepm-schema163-ephemeral-reset-qualification-v1"
BASELINE_EVIDENCE_FORMAT = "openepm-schema163-baseline-framework-qualification-v1"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z0-9][a-z0-9._-]{7,127}\Z")


def _fail(code: str) -> None:
    raise ValueError(code)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dsn_sha256(dsn: str) -> str:
    if not isinstance(dsn, str) or not dsn:
        _fail("SCHEMA163_RESET_QUALIFICATION_DSN_INVALID")
    return hashlib.sha256(dsn.encode()).hexdigest()


def manifest_signature(document: dict[str, Any], secret: bytes) -> str:
    if not isinstance(secret, bytes) or len(secret) < 32:
        _fail("SCHEMA163_RESET_QUALIFICATION_SECRET_INVALID")
    unsigned = {key: value for key, value in document.items()
                if key != "signature"}
    return hmac.new(secret, b"openepm-schema163-reset-qualification-v1\0" +
                    _canonical(unsigned), hashlib.sha256).hexdigest()


def _bound_file(root: Path, relative: Any, expected: Any, code: str) -> Path:
    if (not isinstance(relative, str) or not relative
            or not isinstance(expected, str) or not _HEX.fullmatch(expected)):
        _fail(code)
    path = (root / relative).resolve()
    if root.resolve() not in path.parents or not path.is_file():
        _fail(code)
    if file_sha256(path) != expected:
        _fail(code)
    return path


def validate_ephemeral_manifest(path: Path, *, secret: bytes,
        owner_dsn: str, lifecycle_dsn: str, database_identity: str,
        database_name: str, expected_source_commit: str,
        expected_reviewer: str, target_workspace: str,
        survivor_workspace: str, now: int | None = None,
        claim: bool = True) -> dict[str, Any]:
    """Validate and optionally one-time claim an exact qualification packet."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("SCHEMA163_RESET_QUALIFICATION_MANIFEST_INVALID") from error
    required = {"format", "purpose", "productionActivationAuthorized",
        "qualificationId", "issuedAt", "expiresAt", "sourceCommit",
        "reviewerIdentity", "artifact", "artifactSha256",
        "constructionEvidence", "constructionEvidenceSha256",
        "verificationEvidence", "verificationEvidenceSha256",
        "baselineQualificationEvidence", "baselineQualificationEvidenceSha256",
        "schemaFingerprint", "databaseIdentity", "databaseName",
        "ownerDsnSha256", "lifecycleDsnSha256", "targetWorkspaceId",
        "survivorWorkspaceId", "signature"}
    if not isinstance(value, dict) or set(value) != required:
        _fail("SCHEMA163_RESET_QUALIFICATION_MANIFEST_SHAPE_INVALID")
    if (value["format"] != FORMAT
            or value["purpose"] != "owner-reset-qualification-only"
            or value["productionActivationAuthorized"] is not False
            or not _ID.fullmatch(str(value["qualificationId"]))):
        _fail("SCHEMA163_RESET_QUALIFICATION_BOUNDARY_INVALID")
    if (not isinstance(value["issuedAt"], int)
            or not isinstance(value["expiresAt"], int)
            or value["expiresAt"] <= value["issuedAt"]
            or value["expiresAt"] - value["issuedAt"] > 3600):
        _fail("SCHEMA163_RESET_QUALIFICATION_TIME_INVALID")
    observed = int(time.time()) if now is None else now
    if observed < value["issuedAt"] or observed > value["expiresAt"]:
        _fail("SCHEMA163_RESET_QUALIFICATION_EXPIRED")
    if not hmac.compare_digest(str(value["signature"]),
                               manifest_signature(value, secret)):
        _fail("SCHEMA163_RESET_QUALIFICATION_SIGNATURE_INVALID")
    if value["sourceCommit"] != expected_source_commit:
        _fail("SCHEMA163_RESET_QUALIFICATION_SOURCE_MISMATCH")
    if value["reviewerIdentity"] != expected_reviewer:
        _fail("SCHEMA163_RESET_QUALIFICATION_REVIEWER_MISMATCH")
    if (value["ownerDsnSha256"] != dsn_sha256(owner_dsn)
            or value["lifecycleDsnSha256"] != dsn_sha256(lifecycle_dsn)
            or value["databaseIdentity"] != database_identity
            or value["databaseName"] != database_name
            or not database_name.startswith("epm_disposable_")):
        _fail("SCHEMA163_RESET_QUALIFICATION_DATABASE_MISMATCH")
    if (value["targetWorkspaceId"] != target_workspace
            or value["survivorWorkspaceId"] != survivor_workspace
            or target_workspace == survivor_workspace
            or not target_workspace.startswith("epm-disposable-")
            or not survivor_workspace.startswith("epm-disposable-")):
        _fail("SCHEMA163_RESET_QUALIFICATION_SHARED_TARGET_REJECTED")
    if not _HEX.fullmatch(str(value["schemaFingerprint"])):
        _fail("SCHEMA163_RESET_QUALIFICATION_FINGERPRINT_INVALID")
    root = path.resolve().parent
    artifact = _bound_file(root, value["artifact"], value["artifactSha256"],
                           "SCHEMA163_RESET_QUALIFICATION_ARTIFACT_MISMATCH")
    construction = _bound_file(root, value["constructionEvidence"],
        value["constructionEvidenceSha256"],
        "SCHEMA163_RESET_QUALIFICATION_CONSTRUCTION_EVIDENCE_MISMATCH")
    verification = _bound_file(root, value["verificationEvidence"],
        value["verificationEvidenceSha256"],
        "SCHEMA163_RESET_QUALIFICATION_VERIFICATION_EVIDENCE_MISMATCH")
    baseline = _bound_file(root, value["baselineQualificationEvidence"],
        value["baselineQualificationEvidenceSha256"],
        "SCHEMA163_RESET_QUALIFICATION_BASELINE_EVIDENCE_MISMATCH")
    try:
        qualified = json.loads(baseline.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("SCHEMA163_RESET_QUALIFICATION_BASELINE_EVIDENCE_INVALID") from error
    expected_baseline = {"format": BASELINE_EVIDENCE_FORMAT, "qualified": True,
        "productionActivationAuthorized": False,
        "artifactSha256": value["artifactSha256"],
        "constructionEvidenceSha256": value["constructionEvidenceSha256"],
        "verificationEvidenceSha256": value["verificationEvidenceSha256"],
        "schemaFingerprint": value["schemaFingerprint"],
        "sourceCommit": value["sourceCommit"],
        "reviewerIdentity": value["reviewerIdentity"],
        "databaseIdentity": value["databaseIdentity"],
        "databaseName": value["databaseName"]}
    if qualified != expected_baseline:
        _fail("SCHEMA163_RESET_QUALIFICATION_BASELINE_EVIDENCE_INVALID")
    if claim:
        claim_path = path.with_name(path.name + ".claimed")
        try:
            descriptor = os.open(claim_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                 0o600)
        except FileExistsError as error:
            raise ValueError("SCHEMA163_RESET_QUALIFICATION_REUSED") from error
        with os.fdopen(descriptor, "wb") as output:
            output.write(_canonical({"qualificationId": value["qualificationId"],
                                     "manifestSha256": file_sha256(path)}))
    return {"qualificationId": value["qualificationId"],
        "artifact": artifact, "constructionEvidence": construction,
        "verificationEvidence": verification,
        "baselineQualificationEvidence": baseline,
        "schemaFingerprint": value["schemaFingerprint"],
        "databaseIdentity": value["databaseIdentity"],
        "databaseName": value["databaseName"],
        "sourceCommit": value["sourceCommit"],
        "reviewerIdentity": value["reviewerIdentity"],
        "productionActivationAuthorized": False,
        "ephemeralQualificationAuthorized": True}
