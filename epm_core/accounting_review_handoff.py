"""Fail-closed validation for externally supplied accounting review responses.

Review evidence is deliberately separate from policy activation.  This module
only validates that a response is bound to the exact packet and covers every
case once; it does not grant capabilities, publish a template, or mutate data.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path


class AccountingReviewResponseError(ValueError):
    """The purported review does not cover the exact review packet."""


def load_and_validate_review_response(packet_path: Path,
                                      response_path: Path) -> dict:
    packet_bytes = packet_path.read_bytes()
    packet = json.loads(packet_bytes)
    response = json.loads(response_path.read_text())
    validate_review_response(packet, sha256(packet_bytes).hexdigest(), response)
    return response


def validate_review_response(packet: dict, packet_sha256: str,
                             response: dict) -> None:
    if response.get("format") != "openepm-accounting-review-response-v1":
        raise AccountingReviewResponseError("REVIEW_RESPONSE_FORMAT_UNSUPPORTED")
    if response.get("packetId") != packet.get("packetId"):
        raise AccountingReviewResponseError("REVIEW_PACKET_ID_MISMATCH")
    if response.get("packetSha256") != packet_sha256:
        raise AccountingReviewResponseError("REVIEW_PACKET_DIGEST_MISMATCH")

    cases = packet.get("goldenCases")
    if not isinstance(cases, list) or not cases:
        raise AccountingReviewResponseError("REVIEW_PACKET_CASES_MISSING")
    expected = [case.get("caseId") for case in cases]
    if any(not isinstance(case_id, str) or not case_id for case_id in expected):
        raise AccountingReviewResponseError("REVIEW_PACKET_CASE_ID_INVALID")
    if len(expected) != len(set(expected)):
        raise AccountingReviewResponseError("REVIEW_PACKET_CASE_ID_DUPLICATE")

    decisions = response.get("caseDecisions")
    if not isinstance(decisions, list):
        raise AccountingReviewResponseError("REVIEW_CASE_DECISIONS_MISSING")
    received = [item.get("caseId") for item in decisions
                if isinstance(item, dict)]
    if (len(received) != len(decisions)
            or len(received) != len(set(received))
            or set(received) != set(expected)):
        raise AccountingReviewResponseError("REVIEW_CASE_COVERAGE_MISMATCH")

    allowed = {"confirm", "reject", "changes-required"}
    if any(item.get("decision") not in allowed for item in decisions):
        raise AccountingReviewResponseError("REVIEW_CASE_DECISION_INVALID")
    if response.get("decision") == "approve-bounded-template" and any(
            item["decision"] != "confirm" for item in decisions):
        raise AccountingReviewResponseError("REVIEW_APPROVAL_REQUIRES_ALL_CASES_CONFIRMED")

