#!/usr/bin/env python3
"""Resolve every release decision explicitly; defaults never imply consent."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_openepm_source_archive import SourcePackageError, canonical


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path, label: str) -> dict:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value
    try:
        value = json.loads(path.read_text(encoding="utf-8"),
                           object_pairs_hook=unique)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise SourcePackageError(f"invalid {label}: {error}") from error
    if not isinstance(value, dict):
        raise SourcePackageError(f"{label} must be an object")
    return value


def sibling(root: Path, record: object, label: str) -> Path:
    if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
        raise SourcePackageError(f"invalid {label} reference")
    parsed = PurePosixPath(record["path"])
    if (parsed.is_absolute() or ".." in parsed.parts or len(parsed.parts) != 1
            or not isinstance(record["sha256"], str)
            or len(record["sha256"]) != 64):
        raise SourcePackageError(f"unsafe {label} reference")
    path = root / parsed.as_posix()
    if not path.is_file() or path.is_symlink() or sha(path) != record["sha256"]:
        raise SourcePackageError(f"{label} identity mismatch")
    return path


def _parameter_present(value: object) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return bool(value) and all(_parameter_present(item) for item in value)
    if isinstance(value, dict):
        return bool(value) and all(isinstance(key, str) and key.strip()
                                   and _parameter_present(item)
                                   for key, item in value.items())
    return isinstance(value, (bool, int, float))


def explicit_parameters(decision: dict, selection: dict) -> dict:
    parameters = selection.get("parameters", {})
    if not isinstance(parameters, dict):
        raise SourcePackageError(
            f"decision parameters must be an object: {decision['id']}")
    required = decision.get("requiredParameters", [])
    if (not isinstance(required, list)
            or any(not isinstance(name, str) or not name.strip()
                   for name in required)
            or len(required) != len(set(required))):
        raise SourcePackageError(
            f"decision required parameters are invalid: {decision['id']}")
    if required:
        missing = [name for name in required
                   if name not in parameters
                   or not _parameter_present(parameters[name])]
        unknown = sorted(set(parameters) - set(required))
        if missing or unknown:
            raise SourcePackageError(
                f"required decision parameters are incomplete: {decision['id']} "
                f"missing={missing} unknown={unknown}")
    elif any(not isinstance(name, str) or not name.strip()
             or not _parameter_present(value)
             for name, value in parameters.items()):
        raise SourcePackageError(
            f"decision parameters are invalid: {decision['id']}")
    return parameters


def resolve(*, packet_path: Path, selections_path: Path) -> dict:
    packet, selections = load(packet_path, "decision packet"), load(
        selections_path, "decision selections")
    if (packet.get("format") != "openepm-owner-decision-packet-v1"
            or packet.get("status") != "decisions-pending"
            or packet.get("approvalsRecorded") is not False):
        raise SourcePackageError("decision packet is not a pending packet")
    packet_sha = sha(packet_path)
    if (selections.get("format") != "openepm-owner-decision-selections-v1"
            or selections.get("decisionPacketSha256") != packet_sha
            or set(selections) != {"format", "decisionPacketSha256", "selections"}
            or not isinstance(selections["selections"], dict)):
        raise SourcePackageError("selection envelope identity is invalid")
    legal = {item["id"]: item for item in packet["legalReviewRequired"]}
    all_decisions = {item["id"]: item for category in (
        "legalReviewRequired", "ownerProductDecisions",
        "ownerSecurityOperationsDecisions") for item in packet[category]}
    if set(selections["selections"]) != set(all_decisions):
        missing = sorted(set(all_decisions) - set(selections["selections"]))
        extra = sorted(set(selections["selections"]) - set(all_decisions))
        raise SourcePackageError(
            f"every decision requires explicit selection missing={missing} extra={extra}")
    resolved = []
    for decision_id, decision in sorted(all_decisions.items()):
        selection = selections["selections"][decision_id]
        if not isinstance(selection, dict) or "optionId" not in selection:
            raise SourcePackageError(f"explicit option is missing: {decision_id}")
        allowed = {option["id"]: option for option in decision["options"]}
        option_id = selection["optionId"]
        if option_id not in allowed:
            raise SourcePackageError(f"option is not allowed: {decision_id}")
        if selection.get("useDefault") is not None:
            raise SourcePackageError("safe defaults cannot be implicit consent")
        record = {"decisionId": decision_id, "optionId": option_id,
                  "effect": allowed[option_id]["effect"],
                  "parameters": explicit_parameters(decision, selection)}
        if decision_id in legal:
            if set(selection) - {"optionId", "parameters", "legalAttestation"}:
                raise SourcePackageError(f"unknown legal selection fields: {decision_id}")
            attestation_path = sibling(selections_path.parent,
                selection.get("legalAttestation"), f"legal attestation {decision_id}")
            attestation = load(attestation_path, f"legal attestation {decision_id}")
            expected_evidence = legal[decision_id]["evidence"]["rawLicenseEvidenceSha256"]
            if (attestation.get("format") !=
                    "openepm-external-legal-review-attestation-v1"
                    or attestation.get("decisionPacketSha256") != packet_sha
                    or attestation.get("decisionId") != decision_id
                    or attestation.get("optionId") != option_id
                    or attestation.get("evidenceSha256") != expected_evidence
                    or not isinstance(attestation.get("reviewerReference"), str)
                    or not attestation["reviewerReference"].strip()
                    or not isinstance(attestation.get("reviewedAt"), str)
                    or not attestation["reviewedAt"].strip()
                    or not isinstance(attestation.get("resolution"), dict)
                    or not attestation["resolution"]):
                raise SourcePackageError(f"legal attestation is forged or incomplete: {decision_id}")
            record["legalAttestation"] = {"path": attestation_path.name,
                                           "sha256": sha(attestation_path)}
            record["legalResolution"] = attestation["resolution"]
        elif set(selection) - {"optionId", "parameters"}:
            raise SourcePackageError(f"unknown owner selection fields: {decision_id}")
        resolved.append(record)
    return {"format": "openepm-resolved-release-policy-v1",
        "status": "resolved-explicit", "allDecisionsExplicit": True,
        "decisionPacketSha256": packet_sha,
        "selectionsSha256": sha(selections_path),
        "decisionCount": len(resolved), "legalAttestationCount": len(legal),
        "decisions": resolved}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decision-packet", type=Path, required=True)
    parser.add_argument("--selections", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    try:
        result = resolve(packet_path=args.decision_packet.resolve(),
                         selections_path=args.selections.resolve())
    except SourcePackageError as error:
        parser.error(str(error))
    args.output.write_bytes(canonical(result) + b"\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
