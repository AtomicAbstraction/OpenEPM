#!/usr/bin/env python3
"""Resolve every release decision explicitly; defaults never imply consent."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_openepm_source_archive import SourcePackageError, canonical
from openepm_release_policy_contract import (
    parameter_present, parse_json_object, resolve_legal_attestation,
)


def load_with_digest(path: Path, label: str) -> tuple[dict, str]:
    try:
        raw = path.read_bytes()
        return parse_json_object(raw, label), hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError) as error:
        raise SourcePackageError(str(error)) from error


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
                   or not parameter_present(parameters[name])]
        unknown = sorted(set(parameters) - set(required))
        if missing or unknown:
            raise SourcePackageError(
                f"required decision parameters are incomplete: {decision['id']} "
                f"missing={missing} unknown={unknown}")
    elif any(not isinstance(name, str) or not name.strip()
             or not parameter_present(value)
             for name, value in parameters.items()):
        raise SourcePackageError(
            f"decision parameters are invalid: {decision['id']}")
    return parameters


def resolve(*, packet_path: Path, selections_path: Path) -> dict:
    packet, packet_sha = load_with_digest(packet_path, "decision packet")
    selections, selections_sha = load_with_digest(selections_path, "decision selections")
    if (packet.get("format") != "openepm-owner-decision-packet-v1"
            or packet.get("status") != "decisions-pending"
            or packet.get("approvalsRecorded") is not False):
        raise SourcePackageError("decision packet is not a pending packet")
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
            if option_id == "replace-or-exclude":
                raise SourcePackageError(
                    "dependency replacement requires regenerated locks, evidence, "
                    f"and decision packet: {decision_id}")
            if set(selection) - {"optionId", "parameters", "legalAttestation"}:
                raise SourcePackageError(f"unknown legal selection fields: {decision_id}")
            try:
                attestation, resolution = resolve_legal_attestation(
                    selections_path.parent, selection.get("legalAttestation"),
                    packet_sha256=packet_sha, decision=decision, option_id=option_id)
            except (OSError, ValueError) as error:
                raise SourcePackageError(str(error)) from error
            record["legalAttestation"] = attestation
            record["legalResolution"] = resolution
        elif set(selection) - {"optionId", "parameters"}:
            raise SourcePackageError(f"unknown owner selection fields: {decision_id}")
        resolved.append(record)
    return {"format": "openepm-resolved-release-policy-v1",
        "status": "resolved-explicit", "allDecisionsExplicit": True,
        "decisionPacketSha256": packet_sha,
        "selectionsSha256": selections_sha,
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
