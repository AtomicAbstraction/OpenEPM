#!/usr/bin/env python3
"""Create non-executable owner/legal decision templates from the bound packet."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate decision packet key: {key}")
            value[key] = item
        return value
    try:
        value = json.loads(path.read_text(encoding="utf-8"),
                           object_pairs_hook=unique)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"decision packet is invalid: {error}") from error
    if (not isinstance(value, dict)
            or value.get("format") != "openepm-owner-decision-packet-v1"
            or value.get("status") != "decisions-pending"
            or value.get("approvalsRecorded") is not False):
        raise ValueError("decision packet is not pending and template-safe")
    return value


def write(path: Path, value: object) -> None:
    path.write_bytes(canonical(value) + b"\n")


def build(packet_path: Path, output: Path) -> dict:
    packet = load(packet_path)
    if (output.exists() and (output.is_symlink() or not output.is_dir()
                             or any(output.iterdir()))):
        raise ValueError("template output must be a new empty directory")
    output.mkdir(parents=True, exist_ok=True)
    packet_sha = sha(packet_path)
    selections = {}
    attestation_files = []
    categories = ("legalReviewRequired", "ownerProductDecisions",
                  "ownerSecurityOperationsDecisions")
    decisions = [item for category in categories for item in packet.get(category, [])]
    if (not decisions or any(not isinstance(item, dict) or not item.get("id") for item in decisions)
            or len({item["id"] for item in decisions}) != len(decisions)):
        raise ValueError("decision packet must contain unique explicit decisions")
    legal_ids = {item["id"] for item in packet["legalReviewRequired"]}
    for decision in decisions:
        decision_id = decision["id"]
        required = decision.get("requiredParameters", [])
        selection = {"optionId": None,
                     "parameters": {name: None for name in required}}
        if decision_id in legal_ids:
            name = f"{decision_id}.legal-attestation.template.json"
            selection["legalAttestation"] = {"path": name, "sha256": None}
            attestation = {
                "format": "openepm-external-legal-review-attestation-v1",
                "templateOnly": True,
                "decisionPacketSha256": packet_sha,
                "decisionId": decision_id,
                "optionId": None,
                "evidenceSha256": decision["evidence"][
                    "rawLicenseEvidenceSha256"],
                "reviewerReference": None,
                "reviewedAt": None,
                "resolution": {
                    "licenseExpression": None,
                    "fileScopes": None,
                    "attributionAndNoticeObligations": None
                }
            }
            path = output / name
            write(path, attestation)
            attestation_files.append({"path": name, "sha256": sha(path)})
        selections[decision_id] = selection
    envelope = {
        "format": "openepm-owner-decision-selections-template-v1",
        "templateOnly": True,
        "decisionPacketSha256": packet_sha,
        "instructions": (
            "Copy this file, remove templateOnly/instructions, change format to "
            "openepm-owner-decision-selections-v1, select every option, fill every "
            "required parameter, and replace legal template references with the "
            "completed attestation filename and SHA-256. Templates are never approvals."),
        "selections": selections
    }
    envelope_path = output / "openepm-owner-decision-selections.template.json"
    write(envelope_path, envelope)
    index = {
        "format": "openepm-release-decision-template-index-v1",
        "status": "template-only-no-approval",
        "decisionPacket": {"path": packet_path.name, "sha256": packet_sha},
        "decisionCount": len(decisions),
        "legalAttestationCount": len(attestation_files),
        "selectionsTemplate": {"path": envelope_path.name,
                               "sha256": sha(envelope_path)},
        "legalAttestationTemplates": sorted(attestation_files,
                                             key=lambda item: item["path"])
    }
    index_path = output / "TEMPLATE_INDEX.json"
    write(index_path, index)
    return index


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decision-packet", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build(args.decision_packet.resolve(),
                       args.output_directory.resolve())
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
