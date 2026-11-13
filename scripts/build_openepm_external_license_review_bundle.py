#!/usr/bin/env python3
"""Preserve the exact evidence required by the release's legal decisions."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path


class ReviewBundleError(ValueError):
    pass


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ReviewBundleError(f"expected object: {path}")
    return value


def build(*, dossier_path: Path, decision_packet_path: Path) -> dict:
    dossier, packet = load(dossier_path), load(decision_packet_path)
    if (dossier.get("format") != "openepm-residual-license-review-dossier-v1"
            or dossier.get("status") != "owner-or-legal-review-required"
            or dossier.get("trustedPolicy") is not False
            or dossier.get("coverage", {}).get("externalDecision") != 8):
        raise ReviewBundleError("residual dossier is not the exact untrusted review input")
    if (packet.get("format") != "openepm-owner-decision-packet-v1"
            or packet.get("status") != "decisions-pending"
            or packet.get("approvalsRecorded") is not False):
        raise ReviewBundleError("owner decision packet is not pending")

    legal = packet.get("legalReviewRequired")
    if (not isinstance(legal, list) or not legal or
            len({item.get("id") for item in legal}) != len(legal)):
        raise ReviewBundleError("distinct external legal decisions are required")
    by_name = {item["name"]: item for item in dossier.get("packages", [])}
    required_hashes, packages = set(), []
    for decision in legal:
        package = by_name.get(decision.get("package"))
        expected = decision.get("evidence", {}).get("rawLicenseEvidenceSha256")
        if (package is None or package.get("decisionClass") != "external-license-review"
                or package.get("proposedSpdxExpression") is not None
                or package.get("evidenceGroupRawSha256") != expected):
            raise ReviewBundleError(
                f"decision evidence differs for {decision.get('package')}")
        required_hashes.update(expected)
        packages.append({"decisionId": decision["id"], "name": package["name"],
            "version": package["version"], "reviewFlags": package["reviewFlags"],
            "reviewQuestion": package["reviewQuestion"],
            "detectedStandardComponents": package["detectedStandardComponents"],
            "customClausesOrScopeSelectors": package["customClausesOrScopeSelectors"],
            "requiredAttributionText": package["requiredAttributionText"],
            "architectures": package["architectures"],
            "evidenceGroupRawSha256": expected})
    groups = {item["rawSha256"]: item for item in dossier.get("evidenceGroups", [])}
    if set(groups).issuperset(required_hashes) is False:
        raise ReviewBundleError("exact license evidence bytes are missing")
    evidence = [groups[value] for value in sorted(required_hashes)]
    if any(sha256(item["exactText"].encode("utf-8")).hexdigest()
           != item["rawSha256"] for item in evidence):
        raise ReviewBundleError("preserved exact license text hash differs")
    return {"format": "openepm-external-license-review-bundle-v1",
        "status": "unreviewed-no-selection", "trustedPolicy": False,
        "sourceCompliancePermitted": False,
        "residualDossierSha256": digest(dossier_path),
        "decisionPacketSha256": digest(decision_packet_path),
        "coverage": {"externalLegalDecisions": len(legal),
                     "packages": len(packages),
                     "exactEvidenceGroups": len(evidence)},
        "packages": sorted(packages, key=lambda item: item["decisionId"]),
        "evidenceGroups": evidence}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--residual-dossier", type=Path, required=True)
    parser.add_argument("--decision-packet", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    try:
        result = build(dossier_path=args.residual_dossier,
                       decision_packet_path=args.decision_packet)
    except (OSError, UnicodeError, json.JSONDecodeError, ReviewBundleError) as error:
        parser.error(str(error))
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2,
                                      ensure_ascii=True) + "\n")
    print(json.dumps(result["coverage"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

