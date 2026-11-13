#!/usr/bin/env python3
"""Build an evidence-bound, explicitly incomplete dependency license policy."""
from __future__ import annotations

import argparse
from email.parser import Parser
import hashlib
import json
from pathlib import Path

from reconcile_openepm_license_evidence import (
    ReconciliationError, canonical, normalize_license_text)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReconciliationError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise ReconciliationError(f"expected object: {path}")
    return value


def require_complete(candidate: dict) -> None:
    """Fail closed before any trusted-policy/source-compliance conversion."""
    unresolved = candidate.get("unresolved")
    if candidate.get("trustedPolicy") is not True or unresolved:
        names = sorted(unresolved) if isinstance(unresolved, dict) else []
        raise ReconciliationError(
            "partial license candidate cannot produce source compliance; "
            f"unresolved={names}")


def build(*, provenance_path: Path, matrix_path: Path,
          dossier_path: Path) -> dict:
    provenance, matrix, dossier = (load(provenance_path), load(matrix_path),
                                   load(dossier_path))
    if provenance.get("status") != "verified-unapproved" or len(
            provenance.get("artifacts", [])) != 266:
        raise ReconciliationError("expected verified 266-wheel provenance")
    if matrix.get("trustedPolicy") is not False or dossier.get("trustedPolicy") is not False:
        raise ReconciliationError("review inputs must remain untrusted")
    if matrix.get("provenanceSha256") != sha(provenance_path.read_bytes()):
        raise ReconciliationError("matrix/provenance identity mismatch")
    if dossier.get("provenanceSha256") != sha(provenance_path.read_bytes()) or dossier.get(
            "reviewMatrixSha256") != sha(matrix_path.read_bytes()):
        raise ReconciliationError("dossier input identities differ")
    if dossier.get("coverage") != {"packages": 13, "mechanicallyReconcilable": 5,
            "externalDecision": 8, "byteIdenticalEvidenceGroups": 25}:
        raise ReconciliationError("expected exact residual decision set")
    roots = {Path(value).name: Path(value).resolve()
             for value in provenance.get("proposalMetadataRoots", [])}
    matrix_packages = {item["name"]: item for item in matrix["packages"]}
    dossier_packages = {item["name"]: item for item in dossier["packages"]}
    artifacts_by_package: dict[str, list[dict]] = {}
    for artifact in provenance["artifacts"]:
        artifacts_by_package.setdefault(artifact["package"], []).append(artifact)
    covered, unresolved = {}, {}
    for name, summary in sorted(matrix_packages.items()):
        residual = dossier_packages.get(name)
        if summary["reviewFlags"]:
            if residual is None:
                raise ReconciliationError(f"dossier omits unresolved package: {name}")
            expression = residual["proposedSpdxExpression"]
            if expression is None:
                unresolved[name] = {"version": summary["version"],
                    "reviewFlags": summary["reviewFlags"],
                    "ownerOrLegalReviewQuestion": residual["reviewQuestion"],
                    "evidenceGroupRawSha256": residual["evidenceGroupRawSha256"]}
                continue
            basis = "mechanically-reconciled-review-pending"
        else:
            if len(summary["matchedExpressions"]) != 1:
                raise ReconciliationError(f"clean package lacks one exact expression: {name}")
            expression = summary["metadataExpressions"][0] if len(
                summary["metadataExpressions"]) == 1 else summary["matchedExpressions"][0]
            basis = "exact-standard-text-match-review-pending"
        architecture_evidence, attribution, notices, components = [], set(), set(), []
        for artifact in sorted(artifacts_by_package[name], key=lambda x: x["target"]):
            root = roots.get(artifact["target"])
            if root is None:
                raise ReconciliationError(f"missing metadata root: {artifact['target']}")
            metadata_path = root / artifact["metadataPath"]
            metadata_bytes = metadata_path.read_bytes()
            if sha(metadata_bytes) != artifact["metadataSha256"]:
                raise ReconciliationError(f"metadata identity mismatch: {name}")
            metadata = Parser().parsestr(metadata_bytes.decode("utf-8"))
            files = []
            for item in artifact.get("licenseFiles", []):
                path = root / item["path"]
                raw = path.read_bytes()
                if sha(raw) != item["sha256"]:
                    raise ReconciliationError(f"license identity mismatch: {path}")
                normalized, holders = normalize_license_text(raw.decode("utf-8"))
                normalized_hash = sha(normalized.encode("utf-8"))
                group = next((value for value in matrix["reviewMatrix"]
                    if value["normalizedSha256"] == normalized_hash), None)
                if group is None:
                    raise ReconciliationError(f"matrix omits evidence: {path}")
                record = {"path": item["path"], "rawSha256": item["sha256"],
                    "normalizedSha256": normalized_hash,
                    "classifications": group["classifications"],
                    "standardExpressions": group["expressions"]}
                files.append(record)
                attribution.update(holders)
                if "bundled-notice" in group["classifications"]:
                    notices.add(raw.decode("utf-8"))
                if "attribution" in group["classifications"]:
                    attribution.add(raw.decode("utf-8"))
                for component in group["expressions"]:
                    components.append({"expression": component, "path": item["path"],
                                       "rawSha256": item["sha256"]})
            architecture_evidence.append({"target": artifact["target"],
                "architecture": artifact["architecture"],
                "wheelFilename": artifact["filename"], "wheelSha256": artifact["sha256"],
                "metadataSha256": artifact["metadataSha256"],
                "metadataLicenseExpression": metadata.get("License-Expression"),
                "licenseFiles": files})
        covered[name] = {"version": summary["version"],
            "licenseExpression": expression, "decisionBasis": basis,
            "attributionText": sorted(attribution), "noticeText": sorted(notices),
            "componentObligations": sorted({json.dumps(item, sort_keys=True)
                for item in components}), "architectures": architecture_evidence}
    if len(covered) != 125 or len(unresolved) != 8:
        raise ReconciliationError(
            f"expected covered=125 unresolved=8, got {len(covered)}/{len(unresolved)}")
    # Decode the canonicalized component records after deterministic deduplication.
    for record in covered.values():
        record["componentObligations"] = [json.loads(value)
                                           for value in record["componentObligations"]]
    return {"format": "openepm-source-license-policy-partial-candidate-v1",
        "status": "incomplete-external-review-required", "trustedPolicy": False,
        "sourceCompliancePermitted": False,
        "provenanceSha256": sha(provenance_path.read_bytes()),
        "reviewMatrixSha256": sha(matrix_path.read_bytes()),
        "residualDossierSha256": sha(dossier_path.read_bytes()),
        "coverage": {"lockedPackages": 133, "coveredCandidates": 125,
                     "unresolvedExternalDecisions": 8},
        "dependencies": covered, "unresolved": unresolved}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--review-matrix", type=Path, required=True)
    parser.add_argument("--residual-dossier", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    try:
        result = build(provenance_path=args.provenance,
                       matrix_path=args.review_matrix,
                       dossier_path=args.residual_dossier)
        # This output is intentionally not accepted by source-compliance tooling.
        require_complete(result)
    except ReconciliationError as error:
        # Incompleteness is the expected state, but other validation errors fail.
        if "partial license candidate cannot produce source compliance" not in str(error):
            parser.error(str(error))
    args.output.write_bytes(canonical(result) + b"\n")
    print(json.dumps(result["coverage"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
