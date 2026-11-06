#!/usr/bin/env python3
"""Build a deterministic, review-only dossier for unresolved wheel licenses."""
from __future__ import annotations

import argparse
from email.parser import Parser
import hashlib
import json
from pathlib import Path
import re

from reconcile_openepm_license_evidence import (
    ReconciliationError, canonical, expression_licenses, normalize_license_text)


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


def decision(*, metadata_expression: str | None, flags: list[str],
             matched: list[str], custom_texts: list[str],
             standard_paths: list[tuple[str, str]]) -> tuple[str | None, str, str]:
    """Return proposal, decision class, and the exact remaining question."""
    if not metadata_expression:
        return None, "external-license-review", (
            "Which SPDX expression and AND/OR relationship governs the package, "
            "given the bundled texts and legacy classifier/free-text metadata?")
    identifiers = expression_licenses(metadata_expression)
    conflict = "metadata-file-expression-conflict" in flags
    scope_ambiguous = any(text.startswith("files:") or
        text.startswith("except when otherwise stated") or
        "some python files have been taken" in text for text in custom_texts)
    if conflict or scope_ambiguous:
        return None, "external-license-review", (
            "Does the metadata expression cover every shipped file, and how should "
            "the unmatched scope/component text alter the release obligations?")
    if identifiers.issubset(set(matched)):
        return metadata_expression, "mechanically-reconcilable", (
            "Confirm the mechanically consistent metadata expression and preserve "
            "all bundled attribution/notice evidence.")
    # A primary standard license plus explicitly named third-party component files.
    primary = {expr for path, expr in standard_paths
               if Path(path).name.lower() in {"license", "license.md", "license.txt"}}
    if identifiers.issubset(primary):
        return metadata_expression, "mechanically-reconcilable", (
            "Confirm the package-level expression; retain separately named "
            "third-party component license obligations.")
    return None, "external-license-review", (
        "Why does the authoritative metadata expression lack matching bundled "
        "standard text, and which evidence governs redistribution?")


def build(*, provenance_path: Path, matrix_path: Path) -> dict:
    provenance, matrix = load(provenance_path), load(matrix_path)
    if provenance.get("status") != "verified-unapproved" or len(
            provenance.get("artifacts", [])) != 266:
        raise ReconciliationError("expected verified 266-wheel provenance")
    if matrix.get("trustedPolicy") is not False or matrix.get("coverage", {}).get(
            "packagesRequiringReview") != 13:
        raise ReconciliationError("expected the exact 13-package review matrix")
    if matrix.get("provenanceSha256") != sha(provenance_path.read_bytes()):
        raise ReconciliationError("matrix does not bind the provenance input")
    roots = {Path(value).name: Path(value).resolve()
             for value in provenance.get("proposalMetadataRoots", [])}
    groups = {item["normalizedSha256"]: item for item in matrix["reviewMatrix"]}
    unresolved = {item["name"]: item for item in matrix["packages"]
                  if item["reviewFlags"]}
    if len(unresolved) != 13:
        raise ReconciliationError("residual package set changed")
    artifact_groups: dict[str, dict] = {}
    package_artifacts: dict[str, list[dict]] = {name: [] for name in unresolved}
    for artifact in provenance["artifacts"]:
        name = artifact["package"]
        if name not in unresolved:
            continue
        root = roots.get(artifact["target"])
        if root is None:
            raise ReconciliationError(f"missing root for {artifact['target']}")
        metadata_path = root / artifact["metadataPath"]
        metadata_bytes = metadata_path.read_bytes()
        if sha(metadata_bytes) != artifact["metadataSha256"]:
            raise ReconciliationError(f"metadata hash mismatch: {name}")
        metadata = Parser().parsestr(metadata_bytes.decode("utf-8"))
        files = []
        for evidence in artifact.get("licenseFiles", []):
            path = root / evidence["path"]
            raw = path.read_bytes()
            if sha(raw) != evidence["sha256"]:
                raise ReconciliationError(f"license hash mismatch: {path}")
            normalized, holders = normalize_license_text(raw.decode("utf-8"))
            normalized_hash = sha(normalized.encode("utf-8"))
            group = groups.get(normalized_hash)
            if group is None:
                raise ReconciliationError(f"matrix omits evidence: {path}")
            record = {"path": evidence["path"], "rawSha256": evidence["sha256"],
                "normalizedSha256": normalized_hash,
                "classifications": group["classifications"],
                "detectedStandardExpressions": group["expressions"],
                "copyrightHolders": holders}
            files.append(record)
            grouped = artifact_groups.setdefault(evidence["sha256"], {
                "rawSha256": evidence["sha256"],
                "normalizedSha256": normalized_hash,
                "classifications": group["classifications"],
                "detectedStandardExpressions": group["expressions"],
                "exactText": raw.decode("utf-8"), "occurrences": []})
            grouped["occurrences"].append({"package": name,
                "version": artifact["version"], "target": artifact["target"],
                "architecture": artifact["architecture"], "path": evidence["path"]})
        package_artifacts[name].append({"target": artifact["target"],
            "architecture": artifact["architecture"], "wheelFilename": artifact["filename"],
            "wheelSha256": artifact["sha256"], "metadataPath": artifact["metadataPath"],
            "metadataSha256": artifact["metadataSha256"],
            "licenseExpression": metadata.get("License-Expression"),
            "licenseFreeText": metadata.get("License"),
            "licenseClassifiers": sorted(value for value in metadata.get_all("Classifier", [])
                if value.startswith("License ::")), "evidenceFiles": files})

    packages, counts = [], {"mechanicallyReconcilable": 0, "externalDecision": 0}
    for name, summary in sorted(unresolved.items()):
        artifacts = sorted(package_artifacts[name], key=lambda x: x["target"])
        metadata_values = {item["licenseExpression"] for item in artifacts
                           if item["licenseExpression"]}
        metadata_expression = next(iter(metadata_values)) if len(metadata_values) == 1 else None
        evidence_hashes = sorted({item["rawSha256"] for artifact in artifacts
                                  for item in artifact["evidenceFiles"]})
        custom_texts, standard_paths, attributions = [], [], []
        for raw_hash in evidence_hashes:
            group = artifact_groups[raw_hash]
            normalized, holders = normalize_license_text(group["exactText"])
            if "custom-or-unmatched" in group["classifications"]:
                custom_texts.append(normalized)
            for occurrence in group["occurrences"]:
                for expression in group["detectedStandardExpressions"]:
                    standard_paths.append((occurrence["path"], expression))
            if ("bundled-notice" in group["classifications"] or
                    "attribution" in group["classifications"]):
                attributions.append(group["exactText"])
            attributions.extend(holders)
        proposal, classification, question = decision(
            metadata_expression=metadata_expression, flags=summary["reviewFlags"],
            matched=summary["matchedExpressions"], custom_texts=custom_texts,
            standard_paths=standard_paths)
        counts["mechanicallyReconcilable" if proposal else "externalDecision"] += 1
        packages.append({"name": name, "version": summary["version"],
            "reviewFlags": summary["reviewFlags"], "decisionClass": classification,
            "proposedSpdxExpression": proposal, "reviewQuestion": question,
            "detectedStandardComponents": summary["matchedExpressions"],
            "customClausesOrScopeSelectors": custom_texts,
            "requiredAttributionText": sorted(set(attributions)),
            "architectures": artifacts, "evidenceGroupRawSha256": evidence_hashes})
    evidence_groups = []
    for group in artifact_groups.values():
        group["occurrences"] = sorted(group["occurrences"], key=lambda x:
            (x["package"], x["target"], x["path"]))
        evidence_groups.append(group)
    evidence_groups.sort(key=lambda x: x["rawSha256"])
    return {"format": "openepm-residual-license-review-dossier-v1",
        "status": "owner-or-legal-review-required", "trustedPolicy": False,
        "provenanceSha256": sha(provenance_path.read_bytes()),
        "reviewMatrixSha256": sha(matrix_path.read_bytes()),
        "coverage": {"packages": 13, **counts,
                     "byteIdenticalEvidenceGroups": len(evidence_groups)},
        "packages": packages, "evidenceGroups": evidence_groups}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--review-matrix", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    try:
        result = build(provenance_path=args.provenance, matrix_path=args.review_matrix)
        args.output.write_bytes(canonical(result) + b"\n")
    except (OSError, UnicodeError, ReconciliationError) as error:
        parser.error(str(error))
    print(json.dumps(result["coverage"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
