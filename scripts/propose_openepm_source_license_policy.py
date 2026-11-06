#!/usr/bin/env python3
"""Create a deterministic, review-only license proposal from local metadata."""
from __future__ import annotations

import argparse
from email.parser import Parser
import hashlib
import json
from pathlib import Path
import re
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from build_openepm_source_archive import ROOT, SourcePackageError, canonical, git  # noqa: E402
from build_openepm_source_compliance import LOCKS, locked_dependencies, normalized  # noqa: E402


KNOWN_LICENSES = {
    "0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BSL-1.0",
    "CC0-1.0", "ISC", "LGPL-2.1-only", "LGPL-2.1-or-later", "MIT",
    "MPL-2.0", "PSF-2.0", "Python-2.0", "Unlicense", "Zlib",
}
CLASSIFIERS = {
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
}
LICENSE_NAMES = re.compile(r"^(license|licence|copying|copyright|authors|notice)(\.|$)", re.I)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def spdx_expression(value: str) -> str | None:
    value = value.strip()
    tokens = re.findall(r"[A-Za-z0-9.+-]+|[()]", value)
    if "".join(tokens).replace("(", "").replace(")", "") == "":
        return None
    identifiers = [token for token in tokens
                   if token not in {"AND", "OR", "WITH", "(", ")"}]
    if not identifiers or any(identifier not in KNOWN_LICENSES
                              for identifier in identifiers):
        return None
    # Reject malformed text even when it happens to contain known identifiers.
    compact = re.sub(r"\s+", "", value)
    if compact != "".join(tokens):
        return None
    return value


def metadata_inventory(roots: list[Path]) -> dict[tuple[str, str], list[dict]]:
    result: dict[tuple[str, str], list[dict]] = {}
    for root_index, root in enumerate(roots):
        root = root.resolve()
        if not root.is_dir() or root.is_symlink():
            raise SourcePackageError(f"metadata root is missing or symbolic: {root}")
        for metadata_path in sorted(root.glob("*.dist-info/METADATA")):
            message = Parser().parsestr(metadata_path.read_text(
                encoding="utf-8", errors="strict"))
            name, version = message.get("Name"), message.get("Version")
            if not name or not version:
                continue
            dist_info = metadata_path.parent
            files = []
            for candidate in sorted(path for path in dist_info.rglob("*")
                                    if path.is_file() and not path.is_symlink()
                                    and LICENSE_NAMES.match(path.name)):
                files.append({"path": candidate.relative_to(root).as_posix(),
                              "sha256": sha(candidate)})
            record = {"root": f"metadata-root-{root_index + 1}",
                "metadataPath": metadata_path.relative_to(root).as_posix(),
                "metadataSha256": sha(metadata_path),
                "licenseExpression": message.get("License-Expression"),
                "licenseFreeText": message.get("License"),
                "licenseClassifiers": sorted(value for value in
                    message.get_all("Classifier", []) if value.startswith("License ::")),
                "bundledLicenseFiles": files}
            result.setdefault((normalized(name), version), []).append(record)
    return result


def propose(*, root: Path, metadata_roots: list[Path], epoch: int) -> dict:
    if epoch < 0:
        raise SourcePackageError("source-date-epoch must be nonnegative")
    dependencies = locked_dependencies(root)
    inventory = metadata_inventory(metadata_roots)
    packages = []
    counts = {key: 0 for key in ("locked", "installedExact", "missingDistribution",
        "duplicateMetadata", "expressionProposed", "classifierReview",
        "freeTextReview", "conflictReview", "unknownExpressionReview",
        "missingNoticeReview")}
    counts["locked"] = len(dependencies)
    for name, dependency in dependencies.items():
        records = inventory.get((name, dependency["version"]), [])
        evidence_signatures = {(record["metadataSha256"], tuple(
            (item["path"].split("/", 1)[-1], item["sha256"])
            for item in record["bundledLicenseFiles"])) for record in records}
        flags = []
        proposal = None
        classifier_suggestions = sorted({CLASSIFIERS[value]
            for record in records for value in record["licenseClassifiers"]
            if value in CLASSIFIERS})
        if not records:
            flags.append("missing-distribution-metadata")
            counts["missingDistribution"] += 1
        elif len(evidence_signatures) > 1:
            flags.append("duplicate-metadata")
            counts["duplicateMetadata"] += 1
        else:
            counts["installedExact"] += 1
            record = records[0]
            raw_expression = record["licenseExpression"]
            expression = spdx_expression(raw_expression) if raw_expression else None
            if raw_expression and expression is None:
                flags.append("unknown-license-expression")
                counts["unknownExpressionReview"] += 1
            if record["licenseClassifiers"]:
                flags.append("classifier-requires-review")
                counts["classifierReview"] += 1
            if record["licenseFreeText"]:
                flags.append("free-text-license-requires-review")
                counts["freeTextReview"] += 1
            if (expression and classifier_suggestions
                    and any(value != expression for value in classifier_suggestions)):
                flags.append("license-evidence-conflict")
                counts["conflictReview"] += 1
            elif expression:
                proposal = expression
                counts["expressionProposed"] += 1
            if not any(Path(item["path"]).name.lower().startswith("notice")
                       for item in record["bundledLicenseFiles"]):
                flags.append("missing-notice-text")
                counts["missingNoticeReview"] += 1
        packages.append({"name": name, "version": dependency["version"],
            "lockedArtifactHashes": dependency["hashes"],
            "lockPaths": dependency["locks"],
            "proposedLicenseExpression": proposal,
            "classifierSuggestions": classifier_suggestions,
            "reviewFlags": sorted(set(flags)), "provenance": records})
    return {"format": "openepm-source-license-policy-proposal-v1",
        "status": "proposal-review-required", "trustedPolicy": False,
        "networkUsed": False, "sourceCommit": git("rev-parse", "HEAD", root=root).strip(),
        "sourceDateEpoch": epoch,
        "lockSha256": {relative: sha(root / relative) for relative in LOCKS},
        "coverage": counts, "packages": packages}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata-root", action="append", type=Path, required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = propose(root=ROOT, metadata_roots=args.metadata_root,
                        epoch=args.source_date_epoch)
        if args.output.exists():
            raise SourcePackageError("proposal output already exists")
        args.output.write_bytes(canonical(value) + b"\n")
    except SourcePackageError as error:
        parser.error(str(error))
    print(json.dumps(value["coverage"], sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
