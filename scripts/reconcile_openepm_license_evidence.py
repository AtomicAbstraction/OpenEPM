#!/usr/bin/env python3
"""Group verified wheel license evidence against reviewed text templates.

This emits a review matrix.  It never writes or approves the trusted policy.
"""
from __future__ import annotations

import argparse
from email.parser import Parser
import hashlib
import json
from pathlib import Path
import re
import unicodedata


class ReconciliationError(ValueError):
    pass


COPYRIGHT = re.compile(r"(?:copyright|\u00a9|\(c\)|copr\.)", re.I)
NOTICE = re.compile(r"^notice(?:\.|$)", re.I)
ATTRIBUTION = re.compile(r"^(?:authors?|contributors?)(?:\.|$)", re.I)
LICENSE = re.compile(r"^(?:licen[cs]e|copying|copyright)(?:\.|$)", re.I)
SPDX_OPERATORS = {"AND", "OR", "WITH"}


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_license_text(raw: str) -> tuple[str, list[str]]:
    """Normalize layout/case while retaining holder lines separately."""
    raw = unicodedata.normalize("NFC", raw.replace("\r\n", "\n").replace("\r", "\n"))
    output, holders = [], []
    previous_blank = False
    for original in raw.split("\n"):
        line = " ".join(original.strip().split())
        if not line:
            if output and not previous_blank:
                output.append("")
            previous_blank = True
            continue
        previous_blank = False
        if COPYRIGHT.search(line):
            holders.append(line)
            output.append("{{COPYRIGHT}}")
        else:
            output.append(line.casefold())
    while output and output[-1] == "":
        output.pop()
    return "\n".join(output), sorted(set(holders))


def expression_licenses(expression: str) -> set[str]:
    return {token for token in re.findall(r"[A-Za-z0-9.+-]+", expression)
            if token not in SPDX_OPERATORS}


def _load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReconciliationError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise ReconciliationError(f"expected JSON object: {path}")
    return value


def reconcile(*, provenance_path: Path, proposal_path: Path,
              templates_path: Path) -> dict:
    provenance, proposal, templates = (_load(provenance_path), _load(proposal_path),
                                       _load(templates_path))
    artifacts = provenance.get("artifacts")
    if provenance.get("status") != "verified-unapproved" or not isinstance(artifacts, list):
        raise ReconciliationError("wheel provenance is not verified-unapproved")
    if len(artifacts) != 266 or provenance.get("lockedPackageCount") != 133:
        raise ReconciliationError("expected exact 266-wheel/133-package corpus")
    if proposal.get("trustedPolicy") is not False:
        raise ReconciliationError("input must remain an untrusted proposal")
    if proposal.get("lockSha256") != provenance.get("lockSha256"):
        raise ReconciliationError("proposal/provenance lock identities differ")
    if templates.get("normalization") != "openepm-license-text-normalization-v1":
        raise ReconciliationError("unsupported template normalization")
    by_hash = {}
    for item in templates.get("templates", []):
        key = item.get("normalizedSha256")
        if not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key):
            raise ReconciliationError("invalid template digest")
        if key in by_hash:
            raise ReconciliationError("duplicate reviewed template digest")
        by_hash[key] = item

    roots = {Path(value).resolve() for value in provenance.get("proposalMetadataRoots", [])}
    if len(roots) != 2 or any(not root.is_dir() or root.is_symlink() for root in roots):
        raise ReconciliationError("exact verified metadata roots are unavailable")
    groups: dict[str, dict] = {}
    package_state: dict[tuple[str, str], dict] = {}
    for artifact in sorted(artifacts, key=lambda x: (x["package"], x["target"])):
        key = (artifact["package"], artifact["version"])
        state = package_state.setdefault(key, {"expressions": set(), "files": set(),
            "notices": set(), "attributions": set(), "unmatched": set(),
            "metadataExpressions": set(), "targets": set()})
        state["targets"].add(artifact["target"])
        candidate_roots = [root for root in roots if root.name == artifact["target"]]
        if len(candidate_roots) != 1:
            raise ReconciliationError(f"no unique metadata root for {artifact['target']}")
        root = candidate_roots[0]
        metadata_path = root / artifact["metadataPath"]
        if not metadata_path.is_file() or digest(metadata_path.read_bytes()) != artifact["metadataSha256"]:
            raise ReconciliationError(f"metadata identity mismatch: {artifact['package']}")
        metadata = Parser().parsestr(metadata_path.read_text(encoding="utf-8"))
        if metadata.get("License-Expression"):
            state["metadataExpressions"].add(metadata["License-Expression"].strip())
        for evidence in artifact.get("licenseFiles", []):
            path = root / evidence["path"]
            raw_bytes = path.read_bytes()
            if digest(raw_bytes) != evidence["sha256"]:
                raise ReconciliationError(f"license identity mismatch: {path}")
            normalized_text, holders = normalize_license_text(raw_bytes.decode("utf-8"))
            normalized_hash = digest(normalized_text.encode("utf-8"))
            name = path.name
            template = by_hash.get(normalized_hash)
            if NOTICE.match(name):
                kind, expression, obligation = "bundled-notice", None, "preserve"
                state["notices"].add(normalized_hash)
            elif ATTRIBUTION.match(name):
                kind, expression, obligation = "attribution", None, "preserve"
                state["attributions"].add(normalized_hash)
            elif template:
                kind = "standard-license"
                expression, obligation = template["expression"], template["noticeRule"]
                state["expressions"].add(expression)
            else:
                kind, expression, obligation = "custom-or-unmatched", None, "review"
                state["unmatched"].add(normalized_hash)
            state["files"].add(normalized_hash)
            group = groups.setdefault(normalized_hash, {"normalizedSha256": normalized_hash,
                "classifications": set(), "expressions": set(),
                "noticeRulesOrObligations": set(), "copyrightHolders": set(),
                "rawEvidenceSha256": set(), "occurrences": []})
            group["classifications"].add(kind)
            if expression:
                group["expressions"].add(expression)
            group["noticeRulesOrObligations"].add(obligation)
            group["copyrightHolders"].update(holders)
            group["rawEvidenceSha256"].add(evidence["sha256"])
            group["occurrences"].append({"package": artifact["package"],
                "version": artifact["version"], "target": artifact["target"],
                "path": evidence["path"]})

    packages, residual = [], {}
    for (name, version), state in sorted(package_state.items()):
        flags = []
        if len(state["expressions"]) > 1:
            flags.append("multiple-standard-license-expressions")
        if state["unmatched"]:
            flags.append("custom-or-unmatched-license-text")
        if not state["files"]:
            flags.append("no-bundled-license-evidence")
        if state["metadataExpressions"] and state["expressions"]:
            metadata_licenses = set().union(*(
                expression_licenses(value) for value in state["metadataExpressions"]))
            if not metadata_licenses.issubset(state["expressions"]):
                flags.append("metadata-file-expression-conflict")
        elif state["metadataExpressions"] and not state["expressions"]:
            flags.append("metadata-expression-without-matched-text")
        for flag in flags:
            residual.setdefault(flag, []).append(name)
        packages.append({"name": name, "version": version,
            "targets": sorted(state["targets"]),
            "matchedExpressions": sorted(state["expressions"]),
            "metadataExpressions": sorted(state["metadataExpressions"]),
            "licenseEvidenceGroups": sorted(state["files"]),
            "bundledNoticeGroups": sorted(state["notices"]),
            "attributionGroups": sorted(state["attributions"]),
            "reviewFlags": flags})
    matrix = []
    for group in groups.values():
        matrix.append({**group,
            "classifications": sorted(group["classifications"]),
            "expressions": sorted(group["expressions"]),
            "noticeRulesOrObligations": sorted(group["noticeRulesOrObligations"]),
            "copyrightHolders": sorted(group["copyrightHolders"]),
            "rawEvidenceSha256": sorted(group["rawEvidenceSha256"]),
            "occurrences": sorted(group["occurrences"], key=lambda x:
                (x["package"], x["target"], x["path"]))})
    matrix.sort(key=lambda x: x["normalizedSha256"])
    coverage = {"wheelRecords": len(artifacts), "packages": len(package_state),
        "uniqueEvidenceGroups": len(matrix),
        "standardLicenseGroups": sum("standard-license" in x["classifications"] for x in matrix),
        "bundledNoticeGroups": sum("bundled-notice" in x["classifications"] for x in matrix),
        "attributionGroups": sum("attribution" in x["classifications"] for x in matrix),
        "customOrUnmatchedGroups": sum("custom-or-unmatched" in x["classifications"] for x in matrix),
        "packagesWithoutReviewFlags": sum(not x["reviewFlags"] for x in packages),
        "packagesRequiringReview": sum(bool(x["reviewFlags"]) for x in packages)}
    return {"format": "openepm-license-evidence-review-matrix-v1",
        "status": "proposal-review-required", "trustedPolicy": False,
        "provenanceSha256": digest(provenance_path.read_bytes()),
        "proposalSha256": digest(proposal_path.read_bytes()),
        "templateSetSha256": digest(templates_path.read_bytes()),
        "coverage": coverage, "residualHumanReview":
            {key: sorted(set(value)) for key, value in sorted(residual.items())},
        "packages": packages, "reviewMatrix": matrix}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--proposal", type=Path, required=True)
    parser.add_argument("--templates", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    try:
        result = reconcile(provenance_path=args.provenance,
                           proposal_path=args.proposal,
                           templates_path=args.templates)
        args.output.write_bytes(canonical(result) + b"\n")
    except (OSError, UnicodeError, ReconciliationError) as error:
        parser.error(str(error))
    print(json.dumps(result["coverage"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
