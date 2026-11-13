#!/usr/bin/env python3
"""Fail-closed validation for Open EPM's OWASP ASVS verification matrix."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


EXPECTED_SOURCE_SHA256 = "6124dba176dc563f66363a11ae0c47f9b86b8a4a84c66a793670bd196ed86cd5"
ALLOWED_DISPOSITIONS = {"verified", "deferred", "not_applicable", "owner_policy_difference"}
CONTROL_ID = re.compile(r"^V(?:[1-9]|1[0-7])\.\d+\.\d+$")


class MatrixError(ValueError):
    pass


def _load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MatrixError(f"cannot read valid JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise MatrixError(f"{path} must contain a JSON object")
    return value


def _test_selector_exists(path: Path, selector: str) -> bool:
    if not re.fullmatch(r"[A-Za-z_]\w*\.test_[A-Za-z0-9_]+", selector):
        return False
    class_name, method_name = selector.split(".", 1)
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError):
        return False
    return any(
        isinstance(node, ast.ClassDef)
        and node.name == class_name
        and any(
            isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name == method_name
            for child in node.body
        )
        for node in tree.body
    )


def validate(repo: Path, matrix_path: Path | None = None) -> dict:
    matrix_path = matrix_path or repo / "docs/security/owasp-asvs-5.0.0-openepm-matrix.json"
    matrix = _load(matrix_path)
    catalogue_path_value = matrix.get("cataloguePath")
    if not isinstance(catalogue_path_value, str) or Path(catalogue_path_value).is_absolute():
        raise MatrixError("cataloguePath must be a repository-relative path")
    catalogue_path = repo / catalogue_path_value
    catalogue = _load(catalogue_path)
    actual_catalogue_digest = hashlib.sha256(catalogue_path.read_bytes()).hexdigest()
    if matrix.get("catalogueSha256") != actual_catalogue_digest:
        raise MatrixError("catalogueSha256 does not match the checked-in catalogue")

    authority = catalogue.get("authority", {})
    if authority.get("version") != "5.0.0" or authority.get("release") != "v5.0.0_release":
        raise MatrixError("catalogue must pin the stable OWASP ASVS 5.0.0 release")
    if authority.get("sourceSha256") != EXPECTED_SOURCE_SHA256:
        raise MatrixError("catalogue source digest is not the pinned official ASVS 5.0.0 CSV")
    if authority.get("sourceUrl") != (
        "https://github.com/OWASP/ASVS/releases/download/v5.0.0_release/"
        "OWASP_Application_Security_Verification_Standard_5.0.0_en.csv"
    ):
        raise MatrixError("catalogue sourceUrl is not the official pinned release asset")

    catalogue_controls = catalogue.get("controls")
    matrix_controls = matrix.get("controls")
    if not isinstance(catalogue_controls, list) or not isinstance(matrix_controls, list):
        raise MatrixError("catalogue and matrix controls must be arrays")
    catalogue_ids = [control.get("id") for control in catalogue_controls if isinstance(control, dict)]
    matrix_ids = [control.get("id") for control in matrix_controls if isinstance(control, dict)]
    if len(catalogue_controls) != len(catalogue_ids) or len(matrix_controls) != len(matrix_ids):
        raise MatrixError("every control entry must be an object")
    if len(catalogue_ids) != 345 or catalogue.get("controlCount") != 345:
        raise MatrixError("catalogue must contain all 345 ASVS 5.0.0 controls")
    if len(set(catalogue_ids)) != len(catalogue_ids) or not all(
        isinstance(control_id, str) and CONTROL_ID.fullmatch(control_id) for control_id in catalogue_ids
    ):
        raise MatrixError("catalogue contains duplicate or malformed control IDs")
    if len(set(matrix_ids)) != len(matrix_ids):
        raise MatrixError("matrix contains duplicate control IDs")
    missing = sorted(set(catalogue_ids) - set(matrix_ids))
    extra = sorted(set(matrix_ids) - set(catalogue_ids))
    if missing or extra:
        raise MatrixError(f"matrix/catalogue control mismatch: missing={missing}, extra={extra}")
    if matrix.get("blanketComplianceClaimed") is not False:
        raise MatrixError("blanketComplianceClaimed must remain false")

    counts: Counter[str] = Counter()
    by_id = {control["id"]: control for control in matrix_controls}
    for control_id in catalogue_ids:
        control = by_id[control_id]
        disposition = control.get("disposition")
        if disposition not in ALLOWED_DISPOSITIONS:
            raise MatrixError(f"{control_id}: disposition is missing or unsupported")
        counts[disposition] += 1
        if not isinstance(control.get("rationale"), str) or not control["rationale"].strip():
            raise MatrixError(f"{control_id}: a non-empty rationale is required")
        if disposition == "verified":
            if control.get("applicable") is not True:
                raise MatrixError(f"{control_id}: verified control must be applicable")
            evidence = control.get("evidence")
            if not isinstance(evidence, list) or not evidence:
                raise MatrixError(f"{control_id}: verified claim has no executable evidence")
            for item in evidence:
                if not isinstance(item, dict) or item.get("kind") != "executable_test":
                    raise MatrixError(f"{control_id}: verified evidence must be executable_test")
                relative = item.get("path")
                selector = item.get("selector")
                if not isinstance(relative, str) or Path(relative).is_absolute() or not relative.startswith("tests/"):
                    raise MatrixError(f"{control_id}: evidence path must be repository-relative under tests/")
                evidence_path = repo / relative
                if not evidence_path.is_file():
                    raise MatrixError(f"{control_id}: evidence path does not exist: {relative}")
                if not isinstance(selector, str) or not _test_selector_exists(evidence_path, selector):
                    raise MatrixError(f"{control_id}: executable selector does not exist: {selector!r}")
        elif disposition == "deferred":
            if control.get("applicable") is not True or not str(control.get("releaseGate", "")).strip():
                raise MatrixError(f"{control_id}: deferred applicable control requires a releaseGate")
            if control.get("evidence"):
                raise MatrixError(f"{control_id}: deferred control must not imply passing evidence")
        elif disposition == "not_applicable":
            if control.get("applicable") is not False or not str(control.get("featureBoundary", "")).strip():
                raise MatrixError(f"{control_id}: not-applicable control requires a featureBoundary")
        elif disposition == "owner_policy_difference":
            if control.get("applicable") is not True:
                raise MatrixError(f"{control_id}: owner policy difference remains applicable")
            for field in ("ownerDecision", "riskTreatment"):
                if not str(control.get(field, "")).strip():
                    raise MatrixError(f"{control_id}: owner policy difference requires {field}")
            if control.get("evidence"):
                raise MatrixError(f"{control_id}: policy difference must not be represented as a pass")

    expected_summary = {"total": len(matrix_controls), **{name: counts[name] for name in ALLOWED_DISPOSITIONS}}
    summary = matrix.get("summary")
    if not isinstance(summary, dict) or any(summary.get(key) != value for key, value in expected_summary.items()):
        raise MatrixError(f"summary does not match controls: expected {expected_summary}")
    if counts["verified"] == len(matrix_controls):
        raise MatrixError("matrix must not claim blanket verification")
    return expected_summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--matrix", type=Path)
    args = parser.parse_args()
    summary = validate(args.repo.resolve(), args.matrix)
    print(json.dumps({"valid": True, "summary": summary}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except MatrixError as exc:
        raise SystemExit(f"ASVS matrix validation failed: {exc}") from exc
