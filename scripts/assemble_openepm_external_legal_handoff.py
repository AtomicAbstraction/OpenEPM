#!/usr/bin/env python3
"""Assemble the exact, non-approving external legal-review handoff."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat

try:
    from scripts.create_openepm_release_decision_templates import (
        build as build_templates)
    from scripts.openepm_release_policy_contract import parse_json_object
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from create_openepm_release_decision_templates import build as build_templates
    from openepm_release_policy_contract import parse_json_object


class HandoffError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_source(path: Path, label: str) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise HandoffError(f"handoff source cannot be opened as a regular file: {label}") from error
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise HandoffError(f"handoff source must be a regular file: {label}")
        return source.read()


def load(data: bytes, label: str) -> dict:
    try:
        return parse_json_object(data, label)
    except ValueError as error:
        raise HandoffError(str(error)) from error


def verify_license_evidence(decisions: list, packages: list, groups: object) -> None:
    if not isinstance(groups, list) or len(packages) != len(decisions):
        raise HandoffError("license evidence must cover each decision once")
    expected_text = set()
    by_id = {}
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("decisionId"), str):
            raise HandoffError("license evidence must identify each package decision")
        by_id[package["decisionId"]] = package
    if len(by_id) != len(packages):
        raise HandoffError("license evidence repeats a package decision")
    for decision in decisions:
        if not isinstance(decision, dict) or not isinstance(decision.get("id"), str):
            raise HandoffError("license evidence must identify each pending decision")
        package = by_id.pop(decision["id"], None)
        evidence = decision.get("evidence")
        digests = evidence.get("rawLicenseEvidenceSha256") if isinstance(evidence, dict) else None
        if (package is None or not isinstance(digests, list) or not digests
                or any(not isinstance(digest, str) for digest in digests)):
            raise HandoffError("license evidence is missing for a pending decision")
        if (not isinstance(package.get("name"), str) or not package["name"]
                or package["name"] != decision.get("package")
                or not isinstance(package.get("version"), str) or not package["version"]
                or package["version"] != decision.get("version")
                or package.get("evidenceGroupRawSha256") != digests):
            raise HandoffError("license evidence differs from the selected package or version")
        expected_text.update(digests)
    observed_text = set()
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("exactText"), str):
            raise HandoffError("license evidence must include the exact review text")
        digest = hashlib.sha256(group["exactText"].encode("utf-8")).hexdigest()
        if digest != group.get("rawSha256") or digest in observed_text:
            raise HandoffError("license evidence text differs or is repeated")
        observed_text.add(digest)
    if observed_text != expected_text:
        raise HandoffError("license evidence text does not cover the selected packages")


def by_architecture(rows: object) -> dict[str, dict]:
    if not isinstance(rows, list) or len(rows) != 2:
        raise HandoffError("wheel evidence must cover both Linux architectures once")
    result = {}
    for row in rows:
        architecture = row.get("architecture") if isinstance(row, dict) else None
        if architecture not in ("linux/amd64", "linux/arm64") or architecture in result:
            raise HandoffError("wheel evidence has a missing or repeated architecture")
        result[architecture] = row
    return result


def review_target(row: dict) -> dict:
    files = row.get("evidenceFiles")
    if not isinstance(files, list) or not files:
        raise HandoffError("wheel license files are missing")
    license_files = []
    paths = set()
    for item in files:
        path = item.get("path") if isinstance(item, dict) else None
        if (not isinstance(path, str) or not path or path.startswith("/")
                or any(part in ("", ".", "..") for part in path.split("/")) or path in paths):
            raise HandoffError("wheel license file path is invalid or repeated")
        paths.add(path)
        license_files.append({"path": path, "sha256": item.get("rawSha256")})
    digests = [row.get("wheelSha256"), row.get("metadataSha256"),
               *(item["sha256"] for item in license_files)]
    if any(not isinstance(digest, str) or not re.fullmatch("[0-9a-f]{64}", digest)
           for digest in digests):
        raise HandoffError("wheel evidence digest is invalid")
    return {"architecture": row["architecture"], "target": row.get("target"),
            "filename": row.get("wheelFilename"), "sha256": row["wheelSha256"],
            "metadataSha256": row["metadataSha256"], "licenseFiles": license_files}


def verify_wheel_scope(packages: list, groups: list, wheel: dict, provenance: dict) -> None:
    reconciliation = provenance.get("residualReviewReconciliation")
    if (not isinstance(reconciliation, dict)
            or set(reconciliation) - {"reviewBundle"} != {package["name"] for package in packages}
            or wheel.get("architectures") != ["linux/amd64", "linux/arm64"]):
        raise HandoffError("wheel evidence package or architecture scope differs")
    targets = provenance["results"].get("targets")
    if not isinstance(targets, list) or len(targets) != 2:
        raise HandoffError("wheel evidence target scope differs")
    occurrences = {group["rawSha256"]: [] for group in groups}
    for package in packages:
        name = package["name"]
        record = reconciliation[name]
        if (not isinstance(record, dict) or record.get("version") != package["version"]
                or record.get("reviewBundleExactMatch") is not True):
            raise HandoffError("wheel evidence version or review state differs")
        rows = by_architecture(package.get("architectures"))
        if "targets" in record:
            recorded = by_architecture(record["targets"])
        elif "inventory" in provenance or "reviewBundle" not in reconciliation:
            raise HandoffError("wheel evidence lacks detailed target records")
        else:
            # Older provenance retained wheel, METADATA and license-file digests only.
            recorded = None
        used_digests = set()
        for architecture, row in rows.items():
            target = review_target(row)
            label = target["target"]
            if (not isinstance(label, str) or label not in targets
                    or not label.startswith(architecture.replace("/", "-") + "-")):
                raise HandoffError("wheel evidence target scope differs")
            if recorded is not None:
                if recorded[architecture] != target:
                    raise HandoffError("wheel evidence differs from the recorded target or license files")
            else:
                arch = architecture.split("/")[1]
                if (target["sha256"] != record.get(arch + "WheelSha256")
                        or target["metadataSha256"] != record.get("metadataSha256")
                        or [item["sha256"] for item in target["licenseFiles"]] != [record.get("licenseFileSha256")]):
                    raise HandoffError("wheel evidence differs from the historical target digests")
            for item in target["licenseFiles"]:
                digest = item["sha256"]
                if digest not in occurrences:
                    raise HandoffError("wheel license file has no matching evidence text")
                used_digests.add(digest)
                occurrences[digest].append({"package": name, "version": package["version"],
                    "architecture": architecture, "target": label, "path": item["path"]})
        if used_digests != set(package["evidenceGroupRawSha256"]):
            raise HandoffError("wheel license files differ from the selected package text")
    for group in groups:
        actual = group.get("occurrences")
        if (not isinstance(actual, list) or sorted(map(canonical, actual))
                != sorted(map(canonical, occurrences[group["rawSha256"]]))):
            raise HandoffError("wheel license file occurrences differ from the review scope")


def assemble(*, packet_path: Path, review_path: Path, provenance_path: Path,
             lock_path: Path, output: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise HandoffError("handoff output must not already exist")
    packet_data = read_source(packet_path, "decision packet")
    review_data = read_source(review_path, "external review evidence")
    provenance_data = read_source(provenance_path, "target-wheel provenance")
    lock_data = read_source(lock_path, "dependency lock")
    packet = load(packet_data, "decision packet")
    review = load(review_data, "external review evidence")
    provenance = load(provenance_data, "target-wheel provenance")
    packet_sha, provenance_sha, lock_sha = (
        hashlib.sha256(data).hexdigest() for data in (packet_data, provenance_data, lock_data))
    legal = packet.get("legalReviewRequired")
    dependency_scope = packet.get("dependencyScope")
    packages = review.get("packages")
    wheel = review.get("targetWheelProvenance")
    if (packet.get("format") != "openepm-owner-decision-packet-v1"
            or packet.get("status") != "decisions-pending"
            or packet.get("approvalsRecorded") is not False
            or not isinstance(legal, list) or not legal):
        raise HandoffError("decision packet is not pending external review")
    if (not isinstance(dependency_scope, dict)
            or dependency_scope.get("lockSha256") != lock_sha
            or dependency_scope.get("trustedSourceCompliance") is not False):
        raise HandoffError("decision packet dependency scope differs from the current lock")
    if (review.get("format") != "openepm-external-license-review-bundle-v1"
            or review.get("status") != "unreviewed-no-selection"
            or review.get("trustedPolicy") is not False
            or review.get("sourceCompliancePermitted") is not False
            or review.get("decisionPacketSha256") != packet_sha
            or not isinstance(packages, list)
            or not isinstance(wheel, dict)
            or wheel.get("evidenceSha256") != provenance_sha
            or wheel.get("lockSha256") != lock_sha
            or wheel.get("residualPackageEvidenceExactMatch") is not True):
        raise HandoffError("review evidence differs from the current decision inputs")
    verify_license_evidence(legal, packages, review.get("evidenceGroups"))
    inputs = provenance.get("inputs")
    results = provenance.get("results")
    if (provenance.get("format") !=
            "openepm-calculation-engine-w12-target-wheel-provenance-v1"
            or provenance.get("status") !=
            "pass-current-lock-provenance-external-review-open"
            or not isinstance(inputs, dict)
            or inputs.get("lock") != dependency_scope.get("lockPath")
            or inputs.get("lockSha256") != lock_sha
            or not isinstance(results, dict)
            or type(results.get("lockedPackages")) is not int
            or results["lockedPackages"] < 1
            or results.get("lockedPackages") != wheel.get("lockedPackages")
            or results.get("verifiedWheels") != wheel.get("verifiedWheels")
            or results.get("verifiedWheels") != 2 * results["lockedPackages"]
            or results.get("packagesInstalled") is not False
            or results.get("sdistsAccepted") is not False):
        raise HandoffError("target-wheel provenance is not current and review-open")
    verify_wheel_scope(packages, review["evidenceGroups"], wheel, provenance)

    output.mkdir(mode=0o755)
    try:
        names = {
            "owner-decision-packet.json": packet_data,
            "external-license-review-evidence.json": review_data,
            "target-wheel-provenance.json": provenance_data,
            "requirements-postgres.lock": lock_data,
        }
        for name, data in names.items():
            (output / name).write_bytes(data)
            (output / name).chmod(0o444)
        templates = output / "completion-templates"
        build_templates(output / "owner-decision-packet.json", templates)
        for path in templates.iterdir():
            path.chmod(0o444)
        records = [{"path": path.relative_to(output).as_posix(),
                    "sha256": sha(path)} for path in sorted(
                        item for item in output.rglob("*") if item.is_file())]
        index = {
            "format": "openepm-external-legal-handoff-index-v1",
            "status": "external-review-required-no-approval",
            "trustedPolicy": False,
            "sourceCompliancePermitted": False,
            "decisionPacketSha256": packet_sha,
            "targetWheelProvenanceSha256": provenance_sha,
            "lockSha256": lock_sha,
            "decisionIds": sorted(item["id"] for item in legal),
            "instructions": (
                "Review only the two evidence-bound legal decisions. Complete each "
                "attestation template with reviewer reference, review date, exact "
                "license expression, file scopes and attribution/NOTICE obligations; "
                "then complete the selections template without changing evidence "
                "identities. This handoff records no approval."),
            "files": records,
        }
        index_path = output / "HANDOFF_INDEX.json"
        index_path.write_bytes(canonical(index) + b"\n")
        index_path.chmod(0o444)
        return index
    except Exception:
        if output.exists():
            shutil.rmtree(output)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decision-packet", type=Path, required=True)
    parser.add_argument("--review-evidence", type=Path, required=True)
    parser.add_argument("--target-wheel-provenance", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        value = assemble(packet_path=arguments.decision_packet,
            review_path=arguments.review_evidence,
            provenance_path=arguments.target_wheel_provenance,
            lock_path=arguments.lock, output=arguments.output)
    except (HandoffError, OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
