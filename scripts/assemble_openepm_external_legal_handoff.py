#!/usr/bin/env python3
"""Assemble the exact, non-approving external legal-review handoff."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil

try:
    from scripts.create_openepm_release_decision_templates import (
        build as build_templates)
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from create_openepm_release_decision_templates import build as build_templates


class HandoffError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise HandoffError(f"invalid {label}: {error}") from error
    if not isinstance(value, dict):
        raise HandoffError(f"{label} must be an object")
    return value


def assemble(*, packet_path: Path, review_path: Path, provenance_path: Path,
             lock_path: Path, output: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise HandoffError("handoff output must not already exist")
    packet = load(packet_path, "decision packet")
    review = load(review_path, "external review evidence")
    provenance = load(provenance_path, "target-wheel provenance")
    packet_sha, provenance_sha, lock_sha = (sha(packet_path),
        sha(provenance_path), sha(lock_path))
    legal = packet.get("legalReviewRequired")
    packages = review.get("packages")
    wheel = review.get("targetWheelProvenance")
    if (packet.get("format") != "openepm-owner-decision-packet-v1"
            or packet.get("status") != "decisions-pending"
            or packet.get("approvalsRecorded") is not False
            or not isinstance(legal, list) or not legal):
        raise HandoffError("decision packet is not pending external review")
    if (review.get("format") != "openepm-external-license-review-bundle-v1"
            or review.get("status") != "unreviewed-no-selection"
            or review.get("trustedPolicy") is not False
            or review.get("sourceCompliancePermitted") is not False
            or review.get("decisionPacketSha256") != packet_sha
            or not isinstance(packages, list)
            or {item.get("decisionId") for item in packages
                if isinstance(item, dict)} != {item.get("id") for item in legal}
            or not isinstance(wheel, dict)
            or wheel.get("evidenceSha256") != provenance_sha
            or wheel.get("lockSha256") != lock_sha
            or wheel.get("residualPackageEvidenceExactMatch") is not True):
        raise HandoffError("review evidence differs from the current decision inputs")
    if (provenance.get("format") !=
            "openepm-calculation-engine-w12-target-wheel-provenance-v1"
            or provenance.get("status") !=
            "pass-current-lock-provenance-external-review-open"):
        raise HandoffError("target-wheel provenance is not current and review-open")

    output.mkdir(mode=0o755)
    try:
        names = {
            "owner-decision-packet.json": packet_path,
            "external-license-review-evidence.json": review_path,
            "target-wheel-provenance.json": provenance_path,
            "requirements-postgres.lock": lock_path,
        }
        for name, source in names.items():
            if not source.is_file() or source.is_symlink():
                raise HandoffError(f"handoff source is missing or symbolic: {name}")
            shutil.copyfile(source, output / name)
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
        value = assemble(packet_path=arguments.decision_packet.resolve(),
            review_path=arguments.review_evidence.resolve(),
            provenance_path=arguments.target_wheel_provenance.resolve(),
            lock_path=arguments.lock.resolve(), output=arguments.output.resolve())
    except (HandoffError, OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
