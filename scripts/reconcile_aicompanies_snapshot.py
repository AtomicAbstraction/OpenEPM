"""Independently reconcile imported AIcompanies numeric snapshot rows offline.

The source packet supplies source identity and business policy. Snapshot capture,
MCP authentication and server paging belong to the maintained client. This module
never writes target facts, generates import rows, rounds values or uses a network.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from decimal import Decimal, InvalidOperation
from fractions import Fraction
import gzip
from hashlib import sha256
import json
from pathlib import Path
import re

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from scripts.aicompanies_mcp_journey import AXES, canonical, load_packet
from scripts.aicompanies_cube_payload import table_rows

NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z")
TARGET_AXES = frozenset(target for _, _, target in AXES) | {"Value"}


def exact(value, error):
    if not isinstance(value, str) or not NUMBER.fullmatch(value):
        raise ValueError(error)
    try:
        number = Decimal(value)
    except InvalidOperation as cause:
        raise ValueError(error) from cause
    # The imported AmountLiteral contract is decimal(28,8). This also bounds
    # exponent work before converting to an exact rational for wide totals.
    if not number.is_finite() or number.as_tuple().exponent < -8 or number.copy_abs() >= Decimal("1e20"):
        raise ValueError(error)
    return Fraction(0) if number.is_zero() else Fraction(number)


def coordinate(members):
    if (not isinstance(members, dict) or set(members) != TARGET_AXES
            or any(not isinstance(v, str) or not v for v in members.values())
            or members["Value"] != "SourceObservation"):
        raise ValueError("TARGET_GRAIN_MISMATCH")
    return tuple(sorted(members.items()))


def reconcile(records, policy, rows):
    """Require a complete bijection, then recompute source policy from target values."""
    source, by_coordinate, expected_values = {}, {}, {}
    for record in records:
        identity, fields = record["recordId"], record["fields"]
        if not isinstance(identity, str) or not identity or identity in source:
            raise ValueError("SOURCE_IDENTITY_DUPLICATE_OR_INVALID")
        members = {target: fields[key] for key, _, target in AXES}
        members["Value"] = "SourceObservation"
        key = coordinate(members)
        if key in by_coordinate:
            raise ValueError("SOURCE_COORDINATE_DUPLICATE")
        if record["numericLexicalValue"] != fields["Value"]:
            raise ValueError("SOURCE_VALUE_ENCODING_MISMATCH")
        expected_values[identity] = exact(record["numericLexicalValue"], "SOURCE_AMOUNT_INVALID")
        source[identity] = fields
        by_coordinate[key] = identity
    target, found, references = {}, set(), set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("TARGET_ROW_INVALID")
        key = coordinate(row.get("members"))
        if key in found:
            raise ValueError("TARGET_COORDINATE_DUPLICATE")
        found.add(key)
        if key not in by_coordinate:
            raise ValueError("TARGET_COORDINATE_UNEXPECTED")
        identity = by_coordinate[key]
        if (row.get("kind") != "numeric" or row.get("present") is not True
                or row.get("text") is not None):
            raise ValueError("TARGET_NUMERIC_STATE_INVALID")
        if "sourceRef" in row:
            if row["sourceRef"] != identity or row["sourceRef"] in references:
                raise ValueError("TARGET_SOURCE_REFERENCE_MISMATCH")
            references.add(row["sourceRef"])
        amount = exact(row.get("amount"), "TARGET_AMOUNT_INVALID")
        if amount != expected_values[identity]:
            raise ValueError("TARGET_VALUE_MISMATCH:" + identity)
        target[identity] = amount
    if found != set(by_coordinate):
        raise ValueError("TARGET_COORDINATE_COVERAGE_INCOMPLETE")
    if references and len(references) != len(target):
        raise ValueError("TARGET_SOURCE_REFERENCE_COVERAGE_INCOMPLETE")
    seeds, families, marginals = 0, 0, 0
    seen_seeds, seen_families = set(), set()
    for link in policy.get("seedLinks", []):
        actual_id, simulation_id = link["actualRecordId"], link["simulationRecordId"]
        if (actual_id not in target or simulation_id not in target
                or (actual_id, simulation_id) in seen_seeds):
            raise ValueError("SIMULATION_LINK_IDENTITY_INVALID")
        seen_seeds.add((actual_id, simulation_id))
        actual, simulation = source[actual_id], source[simulation_id]
        if (actual["ScenarioKey"] != "SC_ACTUALS" or simulation["ScenarioKey"] != "SC_SIMULATION"
                or any(actual[key] != simulation[key] for key, _, _ in AXES if key != "ScenarioKey")):
            raise ValueError("SIMULATION_LINK_GRAIN_MISMATCH")
        if not target[actual_id] == target[simulation_id] == exact(str(link["actualValue"]), "SIMULATION_LINK_AMOUNT_INVALID"):
            raise ValueError("SIMULATION_COPY_MISMATCH")
        seeds += 1
    for family in policy.get("families", []):
        anchor, leaves = family["anchorRecordId"], family["leafRecordIds"]
        identity = (anchor, tuple(leaves))
        if (anchor not in target or not leaves or len(leaves) != len(set(leaves))
                or any(key not in target for key in leaves) or identity in seen_families):
            raise ValueError("ALLOCATION_FAMILY_IDENTITY_INVALID")
        seen_families.add(identity)
        total = sum((target[key] for key in leaves), Fraction(0))
        if not total == target[anchor] == exact(str(family["anchorDecimalValue"]), "ALLOCATION_AMOUNT_INVALID") == exact(str(family["leafDecimalTotal"]), "ALLOCATION_AMOUNT_INVALID"):
            raise ValueError("ALLOCATION_FAMILY_MISMATCH")
        for axis, expected in family["marginals"].items():
            if axis not in {key for key, _, _ in AXES}:
                raise ValueError("ALLOCATION_MARGINAL_AXIS_INVALID")
            actual = defaultdict(Fraction)
            for identity in leaves:
                actual[source[identity][axis]] += target[identity]
            if dict(actual) != {key: exact(str(value), "ALLOCATION_MARGINAL_AMOUNT_INVALID") for key, value in expected.items()}:
                raise ValueError("ALLOCATION_MARGINAL_MISMATCH")
            marginals += len(actual)
        families += 1
    values = [[identity, str(target[identity].numerator), str(target[identity].denominator)] for identity in sorted(target)]
    return {"exactCoordinateAndValueMatch": True, "sourceRows": len(source), "targetRows": len(target),
            "sourceReferenceBinding": "snapshot-sourceRef-and-coordinate" if references else "source-recordId-to-exact-target-coordinate-bijection",
            "zeroValues": sum(v == 0 for v in target.values()), "negativeValues": sum(v < 0 for v in target.values()),
            "scenarioCounts": dict(Counter(fields["ScenarioKey"] for fields in source.values())),
            "exactSimulationCopies": seeds, "allocationFamilies": families, "exactMarginalChecks": marginals,
            "sourceIdentityExactValueDigest": sha256(canonical(values).encode()).hexdigest(),
            "targetMutationPerformed": False}


def reconcile_packet(manifest_path: Path, manifest_sha256: str, rows):
    manifest, _, _ = load_packet(manifest_path, manifest_sha256)
    with gzip.open(manifest_path.parent / "source/model.json.gz", "rt", encoding="utf-8") as stream:
        model = json.load(stream, parse_float=str)
    records = table_rows(manifest_path.parent, manifest, "FactFinancial")
    result = reconcile(records, model.get("simulationPolicy", {}), rows)
    return {**result, "sourcePacketManifestSha256": manifest_sha256,
            "sourceRevision": manifest["sourceRevision"]}


def read_snapshot(path: Path, manifest_sha256: str, *, workspace_id: str, application_id: str):
    from scripts.aicompanies_mcp_journey import contained, exact_json, verify_file
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != manifest_sha256:
        raise ValueError("SNAPSHOT_MANIFEST_PIN_MISMATCH")
    manifest = exact_json(raw)
    if (manifest.get("format") != "openepm-aicompanies-cube-snapshot-v1"
            or manifest.get("workspaceId") != workspace_id or manifest.get("applicationId") != application_id
            or manifest.get("complete") is not True
            or type(manifest.get("snapshotRevision")) is not int or manifest["snapshotRevision"] < 0
            or type(manifest.get("metadataRevision")) is not int or manifest["metadataRevision"] < 0
            or type(manifest.get("rows")) is not int or not 0 <= manifest["rows"] <= 100000):
        raise ValueError("SNAPSHOT_SCOPE_OR_COMPLETENESS_INVALID")
    row_file = contained(path.parent, manifest["rowsFile"])
    verify_file(row_file, manifest["rowFile"])
    rows = []
    with gzip.open(row_file, "rb") as stream:
        while line := stream.readline(65537):
            if len(line) > 65536 or len(rows) >= manifest["rows"]:
                raise ValueError("SNAPSHOT_ROWS_EXCEED_DECLARED_BOUND")
            rows.append(exact_json(line))
    verify_file(row_file, manifest["rowFile"])
    if path.read_bytes() != raw:
        raise ValueError("SNAPSHOT_MANIFEST_CHANGED_DURING_READ")
    if len(rows) != manifest["rows"]:
        raise ValueError("SNAPSHOT_ROW_COUNT_MISMATCH")
    return manifest, rows


def main(argv=None):
    import argparse
    import os
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--source-manifest-sha256", required=True)
    parser.add_argument("--snapshot-manifest", type=Path, required=True)
    parser.add_argument("--snapshot-manifest-sha256", required=True)
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--application-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    snapshot, rows = read_snapshot(args.snapshot_manifest, args.snapshot_manifest_sha256,
        workspace_id=args.workspace_id, application_id=args.application_id)
    result = reconcile_packet(args.source_manifest, args.source_manifest_sha256, rows)
    report = {"format": "openepm-aicompanies-target-reconciliation-v1", **result,
        "workspaceId": args.workspace_id, "applicationId": args.application_id,
        "snapshotRevision": snapshot["snapshotRevision"], "metadataRevision": snapshot["metadataRevision"],
        "snapshotManifestSha256": args.snapshot_manifest_sha256,
        "snapshotRowFile": snapshot["rowFile"],
        "boundary": "Offline verification of a captured complete authorized MCP snapshot; no network or target mutation."}
    # The result is separate evidence, never an edit to the source workbook or packet.
    source_manifest = json.loads(args.source_manifest.read_text())
    if (args.output.resolve().is_relative_to(Path(source_manifest["sourceRoot"]).resolve())
            or args.output.resolve().is_relative_to(args.source_manifest.parent.resolve())):
        raise ValueError("REPORT_PATH_INSIDE_SOURCE")
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    print(json.dumps({key: report[key] for key in ("targetRows", "exactSimulationCopies", "allocationFamilies", "exactMarginalChecks", "targetMutationPerformed")}))
    return report


if __name__ == "__main__":
    main()
