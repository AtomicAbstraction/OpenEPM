"""Prepare exact cube rows and independently reconcile MCP snapshot read-back.

Offline migration tooling only. The maintained native MCP client owns all target
operations. Provenance records supplement, never replace, the numeric cube.
"""
from __future__ import annotations

import argparse
from collections import Counter
from decimal import Decimal
import gzip
from hashlib import sha256
import json
from pathlib import Path

try:
    from scripts.aicompanies_mcp_journey import AXES, canonical, contained, load_packet
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from aicompanies_mcp_journey import AXES, canonical, contained, load_packet

VALUE_MEMBER = "SourceObservation"


def table_rows(root, manifest, table):
    spec = manifest["tables"][table]
    path = contained(root, spec["file"])
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream]
    if len(rows) != spec["recordCount"]:
        raise ValueError("SOURCE_ROW_COUNT_MISMATCH")
    return rows


def source_rows(records, registry):
    """Require bijective source identity/grain and exact registry agreement."""
    seen_ids, seen_coordinates, seen_registry = set(), set(), set()
    numeric, provenance = [], []
    for row in records:
        fields = row["fields"]
        identity = row["recordId"]
        index = row["registryIndex"]
        if (not isinstance(identity, str) or not 1 <= len(identity) <= 200
                or identity in seen_ids or type(index) is not int
                or index < 0 or index >= len(registry) or index in seen_registry):
            raise ValueError("SOURCE_IDENTITY_INVALID")
        original = registry[index]
        coordinate = {target: fields[key] for key, _, target in AXES}
        coordinate["Value"] = VALUE_MEMBER
        coordinate_key = canonical(coordinate)
        if (coordinate_key in seen_coordinates
                or any(not isinstance(value, str) or not value for value in coordinate.values())
                or any(str(original.get(key)) != fields[key] for key, _, _ in AXES)):
            raise ValueError("SOURCE_GRAIN_INVALID")
        value = row["numericLexicalValue"]
        if not isinstance(value, str) or value != fields["Value"]:
            raise ValueError("SOURCE_VALUE_ENCODING_INVALID")
        amount = Decimal(value)
        if (not amount.is_finite() or amount != Decimal(str(original["Value"]))
                or amount.as_tuple().exponent < -8 or amount.copy_abs() >= Decimal("1e20")):
            raise ValueError("SOURCE_VALUE_INVALID_OR_UNSUPPORTED")
        numeric.append({"members": coordinate,
                        "value": {"type": "AmountLiteral", "decimal": value},
                        "sourceRef": identity})
        # Numeric truth lives in the cube; this record preserves source meaning,
        # lineage, original identity and lexical value digest for verification.
        provenance.append({"seriesKey": identity, "value": {
            "format": "openepm-imported-observation-context-v1",
            "recordId": identity, "members": coordinate,
            "sourceTable": row["table"], "sourceRow": row["sourceRow"],
            "canonicalSourceKey": row["canonicalKey"],
            "numericLexicalSha256": sha256(value.encode()).hexdigest(),
            "fields": {key: item for key, item in fields.items() if key != "Value"},
            "registry": {key: item for key, item in original.items() if key != "Value"},
            "cellTypes": row["cellTypes"], "formulas": row["formulas"],
            "numericJsonEncoding": "Fractional registry numbers are decimal strings",
        }})
        if len(canonical(provenance[-1]["value"]).encode()) > 100000:
            raise ValueError("PROVENANCE_RECORD_TOO_LARGE")
        seen_ids.add(identity)
        seen_coordinates.add(coordinate_key)
        seen_registry.add(index)
    if len(seen_registry) != len(registry):
        raise ValueError("REGISTRY_COVERAGE_INCOMPLETE")
    return numeric, provenance


def verify_numeric(expected, actual):
    """Compare a complete server snapshot without depending on row ordering."""
    source = {canonical(row["members"]): row for row in expected}
    if len(source) != len(expected):
        raise ValueError("EXPECTED_DUPLICATE_COORDINATE")
    found = {}
    for row in actual:
        key = canonical(row["members"])
        if key in found:
            raise ValueError("TARGET_DUPLICATE_COORDINATE")
        if (row.get("kind") != "numeric" or row.get("present") is not True
                or not isinstance(row.get("amount"), str)
                or row.get("text") is not None):
            raise ValueError("TARGET_NUMERIC_STATE_INVALID")
        amount = Decimal(row["amount"])
        if not amount.is_finite():
            raise ValueError("TARGET_NUMERIC_STATE_INVALID")
        found[key] = amount
    if set(source) != set(found):
        raise ValueError("TARGET_COORDINATE_COVERAGE_MISMATCH")
    for key, row in source.items():
        if found[key] != Decimal(row["value"]["decimal"]):
            raise ValueError("TARGET_VALUE_MISMATCH:" + row["sourceRef"])
    return {"exactCoordinateAndValueMatch": True, "sourceRows": len(source),
            "targetRows": len(found), "zeroValues": sum(v == 0 for v in found.values()),
            "negativeValues": sum(v < 0 for v in found.values()),
            "scenarioCounts": dict(Counter(row["members"]["Scenario"] for row in expected)),
            "sortedCoordinateValueDigest": sha256(canonical([
                [key, format(found[key], ".8f")] for key in sorted(found)]).encode()).hexdigest()}


def save_rows(path, rows):
    with path.open("xb") as stream:
        with gzip.GzipFile(fileobj=stream, mode="wb", filename="", mtime=0) as zipped:
            for row in rows:
                zipped.write((canonical(row) + "\n").encode())
    return {"bytes": path.stat().st_size, "sha256": sha256(path.read_bytes()).hexdigest(),
            "rows": len(rows)}


def prepare(manifest_path, expected_sha256, output):
    manifest, _, _ = load_packet(manifest_path, expected_sha256)
    root = manifest_path.parent
    with gzip.open(root / "source/accepted-facts.json.gz", "rt", encoding="utf-8") as stream:
        registry = json.load(stream, parse_float=str)["facts"]
    numeric, provenance = source_rows(table_rows(root, manifest, "FactFinancial"), registry)
    for row in provenance:
        row["value"]["sourceRevision"] = manifest["sourceRevision"]
        row["value"]["sourcePacketManifestSha256"] = expected_sha256
        if len(canonical(row["value"]).encode()) > 100000:
            raise ValueError("PROVENANCE_RECORD_TOO_LARGE")
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    files = {"numeric.ndjson.gz": save_rows(output / "numeric.ndjson.gz", numeric),
             "provenance.ndjson.gz": save_rows(output / "provenance.ndjson.gz", provenance)}
    result = {"format": "openepm-aicompanies-cube-payload-v1",
              "sourcePacketManifestSha256": expected_sha256,
              "sourcePacketManifest": str(manifest_path.resolve()),
              "sourceRevision": manifest["sourceRevision"],
              "axisMapping": {key: target for key, _, target in AXES},
              "valueMember": VALUE_MEMBER, "files": files,
              "sourceRows": len(numeric),
              "scenarioCounts": dict(Counter(row["members"]["Scenario"] for row in numeric)),
              "targetMutationPerformed": False}
    (output / "manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--source-manifest-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = prepare(args.source_manifest, args.source_manifest_sha256, args.output)
    print(json.dumps({key: result[key] for key in ("sourceRows", "scenarioCounts", "targetMutationPerformed")}))


if __name__ == "__main__":
    main()
