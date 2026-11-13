"""Prepare bounded source context for the existing generic-fact public API.

These are frozen source records and semantic context, not another executable
model. Native metadata and numeric cube values remain the application truth.
This offline helper performs no target operation or authentication.
"""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
from hashlib import sha256
import json
from pathlib import Path

try:
    from scripts.aicompanies_cube_payload import save_rows, table_rows
    from scripts.aicompanies_mcp_journey import canonical, load_packet
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from aicompanies_cube_payload import save_rows, table_rows
    from aicompanies_mcp_journey import canonical, load_packet

DOCUMENTS = ("model", "dimension-schema", "hierarchies", "comparisons", "identities", "owner-manifest")


def pointer_part(value):
    return str(value).replace("~", "~0").replace("/", "~1")


def document_records(name, value, binding, *, max_bytes=80000):
    """Split only oversized JSON containers; retain unambiguous JSON pointers."""
    result = []

    def visit(item, pointer):
        record = {"format": "openepm-imported-source-document-v1", **binding,
                  "document": name, "pointer": pointer, "kind": "value", "value": item,
                  "numericJsonEncoding": "Fractional JSON numbers are exact decimal strings"}
        if len(canonical(record).encode()) > max_bytes:
            record.pop("value")
            if isinstance(item, dict):
                record.update(kind="object", count=len(item))
                children = item.items()
            elif isinstance(item, list):
                record.update(kind="array", count=len(item))
                children = enumerate(item)
            else:
                raise ValueError("SOURCE_DOCUMENT_SCALAR_TOO_LARGE")
            if len(canonical(record).encode()) > max_bytes:
                raise ValueError("SOURCE_DOCUMENT_PATH_TOO_LARGE")
        else:
            children = ()
        result.append({"seriesKey": name + ":" + sha256(pointer.encode()).hexdigest(),
                       "value": record})
        for key, child in children:
            visit(child, pointer + "/" + pointer_part(key))

    visit(value, "")
    return result


def restore_document(rows, name):
    """Independently reconstruct split context and reject missing/extra nodes."""
    nodes = {}
    for row in rows:
        record = row["value"]
        if record["document"] != name:
            raise ValueError("DOCUMENT_IDENTITY_MISMATCH")
        pointer = record["pointer"]
        if pointer in nodes:
            raise ValueError("DOCUMENT_DUPLICATE_POINTER")
        nodes[pointer] = record
    consumed = set()

    def visit(pointer):
        record = nodes[pointer]
        consumed.add(pointer)
        if record["kind"] == "value":
            return record["value"]
        prefix = pointer + "/"
        children = {p[len(prefix):]: p for p in nodes
                    if p.startswith(prefix) and "/" not in p[len(prefix):]}
        if len(children) != record["count"]:
            raise ValueError("DOCUMENT_CHILD_COVERAGE_MISMATCH")
        if record["kind"] == "array":
            if set(children) != {str(i) for i in range(record["count"])}:
                raise ValueError("DOCUMENT_ARRAY_INDEX_INVALID")
            return [visit(children[str(i)]) for i in range(record["count"])]
        if record["kind"] != "object":
            raise ValueError("DOCUMENT_NODE_KIND_INVALID")
        return {key.replace("~1", "/").replace("~0", "~"): visit(child)
                for key, child in children.items()}

    result = visit("")
    if consumed != set(nodes):
        raise ValueError("DOCUMENT_ORPHAN_NODE")
    return result


def bounded_batches(rows, *, max_rows=100, max_value_bytes=350000):
    """Follow actual generic.bulk count and UTF-8 value budgets."""
    seen, batch, size = set(), [], 0
    for row in rows:
        key = row["seriesKey"]
        value = row["value"]
        encoded = canonical(value)
        value_size = len(encoded.encode())
        if (not isinstance(key, str) or not 1 <= len(key) <= 1000 or key != key.strip()
                or key in seen or value is None or len(encoded) > 100000
                or value_size > max_value_bytes):
            raise ValueError("GENERIC_RECORD_INVALID_OR_TOO_LARGE")
        seen.add(key)
        if batch and (len(batch) == max_rows or size + value_size > max_value_bytes):
            yield batch
            batch, size = [], 0
        batch.append({"action": "Set", "seriesKey": key, "value": value, "expectedChangeId": ""})
        size += value_size
    if batch:
        yield batch


def prepare(manifest_path, expected_sha256, output):
    manifest, _, _ = load_packet(manifest_path, expected_sha256)
    root = manifest_path.parent
    binding = {"sourceRevision": manifest["sourceRevision"],
               "sourcePacketManifestSha256": expected_sha256}
    records = []
    for table in manifest["tables"]:
        if table == "FactFinancial":
            continue
        for row in table_rows(root, manifest, table):
            records.append({"seriesKey": row["recordId"], "value": {
                "format": "openepm-imported-source-record-v1", **binding, **row,
                "usage": "Source context; never an additional accepted cube observation"}})
    model = []
    document_digests = {}
    for name in DOCUMENTS:
        with gzip.open(root / f"source/{name}.json.gz", "rt", encoding="utf-8") as stream:
            document = json.load(stream, parse_float=str)
        rows = document_records(name, document, binding)
        if restore_document(rows, name) != document:
            raise ValueError("SOURCE_DOCUMENT_RECONSTRUCTION_MISMATCH")
        model.extend(rows)
        document_digests[name] = sha256(canonical(document).encode()).hexdigest()
    # Validate every record against public size/key limits before writing output.
    batch_counts = {"source-records": sum(1 for _ in bounded_batches(records)),
                    "source-model": sum(1 for _ in bounded_batches(model))}
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    files = {"source-records.ndjson.gz": save_rows(output / "source-records.ndjson.gz", records),
             "source-model.ndjson.gz": save_rows(output / "source-model.ndjson.gz", model)}
    result = {"format": "openepm-aicompanies-support-payload-v1", **binding,
              "sourcePacketManifest": str(manifest_path.resolve()), "files": files,
              "sourceTableCounts": dict(Counter(row["value"]["table"] for row in records)),
              "documentCanonicalDigests": document_digests, "batchCounts": batch_counts,
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
    print(json.dumps({"files": result["files"], "batchCounts": result["batchCounts"],
                      "targetMutationPerformed": False}))


if __name__ == "__main__":
    main()
