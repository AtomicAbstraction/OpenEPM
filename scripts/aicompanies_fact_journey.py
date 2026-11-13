"""Prepare exact MCP source-staging requests, offline only.

Callers supply acknowledged table/batch identities and current revisions.
The maintained CLI and serial dispatcher own delivery and reconciliation.
"""
from __future__ import annotations

from hashlib import sha256
import gzip
import json
from pathlib import Path
import re

from epm_core.persistence_contract import Coordinate, NumericCell
from scripts.aicompanies_mcp_journey import canonical, contained, verify_file

SCOPE = {"workspace_id": "ws-pilot", "application_id": "AIcompanies"}
SERVER_ID = re.compile(r"[0-9a-f]{32}\Z")


def frame(identity, function, arguments):
    envelope = {**SCOPE, "program": {
        "languageVersion": 2, "function": function, "arguments": arguments}}
    return {"id": identity, "route": "application",
            "tool": "execute_v2_source_program",
            "arguments": envelope}


def load_rows(manifest_path, manifest_sha256, filename):
    raw = manifest_path.read_bytes()
    if sha256(raw).hexdigest() != manifest_sha256:
        raise ValueError("PAYLOAD_MANIFEST_PIN_MISMATCH")
    manifest = json.loads(raw)
    path = contained(manifest_path.parent, filename)
    pin = manifest["files"][filename]
    verify_file(path, {key: pin[key] for key in ("bytes", "sha256")})
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream]
    if len(rows) != pin["rows"]:
        raise ValueError("PAYLOAD_ROW_COUNT_MISMATCH")
    return manifest, rows


def numeric_staging_requests(batch_id, rows, source_schema, *, chunk_size=500):
    if not SERVER_ID.fullmatch(batch_id) or not 1 <= chunk_size <= 500 or not rows:
        raise ValueError("SOURCE_TARGET_BINDING_INVALID")
    requests, chunk_receipts, identities, coordinates = [], [], set(), set()
    content_digest = sha256(b"").hexdigest()
    for index, offset in enumerate(range(0, len(rows), chunk_size)):
        chunk = rows[offset:offset + chunk_size]
        digest_rows = []
        for row in chunk:
            if (set(row) != {"members", "value", "sourceRef"}
                    or set(row["value"]) != {"type", "decimal"}
                    or row["value"]["type"] != "AmountLiteral"
                    or not isinstance(row["sourceRef"], str)
                    or not 1 <= len(row["sourceRef"]) <= 200):
                raise ValueError("SOURCE_NUMERIC_ROW_INVALID")
            coordinate = Coordinate.from_mapping(row["members"])
            if row["sourceRef"] in identities or coordinate.series_key in coordinates:
                raise ValueError("SOURCE_DUPLICATE_IDENTITY_OR_COORDINATE")
            identities.add(row["sourceRef"])
            coordinates.add(coordinate.series_key)
            value = NumericCell.from_wire(present=True, amount=row["value"]["decimal"]).wire_amount()
            digest_rows.append({"series_key": coordinate.series_key,
                "members": dict(coordinate.members), "source_ref": row["sourceRef"], "amount": value})
        chunk_digest = sha256(canonical(digest_rows).encode()).hexdigest()
        content_digest = sha256((content_digest + chunk_digest).encode("ascii")).hexdigest()
        chunk_receipts.append({"batchId": batch_id, "chunkIndex": index,
            "rowCount": offset + len(chunk), "contentDigest": content_digest})
        requests.append(frame(f"aic.cube.append.{index:04}", "facts.source.append", {
            "batchId": batch_id, "chunkIndex": index, "rows": chunk}))
    requests.extend([
        frame("aic.cube.seal", "facts.source.seal", {"batchId": batch_id,
            "expectedRows": len(rows), "expectedContentDigest": content_digest}),
        frame("aic.cube.manifest", "facts.source.manifest.attach", {
            "batchId": batch_id, "requestKey": "aicompanies-cube-manifest-20261109",
            "originKind": "file", "originRef": "AICOmpanies_Financial_Planning_Cube.xlsx#FactFinancial",
            "schemaVersion": "aicompanies-source-observation-v1", "schema": source_schema,
            "contentDigest": content_digest}),
    ])
    return requests, chunk_receipts


def save_requests(path: Path, requests):
    if len({row["id"] for row in requests}) != len(requests):
        raise ValueError("DUPLICATE_REQUEST_ID")
    encoded = "".join(canonical(row) + "\n" for row in requests).encode()
    with path.open("xb") as stream:
        stream.write(encoded)
    path.chmod(0o600)
    return {"requests": len(requests), "bytes": len(encoded), "sha256": sha256(encoded).hexdigest()}
