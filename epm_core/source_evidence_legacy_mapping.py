"""Exact mapping from the retired frozen generic source context.

This module recognizes only the three import formats produced by the reviewed
AIcompanies import. It preserves each JSON value byte-semantically through a
canonical typed envelope while promoting object identity, observation grain,
document identity and JSON Pointer into the fixed source-evidence model.
Unknown formats fail closed; this is not a generic-table compatibility layer.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Iterable

from .postgres_source_evidence import _json, _members, _pointer


OBSERVATION_FORMAT = "openepm-imported-observation-context-v1"
SOURCE_RECORD_FORMAT = "openepm-imported-source-record-v1"
DOCUMENT_NODE_FORMAT = "openepm-imported-source-document-v1"
SUPPORTED_FORMATS = frozenset((OBSERVATION_FORMAT, SOURCE_RECORD_FORMAT,
                               DOCUMENT_NODE_FORMAT))
COLLECTIONS = {
    OBSERVATION_FORMAT: {
        "collectionId": "observation-context",
        "name": "Observation context",
        "collectionKind": "ObservationContext",
        "description": "Frozen source units, qualifiers, evidence and lineage for imported numeric observations.",
        "recordType": "ImportedObservationContext",
    },
    SOURCE_RECORD_FORMAT: {
        "collectionId": "source-records",
        "name": "Source records",
        "collectionKind": "SourceRecords",
        "description": "Frozen non-fact source tables, reviews, comparisons and metadata.",
        "recordType": "ImportedSourceRecord",
    },
    DOCUMENT_NODE_FORMAT: {
        "collectionId": "source-model",
        "name": "Source model",
        "collectionKind": "SourceModel",
        "description": "Frozen original JSON model documents and dimensional semantics.",
        "recordType": "ImportedSourceDocumentNode",
    },
}
_RECORD_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_DOCUMENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def canonical(value: object) -> str:
    """Use the import's exact deterministic JSON representation."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def _required_text(value: object, maximum: int, error: str) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= maximum
            or value != value.strip()
            or any(ord(character) < 32 or ord(character) == 127
                   for character in value)):
        raise ValueError(error)
    return value


def _record_id(series_key: object) -> str:
    if not isinstance(series_key, str) or not series_key:
        raise ValueError("SOURCE_EVIDENCE_LEGACY_SERIES_KEY_INVALID")
    if _RECORD_ID.fullmatch(series_key):
        return series_key
    return "legacy:" + sha256(series_key.encode("utf-8")).hexdigest()


def map_record(*, table_id: object, series_key: object, value: object,
               change_id: object, last_revision: object) -> dict:
    """Promote one recognized frozen generic value into a typed descriptor."""
    table = _required_text(table_id, 200,
                           "SOURCE_EVIDENCE_LEGACY_TABLE_ID_INVALID")
    change = _required_text(change_id, 200,
                            "SOURCE_EVIDENCE_LEGACY_CHANGE_ID_INVALID")
    if type(last_revision) is not int or last_revision < 1:
        raise ValueError("SOURCE_EVIDENCE_LEGACY_REVISION_INVALID")
    normalized = _json(value)
    if not isinstance(normalized, dict) or normalized.get("format") not in SUPPORTED_FORMATS:
        raise ValueError("SOURCE_EVIDENCE_LEGACY_FORMAT_UNSUPPORTED")
    source_format = normalized["format"]
    contract = COLLECTIONS[source_format]
    record_id = _record_id(series_key)
    declared_id = normalized.get("recordId")
    if source_format != DOCUMENT_NODE_FORMAT and declared_id != series_key:
        raise ValueError("SOURCE_EVIDENCE_LEGACY_IDENTITY_MISMATCH")
    members = (_members(normalized.get("members"))
               if source_format == OBSERVATION_FORMAT else {})
    document_id = None
    source_pointer = {}
    if source_format == DOCUMENT_NODE_FORMAT:
        document_id = _required_text(normalized.get("document"), 200,
            "SOURCE_EVIDENCE_LEGACY_DOCUMENT_INVALID")
        if not _DOCUMENT_ID.fullmatch(document_id):
            raise ValueError("SOURCE_EVIDENCE_LEGACY_DOCUMENT_INVALID")
        pointer = normalized.get("pointer")
        if not isinstance(pointer, str):
            raise ValueError("SOURCE_EVIDENCE_LEGACY_POINTER_INVALID")
        source_pointer = _pointer({"jsonPointer": pointer})
    properties = {
        "legacySource": {"tableId": table, "seriesKey": series_key,
                         "changeId": change,
                         "lastRevision": last_revision},
        "sourceValue": normalized,
    }
    return {
        "collectionId": contract["collectionId"],
        "recordId": record_id,
        "recordType": contract["recordType"],
        "documentId": document_id,
        "observationMembers": members,
        "sourcePointer": source_pointer,
        "properties": properties,
        "legacyValueDigest": sha256(canonical(normalized).encode("utf-8")).hexdigest(),
    }


def restore_document(records: Iterable[dict], document_id: str) -> object:
    """Reconstruct one exact source document and reject missing/orphan nodes."""
    document = _required_text(document_id, 200,
                              "SOURCE_EVIDENCE_LEGACY_DOCUMENT_INVALID")
    nodes: dict[str, dict] = {}
    for descriptor in records:
        if (not isinstance(descriptor, dict)
                or descriptor.get("documentId") != document
                or descriptor.get("recordType") !=
                    COLLECTIONS[DOCUMENT_NODE_FORMAT]["recordType"]):
            raise ValueError("SOURCE_EVIDENCE_DOCUMENT_IDENTITY_MISMATCH")
        value = descriptor.get("properties", {}).get("sourceValue")
        if (not isinstance(value, dict)
                or value.get("format") != DOCUMENT_NODE_FORMAT
                or value.get("document") != document):
            raise ValueError("SOURCE_EVIDENCE_DOCUMENT_IDENTITY_MISMATCH")
        pointer = value.get("pointer")
        if not isinstance(pointer, str) or pointer in nodes:
            raise ValueError("SOURCE_EVIDENCE_DOCUMENT_POINTER_INVALID")
        nodes[pointer] = value
    if "" not in nodes:
        raise ValueError("SOURCE_EVIDENCE_DOCUMENT_ROOT_MISSING")
    consumed: set[str] = set()

    def visit(pointer: str) -> object:
        node = nodes[pointer]
        consumed.add(pointer)
        kind = node.get("kind")
        if kind == "value":
            if "value" not in node:
                raise ValueError("SOURCE_EVIDENCE_DOCUMENT_VALUE_MISSING")
            return node["value"]
        count = node.get("count")
        if type(count) is not int or count < 0 or kind not in {"array", "object"}:
            raise ValueError("SOURCE_EVIDENCE_DOCUMENT_CONTAINER_INVALID")
        prefix = pointer + "/"
        children = {candidate[len(prefix):]: candidate for candidate in nodes
                    if candidate.startswith(prefix)
                    and "/" not in candidate[len(prefix):]}
        if len(children) != count:
            raise ValueError("SOURCE_EVIDENCE_DOCUMENT_CHILD_COVERAGE_MISMATCH")
        if kind == "array":
            expected = {str(index) for index in range(count)}
            if set(children) != expected:
                raise ValueError("SOURCE_EVIDENCE_DOCUMENT_ARRAY_INDEX_INVALID")
            return [visit(children[str(index)]) for index in range(count)]
        return {key.replace("~1", "/").replace("~0", "~"):
                visit(child) for key, child in children.items()}

    restored = visit("")
    if consumed != set(nodes):
        raise ValueError("SOURCE_EVIDENCE_DOCUMENT_ORPHAN_NODE")
    return restored


def document_descriptor(records: Iterable[dict], document_id: str) -> dict:
    """Derive the immutable document identity and digest from exact nodes."""
    rows = list(records)
    restored = restore_document(rows, document_id)
    revisions = {row["properties"]["sourceValue"].get("sourceRevision")
                 for row in rows}
    if len(revisions) != 1:
        raise ValueError("SOURCE_EVIDENCE_DOCUMENT_REVISION_MISMATCH")
    revision = _required_text(revisions.pop(), 500,
        "SOURCE_EVIDENCE_DOCUMENT_REVISION_INVALID")
    return {
        "collectionId": COLLECTIONS[DOCUMENT_NODE_FORMAT]["collectionId"],
        "documentId": document_id,
        "title": document_id.replace("-", " ").title(),
        "mediaType": "application/json",
        "sourceUri": "",
        "sourceRevision": revision,
        "contentDigest": sha256(canonical(restored).encode("utf-8")).hexdigest(),
        "recordCount": len(rows),
    }
