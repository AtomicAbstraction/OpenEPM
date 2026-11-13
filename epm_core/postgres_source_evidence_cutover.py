"""Governed one-time cutover from frozen generic source context."""
from __future__ import annotations

import base64
import binascii
from collections import Counter, defaultdict
from hashlib import sha256
import hmac
import json
import time

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .dimensional_security_policy import AccessKind
from .operation_admission_contract import is_signed_operation_id
from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_calculation_impact import object_impact, record_calculation_impact
from .postgres_connection import connect_postgres
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .postgres_source_evidence import PostgresSourceEvidence
from .source_evidence_legacy_mapping import (
    COLLECTIONS, DOCUMENT_NODE_FORMAT, canonical, document_descriptor,
    map_record,
)


PREVIEW = "source.evidence.generic.cutover.preview"
APPLY = "source.evidence.generic.cutover.apply"
FUNCTIONS = frozenset((PREVIEW, APPLY))
EXPECTED_NAMES = frozenset(("Observation context", "Source model",
                            "Source records"))
NAME_COLLECTIONS = {
    "Observation context": "observation-context",
    "Source model": "source-model",
    "Source records": "source-records",
}
TOKEN_TTL = 900


def catalog() -> dict:
    return {
        PREVIEW: {"mode": "read", "permission": "admin",
            "previewRequired": False, "idempotencyRequired": False,
            "workClass": "medium", "arguments": {},
            "result": "exact recognized-source manifest and signed cutover preview"},
        APPLY: {"mode": "atomic_write", "permission": "admin",
            "previewRequired": True, "idempotencyRequired": True,
            "workClass": "medium", "arguments": {
                "previewToken": "exact unexpired cutover preview",
                "expectedMetadataRevision": "preview metadata revision",
                "expectedDataRevision": "preview data revision"},
            "result": "typed reconciliation and physical legacy retirement receipt"},
    }


def _program(raw: object, function: str) -> dict:
    fields = set() if function == PREVIEW else {
        "previewToken", "expectedMetadataRevision", "expectedDataRevision"}
    if (not isinstance(raw, dict)
            or set(raw) != {"languageVersion", "function", "arguments"}
            or raw.get("languageVersion") != 2
            or raw.get("function") != function
            or not isinstance(raw.get("arguments"), dict)
            or set(raw["arguments"]) != fields):
        raise ValueError("SOURCE_EVIDENCE_CUTOVER_PROGRAM_INVALID")
    return raw["arguments"]


class PostgresSourceEvidenceCutover:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 preview_secret: bytes):
        if (not isinstance(dsn, str) or not dsn
                or not isinstance(identity, VerifiedIdentity)
                or not isinstance(preview_secret, bytes)
                or len(preview_secret) < 32):
            raise ValueError("SOURCE_EVIDENCE_CUTOVER_TRUSTED_INPUT_REQUIRED")
        self.dsn, self.identity = dsn, identity
        self.preview_secret = preview_secret

    def _pack(self, value: dict) -> str:
        raw = canonical(value).encode("utf-8")
        return base64.urlsafe_b64encode(raw + hmac.new(
            self.preview_secret, raw, sha256).digest()).decode("ascii")

    def _unpack(self, token: object, scope: ApplicationScope) -> dict:
        try:
            if not isinstance(token, str) or not 1 <= len(token) <= 32768:
                raise ValueError()
            packed = base64.b64decode(token, altchars=b"-_", validate=True)
            raw, signature = packed[:-32], packed[-32:]
            if not hmac.compare_digest(signature, hmac.new(
                    self.preview_secret, raw, sha256).digest()):
                raise ValueError()
            value = json.loads(raw)
            if (not isinstance(value, dict)
                    or set(value) != {"format", "scope", "identity",
                                     "metadataRevision", "dataRevision",
                                     "manifestDigest", "expires"}
                    or value["format"] != "openepm-source-evidence-cutover-preview-v1"
                    or value["scope"] != [scope.workspace_id,
                                           scope.application_id]
                    or value["identity"] != [self.identity.issuer,
                                              self.identity.subject_id]
                    or type(value["metadataRevision"]) is not int
                    or type(value["dataRevision"]) is not int
                    or not isinstance(value["manifestDigest"], str)
                    or len(value["manifestDigest"]) != 64
                    or type(value["expires"]) is not int
                    or value["expires"] <= time.time()):
                raise ValueError()
            return value
        except (ValueError, TypeError, KeyError, UnicodeError,
                binascii.Error, json.JSONDecodeError) as error:
            raise ValueError("SOURCE_EVIDENCE_CUTOVER_PREVIEW_INVALID") from error

    @staticmethod
    def _rows(db, scope: ApplicationScope, generation: int):
        cursor = db.cursor()
        cursor.execute("""SELECT g.table_id,t.name,g.series_key,g.value,
                g.change_id,g.last_revision
            FROM epm.generic_fact_projection g JOIN epm.generic_fact_table t
              USING(workspace_id,application_id,table_id)
            WHERE g.workspace_id=%s AND g.application_id=%s
              AND g.projection_generation=%s AND t.status<>'Deleted'
            ORDER BY g.table_id,g.series_key""",
            (scope.workspace_id, scope.application_id, generation))
        while True:
            batch = cursor.fetchmany(500)
            if not batch:
                return
            yield from batch

    def _snapshot(self, db, scope: ApplicationScope, state: dict) -> dict:
        tables = db.execute("""SELECT table_id,name,status
            FROM epm.generic_fact_table WHERE workspace_id=%s
              AND application_id=%s AND status<>'Deleted' ORDER BY name""",
            (scope.workspace_id, scope.application_id)).fetchall()
        if (len(tables) != 3 or {row["name"] for row in tables} != EXPECTED_NAMES
                or any(row["status"] != "Active" for row in tables)):
            raise ValueError("SOURCE_EVIDENCE_CUTOVER_SOURCE_TABLE_SET_INVALID")
        if db.execute("""SELECT 1 FROM epm.generic_fact_projection
            WHERE workspace_id=%s AND application_id=%s
              AND projection_generation<>%s LIMIT 1""",
            (scope.workspace_id, scope.application_id,
             state["active_projection_generation"])).fetchone():
            raise ValueError("SOURCE_EVIDENCE_CUTOVER_STAGED_LEGACY_STATE")
        if db.execute("""SELECT 1 FROM epm.source_evidence_collection
            WHERE workspace_id=%s AND application_id=%s LIMIT 1""",
            (scope.workspace_id, scope.application_id)).fetchone():
            raise ValueError("SOURCE_EVIDENCE_CUTOVER_TARGET_NOT_EMPTY")
        digest = sha256()
        counts = Counter()
        document_rows = defaultdict(list)
        observation_coordinates = []
        rows = 0
        for row in self._rows(db, scope, state["active_projection_generation"]):
            descriptor = map_record(table_id=row["table_id"],
                series_key=row["series_key"], value=row["value"],
                change_id=row["change_id"], last_revision=row["last_revision"])
            if descriptor["collectionId"] != NAME_COLLECTIONS[row["name"]]:
                raise ValueError("SOURCE_EVIDENCE_CUTOVER_SOURCE_FORMAT_INVALID")
            digest.update((canonical({"tableId": row["table_id"],
                "seriesKey": row["series_key"], "changeId": row["change_id"],
                "lastRevision": row["last_revision"],
                "legacyValueDigest": descriptor["legacyValueDigest"]}) + "\n").encode())
            counts[descriptor["collectionId"]] += 1
            rows += 1
            if descriptor["documentId"] is not None:
                document_rows[descriptor["documentId"]].append(descriptor)
            if descriptor["observationMembers"]:
                observation_coordinates.append(descriptor["observationMembers"])
        if rows == 0:
            raise ValueError("SOURCE_EVIDENCE_CUTOVER_SOURCE_EMPTY")
        documents = [document_descriptor(document_rows[key], key)
                     for key in sorted(document_rows)]
        event_count = db.execute("""SELECT count(*) count
            FROM epm.generic_fact_event WHERE workspace_id=%s
              AND application_id=%s""",
            (scope.workspace_id, scope.application_id)).fetchone()["count"]
        manifest = {"format": "openepm-source-evidence-cutover-manifest-v1",
            "tables": [{"tableId": row["table_id"], "name": row["name"]}
                       for row in tables],
            "sourceRows": rows, "sourceEvents": event_count,
            "collectionCounts": dict(sorted(counts.items())),
            "documents": documents, "sourceDigest": digest.hexdigest(),
            "metadataRevision": state["metadata_revision"],
            "dataRevision": state["data_revision"],
            "activeProjectionGeneration": state["active_projection_generation"]}
        manifest["manifestDigest"] = _canonical_digest(manifest)
        return {"manifest": manifest,
                "observationCoordinates": observation_coordinates}

    def preview(self, scope: ApplicationScope, program: dict) -> dict:
        _program(program, PREVIEW)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY")
                configure_statement_timeout(db, 120000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "admin")
                state = db.execute("""SELECT metadata_revision,data_revision,
                    active_projection_generation FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s""",
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                snapshot = self._snapshot(db, scope, state)
        manifest = snapshot["manifest"]
        token = self._pack({"format": "openepm-source-evidence-cutover-preview-v1",
            "scope": [scope.workspace_id, scope.application_id],
            "identity": [self.identity.issuer, self.identity.subject_id],
            "metadataRevision": state["metadata_revision"],
            "dataRevision": state["data_revision"],
            "manifestDigest": manifest["manifestDigest"],
            "expires": int(time.time()) + TOKEN_TTL})
        return {"manifest": manifest, "previewToken": token}

    def apply(self, scope: ApplicationScope, program: dict, *,
              idempotency_key: str) -> dict:
        args = _program(program, APPLY)
        if not is_signed_operation_id(idempotency_key):
            raise ValueError("OPERATION_ADMISSION_REQUIRED")
        expected_metadata = args["expectedMetadataRevision"]
        expected_data = args["expectedDataRevision"]
        if (type(expected_metadata) is not int or expected_metadata < 0
                or type(expected_data) is not int or expected_data < 0):
            raise ValueError("SOURCE_EVIDENCE_CUTOVER_REVISION_INVALID")
        preview = self._unpack(args["previewToken"], scope)
        command_digest = _canonical_digest(program)
        keys = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 120000)
                PostgresNumericFactStore._set_scope(db, scope)
                state = db.execute("""SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.commit_revision,
                    s.active_projection_generation FROM epm.application_state s
                    JOIN epm.application a USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s""",
                    keys).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "admin")
                prior = db.execute("""SELECT command_digest,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                      AND application_id=%s AND operation_id=%s""",
                    (*keys, idempotency_key)).fetchone()
                if prior:
                    if prior["command_digest"] != command_digest:
                        raise ValueError("SOURCE_EVIDENCE_CUTOVER_IDEMPOTENCY_CONFLICT")
                    PostgresNumericFactStore._require_replay_impact(
                        db, scope, idempotency_key, prior)
                    return {**prior["result"], "duplicate": True}
                if state["status"] != "Active" or state["processing_mode"] != "Active":
                    raise ValueError("APPLICATION_NOT_WRITABLE")
                if (state["metadata_revision"] != expected_metadata
                        or state["data_revision"] != expected_data
                        or preview["metadataRevision"] != expected_metadata
                        or preview["dataRevision"] != expected_data):
                    raise ValueError("SOURCE_EVIDENCE_CUTOVER_REVISION_STALE")
                snapshot = self._snapshot(db, scope, state)
                manifest = snapshot["manifest"]
                if preview["manifestDigest"] != manifest["manifestDigest"]:
                    raise ValueError("SOURCE_EVIDENCE_CUTOVER_SOURCE_CHANGED")
                authorize_coordinates(db, self.identity, scope,
                    (Coordinate.from_mapping(item)
                     for item in snapshot["observationCoordinates"]),
                    kind=AccessKind.WRITE)
                revision = state["metadata_revision"] + 1
                commit = state["commit_revision"] + 1
                impact = object_impact(source_kind="metadata",
                    operation_id=idempotency_key, causal_revision=commit,
                    domain="application", object_type="source-evidence-cutover",
                    object_id=manifest["manifestDigest"], change="replace",
                    reason="definition_changed", old_presence="present",
                    new_presence="present")
                expected_retirement = {"manifestDigest": manifest["manifestDigest"],
                    "sourceRecords": manifest["sourceRows"],
                    "typedRecords": manifest["sourceRows"],
                    "retiredEvents": manifest["sourceEvents"],
                    "retiredProjections": manifest["sourceRows"],
                    "retiredTables": 3}
                result = {"function": APPLY, "operationId": idempotency_key,
                    "metadataRevision": revision, "committedRevision": commit,
                    "manifest": manifest, "retirement": expected_retirement,
                    "impactDigest": impact.digest}
                db.execute("""INSERT INTO epm.operation_receipt(
                    workspace_id,application_id,operation_id,command_digest,
                    actor_id,committed_revision,result)
                    VALUES(%s,%s,%s,%s,%s,%s,%s)""",
                    (*keys, idempotency_key, command_digest,
                     self.identity.subject_id, commit, Jsonb(result)))
                for contract in COLLECTIONS.values():
                    payload = {key: contract[key] for key in
                        ("collectionId", "name", "collectionKind", "description")}
                    token = PostgresSourceEvidence._state_token(
                        "source.evidence.collection.save", payload)
                    db.execute("""INSERT INTO epm.source_evidence_collection(
                        workspace_id,application_id,collection_id,name,collection_kind,
                        description,state_token,metadata_revision,updated_issuer,
                        updated_subject_id,updated_operation_id)
                        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (*keys, payload["collectionId"], payload["name"],
                         payload["collectionKind"], payload["description"], token,
                         revision, self.identity.issuer, self.identity.subject_id,
                         idempotency_key))
                for document in manifest["documents"]:
                    payload = {key: document[key] for key in (
                        "collectionId", "documentId", "title", "mediaType",
                        "sourceUri", "sourceRevision", "contentDigest")}
                    token = PostgresSourceEvidence._state_token(
                        "source.evidence.document.save", payload)
                    db.execute("""INSERT INTO epm.source_evidence_document(
                        workspace_id,application_id,collection_id,document_id,title,
                        media_type,source_uri,source_revision,content_digest,state_token,
                        metadata_revision,updated_issuer,updated_subject_id,
                        updated_operation_id) VALUES
                        (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (*keys, payload["collectionId"], payload["documentId"],
                         payload["title"], payload["mediaType"], payload["sourceUri"],
                         payload["sourceRevision"], payload["contentDigest"], token,
                         revision, self.identity.issuer, self.identity.subject_id,
                         idempotency_key))
                insert = db.cursor()
                pending = []
                for row in self._rows(db, scope, state["active_projection_generation"]):
                    descriptor = map_record(table_id=row["table_id"],
                        series_key=row["series_key"], value=row["value"],
                        change_id=row["change_id"], last_revision=row["last_revision"])
                    payload = {key: descriptor[key] for key in (
                        "collectionId", "recordId", "recordType", "documentId",
                        "observationMembers", "sourcePointer", "properties")}
                    payload["contentDigest"] = _canonical_digest(payload)
                    token = PostgresSourceEvidence._state_token(
                        "source.evidence.record.save", payload)
                    pending.append((*keys, payload["collectionId"],
                        payload["recordId"], payload["recordType"],
                        payload["documentId"], Jsonb(payload["observationMembers"]),
                        Jsonb(payload["sourcePointer"]), Jsonb(payload["properties"]),
                        payload["contentDigest"], token, revision,
                        self.identity.issuer, self.identity.subject_id,
                        idempotency_key))
                    if len(pending) == 500:
                        insert.executemany("""INSERT INTO epm.source_evidence_record(
                            workspace_id,application_id,collection_id,record_id,record_type,
                            document_id,observation_members,source_pointer,properties,
                            content_digest,state_token,metadata_revision,updated_issuer,
                            updated_subject_id,updated_operation_id) VALUES
                            (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                            pending)
                        pending.clear()
                if pending:
                    insert.executemany("""INSERT INTO epm.source_evidence_record(
                        workspace_id,application_id,collection_id,record_id,record_type,
                        document_id,observation_members,source_pointer,properties,
                        content_digest,state_token,metadata_revision,updated_issuer,
                        updated_subject_id,updated_operation_id) VALUES
                        (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        pending)
                # Deferred receipt/provenance checks are forced inside the
                # owner-only retirement boundary. Publish the already locked
                # state first so those checks observe the same atomic commit;
                # any later mismatch still rolls the entire transaction back.
                db.execute("""UPDATE epm.application_state SET
                    metadata_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s""",
                    (revision, commit, *keys))
                retired = db.execute("""SELECT
                    epm.retire_migrated_generic_source_evidence(%s,%s,%s,%s) result""",
                    (*keys, idempotency_key,
                     manifest["manifestDigest"])).fetchone()["result"]
                if retired != expected_retirement:
                    raise ValueError("SOURCE_EVIDENCE_CUTOVER_RETIREMENT_MISMATCH")
                record_calculation_impact(db, scope,
                    operation_id=idempotency_key, impact=impact)
                return {**result, "duplicate": False}
