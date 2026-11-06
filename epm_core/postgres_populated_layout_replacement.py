"""Durable private staging for populated layout replacement.

Acceptance is administrator-only and stores the exact preview and plan
identities. Workers can only create private staged rows through lease-fenced
database functions. This module intentionally has no activation operation.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .populated_layout_mapping import (
    LayoutPins, PopulatedLayoutPlan, SourceCoordinate,
    compile_populated_layout_plan,
)
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_populated_layout_preview import PostgresPopulatedLayoutPreview
from .postgres_processing_limits import configure_lock_wait, configure_statement_timeout


_KEY = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
MAX_PLAN_BYTES = 32 * 1024 * 1024
REQUEST = "metadata.layout.populated.replace.request"
READ = "metadata.layout.populated.replace.read"
CANCEL = "metadata.layout.populated.replace.cancel"
PUBLIC_FUNCTIONS = frozenset((REQUEST, READ, CANCEL))


def _digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def _validated_plan(document: object) -> PopulatedLayoutPlan:
    try:
        if (not isinstance(document, dict) or document.get("format") not in
                ("openepm-populated-layout-plan-v1",
                 "openepm-populated-layout-plan-v2")):
            raise ValueError("shape")
        pins = document["pins"]
        compiled = compile_populated_layout_plan(
            pins=LayoutPins(pins["metadataRevision"], pins["dataRevision"],
                            pins["policyRevision"], pins["schemaEpoch"],
                            pins["sourceCommitRevision"]),
            source_axes=document["sourceAxes"], target_axes=document["targetAxes"],
            axis_mapping=document["axisMapping"],
            source_coordinates=[SourceCoordinate(
                row["sourceCoordinateId"], row["sourceMembers"])
                for row in document["coordinateMappings"]],
            coordinate_mappings=document["coordinateMappings"],
            target_metadata=document.get("targetMetadata"))
        if compiled.to_wire() != document:
            raise ValueError("noncanonical")
        if len(compiled.canonical_bytes) > MAX_PLAN_BYTES:
            raise ValueError("size")
        return compiled
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("LAYOUT_REPLACEMENT_PLAN_INVALID") from error


class PostgresPopulatedLayoutReplacements:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError("A PostgreSQL connection string is required")
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("A verified identity is required")
        self.dsn, self.identity = dsn, identity

    def execute(self, scope: ApplicationScope, program: object) -> dict:
        if (not isinstance(program, dict)
                or set(program) != {"languageVersion", "function", "arguments"}
                or type(program.get("languageVersion")) is not int
                or program["languageVersion"] != 2
                or program.get("function") not in PUBLIC_FUNCTIONS
                or not isinstance(program.get("arguments"), dict)):
            raise ValueError("V2_LAYOUT_REPLACEMENT_INVALID")
        function, arguments = program["function"], program["arguments"]
        if function == REQUEST:
            if set(arguments) != {"preview", "plan", "idempotencyKey"}:
                raise ValueError("V2_LAYOUT_REPLACEMENT_INVALID")
            return self.accept(scope, preview=arguments["preview"],
                               plan_document=arguments["plan"],
                               idempotency_key=arguments["idempotencyKey"])
        if function == READ:
            if set(arguments) != {"requestId"}:
                raise ValueError("V2_LAYOUT_REPLACEMENT_INVALID")
            return self.read(scope, arguments["requestId"])
        if set(arguments) != {"requestId", "expectedStatus"}:
            raise ValueError("V2_LAYOUT_REPLACEMENT_INVALID")
        return self.cancel(scope, arguments["requestId"],
                           expected_status=arguments["expectedStatus"])

    def accept(self, scope: ApplicationScope, *, preview: object,
               plan_document: object, idempotency_key: str) -> dict:
        if not isinstance(scope, ApplicationScope) or not isinstance(preview, dict):
            raise ValueError("LAYOUT_REPLACEMENT_REQUEST_INVALID")
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(idempotency_key):
            raise ValueError("LAYOUT_REPLACEMENT_REQUEST_INVALID")
        plan = _validated_plan(plan_document)
        if (not isinstance(preview.get("previewDigest"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", preview["previewDigest"])
                or preview.get("planDigest") != plan.digest
                or preview.get("pins") != plan_document["pins"]
                or _digest({key: value for key, value in preview.items()
                            if key != "previewDigest"}) != preview["previewDigest"]):
            raise ValueError("LAYOUT_REPLACEMENT_PREVIEW_MISMATCH")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "admin")
                authorization_scope_digest = resolve_effective_dimensional_scope(
                    db, self.identity, scope, access=access,
                    function=REQUEST).scope_digest
                descriptor = {
                    "scope": [scope.workspace_id, scope.application_id],
                    "identity": [self.identity.issuer, self.identity.subject_id],
                    "verifiedGroups": list(self.identity.groups),
                    "authorizationScopeDigest": authorization_scope_digest,
                    "idempotencyKey": idempotency_key,
                    "previewDigest": preview["previewDigest"],
                    "planDigest": plan.digest}
                request_digest = _digest(descriptor)
                prior = db.execute("""SELECT request_id,request_digest,
                    target_generation_id,status,verified_groups,
                    authorization_scope_digest FROM epm.layout_replacement_request
                    WHERE workspace_id=%s AND application_id=%s AND issuer=%s
                    AND subject_id=%s AND idempotency_key=%s""",
                    (scope.workspace_id, scope.application_id,
                     self.identity.issuer, self.identity.subject_id,
                     idempotency_key)).fetchone()
                if prior:
                    if (prior["request_digest"] != request_digest
                            or tuple(prior["verified_groups"]) != self.identity.groups
                            or prior["authorization_scope_digest"] is None
                            or prior["authorization_scope_digest"] !=
                            authorization_scope_digest):
                        raise ValueError("LAYOUT_REPLACEMENT_IDEMPOTENCY_CONFLICT")
                    return {"requestId": prior["request_id"],
                            "targetGenerationId": prior["target_generation_id"],
                            "status": prior["status"], "duplicate": True}
        expected_preview = PostgresPopulatedLayoutPreview(
            self.dsn, identity=self.identity).preview(
                scope, expected_pins=LayoutPins(**{
                    "metadata_revision": plan_document["pins"]["metadataRevision"],
                    "data_revision": plan_document["pins"]["dataRevision"],
                    "policy_revision": plan_document["pins"]["policyRevision"],
                    "schema_epoch": plan_document["pins"]["schemaEpoch"],
                    "source_commit_revision": plan_document["pins"]["sourceCommitRevision"]}),
                target_axes=plan_document["targetAxes"],
                axis_mapping=plan_document["axisMapping"],
                coordinate_mappings=plan_document["coordinateMappings"],
                target_metadata=plan_document.get("targetMetadata"))
        if preview != expected_preview:
            raise ValueError("LAYOUT_REPLACEMENT_PREVIEW_MISMATCH")
        request_id = sha256((request_digest + ":request").encode()).hexdigest()[:32]
        generation_id = sha256((request_digest + ":generation").encode()).hexdigest()[:32]
        pins = plan_document["pins"]
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "admin")
                current_scope_digest = resolve_effective_dimensional_scope(
                    db, self.identity, scope, access=access,
                    function=REQUEST).scope_digest
                if current_scope_digest != authorization_scope_digest:
                    raise ValueError(
                        "LAYOUT_REPLACEMENT_AUTHORIZATION_SCOPE_CHANGED")
                prior = db.execute("""SELECT request_id,request_digest,
                    target_generation_id,status,verified_groups,
                    authorization_scope_digest FROM epm.layout_replacement_request
                    WHERE workspace_id=%s AND application_id=%s AND issuer=%s
                    AND subject_id=%s AND idempotency_key=%s""",
                    (scope.workspace_id, scope.application_id,
                     self.identity.issuer, self.identity.subject_id,
                     idempotency_key)).fetchone()
                if prior:
                    if (prior["request_digest"] != request_digest
                            or tuple(prior["verified_groups"]) != self.identity.groups
                            or prior["authorization_scope_digest"] is None
                            or prior["authorization_scope_digest"] !=
                            current_scope_digest):
                        raise ValueError("LAYOUT_REPLACEMENT_IDEMPOTENCY_CONFLICT")
                    return {"requestId": prior["request_id"],
                            "targetGenerationId": prior["target_generation_id"],
                            "status": prior["status"], "duplicate": True}
                state = db.execute("""SELECT metadata_revision,data_revision,
                    policy_revision,schema_epoch,commit_revision,commit_open
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE""",
                    (scope.workspace_id, scope.application_id)).fetchone()
                actual = {"metadataRevision": state["metadata_revision"],
                          "dataRevision": state["data_revision"],
                          "policyRevision": state["policy_revision"],
                          "schemaEpoch": state["schema_epoch"],
                          "sourceCommitRevision": state["commit_revision"]}
                if state["commit_open"] or actual != pins:
                    raise ValueError("STALE_LAYOUT_PINS")
                db.execute("""INSERT INTO epm.layout_replacement_request
                    (workspace_id,application_id,request_id,issuer,subject_id,
                     idempotency_key,request_digest,preview_digest,plan_digest,plan,
                     metadata_revision,data_revision,policy_revision,schema_epoch,
                     source_commit_revision,target_generation_id,
                     expected_coordinate_count,verified_groups,
                     authorization_scope_digest)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (scope.workspace_id, scope.application_id, request_id,
                     self.identity.issuer, self.identity.subject_id, idempotency_key,
                     request_digest, preview["previewDigest"], plan.digest,
                     Jsonb(plan_document), pins["metadataRevision"],
                     pins["dataRevision"], pins["policyRevision"], pins["schemaEpoch"],
                     pins["sourceCommitRevision"], generation_id,
                     plan_document["sourceCoordinateCount"],
                     list(self.identity.groups), current_scope_digest))
                db.execute("""INSERT INTO epm.layout_replacement_generation
                    (workspace_id,application_id,generation_id,request_id)
                    VALUES(%s,%s,%s,%s)""",
                    (scope.workspace_id, scope.application_id,
                     generation_id, request_id))
        return {"requestId": request_id, "targetGenerationId": generation_id,
                "status": "Accepted", "duplicate": False}

    def read(self, scope: ApplicationScope, request_id: str) -> dict:
        if not isinstance(request_id, str) or not _HEX32.fullmatch(request_id):
            raise ValueError("LAYOUT_REPLACEMENT_REQUEST_INVALID")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "admin")
                authorization_scope_digest = resolve_effective_dimensional_scope(
                    db, self.identity, scope, access=access,
                    function=READ).scope_digest
                row = db.execute("""SELECT r.request_id,r.status,r.preview_digest,
                    r.plan_digest,r.metadata_revision,r.data_revision,r.policy_revision,
                    r.schema_epoch,r.source_commit_revision,r.target_generation_id,
                    r.expected_coordinate_count,r.claim_generation,r.error_code,
                    r.verified_groups,r.authorization_scope_digest,
                    epm.layout_replacement_staged_count(
                     r.workspace_id,r.application_id,r.request_id) AS staged_coordinate_count
                    FROM epm.layout_replacement_request r WHERE r.workspace_id=%s
                    AND r.application_id=%s AND r.request_id=%s""",
                    (scope.workspace_id, scope.application_id, request_id)).fetchone()
                if row is None:
                    raise ValueError("LAYOUT_REPLACEMENT_NOT_FOUND")
                if (tuple(row["verified_groups"]) != self.identity.groups
                        or row["authorization_scope_digest"] is None
                        or row["authorization_scope_digest"] !=
                        authorization_scope_digest):
                    raise ValueError(
                        "LAYOUT_REPLACEMENT_AUTHORIZATION_SCOPE_CHANGED")
                return {"requestId": row["request_id"], "status": row["status"],
                        "previewDigest": row["preview_digest"],
                        "planDigest": row["plan_digest"],
                        "pins": {"metadataRevision": row["metadata_revision"],
                                 "dataRevision": row["data_revision"],
                                 "policyRevision": row["policy_revision"],
                                 "schemaEpoch": row["schema_epoch"],
                                 "sourceCommitRevision": row["source_commit_revision"]},
                        "targetGenerationId": row["target_generation_id"],
                        "expectedCoordinateCount": row["expected_coordinate_count"],
                        "stagedCoordinateCount": row["staged_coordinate_count"],
                        "stateVersion": row["claim_generation"],
                        "errorCode": row["error_code"]}

    def cancel(self, scope: ApplicationScope, request_id: str, *,
               expected_status: str) -> dict:
        if (not isinstance(request_id, str) or not _HEX32.fullmatch(request_id)
                or expected_status not in ("Accepted", "Staging")):
            raise ValueError("LAYOUT_REPLACEMENT_REQUEST_INVALID")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(db, self.identity, scope, "admin")
                pinned = db.execute("""SELECT status FROM epm.layout_replacement_request
                    WHERE workspace_id=%s AND application_id=%s AND request_id=%s""",
                    (scope.workspace_id, scope.application_id, request_id)).fetchone()
                if pinned is None:
                    raise ValueError("LAYOUT_REPLACEMENT_NOT_FOUND")
                if pinned["status"] != expected_status:
                    raise ValueError("LAYOUT_REPLACEMENT_STATE_STALE")
                changed = db.execute("SELECT epm.layout_replacement_cancel(%s,%s,%s) AS changed",
                    (scope.workspace_id, scope.application_id, request_id)).fetchone()["changed"]
                row = db.execute("""SELECT status FROM epm.layout_replacement_request
                    WHERE workspace_id=%s AND application_id=%s AND request_id=%s""",
                    (scope.workspace_id, scope.application_id, request_id)).fetchone()
                if row is None:
                    raise ValueError("LAYOUT_REPLACEMENT_NOT_FOUND")
                if not changed or row["status"] != "Cancelled":
                    raise ValueError("LAYOUT_REPLACEMENT_CANCEL_CONFLICT")
                return {"requestId": request_id, "status": row["status"]}

    def request_cancel_as_task_controller(self, scope: ApplicationScope,
                                          request_id: str) -> dict:
        """Cancel the private build through its native fence as current admin."""
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(request_id, str)
                or not _HEX32.fullmatch(request_id)):
            raise ValueError("LAYOUT_REPLACEMENT_REQUEST_INVALID")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                configure_lock_wait(db)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "admin")
                row = db.execute("""SELECT status
                    FROM epm.layout_replacement_request
                    WHERE workspace_id=%s AND application_id=%s
                    AND request_id=%s""",
                    (scope.workspace_id, scope.application_id,
                     request_id)).fetchone()
                if row is None:
                    raise ValueError("LAYOUT_REPLACEMENT_NOT_FOUND")
                if row["status"] == "Cancelled":
                    return {"requestId": request_id, "status": "Cancelled"}
                if row["status"] not in ("Accepted", "Staging"):
                    raise ValueError("LAYOUT_REPLACEMENT_STATE_STALE")
                changed = db.execute(
                    "SELECT epm.layout_replacement_cancel(%s,%s,%s) AS changed",
                    (scope.workspace_id, scope.application_id,
                     request_id)).fetchone()["changed"]
                if not changed:
                    raise ValueError("LAYOUT_REPLACEMENT_CANCEL_CONFLICT")
                return {"requestId": request_id, "status": "Cancelled"}


class PostgresPopulatedLayoutReplacementWorker:
    def __init__(self, dsn: str):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError("A PostgreSQL worker connection string is required")
        self.dsn = dsn

    def recover_expired(self) -> int:
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            return db.execute(
                "SELECT epm.layout_replacement_worker_recover() AS changed"
            ).fetchone()["changed"]

    def claim(self, scope: ApplicationScope, request_id: str, *,
              claimant: str, lease_seconds: int = 120) -> dict | None:
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            row = db.execute("""SELECT * FROM epm.layout_replacement_authority_claim
                (%s,%s,%s,%s,%s::integer)""", (scope.workspace_id, scope.application_id,
                request_id, claimant, lease_seconds)).fetchone()
        return dict(row) if row else None

    def stage(self, scope: ApplicationScope, request_id: str, *, claimant: str,
              claim_generation: int, source_coordinate_id: int,
              target_members: dict) -> bool:
        target_digest = _digest(target_members)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            return db.execute("""SELECT epm.layout_replacement_worker_stage
                (%s,%s,%s,%s,%s,%s,%s,%s) AS changed""",
                (scope.workspace_id, scope.application_id, request_id, claimant,
                 claim_generation, source_coordinate_id, Jsonb(target_members),
                 target_digest)).fetchone()["changed"]

    def settle(self, scope: ApplicationScope, request_id: str, *, claimant: str,
               claim_generation: int, outcome: str,
               error_code: str | None = None) -> bool:
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            return db.execute("""SELECT epm.layout_replacement_worker_settle
                (%s,%s,%s,%s,%s,%s,%s) AS changed""",
                (scope.workspace_id, scope.application_id, request_id, claimant,
                 claim_generation, outcome, error_code)).fetchone()["changed"]
