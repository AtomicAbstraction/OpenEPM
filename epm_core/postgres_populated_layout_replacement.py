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
from psycopg.errors import RaiseException
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .populated_layout_mapping import (
    LayoutPins, PopulatedLayoutPlan, SourceCoordinate,
    compile_populated_layout_plan,
)
from .postgres_access import (PostgresAccessChecker, VerifiedIdentity,
    durable_authority_fields)
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_populated_layout_preview import DEPENDENCY_REFUSALS, PostgresPopulatedLayoutPreview
from .postgres_processing_limits import configure_lock_wait, configure_statement_timeout


_KEY = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
MAX_PLAN_BYTES = 32 * 1024 * 1024
REQUEST = "metadata.layout.populated.replace.request"
READ = "metadata.layout.populated.replace.read"
CANCEL = "metadata.layout.populated.replace.cancel"
PUBLIC_FUNCTIONS = frozenset((REQUEST, READ, CANCEL))
_STATUSES = ("Accepted", "Staging", "Staged", "Validated", "ValidationFailed",
             "Failed", "Cancelled")


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


def _dependency_decisions(value):
    """Normalize only explicit public intent; None is legacy replay, never admission."""
    if value is None:
        return None
    if type(value) is not list or len(value) > 10000:
        raise ValueError("LAYOUT_REPLACEMENT_DEPENDENCY_DECISIONS_INVALID")
    seen = set(); result = []
    for item in value:
        if (type(item) is not dict or set(item) != {"kind", "id", "decision"}
                or item["kind"] not in ("rule", "publication")
                or type(item["id"]) is not str or not 1 <= len(item["id"]) <= 256
                or item["decision"] not in ("Compatible", "Invalidate", "Rebuild")
                or (item["kind"], item["id"]) in seen):
            raise ValueError("LAYOUT_REPLACEMENT_DEPENDENCY_DECISIONS_INVALID")
        seen.add((item["kind"], item["id"]))
        result.append(dict(item))
    result = sorted(result, key=lambda item: (item["kind"], item["id"]))
    # Match the stored JSON text envelope; ordering does not change byte size.
    # Native JSONB also uses a space after each comma/colon and UTF-8 strings.
    try:
        size = len(json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise ValueError("LAYOUT_REPLACEMENT_DEPENDENCY_DECISIONS_INVALID") from error
    if size > 1048576:
        raise ValueError("LAYOUT_REPLACEMENT_DEPENDENCY_DECISIONS_INVALID")
    return result


class PostgresPopulatedLayoutReplacements:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError("A PostgreSQL connection string is required")
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("A verified identity is required")
        self.dsn, self.identity = dsn, identity

    def _existing_request(self, db, scope, idempotency_key, request_digest,
                          access, authorization_scope_digest):
        prior = db.execute("""SELECT request_id,request_digest,
            target_generation_id,status,verified_groups,
            authorization_scope_digest FROM epm.layout_replacement_request
            WHERE workspace_id=%s AND application_id=%s AND issuer=%s
            AND subject_id=%s AND idempotency_key=%s""",
            (scope.workspace_id, scope.application_id, self.identity.issuer,
             self.identity.subject_id, idempotency_key)).fetchone()
        if prior is None:
            return None
        if (prior["request_digest"] != request_digest
                or tuple(prior["verified_groups"]) != access.groups
                or prior["authorization_scope_digest"] is None
                or prior["authorization_scope_digest"] != authorization_scope_digest):
            raise ValueError("LAYOUT_REPLACEMENT_IDEMPOTENCY_CONFLICT")
        return {"requestId": prior["request_id"],
                "targetGenerationId": prior["target_generation_id"],
                "status": prior["status"], "duplicate": True}

    def execute(self, scope: ApplicationScope, program: object, *,
                replay_only: bool = False) -> dict | None:
        if (not isinstance(program, dict)
                or set(program) != {"languageVersion", "function", "arguments"}
                or type(program.get("languageVersion")) is not int
                or program["languageVersion"] != 2
                or program.get("function") not in PUBLIC_FUNCTIONS
                or not isinstance(program.get("arguments"), dict)):
            raise ValueError("V2_LAYOUT_REPLACEMENT_INVALID")
        function, arguments = program["function"], program["arguments"]
        if replay_only and function != REQUEST:
            raise ValueError("V2_LAYOUT_REPLACEMENT_INVALID")
        if function == REQUEST:
            if set(arguments) not in ({"preview", "plan", "idempotencyKey"},
                    {"preview", "plan", "idempotencyKey", "dependencyDecisions"},
                    {"preview", "plan", "idempotencyKey", "dependencyDecisions",
                     "expectedDependencyDigest"}):
                raise ValueError("V2_LAYOUT_REPLACEMENT_INVALID")
            if ("expectedDependencyDigest" in arguments
                    and not isinstance(arguments["expectedDependencyDigest"], str)):
                raise ValueError("V2_LAYOUT_REPLACEMENT_INVALID")
            return self.accept(scope, preview=arguments["preview"],
                               plan_document=arguments["plan"],
                               idempotency_key=arguments["idempotencyKey"],
                               dependency_decisions=arguments.get("dependencyDecisions"),
                               expected_dependency_digest=arguments.get("expectedDependencyDigest"),
                               replay_only=replay_only)
        if function == READ:
            if set(arguments) != {"requestId"}:
                raise ValueError("V2_LAYOUT_REPLACEMENT_INVALID")
            return self.read(scope, arguments["requestId"])
        if set(arguments) != {"requestId", "expectedStatus", "expectedStateVersion"}:
            raise ValueError("V2_LAYOUT_REPLACEMENT_INVALID")
        return self.cancel(scope, arguments["requestId"],
                           expected_status=arguments["expectedStatus"],
                           expected_state_version=arguments["expectedStateVersion"])

    def accept(self, scope: ApplicationScope, *, preview: object,
               plan_document: object, idempotency_key: str,
               dependency_decisions: list | None = None,
               expected_dependency_digest: str | None = None,
               replay_only: bool = False) -> dict | None:
        if not isinstance(scope, ApplicationScope) or not isinstance(preview, dict):
            raise ValueError("LAYOUT_REPLACEMENT_REQUEST_INVALID")
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(idempotency_key):
            raise ValueError("LAYOUT_REPLACEMENT_REQUEST_INVALID")
        decisions = _dependency_decisions(dependency_decisions)
        if expected_dependency_digest is not None and (
                decisions is None or not isinstance(expected_dependency_digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected_dependency_digest)):
            raise ValueError("LAYOUT_REVIEWED_DEPENDENCY_DIGEST_INVALID")
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
                if replay_only:
                    db.execute('SET TRANSACTION READ ONLY')
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "admin")
                authorization_scope_digest = resolve_effective_dimensional_scope(
                    db, self.identity, scope, access=access,
                    function=REQUEST).scope_digest
                verified_groups = access.groups
                descriptor = {
                    "scope": [scope.workspace_id, scope.application_id],
                    "identity": [self.identity.issuer, self.identity.subject_id],
                    "verifiedGroups": list(access.groups),
                    "authorizationScopeDigest": authorization_scope_digest,
                    "idempotencyKey": idempotency_key,
                    "previewDigest": preview["previewDigest"],
                    "planDigest": plan.digest}
                if decisions is not None:
                    descriptor["dependencyDecisions"] = decisions
                if expected_dependency_digest is not None:
                    descriptor["expectedDependencyDigest"] = expected_dependency_digest
                request_digest = _digest(descriptor)
                prior = self._existing_request(db, scope, idempotency_key,
                    request_digest, access, authorization_scope_digest)
                if prior is not None or replay_only:
                    return prior
        # Old-shaped programs can retrieve only their exact admitted request.
        # No worker may invent dependency intent or revive an unsealed row.
        if decisions is None:
            raise ValueError("LAYOUT_REPLACEMENT_DEPENDENCY_DECISIONS_REQUIRED")
        issued_at, authority_kind = durable_authority_fields(self.identity)
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
                if (current_scope_digest != authorization_scope_digest
                        or access.groups != verified_groups):
                    raise ValueError(
                        "LAYOUT_REPLACEMENT_AUTHORIZATION_SCOPE_CHANGED")
                state = db.execute("""SELECT metadata_revision,data_revision,
                    policy_revision,schema_epoch,commit_revision,commit_open
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE""",
                    (scope.workspace_id, scope.application_id)).fetchone()
                prior = self._existing_request(db, scope, idempotency_key,
                    request_digest, access, current_scope_digest)
                if prior is not None:
                    return prior
                if state is None:
                    raise ValueError("STALE_LAYOUT_PINS")
                actual = {"metadataRevision": state["metadata_revision"],
                          "dataRevision": state["data_revision"],
                          "policyRevision": state["policy_revision"],
                          "schemaEpoch": state["schema_epoch"],
                          "sourceCommitRevision": state["commit_revision"]}
                if state["commit_open"] or actual != pins:
                    raise ValueError("STALE_LAYOUT_PINS")
                reviewed = expected_dependency_digest is not None
                reviewed_column = ",reviewed_dependency_digest" if reviewed else ""
                reviewed_placeholder = ",%s" if reviewed else ""
                reviewed_parameter = (expected_dependency_digest,) if reviewed else ()
                inserted = db.execute("""INSERT INTO epm.layout_replacement_request
                    (workspace_id,application_id,request_id,issuer,subject_id,
                     idempotency_key,request_digest,preview_digest,plan_digest,plan,
                     metadata_revision,data_revision,policy_revision,schema_epoch,
                     source_commit_revision,target_generation_id,
                     expected_coordinate_count,verified_groups,
                     authorization_scope_digest,token_issued_at,authority_kind,
                     dependency_decisions""" + reviewed_column + """)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s""" + reviewed_placeholder + """)
                    ON CONFLICT DO NOTHING RETURNING request_id""",
                    (scope.workspace_id, scope.application_id, request_id,
                     self.identity.issuer, self.identity.subject_id, idempotency_key,
                     request_digest, preview["previewDigest"], plan.digest,
                     Jsonb(plan_document), pins["metadataRevision"],
                     pins["dataRevision"], pins["policyRevision"], pins["schemaEpoch"],
                     pins["sourceCommitRevision"], generation_id,
                     plan_document["sourceCoordinateCount"],
                     list(access.groups), current_scope_digest,
                     issued_at, authority_kind, Jsonb(decisions), *reviewed_parameter)).fetchone()
                if inserted is None:
                    # PostgreSQL has settled the competing insertion. Only an
                    # exact authorized row can explain an insert that lost.
                    prior = self._existing_request(db, scope, idempotency_key,
                        request_digest, access, current_scope_digest)
                    if prior is None:
                        raise ValueError("LAYOUT_REPLACEMENT_IDEMPOTENCY_CONFLICT")
                    current_access = PostgresAccessChecker.check_in_transaction(
                        db, self.identity, scope, "admin")
                    if current_access != access:
                        raise ValueError("LAYOUT_REPLACEMENT_AUTHORIZATION_SCOPE_CHANGED")
                    return prior
                db.execute("""INSERT INTO epm.layout_replacement_generation
                    (workspace_id,application_id,generation_id,request_id)
                    VALUES(%s,%s,%s,%s)""",
                    (scope.workspace_id, scope.application_id,
                     generation_id, request_id))
                # Exact complete intent and the active source inventory are
                # checked by the same current dependency owner used by validation.
                try:
                    db.execute("""SELECT epm.layout_replacement_validation_context(
                        %s,%s,%s,%s)""", (scope.workspace_id, scope.application_id,
                        request_id, Jsonb(decisions))).fetchone()
                except RaiseException as error:
                    code = error.diag.message_primary
                    if code in DEPENDENCY_REFUSALS:
                        raise ValueError(code) from error
                    raise
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
                    r.authority_kind,r.dependency_decisions,r.worker_phase,
                    c.validation_digest,c.activation_eligible,
                    x.activation_id,
                    m.status AS materialization_status,m.next_chunk,m.target_count,
                    m.error_code AS materialization_error,
                    epm.layout_replacement_staged_count(
                     r.workspace_id,r.application_id,r.request_id) AS staged_coordinate_count
                    FROM epm.layout_replacement_request r
                    LEFT JOIN epm.layout_replacement_validation_certificate c
                      USING(workspace_id,application_id,request_id)
                    LEFT JOIN epm.layout_replacement_materialization m
                      USING(workspace_id,application_id,request_id)
                    LEFT JOIN epm.layout_replacement_activation x
                      ON x.workspace_id=r.workspace_id AND x.application_id=r.application_id
                     AND x.request_id=r.request_id AND x.issuer=%s AND x.subject_id=%s
                     AND x.verified_groups=%s AND x.authorization_scope_digest=%s
                    WHERE r.workspace_id=%s
                    AND r.application_id=%s AND r.request_id=%s""",
                    (self.identity.issuer, self.identity.subject_id,
                     list(access.groups), authorization_scope_digest,
                     scope.workspace_id, scope.application_id, request_id)).fetchone()
                if row is None:
                    raise ValueError("LAYOUT_REPLACEMENT_NOT_FOUND")
                if (tuple(row["verified_groups"]) != access.groups
                        or row["authorization_scope_digest"] is None
                        or row["authorization_scope_digest"] !=
                        authorization_scope_digest):
                    raise ValueError(
                        "LAYOUT_REPLACEMENT_AUTHORIZATION_SCOPE_CHANGED")
                return {"requestId": row["request_id"], "status": row["status"],
                        "activationId": row["activation_id"],
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
                        "errorCode": row["error_code"],
                        "workerPhase": row["worker_phase"],
                        "dependencyDecisions": row["dependency_decisions"],
                        "automaticProgressionSupported": (
                            row["authority_kind"] in ("HumanToken", "Technical")
                            and row["dependency_decisions"] is not None),
                        "certificate": (None if row["validation_digest"] is None else {
                            "validationDigest": row["validation_digest"],
                            "activationEligible": row["activation_eligible"],
                            "pins": {"metadataRevision": row["metadata_revision"],
                                "dataRevision": row["data_revision"],
                                "policyRevision": row["policy_revision"],
                                "schemaEpoch": row["schema_epoch"],
                                "sourceCommitRevision": row["source_commit_revision"]}}),
                        "materialization": (None if row["materialization_status"] is None else {
                            "status": row["materialization_status"],
                            "nextChunk": row["next_chunk"], "targetCount": row["target_count"],
                            "errorCode": row["materialization_error"]})}

    def cancel(self, scope: ApplicationScope, request_id: str, *,
               expected_status: str, expected_state_version: int) -> dict:
        if (not isinstance(request_id, str) or not _HEX32.fullmatch(request_id)
                or expected_status not in _STATUSES
                or type(expected_state_version) is not int or expected_state_version < 0):
            raise ValueError("LAYOUT_REPLACEMENT_REQUEST_INVALID")
        with connect_postgres(self.dsn, row_factory=dict_row) as db, db.transaction():
            configure_statement_timeout(db, 5000); configure_lock_wait(db)
            PostgresNumericFactStore._set_scope(db, scope)
            PostgresAccessChecker.check_in_transaction(db, self.identity, scope, "admin")
            pinned=db.execute("""SELECT status,claim_generation FROM epm.layout_replacement_request
                WHERE workspace_id=%s AND application_id=%s AND request_id=%s""",
                (scope.workspace_id,scope.application_id,request_id)).fetchone()
            if pinned is None:raise ValueError("LAYOUT_REPLACEMENT_NOT_FOUND")
            if pinned["status"] != expected_status or pinned["claim_generation"] != expected_state_version:
                raise ValueError("LAYOUT_REPLACEMENT_STATE_STALE")
            try:
                version = db.execute("SELECT epm.layout_replacement_private_cancel(%s,%s,%s,%s,%s) AS version",
                    (scope.workspace_id, scope.application_id, request_id,
                        expected_status, expected_state_version)).fetchone()["version"]
            except RaiseException as error:
                code = error.diag.message_primary
                if code in ("LAYOUT_REPLACEMENT_STATE_STALE", "LAYOUT_REPLACEMENT_WORK_IN_PROGRESS"):
                    raise ValueError(code) from error
                raise
            return {"requestId": request_id, "status": "Cancelled", "stateVersion": version}

    def request_cancel_as_task_controller(self, scope: ApplicationScope,
                                          request_id: str) -> dict:
        """Current admin control of exact unpublished work, including old rows."""
        if (not isinstance(scope, ApplicationScope) or not isinstance(request_id, str)
                or not _HEX32.fullmatch(request_id)):
            raise ValueError("LAYOUT_REPLACEMENT_REQUEST_INVALID")
        with connect_postgres(self.dsn, row_factory=dict_row) as db, db.transaction():
            configure_statement_timeout(db, 5000); configure_lock_wait(db)
            PostgresNumericFactStore._set_scope(db, scope)
            PostgresAccessChecker.check_in_transaction(db, self.identity, scope, "admin")
            row = db.execute("""SELECT status,claim_generation FROM epm.layout_replacement_request
                WHERE workspace_id=%s AND application_id=%s AND request_id=%s""",
                (scope.workspace_id, scope.application_id, request_id)).fetchone()
            if row is None:
                raise ValueError("LAYOUT_REPLACEMENT_NOT_FOUND")
            version=db.execute("SELECT epm.layout_replacement_private_cancel(%s,%s,%s,%s,%s) AS version",
                (scope.workspace_id,scope.application_id,request_id,
                    row["status"],row["claim_generation"])).fetchone()["version"]
            return {"requestId":request_id,"status":"Cancelled","stateVersion":version}


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


def read_program_contract(function):
    if function != READ:
        return None
    from .metadata_read_contract import read_contract, read_example, obj
    identifier = {'type': 'string', 'pattern': '^[0-9a-f]{32}$'}
    digest = {'type': 'string', 'pattern': '^[0-9a-f]{64}$'}
    count = {'type': 'integer', 'minimum': 0}
    pins = obj({key: count for key in ('metadataRevision', 'dataRevision',
        'policyRevision', 'schemaEpoch', 'sourceCommitRevision')})
    properties = {'requestId': identifier,
        'status': {'enum': list(_STATUSES)},
        'activationId': {'oneOf': [{'type': 'null'}, identifier]},
        'previewDigest': digest, 'planDigest': digest, 'pins': pins,
        'targetGenerationId': identifier, 'expectedCoordinateCount': count,
        'stagedCoordinateCount': count, 'stateVersion': count,
        'errorCode': {'type': ['string', 'null']},
        'workerPhase': {'enum': ['Stage', 'Validate', None]},
        'automaticProgressionSupported': {'type': 'boolean'},
        'dependencyDecisions': {'oneOf': [{'type': 'null'}, {'type': 'array',
            'maxItems': 10000, 'items': obj({'kind': {'enum': ['rule', 'publication']},
                'id': {'type': 'string', 'minLength': 1, 'maxLength': 256},
                'decision': {'enum': ['Compatible', 'Invalidate', 'Rebuild']}})}]},
        'certificate': {'oneOf': [{'type': 'null'}, obj({
            'validationDigest': digest, 'activationEligible': {'type': 'boolean'}, 'pins': pins})]},
        'materialization': {'oneOf': [{'type': 'null'}, obj({
            'status': {'enum': ['Ready', 'Running', 'Complete', 'Failed']},
            'nextChunk': count, 'targetCount': count,
            'errorCode': {'type': ['string', 'null']}})]}}
    result = obj(properties, [field for field in properties if field != 'activationId'])
    return read_contract(function, obj({'requestId': identifier}), result,
        owner='PostgresPopulatedLayoutReplacement.read',
        examples=[read_example(function, {'requestId': 'a' * 32},
            name='Read an existing populated-layout replacement',
            binding='Use the requestId returned by the authorized replace.request operation; the example does not request or stage another replacement.')],
        semantic_rules=['Current administrator authority and the original verified-group/dimensional-authority digest are rechecked.',
            'The actual status, stored workerPhase and staged count describe the existing durable request. workerPhase describes its retained Stage/Validate lease until settlement or recovery; it is not a liveness promise. Materialization has its own displayed state. Staged/Validated are not activation or publication.',
            'The persisted certificate, when present, supplies the actual validation digest and eligibility for a separate explicit activation request; nullable materialization reports private phase progress, never publication.',
            'When present, activationId identifies the existing activation for this exact replacement under the current calling identity, verified groups and dimensional authority. Call activate.read to establish publication from its receipt.',
            'automaticProgressionSupported is false for old requests without admitted dependency intent and a proven durable authority seal. They are never enriched in place; retain their evidence and request a fresh replacement using current source/preview and explicit decisions.',
            'Current administrators may cancel only unpublished, unclaimed private work through metadata.layout.populated.replace.cancel with the exact read status and stateVersion; live leases or any pending/sealed activation refuse cancellation.',
            'This read does not cancel, retry, rebase or activate the request.'])


def effect_program_contract(function):
    from .metadata_read_contract import obj, read_contract, read_example

    identifier = {'type': 'string', 'pattern': r'^[0-9a-f]{32}(?![\s\S])'}
    revision = {'type': 'integer', 'minimum': 0}
    status = {'enum': list(_STATUSES)}
    if function == CANCEL:
        contract = read_contract(CANCEL, obj({'requestId': identifier,
            'expectedStatus': status, 'expectedStateVersion': revision}),
            obj({'requestId': identifier, 'status': {'const': 'Cancelled'}, 'stateVersion': revision}),
            owner='PostgresPopulatedLayoutReplacements.cancel', examples=[
                read_example(CANCEL, {'requestId': 'a' * 32, 'expectedStatus': 'Accepted',
                    'expectedStateVersion': 0}, name='Cancel an unclaimed private replacement',
                    binding='Read replace.read and use its actual requestId, status and stateVersion.')],
            semantic_rules=['Cancellation uses the exact current state version and refuses active leases or pending or sealed activation.',
                'A read after an interrupted cancellation can show Cancelled and its stateVersion. This control retains private-work evidence.'])
        contract['programContract']['recovery'] = (
            'Read replace.read for the same request after an interrupted response or stale state version. '
            'Use the current status and stateVersion if cancellation is still available.')
        return contract
    if function != REQUEST:
        return None
    from .populated_layout_mapping import MAX_COORDINATES
    from .postgres_populated_layout_preview import FUNCTION as PREVIEW, read_program_contract as preview_contract

    preview = preview_contract(PREVIEW)
    preview_shape = preview['resultSchema']['properties']['result']
    preview_args = preview['programSchema']['properties']['arguments']['properties']
    example_args = preview['programContract']['examples'][0]['program']['arguments']
    preview_v1, preview_v2 = [variant['properties'] for variant in preview_shape['oneOf']]
    count = {'type': 'integer', 'minimum': 1, 'maximum': MAX_COORDINATES}
    plan_fields = {'pins': preview_v1['pins'], 'sourceAxes': preview_args['targetAxes'],
        'targetAxes': preview_args['targetAxes'], 'axisMapping': preview_args['axisMapping'],
        'coordinateMappings': preview_args['coordinateMappings'],
        'sourceCoordinateCount': count, 'targetCoordinateCount': count}
    plan_shape = {'oneOf': [
        obj({**plan_fields, 'format': {'const': 'openepm-populated-layout-plan-v1'}}),
        obj({**plan_fields, 'format': {'const': 'openepm-populated-layout-plan-v2'},
             'targetMetadata': preview_v2['targetMetadata']})]}
    decisions = {'type': 'array', 'maxItems': 10000, 'items': obj({
        'kind': {'enum': ['rule', 'publication']},
        'id': {'type': 'string', 'minLength': 1, 'maxLength': 256},
        'decision': {'enum': ['Compatible', 'Invalidate', 'Rebuild']}})}
    # Build the structural example from the same plan compiler as admission.
    axes = example_args['targetAxes']
    plan = compile_populated_layout_plan(pins=LayoutPins(1, 2, 3, 4, 5),
        source_axes=axes, target_axes=axes, axis_mapping=example_args['axisMapping'],
        source_coordinates=[SourceCoordinate(row['sourceCoordinateId'], row['sourceMembers'])
                            for row in example_args['coordinateMappings']],
        coordinate_mappings=example_args['coordinateMappings'])
    preview_example = {'format': 'openepm-populated-layout-preview-v1',
        'pins': plan.to_wire()['pins'], 'planDigest': plan.digest, 'sourceAxes': axes,
        'targetAxes': axes, 'affectedDimensions': [axis['dimensionId'] for axis in axes],
        'impact': {'coordinates': 1, 'facts': {'numericCells': 1, 'textCells': 0, 'detailLines': 0},
            'hierarchies': 0, 'rules': 0, 'publications': {'calculations': 0, 'eliminations': 0, 'pythonPrograms': 0}}}
    preview_example['previewDigest'] = _digest(preview_example)
    result = obj({'requestId': identifier, 'targetGenerationId': identifier,
                  'status': status, 'duplicate': {'type': 'boolean'}})
    contract = read_contract(REQUEST, obj({'preview': preview_shape, 'plan': plan_shape,
        'dependencyDecisions': decisions, 'expectedDependencyDigest': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'},
        'idempotencyKey': {'type': 'string', 'pattern': r'^[A-Za-z0-9._-]{8,128}(?![\s\S])'}},
        ['preview', 'plan', 'idempotencyKey']), result,
        owner='PostgresPopulatedLayoutReplacements.accept', examples=[
            read_example(REQUEST, {'preview': preview_example, 'plan': plan.to_wire(),
                'dependencyDecisions': [], 'idempotencyKey': 'reviewed-layout-001'},
                name='Request a private replacement for a reviewed populated layout',
                binding='Use the full preview and matching canonical plan from the current source and mapping. Bind every dependency decision, using an explicit empty array only for an empty inventory.')],
        semantic_rules=['Fresh requests require complete dependency decisions. Omitting that field is reserved for exact legacy replay.',
            'Use expectedDependencyDigest from the typed review to seal the current dependency tokens. Admission and certificate validation refuse changed inventory or definitions when this digest is supplied.',
            'Native checks validate canonical plan and preview digests, complete coordinates and dependencies, current pins and authorization, and the JSON byte limits.',
            'Acceptance creates private replacement work. Activation and publication require the separate validated-certificate workflow.'])
    contract['programContract']['recovery'] = (
        'Keep the exact original program, its native key and the signed admission ID. An identical retry, including one that overlaps an in-flight request, returns the original request and generation with current status. '
        'An expired signed request can retrieve an original only. '
        'Use replace.read with the requestId to inspect the outcome. A changed intent with the same key refuses. '
        'If a fresh request has stale pins, read the complete current source and review the new mapping before choosing a new key.')
    return contract
