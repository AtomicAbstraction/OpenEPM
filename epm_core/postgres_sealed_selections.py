"""Durable subject-bound artifacts for exact generic cube selections."""

from __future__ import annotations

import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity, assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait, configure_statement_timeout
from .postgres_selection_preview import PostgresSelectionPreview, PREVIEW
from .selection_contract import canonical_selection, selection_digest


SEAL = "cube.selection.seal"
READ = "cube.selection.read"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,199}\Z")


def catalog() -> dict:
    common = {"permission": "read", "workClass": "short",
              "previewRequired": False}
    return {
        SEAL: {**common, "mode": "technical_artifact_write",
               "idempotencyRequired": True,
               "arguments": {
                   "selectionId": "caller-stable 8-200 character request identity",
                   "selection": "complete-grain openepm-cube-selection-v1",
                   "expectedPolicyRevision": "current authorization policy revision",
                   "ttlSeconds": "60-3600",
               },
               "result": "durable subject-bound resolved selection artifact"},
        READ: {**common, "mode": "read", "idempotencyRequired": False,
               "arguments": {"selectionId": "sealed selection identity"},
               "result": "current authorized unexpired sealed selection"},
    }


def _id(value: object) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("CUBE_SELECTION_ID_INVALID")
    return value


def _program(raw: object) -> tuple[str, dict]:
    if (not isinstance(raw, dict)
            or set(raw) != {"languageVersion", "function", "arguments"}
            or raw.get("languageVersion") != 2
            or raw.get("function") not in {SEAL, READ}
            or not isinstance(raw.get("arguments"), dict)):
        raise ValueError("SEALED_SELECTION_PROGRAM_INVALID")
    function, args = raw["function"], raw["arguments"]
    expected = ({"selectionId", "selection", "expectedPolicyRevision", "ttlSeconds"}
                if function == SEAL else {"selectionId"})
    if set(args) != expected:
        raise ValueError("SEALED_SELECTION_ARGUMENTS_INVALID")
    _id(args["selectionId"])
    if function == SEAL and (
            type(args["expectedPolicyRevision"]) is not int
            or args["expectedPolicyRevision"] < 0
            or type(args["ttlSeconds"]) is not int
            or not 60 <= args["ttlSeconds"] <= 3600):
        raise ValueError("SEALED_SELECTION_ARGUMENTS_INVALID")
    return function, args


class PostgresSealedSelections:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("A verified identity is required")
        assert_nonowner_role(dsn, "epm_runtime", ("sealed_cube_selection",))
        self.dsn, self.identity = dsn, identity

    @staticmethod
    def _scope(db, scope: ApplicationScope) -> None:
        if not isinstance(scope, ApplicationScope):
            raise ValueError("CUBE_SELECTION_SCOPE_INVALID")
        configure_lock_wait(db)
        configure_statement_timeout(db, 5000)
        PostgresNumericFactStore._set_scope(db, scope)

    @staticmethod
    def _result(row: dict) -> dict:
        return {"selectionId": row["selection_id"],
                "selection": row["selection"],
                "resolvedSelection": row["resolved_selection"],
                "selectionDigest": row["selection_digest"],
                "resolutionDigest": row["resolution_digest"],
                "metadataRevision": row["metadata_revision"],
                "policyRevision": row["policy_revision"],
                "commitRevision": row["commit_revision"],
                "createdAt": row["created_at"].isoformat(),
                "expiresAt": row["expires_at"].isoformat()}

    def execute(self, scope: ApplicationScope, raw: dict) -> dict:
        function, args = _program(raw)
        if function == READ:
            return self._read(scope, args["selectionId"])
        canonical = canonical_selection(args["selection"])
        request = {
            "scope": [scope.workspace_id, scope.application_id],
            "identity": [self.identity.issuer, self.identity.subject_id],
            "verifiedGroups": list(self.identity.groups),
            "selectionId": args["selectionId"], "selection": canonical,
            "expectedPolicyRevision": args["expectedPolicyRevision"],
            "ttlSeconds": args["ttlSeconds"],
        }
        preview = PostgresSelectionPreview(
            self.dsn, identity=self.identity).read(scope, {
                "languageVersion": 2, "function": PREVIEW,
                "arguments": {"selection": canonical,
                    "expectedPolicyRevision": args["expectedPolicyRevision"]}})
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                self._scope(db, scope)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "read", function=SEAL)
                authorization_scope_digest = resolve_effective_dimensional_scope(
                    db, self.identity, scope, access=access,
                    function=SEAL).scope_digest
                request_digest = _canonical_digest({**request,
                    "authorizationScopeDigest": authorization_scope_digest})
                state = db.execute("""SELECT metadata_revision,policy_revision,
                    commit_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s FOR UPDATE""",
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                if (state["metadata_revision"] != preview["metadataRevision"]
                        or state["policy_revision"] != preview["policyRevision"]
                        or state["commit_revision"] != preview["commitRevision"]):
                    raise ValueError("CUBE_SELECTION_STATE_CHANGED_BEFORE_SEAL")
                prior = db.execute("""SELECT * FROM epm.sealed_cube_selection
                    WHERE workspace_id=%s AND application_id=%s
                    AND selection_id=%s AND issuer=%s AND subject_id=%s""",
                    (scope.workspace_id, scope.application_id,
                     args["selectionId"], self.identity.issuer,
                     self.identity.subject_id)).fetchone()
                if prior is not None:
                    if (prior["request_digest"] != request_digest
                            or tuple(prior["verified_groups"]) !=
                               self.identity.groups
                            or prior["authorization_scope_digest"] is None
                            or prior["authorization_scope_digest"] !=
                               authorization_scope_digest):
                        raise ValueError("SEALED_SELECTION_IDEMPOTENCY_CONFLICT")
                    return self._result(prior)
                row = db.execute("""INSERT INTO epm.sealed_cube_selection
                    (workspace_id,application_id,selection_id,issuer,subject_id,
                     request_digest,selection,resolved_selection,selection_digest,
                     resolution_digest,metadata_revision,policy_revision,
                     commit_revision,expires_at,verified_groups,
                     authorization_scope_digest)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                      transaction_timestamp()+(%s*interval '1 second'),%s,%s)
                    RETURNING *""", (scope.workspace_id, scope.application_id,
                    args["selectionId"], self.identity.issuer,
                    self.identity.subject_id, request_digest, Jsonb(canonical),
                    Jsonb(preview), selection_digest(canonical),
                    preview["resolutionDigest"], preview["metadataRevision"],
                    preview["policyRevision"], preview["commitRevision"],
                    args["ttlSeconds"], list(self.identity.groups),
                    authorization_scope_digest)).fetchone()
                return self._result(row)

    def _read(self, scope: ApplicationScope, selection_id: str) -> dict:
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION READ ONLY")
                self._scope(db, scope)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "read", function=READ)
                authorization_scope_digest = resolve_effective_dimensional_scope(
                    db, self.identity, scope, access=access,
                    function=READ).scope_digest
                row = db.execute("""SELECT s.*,
                    a.metadata_revision current_metadata_revision,
                    a.policy_revision current_policy_revision
                    FROM epm.sealed_cube_selection s JOIN epm.application_state a
                    USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    AND s.selection_id=%s AND s.issuer=%s AND s.subject_id=%s""",
                    (scope.workspace_id, scope.application_id, selection_id,
                     self.identity.issuer, self.identity.subject_id)).fetchone()
                if row is None:
                    raise ValueError("SEALED_SELECTION_UNAVAILABLE")
                if (tuple(row["verified_groups"]) != self.identity.groups
                        or row["authorization_scope_digest"] is None
                        or row["authorization_scope_digest"] !=
                           authorization_scope_digest):
                    raise ValueError(
                        "SEALED_SELECTION_AUTHORIZATION_SCOPE_CHANGED")
                expired = db.execute(
                    "SELECT %s::timestamptz<=clock_timestamp() AS expired",
                    (row["expires_at"],)).fetchone()["expired"]
                if expired:
                    raise ValueError("SEALED_SELECTION_EXPIRED")
                if row["metadata_revision"] != row["current_metadata_revision"]:
                    raise ValueError("SEALED_SELECTION_METADATA_STALE")
                if row["policy_revision"] != row["current_policy_revision"]:
                    raise ValueError("SEALED_SELECTION_POLICY_STALE")
                return self._result(row)
