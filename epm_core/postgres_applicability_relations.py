"""Current PostgreSQL sparse applicability-relation repository."""
from __future__ import annotations

import re
from contextlib import nullcontext

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .applicability_relation_contract import (
    applicability_relation_digest, canonical_applicability_relation)
from .applicability_domain_contract import canonical_applicability_domain
from .apportionment_domain_contract import canonical_apportionment_domain
from .current_object_contract import collection_token, new_state_token, require_state_token
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity, assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait, configure_statement_timeout


SAVE = "metadata.applicability_relation.save"
READ = "metadata.applicability_relation.read"
LIST = "metadata.applicability_relation.list"
ACTIVATE = "metadata.applicability_relation.activate"
DEACTIVATE = "metadata.applicability_relation.deactivate"
DELETE = "metadata.applicability_relation.delete"
WRITE_FUNCTIONS = frozenset((SAVE, ACTIVATE, DEACTIVATE, DELETE))
READ_FUNCTIONS = frozenset((READ, LIST))
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_KEY = re.compile(r"[A-Za-z0-9._-]{8,128}\Z")


def resolve_apportionment_domain(db, scope, value, *, active_dimensions):
    """Resolve and validate grouped allocation policy rows as one business domain."""
    from decimal import Decimal
    from .expression_apportionment import QUANTA
    if not isinstance(scope, ApplicationScope):
        raise ValueError("APPLICABILITY_RELATION_SCOPE_INVALID")
    relation_id = value.get("relationId") if isinstance(value, dict) else None
    _id(relation_id)
    state = db.execute('''SELECT metadata_revision FROM epm.application_state
        WHERE workspace_id=%s AND application_id=%s''',
        (scope.workspace_id, scope.application_id)).fetchone()
    definition = db.execute('''SELECT * FROM epm.applicability_relation_definition
        WHERE workspace_id=%s AND application_id=%s AND relation_id=%s''',
        (scope.workspace_id, scope.application_id, relation_id)).fetchone()
    if definition is None or definition["status"] != "Active":
        raise ValueError("APPLICABILITY_RELATION_NOT_ACTIVE")
    if (definition["state_token"] != value.get("relationStateToken")
            or definition["definition_digest"] != value.get("relationDigest")):
        raise ValueError("APPLICABILITY_RELATION_PIN_STALE")
    if (state is None
            or definition["metadata_revision"] != state["metadata_revision"]):
        raise ValueError("APPLICABILITY_RELATION_METADATA_STALE")
    domain = canonical_apportionment_domain(value,
        active_dimensions=tuple(active_dimensions),
        relation_columns=tuple(definition["columns"]))
    rows = db.execute('''SELECT row_id,values
        FROM epm.applicability_relation_row
        WHERE workspace_id=%s AND application_id=%s AND relation_id=%s
        ORDER BY row_id LIMIT %s''',
        (scope.workspace_id, scope.application_id, relation_id,
         domain["maxRows"] + 1)).fetchall()
    if len(rows) > domain["maxRows"]:
        raise ValueError("APPORTIONMENT_DOMAIN_ROW_BUDGET_EXCEEDED")
    anchors = {item["dimensionId"]: item["columnId"]
               for item in domain["anchorMemberColumns"]}
    overrides = {item["dimensionId"]: item["columnId"]
                 for item in domain["targetMemberColumns"]}
    groups = {}
    target_owners = {}
    allowed_quanta = {Decimal(item) for item in QUANTA}
    for relation_row in rows:
        values = relation_row["values"]
        group_id = values[domain["groupColumnId"]]
        component_id = values[domain["componentColumnId"]]
        formula_id = values[domain["formulaColumnId"]]
        rounding = values[domain["roundingColumnId"]]
        quantum = Decimal(values[domain["quantumColumnId"]])
        weight = Decimal(values[domain["weightColumnId"]])
        if weight <= 0:
            raise ValueError("APPORTIONMENT_DOMAIN_WEIGHT_INVALID")
        if quantum not in allowed_quanta:
            raise ValueError("APPORTIONMENT_DOMAIN_QUANTUM_INVALID")
        if rounding not in ("exact", "half_even"):
            raise ValueError("APPORTIONMENT_DOMAIN_ROUNDING_INVALID")
        anchor = tuple(sorted((axis, values[column])
                              for axis, column in anchors.items()))
        target = tuple(sorted((axis, values[overrides.get(axis, column)])
                              for axis, column in anchors.items()))
        group = groups.setdefault(group_id, {"anchor": anchor,
            "quantum": quantum, "components": {}})
        if group["anchor"] != anchor or group["quantum"] != quantum:
            raise ValueError("APPORTIONMENT_DOMAIN_GROUP_INCONSISTENT")
        component = group["components"].setdefault(component_id, {
            "formula": (formula_id, rounding), "targets": set(),
            "ties": set()})
        if component["formula"] != (formula_id, rounding):
            raise ValueError("APPORTIONMENT_DOMAIN_COMPONENT_INCONSISTENT")
        tie = tuple(dict(target)[axis] for axis in domain["tieDimensions"])
        if target in component["targets"] or tie in component["ties"]:
            raise ValueError("APPORTIONMENT_DOMAIN_TARGET_NOT_EXCLUSIVE")
        owner = target_owners.setdefault(target, group_id)
        if owner != group_id:
            raise ValueError("APPORTIONMENT_DOMAIN_TARGET_NOT_EXCLUSIVE")
        component["targets"].add(target); component["ties"].add(tie)
    if len(groups) > domain["maxGroups"]:
        raise ValueError("APPORTIONMENT_DOMAIN_GROUP_BUDGET_EXCEEDED")
    return {"domain": domain, "rowCount": len(rows),
        "groupCount": len(groups), "relationId": relation_id,
        "relationStateToken": definition["state_token"],
        "relationDigest": definition["definition_digest"],
        "metadataRevision": definition["metadata_revision"]}


def resolve_applicability_domain(db, scope, value, *, active_dimensions):
    """Pin and validate one active relation interpretation for execution.

    Rows remain in PostgreSQL for set-wise lowering.  This pass proves the
    exact current definition, metadata fence, row budget and exclusive target
    ownership without copying the relation into an authored calculation plan.
    """
    if not isinstance(scope, ApplicationScope):
        raise ValueError("APPLICABILITY_RELATION_SCOPE_INVALID")
    relation_id = (value.get("relationId")
                   if isinstance(value, dict) else None)
    _id(relation_id)
    state = db.execute('''SELECT metadata_revision FROM epm.application_state
        WHERE workspace_id=%s AND application_id=%s''',
        (scope.workspace_id, scope.application_id)).fetchone()
    row = db.execute('''SELECT * FROM epm.applicability_relation_definition
        WHERE workspace_id=%s AND application_id=%s AND relation_id=%s''',
        (scope.workspace_id, scope.application_id, relation_id)).fetchone()
    if row is None or row["status"] != "Active":
        raise ValueError("APPLICABILITY_RELATION_NOT_ACTIVE")
    if (row["state_token"] != value.get("relationStateToken")
            or row["definition_digest"] != value.get("relationDigest")):
        raise ValueError("APPLICABILITY_RELATION_PIN_STALE")
    if state is None or row["metadata_revision"] != state["metadata_revision"]:
        raise ValueError("APPLICABILITY_RELATION_METADATA_STALE")
    domain = canonical_applicability_domain(value,
        active_dimensions=tuple(active_dimensions),
        relation_columns=tuple(row["columns"]))
    rows = db.execute('''SELECT row_id,values
        FROM epm.applicability_relation_row
        WHERE workspace_id=%s AND application_id=%s AND relation_id=%s
        ORDER BY row_id LIMIT %s''',
        (scope.workspace_id, scope.application_id, relation_id,
         domain["maxRows"] + 1)).fetchall()
    if len(rows) > domain["maxRows"]:
        raise ValueError("APPLICABILITY_DOMAIN_ROW_BUDGET_EXCEEDED")
    anchor_columns = {item["dimensionId"]: item["columnId"]
                      for item in domain["anchorMemberColumns"]}
    target_columns = {item["dimensionId"]: item["columnId"]
                      for item in domain["targetMemberColumns"]}
    targets = set()
    for relation_row in rows:
        values = relation_row["values"]
        target = tuple(sorted((dimension,
            values[target_columns.get(dimension, column)])
            for dimension, column in anchor_columns.items()))
        if target in targets:
            raise ValueError("APPLICABILITY_DOMAIN_TARGET_NOT_EXCLUSIVE")
        targets.add(target)
    return {"domain": domain, "rowCount": len(rows),
        "relationId": relation_id, "relationStateToken": row["state_token"],
        "relationDigest": row["definition_digest"],
        "metadataRevision": row["metadata_revision"]}


def catalog() -> dict:
    common = {"previewRequired": False, "workClass": "short"}
    lifecycle = {
        "mode": "current_definition_activation",
        "permission": "rule_publish",
        "idempotencyRequired": True,
        "arguments": {
            "relationId": "stable relation ID",
            "expectedStateToken": "current opaque relation token",
            "expectedMetadataRevision": "current metadata revision",
            "expectedPolicyRevision": "current policy revision",
        },
    }
    return {
        SAVE: {**common, "mode": "current_definition_write",
            "permission": "rule_design", "idempotencyRequired": True,
            "arguments": {
                "definition": "canonical current sparse business relation",
                "expectedMetadataRevision": "current metadata revision",
                "expectedPolicyRevision": "current policy revision",
            },
            "optionalArguments": {
                "expectedStateToken": "required when replacing a relation"},
            "result": "saved current relation and opaque state token"},
        ACTIVATE: {**common, **lifecycle,
            "result": "activated current sparse business relation"},
        DEACTIVATE: {**common, **lifecycle,
            "result": "inactive current sparse business relation"},
        DELETE: {**common, **lifecycle, "mode": "current_definition_delete",
            "result": "current relation deletion receipt"},
        READ: {**common, "mode": "read", "permission": "read",
            "idempotencyRequired": False,
            "arguments": {"relationId": "stable relation ID"},
            "result": "current relation definition and rows"},
        LIST: {**common, "mode": "read", "permission": "read",
            "idempotencyRequired": False, "arguments": {},
            "optionalArguments": {"limit": "1-100",
                "afterRelationId": "stable keyset cursor",
                "expectedCollectionToken": "required with cursor"},
            "result": "bounded current relation summaries"},
    }


def _id(value: object) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError("APPLICABILITY_RELATION_ID_INVALID")
    return value


def _revision(value: object, code: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(code)
    return value


def _program(raw: object, functions: frozenset[str]) -> tuple[str, dict]:
    if (not isinstance(raw, dict)
            or set(raw) != {"languageVersion", "function", "arguments"}
            or raw.get("languageVersion") != 2
            or raw.get("function") not in functions
            or type(raw.get("arguments")) is not dict):
        raise ValueError("APPLICABILITY_RELATION_PROGRAM_INVALID")
    return raw["function"], raw["arguments"]


class PostgresApplicabilityRelations:
    def __init__(self, dsn, *, identity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("A verified identity is required")
        assert_nonowner_role(dsn, "epm_runtime", (
            "applicability_relation_definition", "applicability_relation_row"))
        self.dsn, self.identity = dsn, identity

    @staticmethod
    def _scope(db, scope):
        if not isinstance(scope, ApplicationScope):
            raise ValueError("APPLICABILITY_RELATION_SCOPE_INVALID")
        configure_lock_wait(db)
        configure_statement_timeout(db, 30_000)
        PostgresNumericFactStore._set_scope(db, scope)

    @staticmethod
    def _validate_members(db, scope, definition):
        member_columns = [item for item in definition["columns"]
                          if item["type"] == "Member"]
        dimensions = sorted({item["dimensionId"] for item in member_columns})
        if dimensions:
            found = db.execute('''SELECT dimension_id FROM epm.dimension
                WHERE workspace_id=%s AND application_id=%s
                  AND dimension_id=ANY(%s) AND status='Active' ''',
                (scope.workspace_id, scope.application_id, dimensions)).fetchall()
            if {row["dimension_id"] for row in found} != set(dimensions):
                raise ValueError("APPLICABILITY_RELATION_DIMENSION_UNAVAILABLE")
        for dimension in dimensions:
            column_ids = [item["columnId"] for item in member_columns
                          if item["dimensionId"] == dimension]
            requested = {row["values"][column_id]
                         for row in definition["rows"]
                         for column_id in column_ids}
            found = db.execute('''SELECT member_id FROM epm.member
                WHERE workspace_id=%s AND application_id=%s
                  AND dimension_id=%s AND member_id=ANY(%s)
                  AND status='Active' ''',
                (scope.workspace_id, scope.application_id, dimension,
                 sorted(requested))).fetchall()
            if {row["member_id"] for row in found} != requested:
                raise ValueError("APPLICABILITY_RELATION_MEMBER_UNAVAILABLE")

    @staticmethod
    def _summary(row: dict) -> dict:
        return {"relationId": row["relation_id"],
            "stateToken": row["state_token"], "name": row["name"],
            "columns": row["columns"],
            "definitionDigest": row["definition_digest"],
            "status": row["status"],
            "definitionMetadataRevision": row["metadata_revision"],
            "updatedAt": row["updated_at"].isoformat()}

    def execute(self, scope, raw, *, idempotency_key, _connection=None):
        function, args = _program(raw, WRITE_FUNCTIONS)
        if not isinstance(idempotency_key, str) or _KEY.fullmatch(idempotency_key) is None:
            raise ValueError("APPLICABILITY_RELATION_IDEMPOTENCY_KEY_INVALID")
        base = {"expectedMetadataRevision", "expectedPolicyRevision"}
        if function == SAVE:
            required = base | {"definition"}
            if not required <= set(args) or set(args) - required - {"expectedStateToken"}:
                raise ValueError("APPLICABILITY_RELATION_ARGUMENTS_INVALID")
            definition = canonical_applicability_relation(args["definition"])
            relation_id = definition["relationId"]
        else:
            if set(args) != base | {"relationId", "expectedStateToken"}:
                raise ValueError("APPLICABILITY_RELATION_ARGUMENTS_INVALID")
            definition = None
            relation_id = _id(args["relationId"])
        expected_metadata = _revision(args["expectedMetadataRevision"],
                                      "STALE_METADATA_REVISION")
        expected_policy = _revision(args["expectedPolicyRevision"],
                                    "STALE_POLICY_REVISION")
        expected_token = args.get("expectedStateToken")
        if expected_token is not None:
            require_state_token(expected_token,
                                error="APPLICABILITY_RELATION_STATE_TOKEN_INVALID")
        command_digest = _canonical_digest({
            "scope": [scope.workspace_id, scope.application_id],
            "identity": [self.identity.issuer, self.identity.subject_id],
            "program": raw})
        connection = (nullcontext(_connection) if _connection is not None
                      else connect_postgres(self.dsn, row_factory=dict_row))
        with connection as db:
            with db.transaction():
                self._scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                state = db.execute('''SELECT s.metadata_revision,s.policy_revision,
                    s.commit_revision,s.processing_mode,a.status application_status
                    FROM epm.application_state s JOIN epm.application a
                      USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "write")
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope,
                    "rule_design" if function == SAVE else "rule_publish")
                prior = db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                      AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     idempotency_key)).fetchone()
                if prior:
                    if (prior["command_digest"] != command_digest
                            or prior["actor_id"] != self.identity.subject_id):
                        raise ValueError("APPLICABILITY_RELATION_IDEMPOTENCY_CONFLICT")
                    return prior["result"]
                if (state["application_status"] != "Active"
                        or state["processing_mode"] != "Active"):
                    raise ValueError("APPLICATION_NOT_WRITABLE")
                if state["metadata_revision"] != expected_metadata:
                    raise ValueError("STALE_METADATA_REVISION")
                if state["policy_revision"] != expected_policy:
                    raise ValueError("STALE_POLICY_REVISION")
                existing = db.execute('''SELECT *
                    FROM epm.applicability_relation_definition
                    WHERE workspace_id=%s AND application_id=%s
                      AND relation_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id,
                     relation_id)).fetchone()
                if existing is None and expected_token is not None:
                    raise ValueError("APPLICABILITY_RELATION_NOT_FOUND")
                if existing is not None:
                    if expected_token is None:
                        raise ValueError("APPLICABILITY_RELATION_STATE_TOKEN_REQUIRED")
                    if expected_token != existing["state_token"]:
                        raise ValueError("APPLICABILITY_RELATION_STATE_CONFLICT")
                elif function != SAVE:
                    raise ValueError("APPLICABILITY_RELATION_NOT_FOUND")
                if function == SAVE:
                    self._validate_members(db, scope, definition)
                    digest = applicability_relation_digest(definition)
                    status = "Saved"
                elif function == ACTIVATE:
                    if existing["status"] == "Active":
                        raise ValueError("APPLICABILITY_RELATION_ALREADY_ACTIVE")
                    if existing["metadata_revision"] != expected_metadata:
                        raise ValueError("APPLICABILITY_RELATION_METADATA_STALE")
                    digest, status = existing["definition_digest"], "Active"
                elif function == DEACTIVATE:
                    if existing["status"] != "Active":
                        raise ValueError("APPLICABILITY_RELATION_NOT_ACTIVE")
                    digest, status = existing["definition_digest"], "Inactive"
                else:
                    digest, status = existing["definition_digest"], "Deleted"
                policy = state["policy_revision"]
                if function != SAVE or existing and existing["status"] == "Active":
                    policy += 1
                committed = state["commit_revision"] + 1
                token = new_state_token()
                result = {"operationId": idempotency_key,
                    "relationId": relation_id, "status": status,
                    "definitionDigest": digest,
                    "stateToken": None if function == DELETE else token,
                    "metadataRevision": expected_metadata,
                    "policyRevision": policy}
                impact=None
                if function!=SAVE or existing and existing["status"]=="Active":
                    from .postgres_calculation_impact import object_impact
                    impact=object_impact(source_kind="definition",
                        operation_id=idempotency_key,
                        causal_revision=committed,domain="definition",
                        object_type="applicability-relation",
                        object_id=relation_id,
                        change=({ACTIVATE:"activate",DEACTIVATE:"deactivate",
                                 DELETE:"delete"}.get(function,"replace")),
                        reason="definition_changed",
                        old_presence=("present" if existing is not None and
                            existing["status"]=="Active" else "absent"),
                        new_presence=("present" if status=="Active"
                                      else "absent"))
                    result["impactDigest"]=impact.digest
                db.execute('''UPDATE epm.application_state
                    SET policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (policy, committed, scope.workspace_id,
                     scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt(
                    workspace_id,application_id,operation_id,command_digest,
                    actor_id,committed_revision,result)
                    VALUES(%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id, scope.application_id,
                     idempotency_key, command_digest,
                     self.identity.subject_id, committed, Jsonb(result)))
                if existing is not None and function in (SAVE, DELETE):
                    db.execute('''DELETE FROM epm.applicability_relation_row
                        WHERE workspace_id=%s AND application_id=%s
                          AND relation_id=%s''',
                        (scope.workspace_id, scope.application_id, relation_id))
                if function == DELETE:
                    db.execute('''DELETE FROM epm.applicability_relation_definition
                        WHERE workspace_id=%s AND application_id=%s
                          AND relation_id=%s''',
                        (scope.workspace_id, scope.application_id, relation_id))
                elif function == SAVE:
                    db.execute('''INSERT INTO epm.applicability_relation_definition(
                        workspace_id,application_id,relation_id,name,columns,
                        definition_digest,state_token,status,metadata_revision,
                        updated_issuer,updated_subject_id,updated_operation_id)
                        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT(workspace_id,application_id,relation_id)
                        DO UPDATE SET name=EXCLUDED.name,columns=EXCLUDED.columns,
                          definition_digest=EXCLUDED.definition_digest,
                          state_token=EXCLUDED.state_token,status=EXCLUDED.status,
                          metadata_revision=EXCLUDED.metadata_revision,
                          updated_issuer=EXCLUDED.updated_issuer,
                          updated_subject_id=EXCLUDED.updated_subject_id,
                          updated_operation_id=EXCLUDED.updated_operation_id,
                          updated_at=transaction_timestamp()''',
                        (scope.workspace_id, scope.application_id, relation_id,
                         definition["name"], Jsonb(definition["columns"]),
                         digest, token, status, expected_metadata,
                         self.identity.issuer, self.identity.subject_id,
                         idempotency_key))
                    with db.cursor() as cursor:
                        cursor.executemany('''INSERT INTO epm.applicability_relation_row(
                            workspace_id,application_id,relation_id,row_id,values)
                            VALUES(%s,%s,%s,%s,%s)''',
                            ((scope.workspace_id, scope.application_id,
                              relation_id, row["rowId"], Jsonb(row["values"]))
                             for row in definition["rows"]))
                else:
                    db.execute('''UPDATE epm.applicability_relation_definition
                        SET status=%s,state_token=%s,updated_issuer=%s,
                          updated_subject_id=%s,updated_operation_id=%s,
                          updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                          AND relation_id=%s''',
                        (status, token, self.identity.issuer,
                         self.identity.subject_id, idempotency_key,
                         scope.workspace_id, scope.application_id, relation_id))
                if impact is not None:
                    from .postgres_calculation_impact import (
                        record_calculation_impact)
                    record_calculation_impact(db,scope,
                        operation_id=idempotency_key,impact=impact)
                return result

    def read(self, scope, raw):
        function, args = _program(raw, READ_FUNCTIONS)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION READ ONLY")
                self._scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "read", function=function)
                state = db.execute('''SELECT metadata_revision,policy_revision,
                    commit_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                if function == LIST:
                    if set(args) - {"limit", "afterRelationId",
                                    "expectedCollectionToken"}:
                        raise ValueError("APPLICABILITY_RELATION_ARGUMENTS_INVALID")
                    limit = args.get("limit", 100)
                    after = args.get("afterRelationId")
                    if type(limit) is not int or not 1 <= limit <= 100:
                        raise ValueError("APPLICABILITY_RELATION_LIMIT_INVALID")
                    if after is not None:
                        _id(after)
                    if after is not None and "expectedCollectionToken" not in args:
                        raise ValueError("APPLICABILITY_RELATION_CONTINUATION_PIN_REQUIRED")
                    if "expectedCollectionToken" in args:
                        require_state_token(args["expectedCollectionToken"],
                            error="APPLICABILITY_RELATION_COLLECTION_TOKEN_INVALID")
                    token_rows = db.execute('''SELECT relation_id,state_token
                        FROM epm.applicability_relation_definition
                        WHERE workspace_id=%s AND application_id=%s
                        ORDER BY relation_id''',
                        (scope.workspace_id, scope.application_id)).fetchall()
                    token = collection_token((row["relation_id"], row["state_token"])
                                             for row in token_rows)
                    if args.get("expectedCollectionToken", token) != token:
                        raise ValueError("APPLICABILITY_RELATION_LIST_STALE")
                    rows = db.execute('''SELECT *
                        FROM epm.applicability_relation_definition
                        WHERE workspace_id=%s AND application_id=%s
                          AND (%s::text IS NULL OR relation_id>%s)
                        ORDER BY relation_id LIMIT %s''',
                        (scope.workspace_id, scope.application_id, after, after,
                         limit + 1)).fetchall()
                    values = [self._summary(row) for row in rows[:limit]]
                    return {"applicabilityRelations": values,
                        "nextAfterRelationId": (values[-1]["relationId"]
                            if len(rows) > limit else None),
                        "collectionToken": token}
                if set(args) != {"relationId"}:
                    raise ValueError("APPLICABILITY_RELATION_ARGUMENTS_INVALID")
                relation_id = _id(args["relationId"])
                row = db.execute('''SELECT *
                    FROM epm.applicability_relation_definition
                    WHERE workspace_id=%s AND application_id=%s
                      AND relation_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     relation_id)).fetchone()
                if row is None:
                    raise ValueError("APPLICABILITY_RELATION_NOT_FOUND")
                relation_rows = db.execute('''SELECT row_id,values
                    FROM epm.applicability_relation_row
                    WHERE workspace_id=%s AND application_id=%s
                      AND relation_id=%s ORDER BY row_id''',
                    (scope.workspace_id, scope.application_id,
                     relation_id)).fetchall()
                definition = {"format": "openepm-applicability-relation-v1",
                    "relationId": relation_id, "name": row["name"],
                    "columns": row["columns"],
                    "rows": [{"rowId": item["row_id"],
                              "values": item["values"]}
                             for item in relation_rows]}
                if applicability_relation_digest(definition) != row["definition_digest"]:
                    raise ValueError("APPLICABILITY_RELATION_STORAGE_CORRUPT")
                return {**self._summary(row), "definition": definition,
                    "currentMetadataRevision": state["metadata_revision"],
                    "policyRevision": state["policy_revision"],
                    "commitRevision": state["commit_revision"]}
