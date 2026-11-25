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
from .dimensional_security_policy import ResolvedMemberSecurity
from .persistence_contract import ApplicationScope
from .postgres_access import AccessDenied, PostgresAccessChecker, VerifiedIdentity, assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import metadata_reference_read_allowed, resolve_effective_dimensional_scope
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


def _pinned_apportionment_definition(db, scope, relation_id, value):
    definition = db.execute('''SELECT d.status,d.state_token,d.definition_digest,
        d.metadata_revision,d.columns,s.metadata_revision AS current_metadata_revision
        FROM epm.applicability_relation_definition d
        JOIN epm.application_state s USING (workspace_id,application_id)
        WHERE d.workspace_id=%s AND d.application_id=%s AND d.relation_id=%s''',
        (scope.workspace_id, scope.application_id, relation_id)).fetchone()
    if definition is None or definition["status"] != "Active":
        raise ValueError("APPLICABILITY_RELATION_NOT_ACTIVE")
    if (definition["state_token"] != value.get("relationStateToken")
            or definition["definition_digest"] != value.get("relationDigest")):
        raise ValueError("APPLICABILITY_RELATION_PIN_STALE")
    if definition["metadata_revision"] != definition["current_metadata_revision"]:
        raise ValueError("APPLICABILITY_RELATION_METADATA_STALE")
    return definition


def resolve_apportionment_domain(db, scope, value, *, active_dimensions):
    """Return the exact bounded rows validated under the requested relation pins."""
    from decimal import Decimal
    from .expression_apportionment import QUANTA
    if not isinstance(scope, ApplicationScope):
        raise ValueError("APPLICABILITY_RELATION_SCOPE_INVALID")
    relation_id = value.get("relationId") if isinstance(value, dict) else None
    _id(relation_id)
    definition = _pinned_apportionment_definition(db, scope, relation_id, value)
    domain = canonical_apportionment_domain(value,
        active_dimensions=tuple(active_dimensions),
        relation_columns=tuple(definition["columns"]))
    rows = db.execute('''SELECT row_id,values
        FROM epm.applicability_relation_row
        WHERE workspace_id=%s AND application_id=%s AND relation_id=%s
        ORDER BY row_id LIMIT %s''',
        (scope.workspace_id, scope.application_id, relation_id,
         domain["maxRows"] + 1)).fetchall()
    # A writer can commit between the header and row reads at READ COMMITTED.
    # Each relation lifecycle effect replaces the token. Rechecking it binds
    # the bounded row set to the header used to validate its interpretation.
    _pinned_apportionment_definition(db, scope, relation_id, domain)
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
        "metadataRevision": definition["metadata_revision"]}, rows


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
    functions = {
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
    for function in WRITE_FUNCTIONS:
        functions[function].update(write_program_contract(function))
    return functions


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
    def _member_references(definition):
        references = {}
        for column in definition["columns"]:
            if column["type"] == "Member":
                column_id = column["columnId"]
                references.setdefault(column["dimensionId"], set()).update(
                    row["values"][column_id] for row in definition["rows"])
        return references

    @classmethod
    def _validate_members(cls, db, scope, definition):
        references = cls._member_references(definition)
        dimensions = sorted(references)
        if dimensions:
            found = db.execute('''SELECT dimension_id FROM epm.dimension
                WHERE workspace_id=%s AND application_id=%s
                  AND dimension_id=ANY(%s) AND status='Active' ''',
                (scope.workspace_id, scope.application_id, dimensions)).fetchall()
            if {row["dimension_id"] for row in found} != set(dimensions):
                raise ValueError("APPLICABILITY_RELATION_DIMENSION_UNAVAILABLE")
        for dimension in dimensions:
            requested = references[dimension]
            found = db.execute('''SELECT member_id FROM epm.member
                WHERE workspace_id=%s AND application_id=%s
                  AND dimension_id=%s AND member_id=ANY(%s)
                  AND status='Active' ''',
                (scope.workspace_id, scope.application_id, dimension,
                 sorted(requested))).fetchall()
            if {row["member_id"] for row in found} != requested:
                raise ValueError("APPLICABILITY_RELATION_MEMBER_UNAVAILABLE")

    @staticmethod
    def _authorize_member_references(db, scope, authority, references):
        rows = db.execute('''WITH requested AS (
            SELECT dimensions.key AS dimension_id, members.member_id
            FROM jsonb_each(%s::jsonb) AS dimensions
            CROSS JOIN LATERAL jsonb_array_elements_text(dimensions.value) AS members(member_id)
        )
        SELECT r.dimension_id,r.member_id,d.read_security_tags AS dimension_read,
          d.write_security_tags AS dimension_write,
          m.read_security_tags AS member_read,m.write_security_tags AS member_write
        FROM requested r
        LEFT JOIN epm.dimension d ON d.workspace_id=%s AND d.application_id=%s
          AND d.dimension_id=r.dimension_id
        LEFT JOIN epm.member m ON m.workspace_id=d.workspace_id AND m.application_id=d.application_id
          AND m.dimension_id=r.dimension_id AND m.member_id=r.member_id''', (
            Jsonb({axis: sorted(members) for axis, members in references.items()}),
            scope.workspace_id, scope.application_id)).fetchall()
        checked_dimensions = set()
        for row in rows:
            axis = row["dimension_id"]
            if row["dimension_read"] is None or row["member_read"] is None:
                raise AccessDenied("APPLICABILITY_RELATION_SCOPE_UNAVAILABLE")
            if axis not in checked_dimensions:
                reference = ResolvedMemberSecurity(axis, axis, tuple(row["dimension_read"]),
                    tuple(row["dimension_write"]))
                if not metadata_reference_read_allowed(authority, reference):
                    raise AccessDenied("APPLICABILITY_RELATION_SCOPE_UNAVAILABLE")
                checked_dimensions.add(axis)
            reference = ResolvedMemberSecurity(axis, row["member_id"], tuple(row["member_read"]),
                tuple(row["member_write"]))
            if not metadata_reference_read_allowed(authority, reference):
                raise AccessDenied("APPLICABILITY_RELATION_SCOPE_UNAVAILABLE")

    def _recheck_read_access(self, db, scope, function, access):
        # Directory membership changes independently of the workspace fence.
        if PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, "read", function=function) != access:
            raise ValueError("APPLICABILITY_RELATION_AUTHORIZATION_STALE")

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
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "read", function=function)
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
                    # The complete token set and page come from one snapshot.
                    # Only the bounded page carries the column definitions.
                    rows = db.execute('''WITH page AS (
                        SELECT relation_id,name,columns,definition_digest,status,
                            metadata_revision,updated_at
                        FROM epm.applicability_relation_definition
                        WHERE workspace_id=%(workspace)s AND application_id=%(application)s
                          AND (%(after)s::text IS NULL OR relation_id>%(after)s)
                        ORDER BY relation_id LIMIT %(limit)s
                    )
                    SELECT d.relation_id,d.state_token,page.relation_id IS NOT NULL AS on_page,
                        page.name,page.columns,page.definition_digest,page.status,
                        page.metadata_revision,page.updated_at
                    FROM epm.application_state s
                    LEFT JOIN epm.applicability_relation_definition d USING (workspace_id,application_id)
                    LEFT JOIN page ON page.relation_id=d.relation_id
                    WHERE s.workspace_id=%(workspace)s AND s.application_id=%(application)s
                    ORDER BY d.relation_id''', {'workspace': scope.workspace_id,
                        'application': scope.application_id, 'after': after, 'limit': limit + 1}).fetchall()
                    if not rows:
                        raise ValueError("APPLICATION_UNAVAILABLE")
                    token = collection_token((row["relation_id"], row["state_token"])
                                             for row in rows if row["relation_id"] is not None)
                    if args.get("expectedCollectionToken", token) != token:
                        raise ValueError("APPLICABILITY_RELATION_LIST_STALE")
                    page = [row for row in rows if row["on_page"]]
                    values = [self._summary(row) for row in page[:limit]]
                    self._recheck_read_access(db, scope, function, access)
                    return {"applicabilityRelations": values,
                        "nextAfterRelationId": (values[-1]["relationId"]
                            if len(page) > limit else None),
                        "collectionToken": token}
                if set(args) != {"relationId"}:
                    raise ValueError("APPLICABILITY_RELATION_ARGUMENTS_INVALID")
                relation_id = _id(args["relationId"])
                # Aggregate once to avoid repeating the header for each row.
                row = db.execute('''SELECT d.relation_id,d.name,d.columns,d.state_token,
                    d.definition_digest,d.status,d.metadata_revision,d.updated_at,
                    s.metadata_revision AS current_metadata_revision,s.policy_revision,s.commit_revision,s.security_revision,
                    COALESCE((SELECT jsonb_agg(jsonb_build_object('rowId',r.row_id,'values',r.values)
                        ORDER BY r.row_id) FROM epm.applicability_relation_row r
                        WHERE r.workspace_id=d.workspace_id AND r.application_id=d.application_id
                          AND r.relation_id=d.relation_id), '[]'::jsonb) AS relation_rows
                    FROM epm.application_state s
                    LEFT JOIN epm.applicability_relation_definition d
                      ON d.workspace_id=s.workspace_id AND d.application_id=s.application_id
                      AND d.relation_id=%s
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    (relation_id, scope.workspace_id, scope.application_id)).fetchone()
                if row is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                if row["relation_id"] is None:
                    raise ValueError("APPLICABILITY_RELATION_NOT_FOUND")
                definition = {"format": "openepm-applicability-relation-v1",
                    "relationId": relation_id, "name": row["name"],
                    "columns": row["columns"], "rows": row["relation_rows"]}
                if applicability_relation_digest(definition) != row["definition_digest"]:
                    raise ValueError("APPLICABILITY_RELATION_STORAGE_CORRUPT")
                references = self._member_references(definition)
                if references:
                    authority = resolve_effective_dimensional_scope(db, self.identity, scope, access=access)
                    if authority.policy is not None:
                        self._authorize_member_references(db, scope, authority, references)
                        revisions = db.execute('''SELECT metadata_revision,security_revision
                            FROM epm.application_state WHERE workspace_id=%s AND application_id=%s''',
                            (scope.workspace_id, scope.application_id)).fetchone()
                        if revisions != {"metadata_revision": row["current_metadata_revision"],
                                         "security_revision": row["security_revision"]}:
                            raise ValueError("APPLICABILITY_RELATION_READ_STALE")
                self._recheck_read_access(db, scope, function, access)
                return {**self._summary(row), "definition": definition,
                    "currentMetadataRevision": row["current_metadata_revision"],
                    "policyRevision": row["policy_revision"],
                    "commitRevision": row["commit_revision"]}


def write_program_contract(function):
    """Project the existing relation lifecycle contract for both clients."""
    from .metadata_read_contract import obj, read_contract, read_example
    from .applicability_relation_contract import FORMAT, structural_schema_definitions

    identifier = {'type': 'string', 'pattern': '^' + _ID.pattern.removesuffix(r'\Z') + r'(?![\s\S])'}
    token = {'type': 'string', 'minLength': 64, 'maxLength': 64, 'pattern': '^[0-9a-f]{64}$'}
    revision = {'type': 'integer', 'minimum': 0}
    pins = {'expectedMetadataRevision': revision, 'expectedPolicyRevision': revision}
    example_pins = dict.fromkeys(pins, 1)
    relation = 'business-mapping'
    state = 'a' * 64
    lifecycle = {ACTIVATE: ('Active', 'Activate the exact saved or inactive relation'),
        DEACTIVATE: ('Inactive', 'Deactivate the exact active relation'),
        DELETE: ('Deleted', 'Delete the exact current relation')}
    if function == SAVE:
        status = 'Saved'
        arguments = obj({'definition': {'$ref': '#/$defs/applicabilityDefinition'}, **pins,
            'expectedStateToken': {'anyOf': [token, {'type': 'null'}]}}, ['definition', *pins])
        example = {'definition': {'format': FORMAT, 'relationId': relation,
            'name': 'Resource eligibility', 'columns': [
                {'columnId': 'Resource', 'type': 'Member', 'dimensionId': 'Resource'},
                {'columnId': 'Weight', 'type': 'Ratio', 'dimensionId': None}],
            'rows': [{'rowId': 'eligibility-a', 'values': {'Resource': 'ResourceA', 'Weight': '1.000000000000'}}]},
            **example_pins}
        binding = ('Use active dimension and member IDs from the selected application. '
            'Read metadataRevision and policyRevision from application.state.read.')
        examples = [read_example(function, example, name='Save a new business relation', binding=binding),
            read_example(function, {**example, 'expectedStateToken': state},
                name='Replace a current business relation', binding=binding +
                ' Read the current definition and copy its stateToken from metadata.applicability_relation.read.')]
    else:
        status, name = lifecycle[function]
        arguments = obj({'relationId': identifier, 'expectedStateToken': token, **pins})
        examples = [read_example(function, {'relationId': relation, 'expectedStateToken': state, **example_pins},
            name=name, binding='Read the current relation and copy relationId, stateToken, currentMetadataRevision '
                'and policyRevision into their corresponding request fields. Confirm the intended lifecycle effect.')]
    result = {'operationId': {'type': 'string', 'pattern': '^' + _KEY.pattern.removesuffix(r'\Z') + r'(?![\s\S])'},
        'relationId': identifier, 'status': {'const': status}, 'definitionDigest': token,
        'stateToken': {'type': 'null'} if function == DELETE else token,
        'metadataRevision': revision, 'policyRevision': revision, 'impactDigest': token}
    required = [field for field in result if function != SAVE or field != 'impactDigest']
    contract = read_contract(function, arguments, obj(result, required),
        owner='PostgresApplicabilityRelations.execute', examples=examples,
        definitions=structural_schema_definitions() if function == SAVE else None,
        semantic_rules=[
            'Every row has exactly the declared column IDs and values of the corresponding native types. '
            'Use strings for exact Amount and Ratio values. Row identity, tuple uniqueness and active '
            'dimension/member resolution are checked by the fixed core.',
            'A new relation has no prior state token. Replacement requires its exact current token. '
            'Save returns Saved. Replacing an Active relation removes its active pin and advances policy.',
            'Activate and Deactivate rotate the state token. Delete returns a null token. An operation '
            'that advances policy returns an impactDigest. These are receipts for the accepted effect.',
            'The authenticated scope, current rule authority and an operation ID bound to this exact '
            'intent are checked separately from the application program shape.',
        ])
    contract['programContract']['recovery'] = (
        'If the reply is lost, reconcile the original operation by its operationId or replay the exact '
        'accepted program with the same valid operation ID. For a definite stale refusal, re-read the '
        'application and relation, review the changed intent, then obtain a new operation ID.')
    return contract


def read_program_contract(function):
    if function not in READ_FUNCTIONS:
        return None
    from .metadata_read_contract import read_contract, read_example, obj
    from .applicability_relation_contract import structural_schema_definitions
    identifier = {'type': 'string', 'pattern': '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'}
    token = {'type': 'string', 'pattern': '^[0-9a-f]{64}$'}
    revision = {'type': 'integer', 'minimum': 0}
    definitions = structural_schema_definitions()
    summary = {'relationId': identifier, 'stateToken': token,
        'name': {'type': 'string', 'minLength': 1, 'maxLength': 200},
        'columns': {'$ref': '#/$defs/applicabilityColumns'},
        'definitionDigest': token, 'status': {'enum': ['Saved', 'Active', 'Inactive']},
        'definitionMetadataRevision': revision, 'updatedAt': {'type': 'string'}}
    if function == LIST:
        arguments = obj({'limit': {'type': 'integer', 'minimum': 1, 'maximum': 100},
            'afterRelationId': {'anyOf': [identifier, {'type': 'null'}]},
            'expectedCollectionToken': token}, [])
        arguments['allOf'] = [{'if': {'required': ['afterRelationId'],
            'properties': {'afterRelationId': {'type': 'string'}}},
            'then': {'required': ['expectedCollectionToken']}}]
        result = obj({'applicabilityRelations': {'type': 'array', 'maxItems': 100,
            'items': obj(summary)}, 'nextAfterRelationId': {'anyOf': [identifier, {'type': 'null'}]},
            'collectionToken': token})
        example = {'limit': 100}
        boundary = ('List returns relation summaries without row values. A listed summary does not grant '
                    'access to its complete definition.',)
    else:
        arguments = obj({'relationId': identifier})
        result = obj({**summary, 'definition': {'$ref': '#/$defs/applicabilityDefinition'},
            'currentMetadataRevision': revision, 'policyRevision': revision, 'commitRevision': revision})
        example = {'relationId': 'business-mapping'}
        boundary = ('Read returns the definition and application revisions from the same snapshot and '
                    'verifies the persisted canonical content before returning it.',
                    'The active dimensional read policy must permit every Member reference and its dimension. '
                    'An unavailable scope returns APPLICABILITY_RELATION_SCOPE_UNAVAILABLE instead of a partial definition.')
    contract = read_contract(function, arguments, result, owner='PostgresApplicabilityRelations.read',
        definitions=definitions,
        examples=[read_example(function, example, name='Inspect a current business applicability relation',
            binding='List needs no relation. Read uses an exact relationId from the authorized list.')],
        semantic_rules=['Relation row values have the exact declared column set and native column types; dynamic column/value correspondence, canonical digest and duplicate tuple checks remain native.',
            'Amounts and ratios are strings with native exact numeric limits, not binary floats. A relation is business mapping data, not worker partition state.',
            'A list page and its collectionToken describe the same snapshot. Continue with the returned '
            'nextAfterRelationId and collectionToken. A null nextAfterRelationId ends the list.',
            *boundary])
    contract['programContract']['recovery'] = (
        'On APPLICABILITY_RELATION_LIST_STALE, restart from the first page without the old '
        'cursor or collection token. On APPLICABILITY_RELATION_NOT_FOUND, list current '
        'relations and select an authorized relation ID. On APPLICABILITY_RELATION_AUTHORIZATION_STALE, '
        'check current application access and repeat the read. On APPLICABILITY_RELATION_READ_STALE, '
        'repeat the exact definition read with current dimensional metadata.')
    return contract
