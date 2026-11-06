"""Immutable PostgreSQL member-list registry and bounded evaluator."""

from __future__ import annotations

import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .member_list_contract import canonical_member_list_version, member_list_digest
from .member_list_evaluator import evaluate_member_list
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity, assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait, configure_statement_timeout


SAVE = "metadata.member_list.version.save"
READ = "metadata.member_list.version.read"
LIST = "metadata.member_list.version.list"
PUBLISH = "metadata.member_list.publish"
DEACTIVATE = "metadata.member_list.deactivate"
EVALUATE = "metadata.member_list.evaluate"
WRITE_FUNCTIONS = frozenset((SAVE, PUBLISH, DEACTIVATE))
READ_FUNCTIONS = frozenset((READ, LIST, EVALUATE))
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_KEY = re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_SLOT = re.compile(r"Custom(0[1-9]|[12][0-9]|30)\Z")


def catalog() -> dict:
    common = {"previewRequired": False, "workClass": "short"}
    return {
        SAVE: {**common, "mode": "immutable_definition_write",
               "permission": "rule_design", "idempotencyRequired": True,
               "arguments": {"definition": "canonical member-list v1 definition",
                   "expectedMetadataRevision": "current metadata revision",
                   "expectedPolicyRevision": "current policy revision"},
               "result": "immutable version, digest and receipt"},
        READ: {**common, "mode": "read", "permission": "read",
               "idempotencyRequired": False,
               "arguments": {"listId": "stable list ID"},
               "optionalArguments": {"version": "positive immutable version"},
               "result": "definition and current publication state"},
        LIST: {**common, "mode": "read", "permission": "read",
               "idempotencyRequired": False, "arguments": {},
               "optionalArguments": {"limit": "1-100",
                   "afterListId": "stable keyset cursor",
                   "expectedMetadataRevision": "cursor metadata revision",
                   "expectedPolicyRevision": "cursor policy revision"},
               "result": "bounded latest definitions and publication states"},
        PUBLISH: {**common, "mode": "atomic_publication",
                  "permission": "rule_publish", "idempotencyRequired": True,
                  "arguments": {"listId": "stable list ID",
                      "version": "saved immutable version",
                      "expectedStateRevision": "current list state revision",
                      "expectedMetadataRevision": "current metadata revision",
                      "expectedPolicyRevision": "current policy revision"},
                  "result": "published pointer and receipt"},
        DEACTIVATE: {**common, "mode": "atomic_publication",
                     "permission": "rule_publish", "idempotencyRequired": True,
                     "arguments": {"listId": "stable list ID",
                         "expectedStateRevision": "current list state revision",
                         "expectedMetadataRevision": "current metadata revision",
                         "expectedPolicyRevision": "current policy revision"},
                     "result": "inactive pointer and receipt"},
        EVALUATE: {**common, "mode": "read", "permission": "read",
                   "idempotencyRequired": False,
                   "arguments": {"listId": "stable list ID",
                       "version": "exact immutable version",
                       "parameters": "declared typed parameter bindings",
                       "expectedMetadataRevision": "current metadata revision"},
                   "result": "bounded stable member IDs with definition pin"},
    }


def _id(value: object) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("MEMBER_LIST_ID_INVALID")
    return value


def _program(raw: object, functions: set[str] | frozenset[str]) -> tuple[str, dict]:
    if (not isinstance(raw, dict)
            or set(raw) != {"languageVersion", "function", "arguments"}
            or raw.get("languageVersion") != 2
            or raw.get("function") not in functions
            or type(raw.get("arguments")) is not dict):
        raise ValueError("MEMBER_LIST_PROGRAM_INVALID")
    return raw["function"], raw["arguments"]


def _version(value: object) -> int:
    if type(value) is not int or value < 1:
        raise ValueError("MEMBER_LIST_VERSION_INVALID")
    return value


def _revision(value: object, code: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(code)
    return value


def _references(node: dict) -> tuple[set[str], set[str], set[str]]:
    members: set[str] = set()
    hierarchies: set[str] = set()
    attributes: set[str] = set()
    kind = node["kind"]
    if kind == "explicit":
        members.update(node["memberIds"])
    elif kind in {"children", "descendants", "ancestors", "siblings", "leaves"}:
        members.add(node["memberId"]); hierarchies.add(node["hierarchyId"])
    elif kind == "attribute":
        attributes.add(node["attributeId"])
    elif kind in {"union", "intersection"}:
        for item in node["items"]:
            child = _references(item)
            members.update(child[0]); hierarchies.update(child[1]); attributes.update(child[2])
    elif kind == "difference":
        for item in (node["source"], node["subtract"]):
            child = _references(item)
            members.update(child[0]); hierarchies.update(child[1]); attributes.update(child[2])
    elif kind == "order":
        child = _references(node["source"])
        members.update(child[0]); hierarchies.update(child[1]); attributes.update(child[2])
        if node["attributeId"] is not None:
            attributes.add(node["attributeId"])
    return members, hierarchies, attributes


class PostgresMemberLists:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("A verified identity is required")
        assert_nonowner_role(dsn, "epm_runtime",
            ("member_list_version", "member_list_publication"))
        self.dsn, self.identity = dsn, identity

    @staticmethod
    def _scope(db, scope: ApplicationScope) -> None:
        if not isinstance(scope, ApplicationScope):
            raise ValueError("MEMBER_LIST_SCOPE_INVALID")
        configure_lock_wait(db); configure_statement_timeout(db, 5000)
        PostgresNumericFactStore._set_scope(db, scope)

    @staticmethod
    def _validate_definition(db, scope: ApplicationScope, definition: dict) -> None:
        dimension = db.execute("""SELECT 1 FROM epm.dimension
            WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s
            AND status='Active'""", (scope.workspace_id, scope.application_id,
            definition["dimensionId"])).fetchone()
        if dimension is None:
            raise ValueError("MEMBER_LIST_DIMENSION_UNAVAILABLE")
        members, hierarchies, attributes = _references(definition["expression"])
        if hierarchies - {"primary", definition["dimensionId"]}:
            raise ValueError("MEMBER_LIST_HIERARCHY_UNAVAILABLE")
        if members:
            found = db.execute("""SELECT member_id FROM epm.member
                WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s
                AND status='Active' AND member_id=ANY(%s)""",
                (scope.workspace_id, scope.application_id,
                 definition["dimensionId"], list(members))).fetchall()
            if {row["member_id"] for row in found} != members:
                raise ValueError("MEMBER_LIST_MEMBER_UNAVAILABLE")
        for attribute in attributes:
            slot = int(attribute[6:]) if _SLOT.fullmatch(attribute) else None
            legacy = db.execute("""SELECT 1 FROM epm.semantic_column
                WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s
                AND scope='Member' AND ((%s::integer IS NOT NULL AND slot=%s)
                  OR (%s::integer IS NULL AND display_name=%s))""",
                (scope.workspace_id, scope.application_id,
                 definition["dimensionId"], slot, slot, slot, attribute)).fetchone()
            current = db.execute("""SELECT 1 FROM epm.attribute_definition
                WHERE workspace_id=%s AND application_id=%s
                  AND scope='Member' AND dimension_id=%s
                  AND attribute_id=%s AND status='Active'""",
                (scope.workspace_id, scope.application_id,
                 definition["dimensionId"], attribute)).fetchone()
            if legacy is not None and current is not None:
                raise ValueError("MEMBER_LIST_ATTRIBUTE_AMBIGUOUS")
            if legacy is None and current is None:
                raise ValueError("MEMBER_LIST_ATTRIBUTE_UNAVAILABLE")

    @staticmethod
    def _definition_result(row: dict | None, pointer: dict | None) -> dict | None:
        if row is None:
            return None
        published = (pointer is not None and pointer["status"] == "Published"
                     and pointer["version"] == row["version"])
        return {"listId": row["list_id"], "version": row["version"],
            "dimensionId": row["dimension_id"], "name": row["name"],
            "definition": row["definition"],
            "canonicalDigest": row["canonical_digest"],
            "definitionMetadataRevision": row["metadata_revision"],
            "createdRevision": row["created_revision"],
            "createdAt": row["created_at"].isoformat(),
            "status": "Published" if published else "Saved",
            "stateRevision": pointer["state_revision"] if pointer else 0}

    def execute(self, scope: ApplicationScope, raw: dict, *,
                idempotency_key: str) -> dict:
        function, args = _program(raw, WRITE_FUNCTIONS)
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(idempotency_key):
            raise ValueError("MEMBER_LIST_IDEMPOTENCY_KEY_INVALID")
        if function == SAVE:
            if set(args) != {"definition", "expectedMetadataRevision",
                             "expectedPolicyRevision"}:
                raise ValueError("MEMBER_LIST_ARGUMENTS_INVALID")
            definition = canonical_member_list_version(args["definition"])
            list_id = definition["listId"]; version = definition["version"]
        elif function == PUBLISH:
            if set(args) != {"listId", "version", "expectedStateRevision",
                             "expectedMetadataRevision", "expectedPolicyRevision"}:
                raise ValueError("MEMBER_LIST_ARGUMENTS_INVALID")
            list_id = _id(args["listId"]); version = _version(args["version"])
            definition = None
        else:
            if set(args) != {"listId", "expectedStateRevision",
                             "expectedMetadataRevision", "expectedPolicyRevision"}:
                raise ValueError("MEMBER_LIST_ARGUMENTS_INVALID")
            list_id = _id(args["listId"]); version = None; definition = None
        expected_metadata = _revision(args["expectedMetadataRevision"],
                                      "STALE_METADATA_REVISION")
        expected_policy = _revision(args["expectedPolicyRevision"],
                                    "STALE_POLICY_REVISION")
        expected_state = (_revision(args["expectedStateRevision"],
            "STALE_MEMBER_LIST_STATE_REVISION") if function != SAVE else None)
        command_digest = _canonical_digest({"scope":[scope.workspace_id,
            scope.application_id], "identity":[self.identity.issuer,
            self.identity.subject_id], "program":raw})
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                self._scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                state = db.execute("""SELECT s.metadata_revision,s.policy_revision,
                    s.commit_revision,s.processing_mode,a.status application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s""",
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                PostgresAccessChecker.check_in_transaction(db, self.identity, scope, "write")
                PostgresAccessChecker.check_in_transaction(db, self.identity, scope,
                    "rule_design" if function == SAVE else "rule_publish")
                prior = db.execute("""SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s""",
                    (scope.workspace_id, scope.application_id,
                     idempotency_key)).fetchone()
                if prior:
                    if (prior["command_digest"] != command_digest
                            or prior["actor_id"] != self.identity.subject_id):
                        raise ValueError("MEMBER_LIST_IDEMPOTENCY_CONFLICT")
                    return prior["result"]
                if (state["application_status"] != "Active"
                        or state["processing_mode"] != "Active"):
                    raise ValueError("APPLICATION_NOT_WRITABLE")
                if state["metadata_revision"] != expected_metadata:
                    raise ValueError("STALE_METADATA_REVISION")
                if state["policy_revision"] != expected_policy:
                    raise ValueError("STALE_POLICY_REVISION")
                pointer = db.execute("""SELECT version,status,state_revision
                    FROM epm.member_list_publication WHERE workspace_id=%s
                    AND application_id=%s AND list_id=%s FOR UPDATE""",
                    (scope.workspace_id, scope.application_id, list_id)).fetchone()
                if expected_state is not None and (pointer["state_revision"]
                        if pointer else 0) != expected_state:
                    raise ValueError("STALE_MEMBER_LIST_STATE_REVISION")
                commit = state["commit_revision"] + 1
                policy = state["policy_revision"]
                if function == SAVE:
                    latest = db.execute("""SELECT version,canonical_digest
                        FROM epm.member_list_version WHERE workspace_id=%s
                        AND application_id=%s AND list_id=%s
                        ORDER BY version DESC LIMIT 1""",
                        (scope.workspace_id, scope.application_id, list_id)).fetchone()
                    if version != (latest["version"] if latest else 0) + 1:
                        raise ValueError("MEMBER_LIST_VERSION_NOT_NEXT")
                    self._validate_definition(db, scope, definition)
                    canonical_digest = member_list_digest(definition)
                    result = {"operationId":idempotency_key,"listId":list_id,
                        "version":version,"status":"Saved",
                        "canonicalDigest":canonical_digest,
                        "metadataRevision":expected_metadata,
                        "policyRevision":policy,"committedRevision":commit}
                elif function == PUBLISH:
                    row = db.execute("""SELECT canonical_digest,metadata_revision
                        FROM epm.member_list_version WHERE workspace_id=%s
                        AND application_id=%s AND list_id=%s AND version=%s""",
                        (scope.workspace_id, scope.application_id,
                         list_id, version)).fetchone()
                    if row is None:
                        raise ValueError("MEMBER_LIST_VERSION_UNAVAILABLE")
                    if row["metadata_revision"] != expected_metadata:
                        raise ValueError("MEMBER_LIST_METADATA_STALE")
                    if pointer and pointer["status"] == "Published" and pointer["version"] == version:
                        raise ValueError("MEMBER_LIST_VERSION_ALREADY_PUBLISHED")
                    policy += 1
                    result = {"operationId":idempotency_key,"listId":list_id,
                        "version":version,"status":"Published",
                        "canonicalDigest":row["canonical_digest"],
                        "stateRevision":expected_state+1,
                        "policyRevision":policy,"committedRevision":commit}
                else:
                    if pointer is None or pointer["status"] != "Published":
                        raise ValueError("MEMBER_LIST_NOT_PUBLISHED")
                    policy += 1
                    result = {"operationId":idempotency_key,"listId":list_id,
                        "version":None,"status":"Inactive",
                        "stateRevision":expected_state+1,
                        "policyRevision":policy,"committedRevision":commit}
                db.execute("""UPDATE epm.application_state SET
                    policy_revision=%s,commit_revision=%s WHERE workspace_id=%s
                    AND application_id=%s""", (policy, commit,
                    scope.workspace_id, scope.application_id))
                db.execute("""INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,command_digest,
                     actor_id,committed_revision,result)
                    VALUES(%s,%s,%s,%s,%s,%s,%s)""", (scope.workspace_id,
                    scope.application_id,idempotency_key,command_digest,
                    self.identity.subject_id,commit,Jsonb(result)))
                if function == SAVE:
                    db.execute("""INSERT INTO epm.member_list_version
                        (workspace_id,application_id,list_id,version,dimension_id,
                         name,definition,canonical_digest,metadata_revision,
                         created_operation_id,created_revision,creator_issuer,
                         creator_subject_id) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,
                         %s,%s,%s,%s,%s)""", (scope.workspace_id,
                        scope.application_id,list_id,version,
                        definition["dimensionId"],definition["name"],
                        Jsonb(definition),canonical_digest,expected_metadata,
                        idempotency_key,commit,self.identity.issuer,
                        self.identity.subject_id))
                else:
                    db.execute("""INSERT INTO epm.member_list_publication
                        (workspace_id,application_id,list_id,version,status,
                         state_revision,operation_id) VALUES(%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT(workspace_id,application_id,list_id)
                        DO UPDATE SET version=EXCLUDED.version,status=EXCLUDED.status,
                          state_revision=EXCLUDED.state_revision,
                          operation_id=EXCLUDED.operation_id,
                          updated_at=transaction_timestamp()""",
                        (scope.workspace_id,scope.application_id,list_id,
                         version if function == PUBLISH else None,
                         "Published" if function == PUBLISH else "Inactive",
                         expected_state+1,idempotency_key))
                return result

    def read(self, scope: ApplicationScope, raw: dict) -> dict:
        function, args = _program(raw, READ_FUNCTIONS)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION READ ONLY")
                self._scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "read", function=function)
                state = db.execute("""SELECT metadata_revision,policy_revision,
                    commit_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s""",
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                if function == LIST:
                    if set(args) - {"limit","afterListId","expectedMetadataRevision",
                                    "expectedPolicyRevision"}:
                        raise ValueError("MEMBER_LIST_ARGUMENTS_INVALID")
                    limit=args.get("limit",100); after=args.get("afterListId")
                    if type(limit) is not int or not 1 <= limit <= 100:
                        raise ValueError("MEMBER_LIST_LIMIT_INVALID")
                    if after is not None: _id(after)
                    for field, column in (("expectedMetadataRevision","metadata_revision"),
                                          ("expectedPolicyRevision","policy_revision")):
                        if field in args and args[field] != state[column]:
                            raise ValueError("STALE_MEMBER_LIST_LIST_REVISION")
                    rows=db.execute("""SELECT DISTINCT ON(v.list_id) v.*,
                        p.version published_version,p.status publication_status,
                        p.state_revision FROM epm.member_list_version v
                        LEFT JOIN epm.member_list_publication p USING(
                          workspace_id,application_id,list_id)
                        WHERE v.workspace_id=%s AND v.application_id=%s
                        AND (%s::text IS NULL OR v.list_id>%s)
                        ORDER BY v.list_id,v.version DESC LIMIT %s""",
                        (scope.workspace_id,scope.application_id,after,after,
                         limit+1)).fetchall()
                    values=[]
                    for row in rows[:limit]:
                        pointer={"version":row["published_version"],
                            "status":row["publication_status"],
                            "state_revision":row["state_revision"]} if row[
                                "publication_status"] else None
                        values.append(self._definition_result(row,pointer))
                    return {"memberLists":values,
                        "nextAfterListId":values[-1]["listId"] if len(rows)>limit else None,
                        "metadataRevision":state["metadata_revision"],
                        "policyRevision":state["policy_revision"]}
                if function == READ:
                    if set(args) not in ({"listId"},{"listId","version"}):
                        raise ValueError("MEMBER_LIST_ARGUMENTS_INVALID")
                    list_id=_id(args["listId"])
                    requested=_version(args["version"]) if "version" in args else None
                else:
                    if set(args) != {"listId","version","parameters",
                                     "expectedMetadataRevision"}:
                        raise ValueError("MEMBER_LIST_ARGUMENTS_INVALID")
                    list_id=_id(args["listId"]); requested=_version(args["version"])
                    if type(args["parameters"]) is not dict or len(args["parameters"])>100:
                        raise ValueError("MEMBER_LIST_PARAMETERS_INVALID")
                    if args["expectedMetadataRevision"] != state["metadata_revision"]:
                        raise ValueError("STALE_METADATA_REVISION")
                pointer=db.execute("""SELECT version,status,state_revision
                    FROM epm.member_list_publication WHERE workspace_id=%s
                    AND application_id=%s AND list_id=%s""",
                    (scope.workspace_id,scope.application_id,list_id)).fetchone()
                version=requested if requested is not None else (
                    pointer["version"] if pointer and pointer["status"]=="Published" else None)
                if version is None:
                    row=db.execute("""SELECT * FROM epm.member_list_version
                        WHERE workspace_id=%s AND application_id=%s AND list_id=%s
                        ORDER BY version DESC LIMIT 1""",
                        (scope.workspace_id,scope.application_id,list_id)).fetchone()
                else:
                    row=db.execute("""SELECT * FROM epm.member_list_version
                        WHERE workspace_id=%s AND application_id=%s AND list_id=%s
                        AND version=%s""", (scope.workspace_id,
                        scope.application_id,list_id,version)).fetchone()
                if row is None:
                    raise ValueError("MEMBER_LIST_VERSION_UNAVAILABLE")
                if function == READ:
                    return {**self._definition_result(row,pointer),
                        "currentMetadataRevision":state["metadata_revision"],
                        "policyRevision":state["policy_revision"],
                        "commitRevision":state["commit_revision"]}
                if row["metadata_revision"] != state["metadata_revision"]:
                    raise ValueError("MEMBER_LIST_METADATA_STALE")
                dimension=row["dimension_id"]
                member_rows=db.execute("""SELECT member_id,name,custom_values
                    FROM epm.member WHERE workspace_id=%s AND application_id=%s
                    AND dimension_id=%s AND status='Active' ORDER BY member_id""",
                    (scope.workspace_id,scope.application_id,dimension)).fetchall()
                relation_rows=db.execute("""SELECT parent_member_id,child_member_id
                    FROM epm.relationship WHERE workspace_id=%s AND application_id=%s
                    AND dimension_id=%s AND status='Active'
                    ORDER BY parent_member_id,child_member_id""",
                    (scope.workspace_id,scope.application_id,dimension)).fetchall()
                columns=db.execute("""SELECT slot,display_name,properties
                    FROM epm.semantic_column WHERE workspace_id=%s
                    AND application_id=%s AND dimension_id=%s AND scope='Member'""",
                    (scope.workspace_id,scope.application_id,dimension)).fetchall()
                definitions=db.execute("""SELECT attribute_id,value_type
                    FROM epm.attribute_definition WHERE workspace_id=%s
                    AND application_id=%s AND dimension_id=%s
                    AND scope='Member' AND status='Active'""",
                    (scope.workspace_id,scope.application_id,dimension)).fetchall()
                types={f"Custom{column['slot']:02d}":column["properties"]["valueType"]
                       for column in columns}
                types.update({column["display_name"]:column["properties"]["valueType"]
                              for column in columns})
                for definition in definitions:
                    if definition["attribute_id"] in types:
                        raise ValueError("MEMBER_LIST_ATTRIBUTE_AMBIGUOUS")
                    types[definition["attribute_id"]] = definition["value_type"]
                attributes={item["member_id"]:{**item["custom_values"], **{
                    column["display_name"]:item["custom_values"].get(
                        f"Custom{column['slot']:02d}") for column in columns}}
                    for item in member_rows}
                members={item["member_id"]:item["name"] for item in member_rows}
                resolved=evaluate_member_list(row["definition"],members=members,
                    relationships=[(item["parent_member_id"],item["child_member_id"])
                                   for item in relation_rows],attributes=attributes,
                    attribute_types=types,parameters=args["parameters"])
                end=db.execute("""SELECT metadata_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s""",
                    (scope.workspace_id,scope.application_id)).fetchone()
                if end is None or end["metadata_revision"] != state["metadata_revision"]:
                    raise ValueError("METADATA_CHANGED_DURING_MEMBER_LIST_EVALUATION")
                return {"listId":list_id,"version":row["version"],
                    "dimensionId":dimension,"memberIds":resolved,
                    "memberCount":len(resolved),
                    "canonicalDigest":row["canonical_digest"],
                    "metadataRevision":state["metadata_revision"],
                    "stateRevision":pointer["state_revision"] if pointer else 0,
                    "status":("Published" if pointer and pointer["status"]=="Published"
                              and pointer["version"]==row["version"] else "Saved")}
