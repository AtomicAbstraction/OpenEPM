"""Governed extensible metadata attributes on PostgreSQL.

The catalogue is the schema-247 authority for new definitions. Legacy
``metadata.semantic_column.*`` functions remain a compatibility boundary until
their admitted consumers are migrated; this module never invents physical
columns or evaluates caller SQL.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .current_object_contract import new_state_token, require_state_token
from .persistence_contract import ApplicationScope, NumericCell
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout


DEFINITION_CREATE = "metadata.attribute-definition.create"
DEFINITION_UPDATE = "metadata.attribute-definition.update"
DEFINITION_STATUS = "metadata.attribute-definition.status.set"
DEFINITION_LIST = "metadata.attribute-definition.list"
DEFINITION_USAGE = "metadata.attribute-definition.usage.read"
VALUE_SET = "metadata.attribute-value.set"
VALUES_REPLACE = "metadata.attribute-values.replace"
VALUE_READ = "metadata.attribute-value.read"

WRITE_FUNCTIONS = frozenset((
    DEFINITION_CREATE, DEFINITION_UPDATE, DEFINITION_STATUS, VALUE_SET,
    VALUES_REPLACE))
READ_FUNCTIONS = frozenset((DEFINITION_LIST, DEFINITION_USAGE, VALUE_READ))

_SCOPES = frozenset(("Dimension", "Member", "Relationship"))
_TYPES = frozenset(("Text", "Decimal", "Boolean", "MemberReference"))
_ID = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,199}\Z")
_KEY = re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_MAX_DEFINITIONS_PER_CONTEXT = 200
_MAX_REPLACE_OBJECTS = 1000
_MAX_REPLACE_VALUES = 100000
_MAX_REPLACE_BYTES = 16 * 1024 * 1024


def _exact_active_definition_inventory(rows: list[dict],
                                       requested: list[str]) -> bool:
    """Compare identities, never database/Python collation order."""
    return (len(rows) == len(requested)
            and {row["attribute_id"] for row in rows} == set(requested))


def _text(value: object, maximum: int, *, required: bool = False) -> str:
    if (not isinstance(value, str) or len(value) > maximum or "\x00" in value
            or (required and (not value or value != value.strip()))):
        raise ValueError("ATTRIBUTE_TEXT_INVALID")
    return value


def _id(value: object) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("ATTRIBUTE_ID_INVALID")
    return value


def _scope(value: object) -> str:
    if not isinstance(value, str) or value not in _SCOPES:
        raise ValueError("ATTRIBUTE_SCOPE_INVALID")
    return value


def _context(scope: str, args: dict) -> str:
    dimension = args.get("dimensionId")
    if scope == "Dimension":
        if dimension is not None:
            raise ValueError("ATTRIBUTE_DIMENSION_CONTEXT_FORBIDDEN")
        return ""
    return _id(dimension)


def _program(program: object, function: str, required: set[str],
             optional: set[str] = frozenset()) -> dict:
    if (not isinstance(program, dict)
            or set(program) != {"languageVersion", "function", "arguments"}
            or program.get("languageVersion") != 2
            or type(program.get("languageVersion")) is not int
            or program.get("function") != function
            or not isinstance(program.get("arguments"), dict)
            or not required <= set(program["arguments"])
            or set(program["arguments"]) - (required | optional)):
        raise ValueError("ATTRIBUTE_PROGRAM_INVALID")
    return program["arguments"]


def _definition_context(args: dict) -> tuple[str, str, str]:
    scope = _scope(args["scope"])
    return scope, _context(scope, args), _id(args["attributeId"])


def _constraints(kind: str, value: object) -> dict:
    if not isinstance(value, dict) or len(value) > 8:
        raise ValueError("ATTRIBUTE_CONSTRAINTS_INVALID")
    allowed = {"allowedValues", "referenceDimensionId", "maximumLength",
               "minimum", "maximum"}
    if set(value) - allowed:
        raise ValueError("ATTRIBUTE_CONSTRAINTS_INVALID")
    result = dict(value)
    choices = result.get("allowedValues")
    if choices is not None:
        if (kind != "Text" or not isinstance(choices, list)
                or len(choices) > 1000 or len(set(choices)) != len(choices)
                or any(not isinstance(item, str) or not item
                       or len(item) > 200 or "\x00" in item
                       for item in choices)):
            raise ValueError("ATTRIBUTE_ALLOWED_VALUES_INVALID")
    reference = result.get("referenceDimensionId")
    if kind == "MemberReference":
        result["referenceDimensionId"] = _id(reference)
    elif reference is not None:
        raise ValueError("ATTRIBUTE_REFERENCE_DIMENSION_INVALID")
    maximum = result.get("maximumLength")
    if maximum is not None and (kind != "Text" or type(maximum) is not int
                                or not 1 <= maximum <= 10000):
        raise ValueError("ATTRIBUTE_MAXIMUM_LENGTH_INVALID")
    for key in ("minimum", "maximum"):
        if key in result:
            if kind != "Decimal" or not isinstance(result[key], str):
                raise ValueError("ATTRIBUTE_DECIMAL_BOUND_INVALID")
            try:
                number = Decimal(result[key])
                NumericCell(True, number, "")
            except (InvalidOperation, ValueError) as error:
                raise ValueError("ATTRIBUTE_DECIMAL_BOUND_INVALID") from error
    if "minimum" in result and "maximum" in result:
        if Decimal(result["minimum"]) > Decimal(result["maximum"]):
            raise ValueError("ATTRIBUTE_DECIMAL_RANGE_INVALID")
    return result


def _typed_value(db, application: ApplicationScope, definition: dict,
                 supplied: object) -> object:
    if supplied is None:
        return None
    kind = definition["value_type"]
    constraints = definition["validation_constraints"]
    if kind == "Text":
        maximum = constraints.get("maximumLength", 10000)
        value = _text(supplied, maximum)
        choices = constraints.get("allowedValues")
        if choices and value not in choices:
            raise ValueError("ATTRIBUTE_VALUE_CHOICE_INVALID")
        return value
    if kind == "Boolean":
        if type(supplied) is not bool:
            raise ValueError("ATTRIBUTE_VALUE_BOOLEAN_INVALID")
        return supplied
    if kind == "Decimal":
        if not isinstance(supplied, str):
            raise ValueError("ATTRIBUTE_VALUE_DECIMAL_STRING_REQUIRED")
        try:
            number = Decimal(supplied)
            NumericCell(True, number, "")
        except (InvalidOperation, ValueError) as error:
            raise ValueError("ATTRIBUTE_VALUE_DECIMAL_INVALID") from error
        if ("minimum" in constraints
                and number < Decimal(constraints["minimum"])):
            raise ValueError("ATTRIBUTE_VALUE_BELOW_MINIMUM")
        if ("maximum" in constraints
                and number > Decimal(constraints["maximum"])):
            raise ValueError("ATTRIBUTE_VALUE_ABOVE_MAXIMUM")
        return format(number, ".8f")
    if kind == "MemberReference":
        member = _id(supplied)
        found = db.execute("""SELECT 1 FROM epm.member
            WHERE workspace_id=%s AND application_id=%s
              AND dimension_id=%s AND member_id=%s AND status='Active'""",
            (application.workspace_id, application.application_id,
             constraints["referenceDimensionId"], member)).fetchone()
        if found is None:
            raise ValueError("ATTRIBUTE_REFERENCE_MEMBER_UNAVAILABLE")
        return member
    raise ValueError("ATTRIBUTE_VALUE_TYPE_INVALID")


class PostgresAttributeCatalog:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError("A PostgreSQL runtime DSN is required")
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("A verified identity is required")
        self.dsn = dsn
        self.identity = identity

    @staticmethod
    def _definition_payload(function: str, args: dict) -> dict:
        scope, dimension, attribute = _definition_context(args)
        payload = {"scope": scope, "dimensionId": dimension,
                   "attributeId": attribute}
        if function == DEFINITION_CREATE:
            kind = args["valueType"]
            if kind not in _TYPES:
                raise ValueError("ATTRIBUTE_VALUE_TYPE_INVALID")
            payload.update({
                "defaultName": _text(args["defaultName"], 200, required=True),
                "displayName": _text(args["displayName"], 200, required=True),
                "shortDescription": _text(args["shortDescription"], 500),
                "semanticDescription": _text(
                    args["semanticDescription"], 10000),
                "valueType": kind,
                "validationConstraints": _constraints(
                    kind, args["validationConstraints"]),
            })
        elif function == DEFINITION_UPDATE:
            kind = args["valueType"]
            if kind not in _TYPES:
                raise ValueError("ATTRIBUTE_VALUE_TYPE_INVALID")
            payload.update({
                "displayName": _text(args["displayName"], 200, required=True),
                "shortDescription": _text(args["shortDescription"], 500),
                "semanticDescription": _text(
                    args["semanticDescription"], 10000),
                "valueType": kind,
                "validationConstraints": _constraints(
                    kind, args["validationConstraints"]),
                "expectedStateToken": require_state_token(
                    args["expectedStateToken"],
                    error="ATTRIBUTE_STATE_TOKEN_INVALID"),
            })
        elif function == DEFINITION_STATUS:
            if args["status"] not in ("Active", "Inactive"):
                raise ValueError("ATTRIBUTE_STATUS_INVALID")
            payload.update({"status": args["status"],
                            "expectedStateToken": require_state_token(
                                args["expectedStateToken"],
                                error="ATTRIBUTE_STATE_TOKEN_INVALID")})
        return payload

    @staticmethod
    def _definition(db, application: ApplicationScope, payload: dict,
                    *, lock: bool = False) -> dict | None:
        return db.execute("""SELECT attribute_id,default_name,display_name,
                short_description,semantic_description,value_type,
                validation_constraints,status,state_token
            FROM epm.attribute_definition
            WHERE workspace_id=%s AND application_id=%s AND scope=%s
              AND dimension_id=%s AND attribute_id=%s""" +
            (" FOR UPDATE" if lock else ""),
            (application.workspace_id, application.application_id,
             payload["scope"], payload["dimensionId"],
             payload["attributeId"])).fetchone()

    @staticmethod
    def _usage(db, application: ApplicationScope, scope: str,
               dimension: str, attribute: str, *, limit: int = 50) -> dict:
        table, id_column = {
            "Dimension": ("dimension", "dimension_id"),
            "Member": ("member", "member_id"),
            "Relationship": ("relationship", "relationship_id"),
        }[scope]
        where = "" if scope == "Dimension" else " AND dimension_id=%s"
        parameters: tuple = (application.workspace_id,
                             application.application_id)
        if scope != "Dimension":
            parameters += (dimension,)
        parameters += (attribute,)
        rows = db.execute("SELECT " + id_column + " object_id FROM epm." +
            table + " WHERE workspace_id=%s AND application_id=%s" + where +
            " AND custom_values ? %s ORDER BY " + id_column + " LIMIT " +
            str(limit + 1), parameters).fetchall()
        count = db.execute("SELECT count(*) n FROM epm." + table +
            " WHERE workspace_id=%s AND application_id=%s" + where +
            " AND custom_values ? %s", parameters).fetchone()["n"]
        return {"valueCount": count,
                "sampleObjectIds": [row["object_id"] for row in rows[:limit]],
                "sampleTruncated": len(rows) > limit}

    def execute(self, application: ApplicationScope, program: dict, *,
                idempotency_key: str) -> dict:
        if not isinstance(application, ApplicationScope):
            raise ValueError("Application scope is required")
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(
                idempotency_key):
            raise ValueError("ATTRIBUTE_IDEMPOTENCY_KEY_INVALID")
        function = program.get("function") if isinstance(program, dict) else None
        if function == DEFINITION_CREATE:
            args = _program(program, function, {
                "scope", "attributeId", "defaultName", "displayName",
                "shortDescription", "semanticDescription", "valueType",
                "validationConstraints", "expectedMetadataRevision"},
                {"dimensionId"})
            payload = self._definition_payload(function, args)
        elif function == DEFINITION_UPDATE:
            args = _program(program, function, {
                "scope", "attributeId", "displayName", "shortDescription",
                "semanticDescription", "valueType", "validationConstraints",
                "expectedStateToken", "expectedMetadataRevision"},
                {"dimensionId"})
            payload = self._definition_payload(function, args)
        elif function == DEFINITION_STATUS:
            args = _program(program, function, {
                "scope", "attributeId", "status", "expectedStateToken",
                "expectedMetadataRevision"}, {"dimensionId"})
            payload = self._definition_payload(function, args)
        elif function == VALUE_SET:
            args = _program(program, function, {
                "scope", "attributeId", "objectId", "value",
                "expectedMetadataRevision"}, {"dimensionId"})
            scope, dimension, attribute = _definition_context(args)
            payload = {"scope": scope, "dimensionId": dimension,
                       "attributeId": attribute,
                       "objectId": _id(args["objectId"]),
                       "value": args["value"]}
        elif function == VALUES_REPLACE:
            args = _program(program, function, {
                "scope", "dimensionId", "attributeIds", "rows",
                "expectedMetadataRevision"})
            if args["scope"] != "Member":
                raise ValueError("ATTRIBUTE_REPLACE_SCOPE_INVALID")
            dimension = _id(args["dimensionId"])
            attribute_ids = args["attributeIds"]
            rows = args["rows"]
            if (not isinstance(attribute_ids, list)
                    or not 1 <= len(attribute_ids) <=
                    _MAX_DEFINITIONS_PER_CONTEXT
                    or len(set(attribute_ids)) != len(attribute_ids)):
                raise ValueError("ATTRIBUTE_REPLACE_DEFINITIONS_INVALID")
            attribute_ids = [_id(value) for value in attribute_ids]
            if (not isinstance(rows, list)
                    or not 1 <= len(rows) <= _MAX_REPLACE_OBJECTS):
                raise ValueError("ATTRIBUTE_REPLACE_ROWS_INVALID")
            normalized_rows = []
            seen = set()
            value_count = 0
            for row in rows:
                if (not isinstance(row, dict)
                        or set(row) != {"objectId", "values"}
                        or not isinstance(row["values"], dict)):
                    raise ValueError("ATTRIBUTE_REPLACE_ROW_INVALID")
                object_id = _id(row["objectId"])
                if object_id in seen:
                    raise ValueError("ATTRIBUTE_REPLACE_OBJECT_DUPLICATE")
                seen.add(object_id)
                if set(row["values"]) - set(attribute_ids):
                    raise ValueError("ATTRIBUTE_REPLACE_VALUE_UNDECLARED")
                value_count += len(row["values"])
                normalized_rows.append({"objectId": object_id,
                                        "values": dict(row["values"])})
            if value_count > _MAX_REPLACE_VALUES:
                raise ValueError("ATTRIBUTE_REPLACE_VALUE_LIMIT")
            payload = {"scope": "Member", "dimensionId": dimension,
                       "attributeIds": attribute_ids,
                       "rows": normalized_rows}
            if len(json.dumps(payload, ensure_ascii=False, sort_keys=True,
                              separators=(",", ":"), allow_nan=False
                              ).encode("utf-8")) > \
                    _MAX_REPLACE_BYTES:
                raise ValueError("ATTRIBUTE_REPLACE_BYTES_LIMIT")
        else:
            raise ValueError("ATTRIBUTE_PROGRAM_INVALID")
        expected = args["expectedMetadataRevision"]
        if type(expected) is not int or expected < 0:
            raise ValueError("STALE_METADATA_REVISION")
        digest = _canonical_digest(program)
        payload_digest = _canonical_digest({
            "application": [application.workspace_id,
                            application.application_id],
            "identity": [self.identity.issuer, self.identity.subject_id],
            "payload": payload, "expectedMetadataRevision": expected})
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, application)
                state = db.execute("""SELECT a.status,s.processing_mode,
                        s.metadata_revision,s.commit_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s""",
                    (application.workspace_id,
                     application.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, application, "admin")
                prior = db.execute("""SELECT command_digest,
                        committed_revision,result FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s
                      AND operation_id=%s""",
                    (application.workspace_id, application.application_id,
                     idempotency_key)).fetchone()
                if prior is not None:
                    if (prior["command_digest"] != digest
                            or prior["result"].get("payloadDigest") !=
                            payload_digest):
                        raise ValueError("ATTRIBUTE_IDEMPOTENCY_CONFLICT")
                    PostgresNumericFactStore._require_replay_impact(
                        db,application,idempotency_key,prior)
                    return {**prior["result"],
                            "operationId": idempotency_key,
                            "committedRevision": prior["committed_revision"],
                            "duplicate": True}
                if (state["status"] != "Active"
                        or state["processing_mode"] != "Active"):
                    raise ValueError("APPLICATION_NOT_WRITABLE")
                if state["metadata_revision"] != expected:
                    raise ValueError("STALE_METADATA_REVISION")
                keys = (application.workspace_id,
                        application.application_id)
                current = (None if function == VALUES_REPLACE else
                           self._definition(db, application, payload,
                                            lock=True))
                if function == DEFINITION_CREATE:
                    if current is not None:
                        raise ValueError("ATTRIBUTE_DEFINITION_EXISTS")
                    if payload["scope"] != "Dimension" and db.execute(
                            """SELECT 1 FROM epm.dimension
                            WHERE workspace_id=%s AND application_id=%s
                              AND dimension_id=%s AND status='Active'""",
                            (*keys, payload["dimensionId"])).fetchone() is None:
                        raise ValueError("ACTIVE_DIMENSION_REQUIRED")
                    count = db.execute("""SELECT count(*) n
                        FROM epm.attribute_definition
                        WHERE workspace_id=%s AND application_id=%s
                          AND scope=%s AND dimension_id=%s""",
                        (*keys, payload["scope"],
                         payload["dimensionId"])).fetchone()["n"]
                    if count >= _MAX_DEFINITIONS_PER_CONTEXT:
                        raise ValueError("ATTRIBUTE_DEFINITION_LIMIT")
                    constraints = payload["validationConstraints"]
                    if payload["valueType"] == "MemberReference":
                        if db.execute("""SELECT 1 FROM epm.dimension
                                WHERE workspace_id=%s AND application_id=%s
                                  AND dimension_id=%s AND status='Active'""",
                                (*keys, constraints[
                                    "referenceDimensionId"])).fetchone() is None:
                            raise ValueError(
                                "ATTRIBUTE_REFERENCE_DIMENSION_UNAVAILABLE")
                    state_token = new_state_token()
                    db.execute("""INSERT INTO epm.attribute_definition(
                        workspace_id,application_id,scope,dimension_id,
                        attribute_id,default_name,display_name,
                        short_description,semantic_description,value_type,
                        validation_constraints,state_token)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (*keys, payload["scope"], payload["dimensionId"],
                         payload["attributeId"], payload["defaultName"],
                         payload["displayName"], payload["shortDescription"],
                         payload["semanticDescription"], payload["valueType"],
                         Jsonb(constraints),state_token))
                elif function in (DEFINITION_UPDATE, DEFINITION_STATUS):
                    if current is None:
                        raise ValueError("ATTRIBUTE_DEFINITION_UNAVAILABLE")
                    if current["state_token"] != payload["expectedStateToken"]:
                        raise ValueError("STALE_ATTRIBUTE_STATE_TOKEN")
                    state_token = new_state_token()
                    usage = self._usage(db, application, payload["scope"],
                                        payload["dimensionId"],
                                        payload["attributeId"], limit=1)
                    if function == DEFINITION_UPDATE:
                        if (usage["valueCount"] and
                                (current["value_type"] != payload["valueType"]
                                 or current["validation_constraints"] !=
                                 payload["validationConstraints"])):
                            raise ValueError(
                                "ATTRIBUTE_DEFINITION_IN_USE_TYPE_IMMUTABLE")
                        db.execute("""UPDATE epm.attribute_definition SET
                            display_name=%s,short_description=%s,
                            semantic_description=%s,value_type=%s,
                            validation_constraints=%s,state_token=%s
                            WHERE workspace_id=%s AND application_id=%s
                              AND scope=%s AND dimension_id=%s
                              AND attribute_id=%s""",
                            (payload["displayName"],
                             payload["shortDescription"],
                             payload["semanticDescription"],
                             payload["valueType"],
                             Jsonb(payload["validationConstraints"]),state_token,*keys,
                             payload["scope"], payload["dimensionId"],
                             payload["attributeId"]))
                    else:
                        if current["status"] == payload["status"]:
                            raise ValueError("ATTRIBUTE_STATUS_UNCHANGED")
                        if (payload["status"] == "Inactive"
                                and usage["valueCount"]):
                            raise ValueError("ATTRIBUTE_DEFINITION_IN_USE")
                        db.execute("""UPDATE epm.attribute_definition
                            SET status=%s,state_token=%s
                            WHERE workspace_id=%s AND application_id=%s
                              AND scope=%s AND dimension_id=%s
                              AND attribute_id=%s""",
                            (payload["status"],state_token,*keys,payload["scope"],
                             payload["dimensionId"], payload["attributeId"]))
                elif function == VALUE_SET:
                    if current is None or current["status"] != "Active":
                        raise ValueError("ACTIVE_ATTRIBUTE_DEFINITION_REQUIRED")
                    table, id_column = {
                        "Dimension": ("dimension", "dimension_id"),
                        "Member": ("member", "member_id"),
                        "Relationship": ("relationship", "relationship_id"),
                    }[payload["scope"]]
                    where = "" if payload["scope"] == "Dimension" else (
                        " AND dimension_id=%s")
                    parameters: tuple = (*keys,)
                    if payload["scope"] != "Dimension":
                        parameters += (payload["dimensionId"],)
                    parameters += (payload["objectId"],)
                    record = db.execute("SELECT custom_values FROM epm." +
                        table + " WHERE workspace_id=%s AND application_id=%s" +
                        where + " AND " + id_column + "=%s AND status='Active'"
                        " FOR UPDATE", parameters).fetchone()
                    if record is None:
                        raise ValueError("ACTIVE_ATTRIBUTE_OBJECT_REQUIRED")
                    value = _typed_value(db, application, current,
                                         payload["value"])
                    values = dict(record["custom_values"])
                    before = values.get(payload["attributeId"])
                    if value is None:
                        values.pop(payload["attributeId"], None)
                    else:
                        values[payload["attributeId"]] = value
                    if before == value:
                        raise ValueError("ATTRIBUTE_VALUE_UNCHANGED")
                    db.execute("UPDATE epm." + table + " SET custom_values=%s,"
                        " updated_at=transaction_timestamp()"
                        " WHERE workspace_id=%s AND application_id=%s" + where +
                        " AND " + id_column + "=%s",
                        (Jsonb(values), *parameters))
                    state_token = current["state_token"]
                else:
                    definitions = db.execute("""SELECT attribute_id,
                            value_type,validation_constraints,state_token
                        FROM epm.attribute_definition
                        WHERE workspace_id=%s AND application_id=%s
                          AND scope='Member' AND dimension_id=%s
                          AND attribute_id=ANY(%s::text[]) AND status='Active'
                        ORDER BY attribute_id FOR UPDATE""",
                        (*keys,payload["dimensionId"],
                         payload["attributeIds"])).fetchall()
                    if not _exact_active_definition_inventory(
                            definitions, payload["attributeIds"]):
                        raise ValueError(
                            "ACTIVE_ATTRIBUTE_DEFINITION_REQUIRED")
                    definitions_by_id = {
                        row["attribute_id"]: row for row in definitions}
                    members = db.execute("""SELECT member_id,custom_values
                        FROM epm.member WHERE workspace_id=%s
                          AND application_id=%s AND dimension_id=%s
                          AND status='Active' ORDER BY member_id FOR UPDATE""",
                        (*keys,payload["dimensionId"])).fetchall()
                    members_by_id = {row["member_id"]: row for row in members}
                    if any(row["objectId"] not in members_by_id
                           for row in payload["rows"]):
                        raise ValueError("ACTIVE_ATTRIBUTE_OBJECT_REQUIRED")
                    declared = set(payload["attributeIds"])
                    desired = {member: {} for member in members_by_id}
                    typed_rows = []
                    for row in payload["rows"]:
                        values = {}
                        for attribute,value in row["values"].items():
                            typed = _typed_value(
                                db, application,
                                definitions_by_id[attribute], value)
                            if typed is not None:
                                values[attribute] = typed
                        desired[row["objectId"]] = values
                        typed_rows.append({"objectId": row["objectId"],
                                           "values": values})
                    actual = {member: {key: value for key,value in
                        record["custom_values"].items() if key in declared}
                        for member,record in members_by_id.items()}
                    if actual == desired:
                        raise ValueError("ATTRIBUTE_VALUES_UNCHANGED")
                    db.execute("""UPDATE epm.member
                        SET custom_values=custom_values-%s::text[],
                            updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                          AND dimension_id=%s AND status='Active'""",
                        (payload["attributeIds"],*keys,
                         payload["dimensionId"]))
                    db.execute("""WITH supplied AS (
                          SELECT * FROM jsonb_to_recordset(%s::jsonb)
                            AS x(object_id text,values jsonb)
                        ) UPDATE epm.member m
                        SET custom_values=m.custom_values||supplied.values,
                            updated_at=transaction_timestamp()
                        FROM supplied WHERE m.workspace_id=%s
                          AND m.application_id=%s AND m.dimension_id=%s
                          AND m.member_id=supplied.object_id
                          AND m.status='Active'""",
                        (Jsonb([{"object_id": row["objectId"],
                                 "values": row["values"]}
                                for row in typed_rows]),*keys,
                         payload["dimensionId"]))
                    state_token = _canonical_digest({
                        "dimensionId": payload["dimensionId"],
                        "definitions": [{"attributeId": row["attribute_id"],
                                         "stateToken": row["state_token"]}
                                        for row in definitions],
                        "values": typed_rows})
                revision = state["metadata_revision"] + 1
                commit = state["commit_revision"] + 1
                from .calculation_impact_contract import (
                    compile_calculation_impact)
                is_replace=function==VALUES_REPLACE
                object_id=(f"{payload['dimensionId'] or '__application__'}:"
                    f"{payload.get('attributeId','__set__')}")
                is_value=function in (VALUE_SET,VALUES_REPLACE)
                if is_replace:
                    effects=[{
                        'domain':'attribute','change':'replace',
                        'objectType':'member-attribute-value-set',
                        'objectId':f"{payload['dimensionId']}:{attribute}",
                        'scope':[], 'reason':'membership_changed',
                        'oldPresence':'unknown','newPresence':'present'}
                        for attribute in payload['attributeIds']]
                else:
                    effects=[{
                        'domain':'attribute','change':(
                            'insert' if function==DEFINITION_CREATE else
                            'activate' if payload.get('status')=='Active' else
                            'deactivate' if payload.get('status')=='Inactive'
                            else 'update'),
                        'objectType':payload['scope'].lower() + ('-attribute-value' if is_value
                                      else '-attribute-definition'),
                        'objectId':object_id,
                        'scope':([{'dimensionId':payload['dimensionId'],
                                   'memberId':payload['objectId']}]
                                 if is_value and payload['scope']=='Member'
                                 else []),
                        'reason':('membership_changed' if is_value
                                  else 'definition_changed'),
                        'oldPresence':('absent' if function==DEFINITION_CREATE
                                       else 'unknown'),
                        'newPresence':('absent' if
                            payload.get('status')=='Inactive' else 'present')}]
                impact=compile_calculation_impact({
                    'format':'openepm-calculation-impact-v1',
                    'sourceKind':'attribute','sourceId':idempotency_key,
                    'causalRevision':commit,'effects':effects})
                db.execute("""UPDATE epm.application_state SET
                    metadata_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s""",
                    (revision, commit, *keys))
                result = {"function": function,
                          "metadataRevision": revision,
                          ("contentDigest" if is_replace else "stateToken"):
                              state_token,
                          "payloadDigest": payload_digest,
                          "impactDigest":impact.digest}
                db.execute("""INSERT INTO epm.operation_receipt(
                    workspace_id,application_id,operation_id,command_digest,
                    actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                    (*keys, idempotency_key, digest,
                     self.identity.subject_id, commit, Jsonb(result)))
                from .postgres_calculation_impact import (
                    record_calculation_impact)
                record_calculation_impact(db,application,
                    operation_id=idempotency_key,impact=impact)
                return {**result, "operationId": idempotency_key,
                        "committedRevision": commit, "duplicate": False}

    def read(self, application: ApplicationScope, program: dict) -> dict:
        if not isinstance(application, ApplicationScope):
            raise ValueError("Application scope is required")
        function = program.get("function") if isinstance(program, dict) else None
        if function == DEFINITION_LIST:
            args = _program(program, function, {"scope"}, {
                "dimensionId", "status", "query", "limit",
                "afterAttributeId"})
            scope = _scope(args["scope"])
            dimension = _context(scope, args)
            status = args.get("status")
            if status not in (None, "Active", "Inactive"):
                raise ValueError("ATTRIBUTE_STATUS_INVALID")
            query = _text(args.get("query", ""), 200)
            limit = args.get("limit", 100)
            if type(limit) is not int or not 1 <= limit <= 500:
                raise ValueError("ATTRIBUTE_PAGE_LIMIT_INVALID")
            after = args.get("afterAttributeId")
            if after is not None:
                after = _id(after)
        elif function in (DEFINITION_USAGE, VALUE_READ):
            required = {"scope", "attributeId"}
            if function == VALUE_READ:
                required.add("objectId")
            args = _program(program, function, required, {"dimensionId"})
            scope, dimension, attribute = _definition_context(args)
            if function == VALUE_READ:
                object_id = _id(args["objectId"])
        else:
            raise ValueError("ATTRIBUTE_PROGRAM_INVALID")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY")
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, application)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, application, "read")
                start = db.execute("""SELECT metadata_revision
                    FROM epm.application_state WHERE workspace_id=%s
                      AND application_id=%s""",
                    (application.workspace_id,
                     application.application_id)).fetchone()
                if start is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                keys = (application.workspace_id,
                        application.application_id)
                if function == DEFINITION_LIST:
                    rows = db.execute("""SELECT attribute_id,default_name,
                            display_name,short_description,semantic_description,
                            value_type,validation_constraints,status,
                            state_token
                        FROM epm.attribute_definition
                        WHERE workspace_id=%s AND application_id=%s
                          AND scope=%s AND dimension_id=%s
                          AND (%s::text IS NULL OR status=%s)
                          AND (%s='' OR attribute_id ILIKE '%%'||%s||'%%'
                               OR display_name ILIKE '%%'||%s||'%%'
                               OR semantic_description ILIKE '%%'||%s||'%%')
                          AND (%s::text IS NULL OR attribute_id>%s)
                        ORDER BY attribute_id LIMIT %s""",
                        (*keys, scope, dimension, status, status,
                         query, query, query, query, after, after,
                         limit + 1)).fetchall()
                    result = {"scope": scope,
                              "dimensionId": dimension or None,
                              "rows": [dict(row) for row in rows[:limit]],
                              "hasMore": len(rows) > limit,
                              "nextAfterAttributeId":
                                  rows[limit - 1]["attribute_id"]
                                  if len(rows) > limit else None}
                else:
                    payload = {"scope": scope, "dimensionId": dimension,
                               "attributeId": attribute}
                    definition = self._definition(db, application, payload)
                    if definition is None:
                        raise ValueError("ATTRIBUTE_DEFINITION_UNAVAILABLE")
                    usage = self._usage(db, application, scope, dimension,
                                        attribute)
                    if function == DEFINITION_USAGE:
                        result = {"scope": scope,
                                  "dimensionId": dimension or None,
                                  "definition": dict(definition), **usage}
                    else:
                        table, id_column = {
                            "Dimension": ("dimension", "dimension_id"),
                            "Member": ("member", "member_id"),
                            "Relationship": ("relationship",
                                             "relationship_id"),
                        }[scope]
                        where = "" if scope == "Dimension" else (
                            " AND dimension_id=%s")
                        parameters: tuple = (*keys,)
                        if scope != "Dimension":
                            parameters += (dimension,)
                        parameters += (object_id,)
                        record = db.execute("SELECT custom_values FROM epm." +
                            table + " WHERE workspace_id=%s AND application_id=%s" +
                            where + " AND " + id_column +
                            "=%s AND status='Active'", parameters).fetchone()
                        if record is None:
                            raise ValueError("ACTIVE_ATTRIBUTE_OBJECT_REQUIRED")
                        result = {"scope": scope,
                                  "dimensionId": dimension or None,
                                  "objectId": object_id,
                                  "definition": dict(definition),
                                  "present": attribute in record["custom_values"],
                                  "value": record["custom_values"].get(attribute)}
                end = db.execute("""SELECT metadata_revision
                    FROM epm.application_state WHERE workspace_id=%s
                      AND application_id=%s""", keys).fetchone()
                if (end is None or end["metadata_revision"] !=
                        start["metadata_revision"]):
                    raise ValueError("METADATA_CHANGED_DURING_READ")
                return {**result,
                        "metadataRevision": start["metadata_revision"]}
