"""Current generic application-rule definitions and activation state.

An application rule is an ordered plan of ordinary V2 primitives.  This
module owns authoring lifecycle only: activating a definition has no business
effect, and execution must validate and seal every operation through the
fixed-core plan admission path before admitting work.
"""
from __future__ import annotations

import json
import re
from datetime import date
from decimal import Decimal, InvalidOperation
from dataclasses import dataclass
from typing import Mapping

from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker
from .postgres_connection import connect_postgres
from .postgres_expression_rules import PostgresExpressionRules
from .postgres_jobs import _canonical_digest
from .postgres_member_lists import EVALUATE as MEMBER_LIST_EVALUATE
from .postgres_member_lists import PostgresMemberLists
from .postgres_numeric_store import PostgresNumericFactStore
from .python_program_execution import (FunctionValidator, SealedPlan,
                                       validate_proposed_plan)


SAVE = "application.rule.save"
PUBLISH = "application.rule.activate"
RETIRE = "application.rule.retire"
READ = "application.rule.read"
LIST = "application.rule.list"
RUN = "application.rule.run"
RUN_READ = "application.rule.run.read"
RUN_CANCEL = "application.rule.run.cancel"
RUN_RECONCILE = "application.rule.run.reconcile"
STORED_FUNCTION = "application.rule.plan"
FORMAT = "openepm-application-rule-v1"
MAX_OPERATIONS = 500
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_PARAMETER_TYPES = frozenset(("Amount", "Ratio", "Member", "MemberList",
                              "String", "Boolean", "Date"))


def _typed_parameter(value: object, specification: dict, *,
                     allow_empty_member_list: bool=False) -> object:
    kind=specification["type"]
    if kind=="MemberList":
        if type(value) is list:
            if ((not value and not allow_empty_member_list) or len(value)>100_000
                    or any(type(member) is not str or not member
                           or _ID.fullmatch(member) is None for member in value)
                    or len(value)!=len(set(value))):
                raise ValueError("APPLICATION_RULE_PARAMETER_BINDING_INVALID")
            return list(value)
        if (type(value) is not dict
                or set(value)!={"listId","parameters"}
                or type(value.get("listId")) is not str
                or _ID.fullmatch(value["listId"]) is None
                or type(value.get("parameters")) is not dict
                or len(value["parameters"])>100):
            raise ValueError("APPLICATION_RULE_PARAMETER_BINDING_INVALID")
        try:
            encoded=json.dumps(value["parameters"],sort_keys=True,
                separators=(",",":"),ensure_ascii=True,allow_nan=False)
            parameters=json.loads(encoded)
        except (TypeError,ValueError,UnicodeEncodeError) as error:
            raise ValueError("APPLICATION_RULE_PARAMETER_BINDING_INVALID") from error
        if any(isinstance(item,float) for item in _walk(parameters)):
            raise ValueError("APPLICATION_RULE_PARAMETER_BINDING_INVALID")
        return {"listId":value["listId"],"parameters":parameters}
    if kind in ("Amount","Ratio"):
        if type(value) is not str or not value or value!=value.strip():
            raise ValueError("APPLICATION_RULE_PARAMETER_BINDING_INVALID")
        try:number=Decimal(value)
        except (InvalidOperation,ValueError) as error:
            raise ValueError("APPLICATION_RULE_PARAMETER_BINDING_INVALID") from error
        if not number.is_finite():
            raise ValueError("APPLICATION_RULE_PARAMETER_BINDING_INVALID")
        _,digits,exponent=number.as_tuple()
        integer_digits=max(0,len(digits)+exponent);scale=max(0,-exponent)
        if ((kind=="Amount" and (integer_digits>20 or scale>8))
                or (kind=="Ratio" and (integer_digits>8 or scale>12))):
            raise ValueError("APPLICATION_RULE_PARAMETER_BINDING_INVALID")
        return format(number,"f")
    if kind=="Boolean":
        if type(value) is not bool:
            raise ValueError("APPLICATION_RULE_PARAMETER_BINDING_INVALID")
        return value
    if (type(value) is not str or not value or value!=value.strip()
            or "\x00" in value or len(value)>32768):
        raise ValueError("APPLICATION_RULE_PARAMETER_BINDING_INVALID")
    if kind=="Date":
        try:
            if date.fromisoformat(value).isoformat()!=value:raise ValueError
        except ValueError as error:
            raise ValueError("APPLICATION_RULE_PARAMETER_BINDING_INVALID") from error
    if kind=="Member" and len(value)>200:
        raise ValueError("APPLICATION_RULE_PARAMETER_BINDING_INVALID")
    return value


def _parameter_definitions(value: object) -> tuple[dict,...]:
    if type(value) is not list or len(value)>100:
        raise ValueError("APPLICATION_RULE_PARAMETERS_INVALID")
    result=[];names=set()
    for raw in value:
        if (type(raw) is not dict or type(raw.get("name")) is not str
                or _ID.fullmatch(raw["name"]) is None
                or raw["name"] in names or raw.get("type") not in _PARAMETER_TYPES
                or set(raw)!=( {"name","type","sample","dimensionId"}
                    if raw.get("type") in ("Member","MemberList")
                    else {"name","type","sample"})):
            raise ValueError("APPLICATION_RULE_PARAMETERS_INVALID")
        if raw["type"] in ("Member","MemberList") and (
                type(raw["dimensionId"]) is not str
                or _ID.fullmatch(raw["dimensionId"]) is None):
            raise ValueError("APPLICATION_RULE_PARAMETERS_INVALID")
        checked=dict(raw);checked["sample"]=_typed_parameter(raw["sample"],raw)
        result.append(checked);names.add(raw["name"])
    return tuple(result)


def _bind_validated(value: dict, bindings: object | None, *,
                    samples: bool=False,
                    resolved_bindings: Mapping[str,object] | None=None
                    ) -> tuple[dict,dict]:
    parameters=_parameter_definitions(value.get("parameters",[]))
    supplied={} if bindings is None else bindings
    if type(supplied) is not dict or (not samples and set(supplied)!=
                                      {item["name"] for item in parameters}):
        raise ValueError("APPLICATION_RULE_PARAMETER_BINDINGS_INVALID")
    if any(item["type"]=="MemberList" and type(
            item["sample"] if samples else supplied[item["name"]]) is not (
                list if samples else dict) for item in parameters):
        raise ValueError("APPLICATION_RULE_PARAMETER_BINDING_INVALID")
    values={item["name"]:_typed_parameter(
        item["sample"] if samples else supplied[item["name"]],item)
        for item in parameters}
    definitions={item["name"]:item for item in parameters}
    replacements=dict(values)
    if not samples:
        resolved={} if resolved_bindings is None else dict(resolved_bindings)
        expected={item["name"] for item in parameters
                  if item["type"]=="MemberList"}
        if set(resolved)!=expected:
            if expected:
                raise ValueError("APPLICATION_RULE_MEMBER_LIST_RESOLUTION_REQUIRED")
            if resolved:
                raise ValueError("APPLICATION_RULE_PARAMETER_BINDINGS_INVALID")
        for name in expected:
            if type(resolved[name]) is not list:
                raise ValueError("APPLICATION_RULE_MEMBER_LIST_RESOLUTION_INVALID")
            replacements[name]=_typed_parameter(resolved[name],
                definitions[name],allow_empty_member_list=True)
    used=set()
    def replace(item,depth=0):
        if depth>64:raise ValueError("APPLICATION_RULE_PARAMETER_BUDGET")
        if isinstance(item,list):return [replace(child,depth+1) for child in item]
        if not isinstance(item,dict):return item
        if item.get("type")=="ApplicationRuleParameter":
            definition=definitions.get(item.get("name"))
            expected=({"type","name","valueType","dimensionId"}
                if definition and definition["type"] in ("Member","MemberList")
                else {"type","name","valueType"})
            if (set(item)!=expected or definition is None
                    or item.get("valueType")!=definition["type"]
                    or (definition["type"] in ("Member","MemberList") and
                        item.get("dimensionId")!=definition["dimensionId"])):
                raise ValueError("APPLICATION_RULE_PARAMETER_REFERENCE_INVALID")
            used.add(item["name"]);return replacements[item["name"]]
        return {key:replace(child,depth+1) for key,child in item.items()}
    bound={key:item for key,item in value.items() if key!="parameters"}
    bound["units"]=replace(value["units"])
    if used!={item["name"] for item in parameters}:
        raise ValueError("APPLICATION_RULE_PARAMETER_UNUSED")
    return bound,values


def bind_definition(definition: object, bindings: object | None, *,
                    samples: bool=False,
                    resolved_bindings: Mapping[str,object] | None=None
                    ) -> tuple[dict,dict]:
    return _bind_validated(validate_definition(definition),bindings,
                           samples=samples,resolved_bindings=resolved_bindings)


def validate_definition(value: object) -> dict:
    if (type(value) is not dict
            or set(value) not in ({"format", "name", "units"},
                                  {"format", "name", "units", "parameters"})
            or value.get("format") != FORMAT
            or type(value.get("name")) is not str
            or not 1 <= len(value["name"]) <= 200
            or value["name"] != value["name"].strip()
            or type(value.get("units")) is not list
            or not value["units"]):
        raise ValueError("APPLICATION_RULE_DEFINITION_INVALID")
    unit_names: set[str] = set()
    operations = 0
    for unit in value["units"]:
        if (type(unit) is not dict
                or set(unit) != {"name", "operations"}
                or type(unit.get("name")) is not str
                or _ID.fullmatch(unit["name"]) is None
                or unit["name"] in unit_names
                or type(unit.get("operations")) is not list
                or not unit["operations"]):
            raise ValueError("APPLICATION_RULE_UNIT_INVALID")
        unit_names.add(unit["name"])
        for operation in unit["operations"]:
            operations += 1
            if operations > MAX_OPERATIONS:
                raise ValueError("APPLICATION_RULE_OPERATION_LIMIT")
            if (type(operation) is not dict
                    or set(operation) != {
                        "languageVersion", "function", "arguments"}
                    or operation.get("languageVersion") != 2
                    or type(operation.get("function")) is not str
                    or _ID.fullmatch(operation["function"]) is None
                    or type(operation.get("arguments")) is not dict):
                raise ValueError("APPLICATION_RULE_OPERATION_INVALID")
    try:
        # Copy and reject floats/non-JSON values before persistent storage.
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False)
        result = json.loads(encoded)
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError("APPLICATION_RULE_DEFINITION_INVALID") from error
    if any(isinstance(item, float) for item in _walk(result)):
        raise ValueError("APPLICATION_RULE_DEFINITION_INVALID")
    _parameter_definitions(result.get("parameters",[]))
    _bind_validated(result,None,samples=True)
    return result


def definition_plan(definition: object) -> dict:
    """Lower an immutable application rule into the shared plan envelope."""
    value = validate_definition(definition)
    return {"format": "openepm-python-plan-v1", "units": value["units"]}


@dataclass(frozen=True, slots=True)
class SealedApplicationRule:
    plan: SealedPlan
    pin: Mapping[str, object]

    def __post_init__(self):
        if not isinstance(self.plan, SealedPlan) or type(self.pin) is not dict:
            raise ValueError("APPLICATION_RULE_SEAL_INVALID")


def seal_definition(scope: ApplicationScope, definition: object, *,
                    registry: FunctionValidator, bindings: object | None=None,
                    resolved_bindings: Mapping[str,object] | None=None,
                    compiler_version: str) -> SealedPlan:
    bound,_=bind_definition(definition,bindings,
                            resolved_bindings=resolved_bindings)
    return validate_proposed_plan(scope, definition_plan(bound),
                                  registry=registry,
                                  compiler_version=compiler_version)


def _walk(value: object):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def parse(raw: object, function: str) -> dict:
    if (type(raw) is not dict
            or set(raw) != {"languageVersion", "function", "arguments"}
            or raw.get("languageVersion") != 2
            or raw.get("function") != function
            or type(raw.get("arguments")) is not dict):
        raise ValueError("APPLICATION_RULE_PROGRAM_INVALID")
    args = raw["arguments"]
    if function == LIST:
        if (set(args) - {"limit", "afterRuleId", "expectedMetadataRevision",
                         "expectedPolicyRevision"}
                or type(args.get("limit", 100)) is not int
                or not 1 <= args.get("limit", 100) <= 100
                or ("afterRuleId" in args and (
                    type(args["afterRuleId"]) is not str
                    or _ID.fullmatch(args["afterRuleId"]) is None
                    or not {"expectedMetadataRevision",
                            "expectedPolicyRevision"} <= set(args)))):
            raise ValueError("APPLICATION_RULE_ARGUMENTS_INVALID")
        for key in ("expectedMetadataRevision", "expectedPolicyRevision"):
            if key in args and (type(args[key]) is not int or args[key] < 0):
                raise ValueError("APPLICATION_RULE_ARGUMENTS_INVALID")
        return args
    if (type(args.get("ruleId")) is not str
            or _ID.fullmatch(args["ruleId"]) is None):
        raise ValueError("APPLICATION_RULE_ARGUMENTS_INVALID")
    if function == READ:
        if set(args) != {"ruleId"}:
            raise ValueError("APPLICATION_RULE_ARGUMENTS_INVALID")
        return args
    if function == RETIRE:
        required = {"ruleId", "expectedStateToken", "expectedProgramDigest",
            "replacementRuleId", "expectedReplacementStateToken",
            "expectedReplacementProgramDigest", "reason",
            "expectedMetadataRevision", "expectedPolicyRevision"}
        if (set(args) != required
                or args["replacementRuleId"] == args["ruleId"]
                or any(type(args[key]) is not str or _ID.fullmatch(args[key]) is None
                       for key in ("replacementRuleId",))
                or args["reason"] != "superseded_by_current_rule"
                or any(type(args[key]) is not str
                       or re.fullmatch(r"[0-9a-f]{64}", args[key]) is None
                       for key in ("expectedStateToken", "expectedProgramDigest",
                           "expectedReplacementStateToken",
                           "expectedReplacementProgramDigest"))
                or any(type(args[key]) is not int or args[key] < 0 for key in
                       ("expectedMetadataRevision", "expectedPolicyRevision"))):
            raise ValueError("APPLICATION_RULE_ARGUMENTS_INVALID")
        return args
    required = {"ruleId", "expectedMetadataRevision",
                "expectedPolicyRevision"}
    if function == SAVE:
        required.add("definition")
        if "expectedStateToken" in args:
            required.add("expectedStateToken")
    else:
        required.add("expectedStateToken")
    if (function not in (SAVE, PUBLISH) or set(args) != required
            or ("expectedStateToken" in args and (
                type(args["expectedStateToken"]) is not str
                or re.fullmatch(r"[0-9a-f]{64}", args["expectedStateToken"]) is None))
            or any(type(args[key]) is not int or args[key] < 0 for key in
                   ("expectedMetadataRevision", "expectedPolicyRevision"))):
        raise ValueError("APPLICATION_RULE_ARGUMENTS_INVALID")
    if function == SAVE:
        definition = validate_definition(args["definition"])
        calculation = {"languageVersion": 2, "function": STORED_FUNCTION,
                       "arguments": definition}
        return {**args, "definition": definition,
                "calculation": calculation, "plan": definition}
    return args


class PostgresApplicationRules(PostgresExpressionRules):
    SAVE, PUBLISH, RETIRE, READ, LIST = SAVE, PUBLISH, RETIRE, READ, LIST
    STORED_FUNCTION = STORED_FUNCTION
    _parse = staticmethod(parse)

    @staticmethod
    def _validate_definition(db, scope, definition):
        del db, scope
        validate_definition(definition)

    @staticmethod
    def _summary(definition):
        result={"name": definition["name"],
                "checkpointCount": len(definition["units"]),
                "statementCount": sum(len(unit["operations"])
                                      for unit in definition["units"])}
        if definition.get("parameters"):
            result["parameterCount"]=len(definition["parameters"])
        return result

    def _published_snapshot(self, scope: ApplicationScope,
                            rule_id: str, *, expected_state_token=None,
                            expected_program_digest=None,
                            require_source_pin=False) -> tuple[dict, dict]:
        if type(rule_id) is not str or _ID.fullmatch(rule_id) is None:
            raise ValueError("APPLICATION_RULE_ARGUMENTS_INVALID")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                state = db.execute('''SELECT metadata_revision,policy_revision,
                    schema_epoch FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s FOR SHARE''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,"write")
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,"rule_run")
                row=db.execute('''SELECT *
                    FROM epm.expression_rule_definition
                    WHERE workspace_id=%s AND application_id=%s
                      AND rule_id=%s''',
                    (scope.workspace_id,scope.application_id,rule_id)).fetchone()
                if row is None or row['definition_kind']!='ApplicationRule':
                    raise ValueError("APPLICATION_RULE_NOT_ACTIVE")
                from .postgres_python_definitions import assert_source_active
                assert_source_active(db,scope,row)
                if (row['ownership_state']=='Source' and require_source_pin
                        and expected_state_token is None):
                    raise ValueError('APPLICATION_RULE_EXPECTED_STATE_TOKEN_REQUIRED')
                if expected_state_token is not None and (
                        row['state_token'] != expected_state_token
                        or row['program_digest'] != expected_program_digest):
                    raise ValueError('APPLICATION_RULE_EXPECTED_STATE_MISMATCH')
                if row['metadata_revision'] != state['metadata_revision']:
                    raise ValueError("APPLICATION_RULE_METADATA_STALE")
                if _canonical_digest(row['program']) != row['program_digest']:
                    raise ValueError("APPLICATION_RULE_DEFINITION_CORRUPT")
                definition=validate_definition(row['program']['arguments'])
                pin={"ruleId":rule_id,"stateToken":row['state_token'],
                     "programDigest":row['program_digest'],
                     "metadataRevision":state['metadata_revision'],
                     "policyRevision":state['policy_revision'],
                     "schemaEpoch":state['schema_epoch'],
                     "owner_certificate_digest":_canonical_digest(row['current_certificate'])}
                return definition,pin

    def _resolve_member_list_bindings(self,scope: ApplicationScope,
                                      definition: dict,bindings: object,
                                      *,metadata_revision: int
                                      ) -> tuple[dict,tuple[dict,...]]:
        """Resolve exact active current lists before sealing the execution plan.

        The user binding identifies an active current list and its
        own typed parameters.  Only the resulting stable member IDs enter the
        operation arguments.  The source identity and resolution digest remain
        in the workflow pin so retry never re-evaluates a changed publication.
        """
        parameters=_parameter_definitions(definition.get("parameters",[]))
        requested={} if bindings is None else bindings
        if type(requested) is not dict:
            raise ValueError("APPLICATION_RULE_PARAMETER_BINDINGS_INVALID")
        member_lists=PostgresMemberLists(self.dsn,identity=self.identity)
        resolved={};pins=[]
        for specification in parameters:
            if specification["type"]!="MemberList":continue
            source=_typed_parameter(requested.get(specification["name"]),
                                    specification)
            if type(source) is not dict:
                raise ValueError("APPLICATION_RULE_PARAMETER_BINDING_INVALID")
            result=member_lists.read(scope,{"languageVersion":2,
                "function":MEMBER_LIST_EVALUATE,"arguments":{
                    "listId":source["listId"],
                    "parameters":source["parameters"],
                    "expectedMetadataRevision":metadata_revision}})
            if result.get("status")!="Published":
                raise ValueError("APPLICATION_RULE_MEMBER_LIST_NOT_PUBLISHED")
            if result.get("dimensionId")!=specification["dimensionId"]:
                raise ValueError("APPLICATION_RULE_MEMBER_LIST_DIMENSION_MISMATCH")
            members=result.get("memberIds")
            resolved[specification["name"]]=members
            pins.append({"parameter":specification["name"],
                "dimensionId":specification["dimensionId"],
                "listId":source["listId"],"stateToken":result["stateToken"],
                "parameters":source["parameters"],
                "canonicalDigest":result["canonicalDigest"],
                "metadataRevision":result["metadataRevision"],
                "memberCount":result["memberCount"],
                "memberIdsDigest":_canonical_digest(members),
                "resolutionDigest":_canonical_digest({
                    "definition":result["canonicalDigest"],
                    "metadataRevision":result["metadataRevision"],
                    "parameters":source["parameters"],"memberIds":members})})
        return resolved,tuple(pins)

    def seal_published(self, scope: ApplicationScope, rule_id: str, *,
                       registry: FunctionValidator, bindings: object | None=None,
                       compiler_version: str, expected_state_token=None,
                       expected_program_digest=None) -> SealedApplicationRule:
        """Seal and recheck one exact published application rule, no effects."""
        definition,before=self._published_snapshot(scope,rule_id,
            expected_state_token=expected_state_token,
            expected_program_digest=expected_program_digest)
        resolved,pins=self._resolve_member_list_bindings(scope,definition,
            bindings,metadata_revision=before["metadataRevision"])
        _,values=bind_definition(definition,bindings,
                                 resolved_bindings=resolved)
        plan=seal_definition(scope,definition,registry=registry,bindings=bindings,
                             resolved_bindings=resolved,
                             compiler_version=compiler_version)
        _,after=self._published_snapshot(scope,rule_id)
        if before != after:
            raise ValueError("APPLICATION_RULE_STALE_DURING_SEAL")
        return SealedApplicationRule(plan,{**before,"bindings":values,
            "bindingDigest":_canonical_digest(values),
            "bindingRequestDigest":_canonical_digest(bindings or {}),
            "argumentsDigest":_canonical_digest({
                "ruleId":rule_id,"bindings":bindings or {}}),
            **({"memberListPins":list(pins)} if pins else {})})


def catalog() -> dict:
    common = {"workClass": "short", "previewRequired": False}
    return {
        SAVE: {**common, "mode": "atomic_rule_definition",
               "permission": "rule_design", "idempotencyRequired": True,
               "arguments": {"ruleId": "stable ID",
                   "definition": "1-500 ordered generic primitive operations with up to 100 typed parameters",
                   "expectedMetadataRevision": "current revision",
                   "expectedPolicyRevision": "current revision"},
               "optionalArguments": {"expectedStateToken": "required to replace the current rule"},
               "result": "current inactive application rule, state token and digest"},
        PUBLISH: {**common, "mode": "atomic_rule_publication",
                  "permission": "rule_publish", "idempotencyRequired": True,
                  "arguments": {"ruleId": "stable ID",
                      "expectedStateToken": "current rule state token",
                      "expectedMetadataRevision": "current revision",
                      "expectedPolicyRevision": "current revision"},
                  "result": "current Active rule state and policy revision"},
        RETIRE: {**common, "mode": "atomic_rule_retirement",
                 "permission": "rule_publish", "idempotencyRequired": True,
                 "arguments": {"ruleId": "unresolved superseded rule ID",
                     "expectedStateToken": "exact inspected legacy state",
                     "expectedProgramDigest": "exact inspected legacy digest",
                     "replacementRuleId": "current active replacement ID",
                     "expectedReplacementStateToken": "exact replacement state",
                     "expectedReplacementProgramDigest": "exact replacement digest",
                     "reason": "superseded_by_current_rule",
                     "expectedMetadataRevision": "current revision",
                     "expectedPolicyRevision": "current revision"},
                 "result": "physical retirement bound to an exact current replacement"},
        READ: {**common, "mode": "read", "permission": "read",
               "idempotencyRequired": False,
               "arguments": {"ruleId": "stable ID"},
               "result": "current definition and activation state"},
        LIST: {**common, "mode": "read", "permission": "read",
               "idempotencyRequired": False, "arguments": {},
               "optionalArguments": {"limit": "1-100", "afterRuleId": "stable keyset cursor",
                   "expectedMetadataRevision": "required with afterRuleId",
                   "expectedPolicyRevision": "required with afterRuleId"},
               "result": "bounded current application-rule summaries"},
        RUN: {**common, "mode": "durable_workflow",
              "permission": "rule_run", "idempotencyRequired": True,
              "workClass": "long",
              "arguments": {"ruleId": "published application rule ID"},
              "optionalArguments": {"bindings":
                  "exact values for every declared typed runtime parameter",
                  "expectedStateToken": "exact inspected Active rule state",
                  "expectedProgramDigest": "exact inspected compiled digest"},
              "result": "durable rule workflow with binding digest and checkpoint receipts"},
        RUN_READ: {**common, "mode": "read", "permission": "read",
                   "idempotencyRequired": False,
                   "arguments": {"workflowId": "caller-owned workflow ID"},
                   "result": "durable workflow, sealed child/receipt lineage and dependency freshness"},
        RUN_CANCEL: {**common, "mode": "technical_control",
                     "permission": "rule_run",
                     "idempotencyRequired": True,
                     "arguments": {"workflowId": "caller-owned workflow ID"},
                     "result": "cancellation state; committed effects remain"},
        RUN_RECONCILE: {**common, "mode": "technical_control",
                        "permission": "rule_run",
                        "idempotencyRequired": True,
                        "arguments": {
                            "workflowId": "needs-inspection workflow ID"},
                        "result": "durable child inspection and safe resume state"},
    }
