"""Fixed-core state boundary for domain-neutral application workflows.

This private service starts exact published workflows, exposes only currently
assigned ready work, reads durable state, completes evidence-backed activities,
returns reviews to configured ancestors and cancels active occurrences. It does
not execute destinations; evidence validation remains server-owned and
function-specific.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
from datetime import datetime
from hashlib import sha256
import json
import re
from typing import Collection

from psycopg import errors
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .application_assignment import (
    ApplicationAssignment, ApplicationAssignmentSet, compile_application_assignment_set)
from .application_workflow import Activity,ApplicationWorkflow,MAX_ACTIVITIES,destination_schema
from .current_object_contract import STATE_TOKEN_PATTERN,new_state_token,require_state_token
from .persistence_contract import ApplicationScope
from .postgres_access import AccessDecision,PostgresAccessChecker,VerifiedIdentity,assert_nonowner_role
from .postgres_application_workflows import PostgresApplicationWorkflows
from .postgres_application_workflow_evidence import (
    CALCULATION_FUNCTION, CALCULATION_IMPACT_PENDING, RECEIPT_ASSESSMENT_BASES,
    WorkflowEvidence, assess_completed_basis,
    matches_completed_attestation, validate_workflow_evidence,
)
from .postgres_application_capabilities import _state as application_state
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_processing_limits import configure_statement_timeout
from .postgres_selection_preview import resolve_selection_in_transaction


START="application.workflow.occurrence.start"
READ="application.workflow.occurrence.read"
WORKLIST="application.workflow.worklist"
EVIDENCE_OPTIONS="application.workflow.activity.evidence.list"
EVIDENCE_ASSESSMENT="application.workflow.activity.evidence.read"
CANCEL="application.workflow.occurrence.cancel"
COMPLETE="application.workflow.activity.complete"
RETURN="application.workflow.activity.return"
FUNCTIONS=frozenset((START,READ,WORKLIST,EVIDENCE_OPTIONS,EVIDENCE_ASSESSMENT,COMPLETE,RETURN,CANCEL))
MUTATIONS=frozenset((START,COMPLETE,RETURN,CANCEL))
READS=frozenset((READ,WORKLIST,EVIDENCE_OPTIONS,EVIDENCE_ASSESSMENT))
_AUTHORITY_STALE="APPLICATION_WORKFLOW_AUTHORIZATION_STALE"
_READ_AUTHORITY_RULE=(
    "The core checks current application access before returning workflow data. On "
    + _AUTHORITY_STALE + ", refresh the application catalogue and restart the read at its first page.")
_ID=re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299}\Z")
_KEY=re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_OCCURRENCE=re.compile(r"[0-9a-f]{32}\Z")
_EVENT_PAGE_LIMIT = 500
_WORKLIST_PAGE_LIMIT = 100
_MAX_BIGINT = 2**63 - 1
_RETURN_REASON_LIMIT = 1000
_MAX_WORKLIST_SCAN=10_000
_WORKFLOW_DEPENDENCY_BLOCKS = {
    "CUBE_SELECTION_METADATA_STALE": "SelectionMetadataChanged",
    "CUBE_SELECTION_MEMBER_LIST_UNPUBLISHED": "WorkflowDependencyUnavailable",
    "MEMBER_LIST_ATTRIBUTE_UNAVAILABLE": "WorkflowDependencyUnavailable",
    "MEMBER_LIST_MEMBER_UNAVAILABLE": "WorkflowDependencyUnavailable",
    "APPLICATION_WORKFLOW_ASSIGNMENT_UNAVAILABLE": "WorkflowDependencyUnavailable",
    "APPLICATION_WORKFLOW_VIEW_UNAVAILABLE": "WorkflowDependencyUnavailable",
    "APPLICATION_WORKFLOW_ARTIFACT_UNAVAILABLE": "WorkflowDependencyUnavailable",
    "APPLICATION_WORKFLOW_FUNCTION_UNAVAILABLE": "WorkflowDependencyUnavailable",
    "APPLICATION_FUNCTION_RETIRED": "WorkflowDependencyUnavailable",
    "ORDERED_RULE_CURRENT_OWNER_UNSUPPORTED": "WorkflowDependencyUnavailable",
}
_ASSIGNMENT_UNAVAILABLE_CODES = {
    "APPLICATION_WORKFLOW_ACTIVITY_NOT_ASSIGNED",
    "APPLICATION_WORKFLOW_ASSIGNMENT_NOT_EFFECTIVE",
    "APPLICATION_WORKFLOW_ASSIGNMENT_UNAVAILABLE",
}
_MAX_EVIDENCE_SCAN=1_000
_EVIDENCE_PAGE_LIMIT=100
_EVIDENCE_ACTION_LABELS={
    "application.rule.run":"Application rule run",
    "facts.numeric.batch":"Numeric data update",
    CALCULATION_FUNCTION:"Calculated result",
}
_TABLES=("application_workflow_definition",
    "application_workflow_assignment_pin","application_workflow_occurrence",
    "application_workflow_activity","application_workflow_event",
    "application_workflow_evidence_link","application_assignment_definition")


def catalog()->dict:
    common={"previewRequired":False,"workClass":"short",
            "requiredCapabilities":[]}
    mutation={**common,"idempotencyRequired":True}
    read={**common,"permission":"read","idempotencyRequired":False,
          "mode":"read"}
    return {
        START:{**mutation,**transition_program_contract(START),"permission":"admin","mode":"atomic_workflow_transition",
            "arguments":{"flowId":"stable workflow ID",
                "expectedStateToken":"exact active workflow state token",
                "expectedMetadataRevision":"current metadata revision",
                "expectedPolicyRevision":"current policy revision",
                "expectedSchemaEpoch":"current schema epoch"},
            "result":"durable occurrence and initial Ready activities"},
        READ:{**read,**navigation_read_contract(READ),"arguments":{"occurrenceId":"stable occurrence ID"},
            "optionalArguments":{"eventLimit":"1-500",
                "afterEventOrdinal":"nonnegative event cursor",
                "includeCurrentReturns":"include instructions for Ready rework"},
            "result":"occurrence, activities and bounded event page"},
        WORKLIST:{**read,**navigation_read_contract(WORKLIST),"arguments":{},"optionalArguments":{
            "limit":"1-100","occurrenceId":"exact occurrence filter","afterOccurrenceId":"keyset cursor",
            "afterActivityId":"paired keyset cursor","includeBlocked":"include assigned activities awaiting workflow repair",
            "includeWaiting":"include assigned activities waiting on dependencies or rework"},
            "result":"currently assigned Ready activities and optional Waiting and blocked activities"},
        EVIDENCE_OPTIONS:{**read,**evidence_options_program_contract(),"arguments":{
            "occurrenceId":"stable occurrence ID",
            "activityId":"stable activity ID"},"optionalArguments":{
            "limit":"1-100",
            "beforeCommittedRevision":"descending evidence cursor"},
            "result":"eligible current receipt choices for one assigned activity"},
        EVIDENCE_ASSESSMENT:{**read,**evidence_assessment_program_contract(),"workClass":"bounded_read","arguments":{
            "occurrenceId":"exact occurrence ID",
            "activityId":"exact activity ID"},
            "result":"current assessment of the exact retained completion basis"},
        COMPLETE:{**mutation,**transition_program_contract(COMPLETE),"permission":"read",
            "mode":"atomic_workflow_transition","arguments":{
                "occurrenceId":"stable occurrence ID",
                "activityId":"stable activity ID",
                "expectedActivityStateToken":"exact current activity state token",
                "evidence":"typed configured evidence reference"},
            "result":"receipt-backed activity transition; review rechecks current-required prerequisite evidence"},
        RETURN:{**mutation,**transition_program_contract(RETURN),"permission":"read",
            "mode":"atomic_workflow_transition","arguments":{
                "occurrenceId":"stable occurrence ID",
                "activityId":"stable review activity ID",
                "expectedActivityStateToken":"exact current activity state token",
                "reason":"bounded return reason"},
            "result":"receipt-backed return and invalidation transition"},
        CANCEL:{**mutation,**transition_program_contract(CANCEL),"permission":"admin",
            "mode":"atomic_workflow_transition","arguments":{
                "occurrenceId":"stable occurrence ID",
                "expectedOccurrenceStateToken":"exact current occurrence state token"},
            "result":"receipt-backed occurrence cancellation"}}


def _identifier(value: object,code: str)->str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError(code)
    return value


def _revision(value: object,code: str)->int:
    if type(value) is not int or value<0:raise ValueError(code)
    return value


def _key(value: object)->str:
    if type(value) is not str or _KEY.fullmatch(value) is None:
        raise ValueError("APPLICATION_WORKFLOW_IDEMPOTENCY_KEY_INVALID")
    return value


def _occurrence_id(value: object)->str:
    if type(value) is not str or _OCCURRENCE.fullmatch(value) is None:
        raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_ID_INVALID")
    return value


_BASIS_STATUS={
    "Current":"SuitableUnderConfiguredEvidenceCondition",
    "NotApplicable":"NotApplicable",
    "UnavailableToAssess":"Unknown",
    "TemporarilyUnavailable":"Unknown",
    "NoCompletedBasis":"NotApplicable",
}


def _assessment_result(occurrence_id, activity_id, state, *,
                       token=None, basis=None, require_current=None):
    suitability=(
        ("UnsuitableNow" if require_current else "HistoricalPermitted")
        if state=="Stale" else _BASIS_STATUS[state])
    result={"occurrenceId":occurrence_id,"activityId":activity_id,
        "state":state,"basis":basis,"requireCurrent":require_current,
        "suitability":suitability,"retryable":state=="TemporarilyUnavailable"}
    if token is not None:
        result["activityStateToken"]=token
    return result


def _text_schema(pattern: re.Pattern) -> dict:
    return {"type":"string", "pattern":"^"+pattern.pattern.removesuffix(r"\Z")+r"(?![\s\S])"}


def transition_program_contract(function: str) -> dict:
    """Project exact occurrence intents and their native operation receipts."""
    from .metadata_read_contract import obj, read_contract, read_example
    from .postgres_application_workflow_evidence import completion_evidence_schema

    identifier, occurrence_id = _text_schema(_ID), _text_schema(_OCCURRENCE)
    token = _text_schema(STATE_TOKEN_PATTERN)
    revision = {"type": "integer", "minimum": 0}
    activity_ids = {"type": "array", "items": identifier, "maxItems": MAX_ACTIVITIES,
                    "uniqueItems": True}
    base = {"operationId": _text_schema(_KEY), "function": {"const": function},
            "status": {"const": "Active"}, "occurrenceId": occurrence_id,
            "occurrenceStateToken": token, "committedRevision": {**revision, "minimum": 1}}
    sample_token = "a" * 64
    sample_occurrence = {"occurrenceId": "1" * 32}
    if function == START:
        pins = dict.fromkeys(("expectedMetadataRevision", "expectedPolicyRevision", "expectedSchemaEpoch"), revision)
        arguments = obj({"flowId": identifier, "expectedStateToken": token, **pins})
        result = obj({**base, "flowId": identifier, "flowStateToken": token,
                      "definitionDigest": token, "readyActivityIds": {**activity_ids, "minItems": 1}})
        examples = [read_example(function, {"flowId": "example-workflow", "expectedStateToken": sample_token,
            **dict.fromkeys(pins, 1)}, name="Start an occurrence of the active workflow",
            binding="Read application.workflow.read in the selected application. Use an Active definition and bind its flowId, stateToken, metadataRevision, policyRevision and schemaEpoch.")]
        recovery = ("After APPLICATION_WORKFLOW_STALE_CONTEXT or APPLICATION_WORKFLOW_CURRENT_UNAVAILABLE, "
                    "read the current workflow definition, status and revision pins before reviewing a new start.")
    elif function == CANCEL:
        arguments = obj({"occurrenceId": occurrence_id, "expectedOccurrenceStateToken": token})
        result = obj({**base, "status": {"const": "Cancelled"}})
        examples = [read_example(function, {**sample_occurrence, "expectedOccurrenceStateToken": sample_token},
            name="Cancel the selected active occurrence",
            binding="Read application.workflow.occurrence.read as an application administrator. Review the Active occurrence and copy its exact occurrenceId and occurrenceStateToken.")]
        recovery = ("After APPLICATION_WORKFLOW_OCCURRENCE_STALE, read the same occurrence and check its current state. "
                    "Cancellation requires an Active occurrence and a fresh approval.")
    elif function in (COMPLETE, RETURN):
        request = {"occurrenceId": occurrence_id, "activityId": identifier, "expectedActivityStateToken": token}
        outcome = {**base, "activityId": identifier, "activityStateToken": token, "evidenceDigest": token}
        sample = {**sample_occurrence, "expectedActivityStateToken": sample_token}
        if function == COMPLETE:
            arguments = obj({**request, "evidence": completion_evidence_schema()})
            result = obj({**outcome, "status": {"enum": ["Active", "Completed"]}, "readyActivityIds": activity_ids})
            examples = [read_example(function, {**sample, "activityId": "review",
                    "evidence": {"kind": "ManualAttestation", "confirmed": True}},
                name="Complete an assigned activity with a manual attestation",
                binding="Read the current Ready activity and authored statement. Confirm the statement only after performing the assigned work, and use the current activityStateToken."),
                read_example(function, {**sample, "activityId": "prepare",
                    "evidence": {"kind": "OperationReceipt", "operationId": "example-evidence-operation"}},
                name="Complete an assigned activity with an eligible receipt",
                binding="Use the current Ready activity and token. Copy selectionKey from application.workflow.activity.evidence.list as evidence.operationId. Follow the authored evidence policy.")]
        else:
            reason = {"type": "string", "minLength": 1, "maxLength": _RETURN_REASON_LIMIT,
                      "pattern": r"^[^\s\u0000](?:[^\u0000]*[^\s\u0000])?(?![\s\S])"}
            arguments = obj({**request, "reason": reason})
            result = obj({**outcome, "returnedToActivityId": identifier, "invalidatedActivityIds": activity_ids})
            examples = [read_example(function, {**sample, "activityId": "review",
                    "reason": "Update the changed inputs and return for review."},
                name="Return an assigned review for correction",
                binding="Read the current Ready review, the configured return target and the activityStateToken. Give a reason for the configured target. Submit the current review ID, then read the occurrence to see the reopened activity.")]
        recovery = ("After APPLICATION_WORKFLOW_ACTIVITY_STALE, APPLICATION_WORKFLOW_OCCURRENCE_STALE or "
                    "APPLICATION_WORKFLOW_RETURN_TARGET_STALE, read the same occurrence and current assigned work. "
                    "Recheck the authored evidence and return conditions before reviewing a new intent. "
                    "If APPLICATION_WORKFLOW_REVIEW_BASIS_STALE is returned, check the prerequisite evidence and use the configured return when available.")
    else:
        raise ValueError("APPLICATION_WORKFLOW_TRANSITION_FUNCTION_INVALID")
    contract = read_contract(function, arguments, result,
        owner="PostgresApplicationWorkflowOccurrences", examples=examples, semantic_rules=[
            "Obtain a signed admission for the exact application, caller and program before dispatch.",
            "Start and Cancel require current application administrator authority. Complete and Return require the current activity assignment and the authored evidence or return policy.",
            "A transition result describes its original committed receipt. For current state, read the occurrence separately.",
        ])
    contract["programContract"]["recovery"] = recovery + (
        " On " + _AUTHORITY_STALE + ", refresh the application catalogue and reassess the exact workflow state."
        " If acknowledgement is missing, use the original admission operationId with application.operation.receipt.read, "
        "or replay the exact admitted request under its current authority. A changed intent requires a new admission.")
    return contract


def evidence_assessment_program_contract():
    """Describe the same closed result variants emitted by the fixed owner."""
    from .metadata_read_contract import obj, read_contract, read_example
    ids={"occurrenceId":_text_schema(_OCCURRENCE), "activityId":_text_schema(_ID)}
    variants=[]
    receipt_variants=tuple((state,basis,condition)
        for basis in RECEIPT_ASSESSMENT_BASES for state in ("Current","Stale")
        for condition in (True,False))
    for state,basis,condition in (*receipt_variants,
        ("NotApplicable","ManualAttestation",None),("NoCompletedBasis",None,None),
        ("UnavailableToAssess",None,None),("TemporarilyUnavailable",None,None),
    ):
        value=_assessment_result("", "", state, basis=basis, require_current=condition,
            token="0"*64 if basis is not None else None)
        fields={**ids,**{key:{"const":value[key]}
                         for key in ("state","basis","requireCurrent","suitability","retryable")}}
        if "activityStateToken" in value:
            fields["activityStateToken"]=_text_schema(STATE_TOKEN_PATTERN)
        variants.append(obj(fields))
    return read_contract(EVIDENCE_ASSESSMENT,obj(ids),{"oneOf":variants},
        owner="PostgresApplicationWorkflowOccurrences.assess_evidence",
        examples=[read_example(EVIDENCE_ASSESSMENT,
            {"occurrenceId":"0"*32,"activityId":"prepare"},
            name="Inspect the retained completion for an activity",
            binding="Use the occurrence and activity identifiers returned by the authorized workflow read.")],
        semantic_rules=[
            "The result assesses one retained completion at read time. It does not change the recorded completion, authorize a transition, or confer an assignment.",
            "Current and Stale describe exact numeric effects, a bound calculation result or the active rule publication and governing revisions, according to the returned basis. A manual attestation is historical. Unavailable or unauthorized evidence receives the same neutral result.",
            "A retryable outcome can be read again. Existing return and completion operations keep their own validation and admission.",
            _READ_AUTHORITY_RULE,
        ])


def evidence_options_program_contract() -> dict:
    """Expose exactly the eligible receipt page returned for a Ready activity."""
    from .metadata_read_contract import obj, read_contract, read_example

    ids={"occurrenceId":_text_schema(_OCCURRENCE), "activityId":_text_schema(_ID)}
    cursor={"anyOf":[{"type":"integer", "minimum":1, "maximum":_MAX_BIGINT},
                    {"type":"null"}]}
    arguments=obj({**ids,
        "limit":{"type":"integer", "minimum":1, "maximum":_EVIDENCE_PAGE_LIMIT, "default":50},
        "beforeCommittedRevision":cursor}, list(ids))
    item=obj({"selectionKey":_text_schema(_KEY),
        "label":{"enum":sorted(_EVIDENCE_ACTION_LABELS.values())},
        "occurredAt":{"type":"string", "format":"date-time"},
        "outcome":{"const":"Committed"}, "current":{"type":"boolean"}})
    result=obj({"items":{"type":"array", "maxItems":_EVIDENCE_PAGE_LIMIT, "items":item},
        "nextBeforeCommittedRevision":cursor})
    result["allOf"]=[{"if":{"properties":{"items":{"maxItems":0}}},
        "then":{"properties":{"nextBeforeCommittedRevision":{"type":"null"}}}}]
    return read_contract(EVIDENCE_OPTIONS, arguments, result,
        owner="PostgresApplicationWorkflowOccurrences.evidence_options",
        examples=[read_example(EVIDENCE_OPTIONS,
            {"occurrenceId":"0"*32, "activityId":"prepare", "limit":20},
            name="Find receipts eligible for an assigned activity",
            binding="Use the exact occurrence and Ready activity IDs from current authorized work.")],
        semantic_rules=[
            "This read checks the current assignment and the activity's authored evidence policy. A manual attestation uses no receipt and has an empty page.",
            "Current is the read-time observation of the exact numeric effects or the active rule publication and its governing revisions. Historical evidence appears only when the activity permits it.",
            "Use selectionKey unchanged as the OperationReceipt operationId. The fixed core checks authority, evidence and currentness again at completion.",
            "Continue using the returned nextBeforeCommittedRevision. A non-null value uses the last visible receipt and is issued only after finding another eligible receipt.",
            "APPLICATION_WORKFLOW_EVIDENCE_LIST_STALE means the application changed during the read. Restart from the first page. APPLICATION_WORKFLOW_EVIDENCE_SEARCH_INCOMPLETE means the bounded scan could not establish the page.",
            _READ_AUTHORITY_RULE,
        ])


def navigation_read_contract(function: str) -> dict:
    """Expose exact current worklist and occurrence read envelopes."""
    from .metadata_read_contract import obj, read_contract, read_example

    def nullable(schema):
        return {"anyOf": [schema, {"type": "null"}]}

    occurrence_id, identifier = _text_schema(_OCCURRENCE), _text_schema(_ID)
    digest = _text_schema(STATE_TOKEN_PATTERN)
    instant = {"type": "string", "format": "date-time"}
    ordinal = {"type": "integer", "minimum": 1, "maximum": _MAX_BIGINT}
    text_value = {"type": "string"}
    kind = {"enum": ["Action", "Review"]}
    assignment = obj({"assignmentSetId": identifier, "stateToken": digest,
        "digest": digest, "assignmentId": identifier, "assignmentCreatorIssuer": text_value,
        "kind": kind})
    if function == WORKLIST:
        cursor_fields = {"afterOccurrenceId": occurrence_id, "afterActivityId": identifier}
        arguments = obj({"limit": {"type": "integer", "minimum": 1, "maximum": _WORKLIST_PAGE_LIMIT},
            "includeBlocked": {"type": "boolean"}, "includeWaiting": {"type": "boolean"},
            "occurrenceId": occurrence_id,
            **{name: nullable(schema) for name, schema in cursor_fields.items()}}, [])
        arguments["allOf"] = [{
            "if": {"required": [current], "properties": {current: {"type": "string"}}},
            "then": {"required": [paired], "properties": {paired: cursor_fields[paired]}},
        } for current, paired in (("afterOccurrenceId", "afterActivityId"),
                                   ("afterActivityId", "afterOccurrenceId"))]
        row = obj({"occurrenceId": occurrence_id, "occurrenceStateToken": digest,
            "flowId": identifier, "flowStateToken": digest, "definitionDigest": digest,
            "activityId": identifier, "activityStateToken": digest, "name": text_value,
            "kind": kind, "destination": destination_schema(), "assignmentResolution": assignment})
        blocked = obj({"occurrenceId": occurrence_id, "flowId": identifier, "activityId": identifier,
            "name": text_value, "reason": {"enum": ["SelectionMetadataChanged",
                "WorkflowDefinitionUnavailable", "WorkflowDependencyUnavailable"]}})
        waiting = obj({"occurrenceId": occurrence_id, "flowId": identifier, "activityId": identifier,
            "name": text_value, "reason": {"enum": ["DependencyPending", "ReturnedForRework"]}})
        result = obj({"items": {"type": "array", "maxItems": _WORKLIST_PAGE_LIMIT, "items": row},
            "blockedItems": {"type": "array", "maxItems": _WORKLIST_PAGE_LIMIT, "items": blocked},
            "waitingItems": {"type": "array", "maxItems": _WORKLIST_PAGE_LIMIT, "items": waiting},
            "nextCursor": nullable(obj(cursor_fields))}, ["items", "nextCursor"])
        examples = [
            read_example(WORKLIST, {"limit": 20, "includeBlocked": True}, name="Read currently assigned work",
                binding="Use the exact application selected in authorized discovery."),
            read_example(WORKLIST, {"occurrenceId": "1" * 32, "includeBlocked": True},
                name="Find assigned work in a known occurrence",
                binding="Use a known occurrenceId from the same application and current task context."),
            read_example(WORKLIST, {"limit": 20, "includeBlocked": True, "includeWaiting": True},
                name="Read assigned Ready and Waiting activities",
                binding="Use the exact application selected in authorized discovery."),
        ]
        rules = [
            "Items contain currently assigned Ready activities under the effective calling identity. Each page resolves the activities and their dependencies from one committed snapshot.",
            "Set includeBlocked to true to receive blockedItems for work still assigned to the caller whose exact workflow definition or dependencies no longer validate. These rows allow history inspection. Ask an application administrator to review the workflow before starting replacement work.",
            "Set includeWaiting to true to receive waitingItems for assigned activities with unresolved predecessors or returned work. A waiting row identifies the exact activity for inspection. Only items contains Ready activities and their action tokens.",
            "Pass occurrenceId to read only assigned work in that exact occurrence. Unknown and unassigned occurrences yield empty results under current application access.",
            "The limit covers all requested activity states together. Keep includeBlocked, includeWaiting and occurrenceId unchanged and pass both nextCursor fields to continue. A filtered continuation must belong to the same occurrence. The cursor uses the last returned activity from any of the requested arrays.",
            "A null cursor means this read established the end of the list. APPLICATION_WORKFLOW_WORKLIST_SEARCH_INCOMPLETE means the bounded read could not establish a complete page.",
        ]
    elif function == READ:
        arguments = obj({"occurrenceId": occurrence_id, "afterEventOrdinal": {**ordinal, "minimum": 0},
                         "eventLimit": {"type": "integer", "minimum": 1, "maximum": _EVENT_PAGE_LIMIT},
                         "includeCurrentReturns": {"type": "boolean"}},
                        ["occurrenceId"])
        activity = obj({"activityId": identifier, "kind": kind,
            "status": {"enum": ["Blocked", "Ready", "Completed", "Returned", "Cancelled"]},
            "activityStateToken": digest, "operationId": nullable(text_value),
            "completedAt": nullable(instant), "returnedToActivityId": nullable(identifier)})
        actor = obj({"issuer": text_value, "subjectId": text_value})
        review_return = obj({
            "kind": {"const": "ReviewReturn"},
            "reason": {"type": "string", "minLength": 1, "maxLength": _RETURN_REASON_LIMIT},
            "targetActivityId": identifier,
            "actor": actor,
            "returnedAt": instant,
            "assignmentResolution": obj({**assignment["properties"], "kind": {"const": "Review"}}),
        })
        event = obj({"ordinal": ordinal, "eventType": {"enum": ["OccurrenceStarted", "ActivityCompleted",
            "ActivityReturned", "OccurrenceCompleted", "OccurrenceCancelled"]},
            "activityId": nullable(identifier), "operationId": text_value,
            "actor": actor,
            "evidence": {"type": ["object", "null"], "description": "Recorded event-specific evidence."},
            "evidenceDigest": nullable(digest), "committedRevision": ordinal, "createdAt": instant})
        event["allOf"] = [{
            "if": {"properties": {"eventType": {"const": "ActivityReturned"}}},
            "then": {"properties": {
                "activityId": identifier,
                "evidence": review_return,
                "evidenceDigest": digest,
            }},
        }]
        result = obj({"occurrenceId": occurrence_id, "flowId": identifier, "flowStateToken": digest,
            "definitionDigest": digest, "status": {"enum": ["Active", "Completed", "Cancelled"]},
            "occurrenceStateToken": digest, "lastEventOrdinal": ordinal, "startedRevision": ordinal,
            "startedAt": instant, "completedAt": nullable(instant), "cancelledAt": nullable(instant),
            "activities": {"type": "array", "maxItems": MAX_ACTIVITIES, "items": activity},
            "events": {"type": "array", "maxItems": _EVENT_PAGE_LIMIT, "items": event},
            "nextEventOrdinal": nullable(ordinal)})
        result["properties"]["currentReturns"] = {
            "type": "array", "maxItems": MAX_ACTIVITIES, "items": {
                **event, "properties": {**event["properties"],
                    "eventType": {"const": "ActivityReturned"},
                    "activityId": identifier, "evidence": review_return,
                    "evidenceDigest": digest}}}
        examples = [read_example(READ, {"occurrenceId": "0" * 32, "eventLimit": 20},
            name="Open an exact workflow occurrence",
            binding="Use the occurrenceId from the current worklist or original workflow response."),
            read_example(READ, {"occurrenceId": "0" * 32, "eventLimit": 20,
                "includeCurrentReturns": True}, name="Open current workflow work and return instructions",
                binding="Use the occurrenceId from the current worklist. Read currentReturns before paging through history.")]
        rules = [
            "The occurrence status and token, activities, and event page describe the same committed snapshot. Events are ascending within that snapshot.",
            "For another event page, use nextEventOrdinal as afterEventOrdinal for the same occurrence. Null means this read reached the end of the observed event history.",
            "ActivityReturned records the review activityId and the configured evidence.targetActivityId together with evidence.reason. For current rework, match the event operationId and target to the returned review activity and the Ready target in this snapshot.",
            "Pass includeCurrentReturns true to receive currentReturns from the same snapshot independently of the event page. It contains the recorded return events for current Returned reviews and their Ready targets. Missing instructions on a history page do not imply the absence of current rework.",
            "Use a current activity state token and follow the separate entitlement and evidence rules before requesting a transition.",
        ]
    else:
        raise ValueError("APPLICATION_WORKFLOW_NAVIGATION_FUNCTION_INVALID")
    return read_contract(function, arguments, result,
        owner="PostgresApplicationWorkflowOccurrences", examples=examples, semantic_rules=[*rules, _READ_AUTHORITY_RULE])


def _program(value: object)->tuple[str,dict]:
    if (type(value) is not dict
            or set(value)!={"languageVersion","function","arguments"}
            or value.get("languageVersion")!=2
            or value.get("function") not in FUNCTIONS
            or type(value.get("arguments")) is not dict):
        raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_PROGRAM_INVALID")
    return value["function"],value["arguments"]


def _review_return_invalidation(model: ApplicationWorkflow,review_id: str,
                                rows: Collection[dict])->tuple[str,list[str]]:
    """Return the configured ancestor and descendants that need resetting.

    The graph contract already proves that the return target is an ancestor of
    the review.  Runtime state still determines which strict descendants need
    a versioned change: rows that are already Blocked with no prior completion
    or return state must remain untouched.
    """
    review=next((item for item in model.activities
                 if item.activity_id==review_id),None)
    if review is None or review.kind!="Review" or review.return_to is None:
        raise ValueError("APPLICATION_WORKFLOW_RETURN_UNAVAILABLE")
    descendants:set[str]=set()
    changed=True
    while changed:
        changed=False
        for candidate in model.activities:
            if (candidate.activity_id not in descendants
                    and candidate.activity_id!=review.return_to
                    and (review.return_to in candidate.depends_on
                         or any(parent in descendants
                                for parent in candidate.depends_on))):
                descendants.add(candidate.activity_id);changed=True
    if review_id not in descendants:
        raise ValueError("APPLICATION_WORKFLOW_RETURN_TARGET_INVALID")
    by_id={row["activity_id"]:row for row in rows}
    invalidated=[]
    for activity_id in sorted(descendants-{review_id}):
        row=by_id.get(activity_id)
        if row is None:
            raise ValueError("APPLICATION_WORKFLOW_ACTIVITY_UNAVAILABLE")
        if (row["status"]!="Blocked" or row.get("operation_id") is not None
                or row.get("completed_by_issuer") is not None
                or row.get("completed_by_subject_id") is not None
                or row.get("completed_at") is not None
                or row.get("returned_to_activity_id") is not None):
            invalidated.append(activity_id)
    return review.return_to,invalidated


def workflow_activity_task_visible_in_transaction(db,scope: ApplicationScope,
        identity: VerifiedIdentity,occurrence_id: str,activity_id: str,*,
        skip_unresolved: bool=False)->bool:
    """Require the exact current assignment before exposing a universal task.

    The worklist owns disclosure of blocked work to its assignee. The task
    monitor and log still require a currently resolved selection. A direct
    read preserves its specific dependency refusal.
    """
    service=object.__new__(PostgresApplicationWorkflowOccurrences)
    service.identity=identity
    try:
        occurrence=service._occurrence(db,scope,_occurrence_id(occurrence_id),
                                       lock=False)
        model=service._occurrence_model(db,scope,occurrence)
        activity=service._activity(model,_identifier(
            activity_id,"APPLICATION_WORKFLOW_ACTIVITY_ID_INVALID"))
        state=service._context(db,scope,lock=False)
        resolved=resolve_selection_in_transaction(
            db,scope,model.normalized()["selection"],state["metadata_revision"])
        now=db.execute("SELECT transaction_timestamp() AS now").fetchone()["now"]
        groups=PostgresAccessChecker.current_groups_in_transaction(db,identity)
        service._assignment(db,scope,activity,resolved["members"],
            require_entitlement=True,now=now,groups=groups)
    except ValueError as error:
        code = str(error)
        if code in _ASSIGNMENT_UNAVAILABLE_CODES or code == "APPLICATION_WORKFLOW_SELECTION_NOT_ASSIGNED":
            return False
        if skip_unresolved and (code in _WORKFLOW_DEPENDENCY_BLOCKS
                                or code == "APPLICATION_WORKFLOW_CURRENT_UNAVAILABLE"):
            return False
        raise
    return True


class PostgresApplicationWorkflowOccurrences:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity):
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError("A verified identity is required")
        assert_nonowner_role(dsn,"epm_runtime",_TABLES)
        self.dsn,self.identity=dsn,identity

    @staticmethod
    def _scope(db,scope: ApplicationScope)->None:
        PostgresApplicationWorkflows._scope(db,scope)

    @staticmethod
    def _context(db,scope: ApplicationScope,*,lock: bool)->dict:
        return PostgresApplicationWorkflows._context(db,scope,lock=lock)

    @staticmethod
    def _active(state: dict)->None:
        if (state["application_status"]!="Active"
                or state["processing_mode"]!="Active"):
            raise ValueError("APPLICATION_NOT_WRITABLE")

    def _prepare(self,db,scope: ApplicationScope,permission: str,
                 function: str) -> AccessDecision:
        self._scope(db,scope)
        PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
        return PostgresAccessChecker.check_in_transaction(
            db,self.identity,scope,permission,function=function)

    def _recheck_authority(self, db, scope: ApplicationScope, function: str,
                           access: AccessDecision, *, permission: str = "read") -> None:
        # Directory membership may change without the workspace advisory fence.
        if PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, permission, function=function) != access:
            raise ValueError(_AUTHORITY_STALE)

    def _prior(self,db,scope: ApplicationScope,operation_id: str,
               digest: str)->dict|None:
        row=db.execute("""SELECT command_digest,actor_id,result
            FROM epm.operation_receipt WHERE workspace_id=%s
              AND application_id=%s AND operation_id=%s""",(
            scope.workspace_id,scope.application_id,operation_id)).fetchone()
        if row is None:return None
        if (row["command_digest"]!=digest
                or row["actor_id"]!=self.identity.subject_id):
            raise ValueError("APPLICATION_WORKFLOW_IDEMPOTENCY_CONFLICT")
        return row["result"]

    def _receipt(self,db,scope: ApplicationScope,operation_id: str,
                 digest: str,revision: int,result: dict)->None:
        db.execute("""INSERT INTO epm.operation_receipt(workspace_id,
            application_id,operation_id,command_digest,actor_id,
            committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)""",(
            scope.workspace_id,scope.application_id,operation_id,digest,
            self.identity.subject_id,revision,Jsonb(result)))

    @staticmethod
    def _workflow(db,scope: ApplicationScope,flow_id: str,state_token: str
                  )->ApplicationWorkflow:
        row=db.execute("""SELECT * FROM epm.application_workflow_definition
            WHERE workspace_id=%s AND application_id=%s AND flow_id=%s
              AND state_token=%s AND status='Active'""",(scope.workspace_id,
            scope.application_id,flow_id,state_token)).fetchone()
        if row is None:raise ValueError("APPLICATION_WORKFLOW_CURRENT_UNAVAILABLE")
        return PostgresApplicationWorkflows._verified(scope,row)

    @staticmethod
    def _occurrence(db,scope: ApplicationScope,value: str,*,lock: bool)->dict:
        row=db.execute("""SELECT * FROM epm.application_workflow_occurrence
            WHERE workspace_id=%s AND application_id=%s AND occurrence_id=%s"""+
            (" FOR UPDATE" if lock else ""),(scope.workspace_id,
            scope.application_id,value)).fetchone()
        if row is None:
            raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_UNAVAILABLE")
        return row

    @classmethod
    def _occurrence_model(cls,db,scope: ApplicationScope,row: dict
                          )->ApplicationWorkflow:
        model=cls._workflow(db,scope,row["flow_id"],row["flow_state_token"])
        if model.digest!=row["flow_digest"]:
            raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_DEFINITION_STALE")
        return model

    @staticmethod
    def _activity(model: ApplicationWorkflow,activity_id: str)->Activity:
        for item in model.activities:
            if item.activity_id==activity_id:return item
        raise ValueError("APPLICATION_WORKFLOW_ACTIVITY_UNAVAILABLE")

    def _worklist_resolution(self, db, scope: ApplicationScope, row: dict,
                             available_functions: Collection[str], metadata_revision: int):
        try:
            model = self._workflow(db, scope, row["flow_id"], row["flow_state_token"])
        except ValueError as error:
            if str(error) != "APPLICATION_WORKFLOW_CURRENT_UNAVAILABLE":
                raise
            # A withdrawal rotates the token while existing occurrences still
            # retain their original definition digest. Use only that definition
            # for disclosing a blocked assignment, never to authorize an effect.
            retained = db.execute("""SELECT * FROM epm.application_workflow_definition
                WHERE workspace_id=%s AND application_id=%s AND flow_id=%s
                  AND definition_digest=%s""", (scope.workspace_id, scope.application_id,
                row["flow_id"], row["flow_digest"])).fetchone()
            if retained is None:
                raise
            return PostgresApplicationWorkflows._verified(scope, retained), None, "WorkflowDefinitionUnavailable"
        if model.digest != row["flow_digest"]:
            raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_DEFINITION_STALE")
        try:
            resolved = PostgresApplicationWorkflows._validate_references(
                db, scope, model, available_functions, metadata_revision)
        except ValueError as error:
            reason = _WORKFLOW_DEPENDENCY_BLOCKS.get(str(error))
            if reason is None:
                raise
            return model, None, reason
        return model, resolved["members"], None

    @staticmethod
    def _current_assignment(db,scope: ApplicationScope,activity: Activity,
                            now: datetime) -> tuple[ApplicationAssignmentSet, ApplicationAssignment, str]:
        ref=activity.assignment_ref
        row=db.execute("""SELECT * FROM epm.application_assignment_definition
            WHERE workspace_id=%s AND application_id=%s
              AND assignment_set_id=%s AND state_token=%s
              AND definition_digest=%s AND status='Active'""",(scope.workspace_id,
            scope.application_id,ref.assignment_set_id,ref.state_token,
            ref.digest)).fetchone()
        if row is None:
            raise ValueError("APPLICATION_WORKFLOW_ASSIGNMENT_UNAVAILABLE")
        model=compile_application_assignment_set(row["definition"])
        if (model.scope!=scope or model.assignment_set_id!=ref.assignment_set_id
                or model.digest!=ref.digest):
            raise ValueError("APPLICATION_WORKFLOW_ASSIGNMENT_UNAVAILABLE")
        assignment=model.assignment(ref.assignment_id)
        if (now<model.effective_from
                or model.effective_to is not None and now>model.effective_to):
            raise ValueError("APPLICATION_WORKFLOW_ASSIGNMENT_NOT_EFFECTIVE")
        return model, assignment, row["updater_issuer"]

    def _require_assignment_principal(self, activity: Activity, assignment: ApplicationAssignment,
                                      issuer: str, groups: tuple[str, ...]) -> None:
        if activity.kind=="Action":
            principal=assignment.principal_matches(self.identity.subject_id, groups)
        else:
            principal=any((reviewer.kind=="Subject"
                and reviewer.identifier==self.identity.subject_id)
                or (reviewer.kind=="Group"
                and reviewer.identifier in groups)
                for reviewer in assignment.reviewer_chain)
        if self.identity.issuer!=issuer or not principal:
            raise ValueError("APPLICATION_WORKFLOW_ACTIVITY_NOT_ASSIGNED")

    def _assignment(self,db,scope: ApplicationScope,activity: Activity,
                    resolved_members: dict[str,list[str]],*,
                    require_entitlement: bool,now: datetime,
                    groups: tuple[str,...]=())->dict:
        model, assignment, issuer = self._current_assignment(db, scope, activity, now)
        for dimension,members in assignment.member_selectors:
            selected=resolved_members.get(dimension)
            if selected is None or not set(selected)<=set(members):
                raise ValueError("APPLICATION_WORKFLOW_SELECTION_NOT_ASSIGNED")
        if require_entitlement:
            self._require_assignment_principal(activity, assignment, issuer, groups)
        return {"assignmentSetId":model.assignment_set_id,
            "stateToken":activity.assignment_ref.state_token,"digest":model.digest,
            "assignmentId":assignment.assignment_id,
            "assignmentCreatorIssuer":issuer,
            "kind":activity.kind}

    def start(self,scope: ApplicationScope,*,flow_id: str,
              expected_state_token: str,expected_metadata_revision: int,
              expected_policy_revision: int,expected_schema_epoch: int,
              idempotency_key: str,
              available_functions: Collection[str],replay_only: bool=False)->dict|None:
        flow_id=_identifier(flow_id,"APPLICATION_WORKFLOW_FLOW_ID_INVALID")
        expected_state_token=require_state_token(expected_state_token,
            error="APPLICATION_WORKFLOW_STATE_TOKEN_INVALID")
        metadata=_revision(expected_metadata_revision,
            "APPLICATION_WORKFLOW_METADATA_REVISION_INVALID")
        policy=_revision(expected_policy_revision,
            "APPLICATION_WORKFLOW_POLICY_REVISION_INVALID")
        schema=_revision(expected_schema_epoch,
            "APPLICATION_WORKFLOW_SCHEMA_EPOCH_INVALID")
        operation_id=_key(idempotency_key)
        command={"function":START,"scope":[scope.workspace_id,
            scope.application_id],"identity":[self.identity.issuer,
            self.identity.subject_id],"flowId":flow_id,
            "expectedStateToken":expected_state_token,
            "expectedMetadataRevision":metadata,
            "expectedPolicyRevision":policy,"expectedSchemaEpoch":schema}
        digest=_canonical_digest(command)
        derived=sha256(json.dumps({"namespace":
            "openepm-application-workflow-occurrence-v1","scope":command["scope"],
            "flowId":flow_id,"stateToken":expected_state_token,
            "idempotencyKey":operation_id},
            sort_keys=True,separators=(",",":")).encode()).hexdigest()[:32]
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            if replay_only:db.execute("SET TRANSACTION READ ONLY")
            access=self._prepare(db,scope,"admin",START)
            prior=self._prior(db,scope,operation_id,digest)
            if prior is not None:
                self._recheck_authority(db, scope, START, access, permission="admin")
                return prior
            if replay_only:return None
            state=self._context(db,scope,lock=True);self._active(state)
            PostgresApplicationWorkflows._assert_context(
                state,metadata,policy,schema)
            model=self._workflow(db,scope,flow_id,expected_state_token)
            resolved=PostgresApplicationWorkflows._validate_references(
                db,scope,model,available_functions,metadata,validate_receipt_contracts=True)
            now=db.execute("SELECT transaction_timestamp() AS now").fetchone()["now"]
            for activity in model.activities:
                self._assignment(db,scope,activity,resolved["members"],
                    require_entitlement=False,now=now)
            revision=state["commit_revision"]+1
            ready=list(model.start_activity_ids)
            occurrence_token=new_state_token()
            result={"operationId":operation_id,"function":START,
                "status":"Active","occurrenceId":derived,
                "occurrenceStateToken":occurrence_token,"flowId":flow_id,
                "flowStateToken":expected_state_token,
                "definitionDigest":model.digest,"readyActivityIds":ready,
                "committedRevision":revision}
            self._receipt(db,scope,operation_id,digest,revision,result)
            db.execute("""INSERT INTO epm.application_workflow_occurrence(
                workspace_id,application_id,occurrence_id,flow_id,flow_state_token,
                flow_digest,status,last_event_ordinal,state_token,started_revision,
                started_operation_id,last_operation_id,started_by_issuer,
                started_by_subject_id) VALUES(%s,%s,%s,%s,%s,%s,'Active',1,%s,
                %s,%s,%s,%s,%s)""",(scope.workspace_id,scope.application_id,
                derived,flow_id,expected_state_token,model.digest,
                occurrence_token,revision,operation_id,operation_id,
                self.identity.issuer,self.identity.subject_id))
            for activity in model.activities:
                activity_token=new_state_token()
                db.execute("""INSERT INTO epm.application_workflow_activity(
                    workspace_id,application_id,occurrence_id,flow_id,
                    activity_id,kind,status,transition_ordinal,state_token)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,1,%s)""",(
                    scope.workspace_id,scope.application_id,derived,flow_id,
                    activity.activity_id,activity.kind,
                    "Ready" if activity.activity_id in ready else "Blocked",
                    activity_token))
            self._event(db,scope,derived,1,"OccurrenceStarted",None,
                operation_id,digest,revision)
            db.execute("""UPDATE epm.application_state SET commit_revision=%s
                WHERE workspace_id=%s AND application_id=%s""",(revision,
                scope.workspace_id,scope.application_id))
            self._recheck_authority(db, scope, START, access, permission="admin")
            return result

    def read(self,scope: ApplicationScope,value: str,*,event_limit: int=100,
             after_event_ordinal: int=0,include_current_returns: bool=False)->dict:
        value=_occurrence_id(value)
        if type(event_limit) is not int or not 1 <= event_limit <= _EVENT_PAGE_LIMIT:
            raise ValueError("APPLICATION_WORKFLOW_EVENT_LIMIT_INVALID")
        if type(after_event_ordinal) is not int or not 0 <= after_event_ordinal <= _MAX_BIGINT:
            raise ValueError("APPLICATION_WORKFLOW_EVENT_CURSOR_INVALID")
        if type(include_current_returns) is not bool:
            raise ValueError("APPLICATION_WORKFLOW_READ_ARGUMENTS_INVALID")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute("SET TRANSACTION READ ONLY")
            access=self._prepare(db,scope,"read",READ)
            # One statement keeps the occurrence, activities and bounded
            # append-only event page on the same visibility cut.
            occurrence = db.execute("""SELECT o.*,
                COALESCE((SELECT jsonb_agg(to_jsonb(a) ORDER BY a.activity_id)
                    FROM (SELECT activity_id,kind,status,state_token,operation_id,completed_at,returned_to_activity_id
                        FROM epm.application_workflow_activity
                        WHERE workspace_id=o.workspace_id AND application_id=o.application_id
                          AND occurrence_id=o.occurrence_id) a), '[]'::jsonb) AS activities,
                COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY e.event_ordinal)
                    FROM (SELECT event_ordinal,event_type,activity_id,operation_id,actor_issuer,actor_subject_id,
                            evidence,evidence_digest,committed_revision,created_at
                        FROM epm.application_workflow_event
                        WHERE workspace_id=o.workspace_id AND application_id=o.application_id
                          AND occurrence_id=o.occurrence_id AND event_ordinal>%s
                        ORDER BY event_ordinal LIMIT %s) e), '[]'::jsonb) AS event_page,
                CASE WHEN %s AND o.status='Active' THEN COALESCE((
                    SELECT jsonb_agg(to_jsonb(e) ORDER BY e.event_ordinal)
                    FROM epm.application_workflow_activity review
                    JOIN epm.application_workflow_activity target
                      ON (target.workspace_id,target.application_id,target.occurrence_id,target.activity_id)
                          =(review.workspace_id,review.application_id,review.occurrence_id,
                            review.returned_to_activity_id)
                    JOIN epm.application_workflow_event e
                      ON (e.workspace_id,e.application_id,e.occurrence_id,e.operation_id)
                          =(review.workspace_id,review.application_id,review.occurrence_id,review.operation_id)
                    WHERE (review.workspace_id,review.application_id,review.occurrence_id)
                        =(o.workspace_id,o.application_id,o.occurrence_id)
                      AND review.kind='Review' AND review.status='Returned' AND target.status='Ready'
                      AND e.event_type='ActivityReturned' AND e.activity_id=review.activity_id
                      AND e.evidence->>'kind'='ReviewReturn'
                      AND e.evidence->>'targetActivityId'=target.activity_id), '[]'::jsonb)
                    ELSE '[]'::jsonb END AS current_returns
                FROM epm.application_workflow_occurrence o
                WHERE o.workspace_id=%s AND o.application_id=%s AND o.occurrence_id=%s""",
                (after_event_ordinal, event_limit + 1, include_current_returns,
                 scope.workspace_id, scope.application_id, value)).fetchone()
            self._recheck_authority(db, scope, READ, access)
            if occurrence is None:
                raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_UNAVAILABLE")
            activities, events = occurrence["activities"], occurrence["event_page"]
            more=len(events)>event_limit;events=events[:event_limit]
            result=self._result(occurrence,activities,events)
            result["nextEventOrdinal"]=(events[-1]["event_ordinal"]
                if more and events else None)
            if include_current_returns:
                result["currentReturns"]=[self._event_result(row) for row in occurrence["current_returns"]]
            return result

    def worklist(self,scope: ApplicationScope,*,limit: int=100,
                 occurrence_id: str|None=None,
                 after_occurrence_id: str|None=None,
                 after_activity_id: str|None=None,
                 include_blocked: bool=False,
                 include_waiting: bool=False,
                 available_functions: Collection[str])->dict:
        if type(limit) is not int or not 1 <= limit <= _WORKLIST_PAGE_LIMIT:
            raise ValueError("APPLICATION_WORKFLOW_WORKLIST_LIMIT_INVALID")
        if type(include_blocked) is not bool or type(include_waiting) is not bool:
            raise ValueError("APPLICATION_WORKFLOW_WORKLIST_ARGUMENTS_INVALID")
        if occurrence_id is not None:
            _occurrence_id(occurrence_id)
        if (after_occurrence_id is None)!=(after_activity_id is None):
            raise ValueError("APPLICATION_WORKFLOW_WORKLIST_CURSOR_INVALID")
        if after_occurrence_id is not None:
            _occurrence_id(after_occurrence_id)
            _identifier(after_activity_id,
                "APPLICATION_WORKFLOW_ACTIVITY_ID_INVALID")
            if occurrence_id is not None and occurrence_id != after_occurrence_id:
                raise ValueError("APPLICATION_WORKFLOW_WORKLIST_CURSOR_INVALID")
        with ExitStack() as stack:
            authority = stack.enter_context(connect_postgres(self.dsn, row_factory=dict_row))
            stack.enter_context(authority.transaction())
            authority.execute("SET TRANSACTION READ ONLY")
            access = self._prepare(authority, scope, "read", WORKLIST)

            # Hold the current authorization fence while resolving the whole
            # worklist against one business snapshot.
            db = stack.enter_context(connect_postgres(self.dsn, row_factory=dict_row))
            stack.enter_context(db.transaction())
            db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            self._scope(db, scope)
            state=self._context(db,scope,lock=False)
            now=db.execute("SELECT transaction_timestamp() AS now").fetchone()["now"]
            # Narrow the scan using the canonical assignment pinned to each
            # workflow activity. The compiled assignment, selection, effective
            # dates and current workflow still govern every returned row.
            rows=db.execute("""WITH principal_candidates AS MATERIALIZED (
                  SELECT d.workspace_id,d.application_id,d.assignment_set_id,
                    d.state_token,d.definition_digest,entry.value->>'assignmentId' AS assignment_id,
                    (entry.value->'subjects' ? %(subject)s
                     OR entry.value->'groups' ?| %(groups)s::text[]) AS can_act,
                    EXISTS (
                      SELECT 1 FROM jsonb_array_elements(entry.value->'reviewerChain') r(value)
                      WHERE (r.value->>'kind'='Subject' AND r.value->>'id'=%(subject)s)
                         OR (r.value->>'kind'='Group' AND r.value->>'id'=ANY(%(groups)s::text[]))
                    ) AS can_review
                  FROM epm.application_assignment_definition d
                  CROSS JOIN LATERAL jsonb_array_elements(d.definition->'assignments') entry(value)
                  WHERE d.workspace_id=%(workspace)s AND d.application_id=%(application)s
                    AND d.status='Active' AND d.updater_issuer=%(issuer)s
                )
                SELECT a.*,o.flow_digest,o.flow_state_token,
                  o.state_token AS occurrence_state_token
                FROM epm.application_workflow_activity a
                JOIN epm.application_workflow_occurrence o USING(
                  workspace_id,application_id,occurrence_id,flow_id)
                JOIN epm.application_workflow_assignment_pin p USING(
                  workspace_id,application_id,flow_id,activity_id)
                JOIN principal_candidates candidate
                  ON (candidate.workspace_id,candidate.application_id,candidate.assignment_set_id,
                      candidate.state_token,candidate.definition_digest,candidate.assignment_id) =
                     (p.workspace_id,p.application_id,p.assignment_set_id,
                      p.assignment_state_token,p.assignment_digest,p.assignment_id)
                WHERE a.workspace_id=%(workspace)s AND a.application_id=%(application)s
                  AND o.status='Active' AND a.status=ANY(%(statuses)s)
                  AND (%(occurrence)s::text IS NULL OR a.occurrence_id=%(occurrence)s)
                  AND ((a.kind='Action' AND candidate.can_act)
                    OR (a.kind='Review' AND candidate.can_review))
                  AND (%(after_occurrence)s::text IS NULL OR
                    (a.occurrence_id,a.activity_id)>(%(after_occurrence)s,%(after_activity)s))
                ORDER BY a.occurrence_id,a.activity_id LIMIT %(scan_limit)s""",{
                "workspace":scope.workspace_id, "application":scope.application_id,
                "subject":self.identity.subject_id, "issuer":self.identity.issuer,
                "groups":list(access.groups), "occurrence":occurrence_id,
                "statuses": ["Ready", "Blocked", "Returned"] if include_waiting else ["Ready"],
                "after_occurrence":after_occurrence_id,
                "after_activity":after_activity_id,
                "scan_limit":_MAX_WORKLIST_SCAN+1,
            }).fetchall()
            cache = {}
            items, blocked, waiting = [], [], []
            result = {"items": items, "nextCursor": None}
            if include_blocked:
                result["blockedItems"] = blocked
            if include_waiting:
                result["waitingItems"] = waiting
            last = None
            for row in rows[:_MAX_WORKLIST_SCAN]:
                key=(row["flow_id"],row["flow_state_token"],row["flow_digest"])
                if key not in cache:
                    cache[key] = self._worklist_resolution(
                        db, scope, row, available_functions, state["metadata_revision"])
                model, members, reason = cache[key]
                if reason and not include_blocked:
                    continue
                activity=self._activity(model,row["activity_id"])
                try:
                    if reason:
                        _, assignment, issuer = self._current_assignment(db, scope, activity, now)
                        self._require_assignment_principal(activity, assignment, issuer, access.groups)
                    else:
                        resolution = self._assignment(db, scope, activity, members,
                            require_entitlement=True, now=now, groups=access.groups)
                except ValueError as error:
                    if str(error) in _ASSIGNMENT_UNAVAILABLE_CODES:
                        continue
                    raise
                if len(items) + len(blocked) + len(waiting) == limit:
                    result["nextCursor"] = last
                    break
                last = {"afterOccurrenceId": row["occurrence_id"], "afterActivityId": row["activity_id"]}
                identity = {"occurrenceId": row["occurrence_id"], "activityId": row["activity_id"],
                    "flowId": row["flow_id"], "name": activity.name}
                if reason:
                    blocked.append({**identity, "reason": reason})
                    continue
                if include_waiting and row["status"] != "Ready":
                    waiting.append({**identity, "reason": (
                        "ReturnedForRework" if row["status"] == "Returned" else "DependencyPending")})
                    continue
                items.append({**identity,
                    "occurrenceStateToken":row["occurrence_state_token"],
                    "flowStateToken":row["flow_state_token"],
                    "definitionDigest":row["flow_digest"],
                    "activityStateToken":row["state_token"],
                    "kind":activity.kind,
                    "destination":dict(activity.destination),
                    "assignmentResolution":resolution})
            self._recheck_authority(authority, scope, WORKLIST, access)
            if result["nextCursor"] is None and len(rows) > _MAX_WORKLIST_SCAN:
                raise ValueError("APPLICATION_WORKFLOW_WORKLIST_SEARCH_INCOMPLETE")
            return result

    def evidence_options(self,scope: ApplicationScope,*,occurrence_id: str,
            activity_id: str,limit: int=50,
            before_committed_revision: int|None=None,
            available_functions: Collection[str])->dict:
        """List only receipts the fixed validator accepts for assigned work.

        Operation identities are opaque selection values.  The caller receives
        bounded business-safe labels and cannot supply function, currentness,
        compiler or result claims.
        """
        occurrence_id=_occurrence_id(occurrence_id)
        activity_id=_identifier(activity_id,
            "APPLICATION_WORKFLOW_ACTIVITY_ID_INVALID")
        if type(limit) is not int or not 1<=limit<=_EVIDENCE_PAGE_LIMIT:
            raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_LIMIT_INVALID")
        if (before_committed_revision is not None
                and (type(before_committed_revision) is not int
                     or not 1<=before_committed_revision<=_MAX_BIGINT)):
            raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_CURSOR_INVALID")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute("SET TRANSACTION READ ONLY")
            access=self._prepare(db,scope,"read",EVIDENCE_OPTIONS)
            state=application_state(db,scope)
            if state is None:
                raise ValueError("APPLICATION_UNAVAILABLE")
            occurrence=self._occurrence(db,scope,occurrence_id,lock=False)
            if occurrence["status"]!="Active":
                raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_STALE")
            row=db.execute("""SELECT * FROM epm.application_workflow_activity
                WHERE workspace_id=%s AND application_id=%s
                  AND occurrence_id=%s AND activity_id=%s""",(
                scope.workspace_id,scope.application_id,occurrence_id,
                activity_id)).fetchone()
            if row is None or row["status"]!="Ready":
                raise ValueError("APPLICATION_WORKFLOW_ACTIVITY_STALE")
            model=self._occurrence_model(db,scope,occurrence)
            resolved=PostgresApplicationWorkflows._validate_references(
                db,scope,model,available_functions,state["metadata_revision"])
            activity=self._activity(model,activity_id)
            now=db.execute(
                "SELECT transaction_timestamp() AS now").fetchone()["now"]
            self._assignment(db,scope,activity,resolved["members"],
                require_entitlement=True,now=now,groups=access.groups)
            items=[]
            reader=replace(self.identity, groups=access.groups)

            def verified_page(cursor=None):
                self._recheck_authority(db, scope, EVIDENCE_OPTIONS, access)
                if application_state(db,scope)!=state:
                    raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_LIST_STALE")
                return {"items":items,"nextBeforeCommittedRevision":cursor}

            contract=dict(activity.evidence_contract)
            if contract.get("kind")!="OperationReceipt":
                return verified_page()
            allowed=list(contract["allowedFunctions"])
            rows=db.execute("""SELECT o.operation_id,o.committed_revision,
                    o.committed_at,COALESCE(j.function_name,
                      o.result->>'function') AS function_name
                FROM epm.operation_receipt o
                LEFT JOIN epm.job j ON j.workspace_id=o.workspace_id
                  AND j.application_id=o.application_id
                  AND j.job_id=o.operation_id
                WHERE o.workspace_id=%s AND o.application_id=%s
                  AND (%s::bigint IS NULL OR o.committed_revision<%s)
                  AND COALESCE(j.function_name,o.result->>'function')=ANY(%s)
                ORDER BY o.committed_revision DESC LIMIT %s""",(
                scope.workspace_id,scope.application_id,
                before_committed_revision,before_committed_revision,allowed,
                _MAX_EVIDENCE_SCAN+1)).fetchall()
            last_visible_revision=None
            for candidate in rows[:_MAX_EVIDENCE_SCAN]:
                try:
                    certificate=validate_workflow_evidence(db,scope,
                        reader,activity,{"kind":"OperationReceipt",
                        "operationId":candidate["operation_id"]},
                        resolved_selection=resolved,include_currentness=True)
                except ValueError as error:
                    if str(error).startswith("APPLICATION_WORKFLOW_EVIDENCE_"):
                        continue
                    raise
                # Advertise a continuation only after proving another visible
                # receipt. Its boundary is the last disclosed choice.
                if len(items)==limit:
                    return verified_page(last_visible_revision)
                last_visible_revision=candidate["committed_revision"]
                items.append({
                    "selectionKey":candidate["operation_id"],
                    "label":_EVIDENCE_ACTION_LABELS[
                        certificate.normalized["function"]],
                    "occurredAt":candidate["committed_at"].isoformat(),
                    "outcome":"Committed",
                    "current":certificate.current_assessment is True,
                })
            if len(rows)>_MAX_EVIDENCE_SCAN:
                raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_SEARCH_INCOMPLETE")
            return verified_page()

    @staticmethod
    def _assessment_activity(db, scope, occurrence_id, activity_id):
        return db.execute("""SELECT status,state_token,operation_id,completed_at,
            completed_by_issuer,completed_by_subject_id
            FROM epm.application_workflow_activity WHERE workspace_id=%s
              AND application_id=%s AND occurrence_id=%s AND activity_id=%s""",
            (scope.workspace_id,scope.application_id,occurrence_id,activity_id)).fetchone()

    @staticmethod
    def _assessment_event(db, scope, occurrence_id, activity_id, completion_id):
        return db.execute("""SELECT e.evidence,e.evidence_digest,e.actor_issuer,
            e.actor_subject_id,e.created_at,
            l.evidence_operation_id,l.evidence_committed_revision,
            l.validator_id,l.validator_version,l.evidence_digest AS link_digest
            FROM epm.application_workflow_event e
            LEFT JOIN epm.application_workflow_evidence_link l
              ON l.workspace_id=e.workspace_id AND l.application_id=e.application_id
              AND l.occurrence_id=e.occurrence_id AND l.activity_id=e.activity_id
              AND l.completion_operation_id=e.operation_id AND l.event_type=e.event_type
            WHERE e.workspace_id=%s AND e.application_id=%s AND e.occurrence_id=%s
              AND e.activity_id=%s AND e.operation_id=%s
              AND e.event_type='ActivityCompleted'""",
            (scope.workspace_id,scope.application_id,occurrence_id,activity_id,
             completion_id)).fetchone()

    def _recorded_evidence(self, db, scope, occurrence_id, row, activity, resolved):
        now=db.execute("SELECT transaction_timestamp() AS now").fetchone()["now"]
        # A reviewer may need to inspect the planner's completed prerequisite.
        # Historical inspection does not confer the planner's action entitlement.
        assignment=self._assignment(db,scope,activity,resolved["members"],
            require_entitlement=False,now=now)
        event=self._assessment_event(
            db,scope,occurrence_id,activity.activity_id,row["operation_id"])
        if event is None or (event["actor_issuer"],event["actor_subject_id"],event["created_at"])!=(
                row["completed_by_issuer"],row["completed_by_subject_id"],row["completed_at"]):
            return None
        payload=event["evidence"]
        if type(payload) is not dict or payload.get("assignmentResolution")!=assignment:
            return None
        normalized=payload.get("artifactEvidence")
        if type(normalized) is not dict or _canonical_digest(normalized)!=event["evidence_digest"]:
            return None
        return event,normalized

    @staticmethod
    def _recorded_receipt(event, normalized):
        if (event["link_digest"]!=event["evidence_digest"]
                or normalized.get("kind")!="OperationReceipt"
                or normalized.get("operationId")!=event["evidence_operation_id"]
                or normalized.get("committedRevision")!=event["evidence_committed_revision"]
                or normalized.get("validator")!={"id":event["validator_id"],"version":event["validator_version"]}):
            return None
        return WorkflowEvidence(normalized,event["evidence_digest"],
            event["validator_id"],event["validator_version"],event["evidence_operation_id"],
            event["evidence_committed_revision"])

    def _evaluate_assessment(self, db, scope, occurrence, row, state, activity_id, reader):
        """Return one proven result variant, or withhold the entire basis."""
        occurrence_id=occurrence["occurrence_id"]
        model=self._occurrence_model(db,scope,occurrence)
        activity=self._activity(model,activity_id)
        resolved=resolve_selection_in_transaction(
            db,scope,model.normalized()["selection"],state["metadata_revision"])
        recorded=self._recorded_evidence(db,scope,occurrence_id,row,activity,resolved)
        if recorded is None:
            return None
        event,normalized=recorded
        condition=dict(activity.evidence_contract)
        if condition["kind"]=="ManualAttestation":
            if event["link_digest"] is not None or not matches_completed_attestation(
                    activity,normalized,issuer=event["actor_issuer"],
                    subject=event["actor_subject_id"],completed_at=event["created_at"]):
                return None
            return _assessment_result(occurrence_id,activity_id,"NotApplicable",
                basis="ManualAttestation",token=row["state_token"])
        completed=self._recorded_receipt(event,normalized)
        if completed is None:
            return None
        assessment=assess_completed_basis(db,scope,reader,activity,
            completed,resolved_selection=resolved)
        if assessment is None:
            return None
        basis,current=assessment
        return _assessment_result(occurrence_id,activity_id,"Current" if current else "Stale",
            basis=basis,token=row["state_token"],
            require_current=condition["requireCurrent"])

    def _assert_current_review_basis(self, db, scope, occurrence_id,
                                     review, model, rows, resolved, reader):
        if review.kind!="Review":
            return
        basis_ids=set(review.depends_on)
        if review.return_to is not None:
            basis_ids.add(review.return_to)
        by_id={item["activity_id"]:item for item in rows}
        unavailable="APPLICATION_WORKFLOW_REVIEW_BASIS_UNAVAILABLE"
        for activity in model.activities:
            if (activity.activity_id not in basis_ids
                    or dict(activity.evidence_contract).get("requireCurrent") is not True):
                continue
            row=by_id.get(activity.activity_id)
            if row is None or row["status"]!="Completed" or row["operation_id"] is None:
                raise ValueError(unavailable)
            try:
                recorded=self._recorded_evidence(db,scope,occurrence_id,row,activity,resolved)
            except ValueError as error:
                if str(error) in ("APPLICATION_WORKFLOW_ASSIGNMENT_UNAVAILABLE",
                        "APPLICATION_WORKFLOW_ASSIGNMENT_NOT_EFFECTIVE",
                        "APPLICATION_WORKFLOW_SELECTION_NOT_ASSIGNED"):
                    raise ValueError(unavailable) from None
                raise
            completed=self._recorded_receipt(*recorded) if recorded is not None else None
            if completed is None:
                raise ValueError(unavailable)
            try:
                current=validate_workflow_evidence(db,scope,reader,activity,
                    {"kind":"OperationReceipt","operationId":completed.evidence_operation_id},
                    resolved_selection=resolved)
            except ValueError as error:
                if str(error)=="APPLICATION_WORKFLOW_EVIDENCE_NOT_CURRENT":
                    raise ValueError("APPLICATION_WORKFLOW_REVIEW_BASIS_STALE") from None
                if str(error).startswith("APPLICATION_WORKFLOW_EVIDENCE_"):
                    raise ValueError(unavailable) from None
                raise
            if current!=completed:
                raise ValueError(unavailable)

    def assess_evidence(self,scope: ApplicationScope,*,occurrence_id: str,
                        activity_id: str)->dict:
        """Assess only the selected retained completion under current authority."""
        occurrence_id=_occurrence_id(occurrence_id)
        activity_id=_identifier(activity_id,"APPLICATION_WORKFLOW_ACTIVITY_ID_INVALID")
        unavailable=_assessment_result(occurrence_id,activity_id,"UnavailableToAssess")
        retry=_assessment_result(occurrence_id,activity_id,"TemporarilyUnavailable")
        try:
            with connect_postgres(self.dsn,row_factory=dict_row) as db:
              with db.transaction():
                db.execute("SET TRANSACTION READ ONLY")
                configure_statement_timeout(db,2000)
                access=self._prepare(db,scope,"read",EVIDENCE_ASSESSMENT)

                def checked(result):
                    self._recheck_authority(db, scope, EVIDENCE_ASSESSMENT, access)
                    return result

                state=application_state(db,scope)
                if state is None:
                    return checked(unavailable)
                try:
                    occurrence=self._occurrence(db,scope,occurrence_id,lock=False)
                except ValueError as error:
                    if str(error)!="APPLICATION_WORKFLOW_OCCURRENCE_UNAVAILABLE":
                        raise
                    return checked(unavailable)
                row=self._assessment_activity(db,scope,occurrence_id,activity_id)
                if row is None:
                    return checked(unavailable)
                result=None
                if row["status"]!="Completed":
                    result=_assessment_result(occurrence_id,activity_id,"NoCompletedBasis")
                elif row["operation_id"] is not None:
                    try:
                        reader=replace(self.identity, groups=access.groups)
                        result=self._evaluate_assessment(db,scope,occurrence,row,state,activity_id,reader)
                    except ValueError as error:
                        # Historical references may no longer resolve or be visible.
                        if str(error)==CALCULATION_IMPACT_PENDING:
                            result=retry
                # Recheck data and all governing revisions after the proof.
                if (self._assessment_activity(db,scope,occurrence_id,activity_id)!=row
                        or self._occurrence(db,scope,occurrence_id,lock=False)!=occurrence
                        or application_state(db,scope)!=state):
                    return checked(retry)
                return checked(result if result is not None else unavailable)
        except (errors.QueryCanceled,errors.LockNotAvailable,
                errors.DeadlockDetected,errors.SerializationFailure):
            return retry

    def cancel(self,scope: ApplicationScope,*,occurrence_id: str,
               expected_occurrence_state_token: str,
               idempotency_key: str,replay_only: bool=False)->dict|None:
        occurrence_id=_occurrence_id(occurrence_id)
        expected=require_state_token(expected_occurrence_state_token,
            error="APPLICATION_WORKFLOW_OCCURRENCE_STATE_TOKEN_INVALID")
        operation_id=_key(idempotency_key)
        command={"function":CANCEL,"scope":[scope.workspace_id,
            scope.application_id],"identity":[self.identity.issuer,
            self.identity.subject_id],"occurrenceId":occurrence_id,
            "expectedOccurrenceStateToken":expected}
        digest=_canonical_digest(command)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            if replay_only:db.execute("SET TRANSACTION READ ONLY")
            access=self._prepare(db,scope,"admin",CANCEL)
            prior=self._prior(db,scope,operation_id,digest)
            if prior is not None:
                self._recheck_authority(db, scope, CANCEL, access, permission="admin")
                return prior
            if replay_only:return None
            state=self._context(db,scope,lock=True);self._active(state)
            occurrence=self._occurrence(db,scope,occurrence_id,lock=True)
            if (occurrence["status"]!="Active"
                    or occurrence["state_token"]!=expected):
                raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_STALE")
            ordinal=occurrence["last_event_ordinal"]+1
            occurrence_token=new_state_token()
            activity_seed=new_state_token()
            revision=state["commit_revision"]+1
            result={"operationId":operation_id,"function":CANCEL,
                "status":"Cancelled","occurrenceId":occurrence_id,
                "occurrenceStateToken":occurrence_token,
                "committedRevision":revision}
            self._receipt(db,scope,operation_id,digest,revision,result)
            db.execute("""UPDATE epm.application_workflow_occurrence SET
                status='Cancelled',last_event_ordinal=%s,state_token=%s,
                last_operation_id=%s,
                cancelled_at=transaction_timestamp() WHERE workspace_id=%s
                  AND application_id=%s AND occurrence_id=%s""",(ordinal,
                occurrence_token,operation_id,scope.workspace_id,scope.application_id,
                occurrence_id))
            db.execute("""UPDATE epm.application_workflow_activity SET
                status='Cancelled',transition_ordinal=transition_ordinal+1,
                state_token=encode(sha256(convert_to(%s||E'\n'||activity_id,
                  'UTF8')),'hex'),
                returned_to_activity_id=NULL WHERE workspace_id=%s
                  AND application_id=%s AND occurrence_id=%s
                  AND status IN('Blocked','Ready','Returned')""",(
                activity_seed,scope.workspace_id,scope.application_id,occurrence_id))
            self._event(db,scope,occurrence_id,ordinal,
                "OccurrenceCancelled",None,operation_id,digest,revision)
            db.execute("""UPDATE epm.application_state SET commit_revision=%s
                WHERE workspace_id=%s AND application_id=%s""",(revision,
                scope.workspace_id,scope.application_id))
            self._recheck_authority(db, scope, CANCEL, access, permission="admin")
            return result

    def _request_cancel_as_task_controller(self,scope: ApplicationScope,
            occurrence_id: str,*,allow_application_admin: bool=False)->dict:
        """Cancel one active occurrence through its governed transition.

        Universal-task control never edits workflow state itself.  It derives
        one stable operation identity from the exact occurrence state and
        delegates to ``cancel``; an acknowledgement retry therefore returns
        the original receipt rather than creating another transition.
        """
        if not allow_application_admin:
            raise ValueError("APPLICATION_WORKFLOW_TASK_ADMIN_REQUIRED")
        occurrence_id=_occurrence_id(occurrence_id)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute("SET TRANSACTION READ ONLY")
            self._prepare(db,scope,"read",READ)
            row=self._occurrence(db,scope,occurrence_id,lock=False)
            if row["status"]=="Cancelled":
                receipt=db.execute("""SELECT result FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s
                      AND operation_id=%s""",(scope.workspace_id,
                    scope.application_id,row["last_operation_id"])).fetchone()
                if (receipt is None
                        or receipt["result"].get("function")!=CANCEL):
                    raise ValueError("APPLICATION_WORKFLOW_TASK_CANCEL_UNAVAILABLE")
                return receipt["result"]
            if row["status"]!="Active":
                raise ValueError("APPLICATION_WORKFLOW_TASK_NOT_INTERRUPTIBLE")
            expected=row["state_token"]
        return self.cancel(scope,occurrence_id=occurrence_id,
            expected_occurrence_state_token=expected,
            idempotency_key=("task-cancel-"+occurrence_id+"-"+expected))

    def complete(self,scope: ApplicationScope,*,occurrence_id: str,
                 activity_id: str,expected_activity_state_token: str,
                 evidence: object,idempotency_key: str,
                 available_functions: Collection[str],replay_only: bool=False)->dict|None:
        occurrence_id=_occurrence_id(occurrence_id)
        activity_id=_identifier(activity_id,
            "APPLICATION_WORKFLOW_ACTIVITY_ID_INVALID")
        expected=require_state_token(expected_activity_state_token,
            error="APPLICATION_WORKFLOW_ACTIVITY_STATE_TOKEN_INVALID")
        if type(evidence) is not dict:
            raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_INVALID")
        operation_id=_key(idempotency_key)
        command={"function":COMPLETE,"scope":[scope.workspace_id,
            scope.application_id],"identity":[self.identity.issuer,
            self.identity.subject_id],"occurrenceId":occurrence_id,
            "activityId":activity_id,"expectedActivityStateToken":expected,
            "evidence":evidence}
        digest=_canonical_digest(command)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            if replay_only:db.execute("SET TRANSACTION READ ONLY")
            access=self._prepare(db,scope,"read",COMPLETE)
            prior=self._prior(db,scope,operation_id,digest)
            if prior is not None:
                self._recheck_authority(db, scope, COMPLETE, access)
                return prior
            if replay_only:return None
            state=self._context(db,scope,lock=True);self._active(state)
            occurrence=self._occurrence(db,scope,occurrence_id,lock=True)
            if occurrence["status"]!="Active":
                raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_STALE")
            row=db.execute("""SELECT * FROM
                epm.application_workflow_activity WHERE workspace_id=%s
                  AND application_id=%s AND occurrence_id=%s
                  AND activity_id=%s FOR UPDATE""",(scope.workspace_id,
                scope.application_id,occurrence_id,activity_id)).fetchone()
            if (row is None or row["status"]!="Ready"
                    or row["state_token"]!=expected):
                raise ValueError("APPLICATION_WORKFLOW_ACTIVITY_STALE")
            model=self._occurrence_model(db,scope,occurrence)
            resolved=PostgresApplicationWorkflows._validate_references(
                db,scope,model,available_functions,
                state["metadata_revision"])
            activity=self._activity(model,activity_id)
            now=db.execute("SELECT transaction_timestamp() AS now").fetchone()["now"]
            assignment=self._assignment(db,scope,activity,
                resolved["members"],require_entitlement=True,now=now,
                groups=access.groups)
            reader=replace(self.identity, groups=access.groups)
            certificate=validate_workflow_evidence(
                db,scope,reader,activity,evidence,
                resolved_selection=resolved)
            if certificate.evidence_operation_id==operation_id:
                raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_SELF_REFERENCE")
            rows=db.execute("""SELECT * FROM
                epm.application_workflow_activity WHERE workspace_id=%s
                  AND application_id=%s AND occurrence_id=%s
                ORDER BY activity_id FOR UPDATE""",(scope.workspace_id,
                scope.application_id,occurrence_id)).fetchall()
            self._assert_current_review_basis(
                db,scope,occurrence_id,activity,model,rows,resolved,reader)
            states={item["activity_id"]:item["status"] for item in rows}
            states[activity_id]="Completed"
            ready=[]
            for candidate in model.activities:
                if (states[candidate.activity_id] in ("Blocked","Returned")
                        and all(states[parent]=="Completed"
                                for parent in candidate.depends_on)):
                    ready.append(candidate.activity_id)
                    states[candidate.activity_id]="Ready"
            completed=all(value=="Completed" for value in states.values())
            activity_ordinal=occurrence["last_event_ordinal"]+1
            last_event_ordinal=(activity_ordinal+1 if completed
                                else activity_ordinal)
            occurrence_token=new_state_token()
            activity_token=new_state_token()
            ready_seed=new_state_token()
            revision=state["commit_revision"]+1
            result={"operationId":operation_id,"function":COMPLETE,
                "status":"Completed" if completed else "Active",
                "occurrenceId":occurrence_id,
                "occurrenceStateToken":occurrence_token,
                "activityId":activity_id,"activityStateToken":activity_token,
                "evidenceDigest":certificate.digest,
                "readyActivityIds":ready,"committedRevision":revision}
            self._receipt(db,scope,operation_id,digest,revision,result)
            db.execute("""UPDATE epm.application_workflow_activity SET
                status='Completed',transition_ordinal=transition_ordinal+1,
                state_token=%s,
                operation_id=%s,completed_by_issuer=%s,
                completed_by_subject_id=%s,
                completed_at=transaction_timestamp(),
                returned_to_activity_id=NULL WHERE workspace_id=%s
                  AND application_id=%s AND occurrence_id=%s
                  AND activity_id=%s""",(activity_token,operation_id,self.identity.issuer,
                self.identity.subject_id,scope.workspace_id,
                scope.application_id,occurrence_id,activity_id))
            if ready:
                db.execute("""UPDATE epm.application_workflow_activity SET
                    status='Ready',transition_ordinal=transition_ordinal+1,
                    state_token=encode(sha256(convert_to(%s||E'\n'||activity_id,
                      'UTF8')),'hex'),
                    operation_id=NULL,completed_by_issuer=NULL,
                    completed_by_subject_id=NULL,completed_at=NULL,
                    returned_to_activity_id=NULL WHERE workspace_id=%s
                      AND application_id=%s AND occurrence_id=%s
                      AND activity_id=ANY(%s::text[])""",(ready_seed,scope.workspace_id,
                    scope.application_id,occurrence_id,ready))
            db.execute("""UPDATE epm.application_workflow_occurrence SET
                status=%s,last_event_ordinal=%s,state_token=%s,last_operation_id=%s,
                completed_at=CASE WHEN %s THEN transaction_timestamp()
                                  ELSE NULL END
                WHERE workspace_id=%s AND application_id=%s
                  AND occurrence_id=%s""",("Completed" if completed else
                "Active",last_event_ordinal,occurrence_token,operation_id,completed,
                scope.workspace_id,scope.application_id,occurrence_id))
            self._event(db,scope,occurrence_id,activity_ordinal,
                "ActivityCompleted",activity_id,operation_id,digest,revision,
                evidence={"artifactEvidence":certificate.normalized,
                    "assignmentResolution":assignment},
                evidence_digest=certificate.digest)
            if certificate.evidence_operation_id is not None:
                db.execute("""INSERT INTO
                    epm.application_workflow_evidence_link(workspace_id,
                    application_id,occurrence_id,activity_id,
                    completion_operation_id,evidence_operation_id,
                    evidence_committed_revision,validator_id,
                    validator_version,evidence_digest)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",(
                    scope.workspace_id,scope.application_id,occurrence_id,
                    activity_id,operation_id,
                    certificate.evidence_operation_id,
                    certificate.evidence_committed_revision,
                    certificate.validator_id,certificate.validator_version,
                    certificate.digest))
            if completed:
                self._event(db,scope,occurrence_id,last_event_ordinal,
                    "OccurrenceCompleted",None,operation_id,digest,revision)
            db.execute("""UPDATE epm.application_state SET commit_revision=%s
                WHERE workspace_id=%s AND application_id=%s""",(revision,
                scope.workspace_id,scope.application_id))
            self._recheck_authority(db, scope, COMPLETE, access)
            return result

    def return_review(self,scope: ApplicationScope,*,occurrence_id: str,
                      activity_id: str,expected_activity_state_token: str,
                      reason: str,idempotency_key: str,
                      available_functions: Collection[str],replay_only: bool=False)->dict|None:
        occurrence_id=_occurrence_id(occurrence_id)
        activity_id=_identifier(activity_id,
            "APPLICATION_WORKFLOW_ACTIVITY_ID_INVALID")
        expected=require_state_token(expected_activity_state_token,
            error="APPLICATION_WORKFLOW_ACTIVITY_STATE_TOKEN_INVALID")
        if (type(reason) is not str or not 1<=len(reason)<=_RETURN_REASON_LIMIT
                or reason!=reason.strip() or "\x00" in reason):
            raise ValueError("APPLICATION_WORKFLOW_RETURN_REASON_INVALID")
        operation_id=_key(idempotency_key)
        command={"function":RETURN,"scope":[scope.workspace_id,
            scope.application_id],"identity":[self.identity.issuer,
            self.identity.subject_id],"occurrenceId":occurrence_id,
            "activityId":activity_id,"expectedActivityStateToken":expected,
            "reason":reason}
        digest=_canonical_digest(command)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            if replay_only:db.execute("SET TRANSACTION READ ONLY")
            access=self._prepare(db,scope,"read",RETURN)
            prior=self._prior(db,scope,operation_id,digest)
            if prior is not None:
                self._recheck_authority(db, scope, RETURN, access)
                return prior
            if replay_only:return None
            state=self._context(db,scope,lock=True);self._active(state)
            occurrence=self._occurrence(db,scope,occurrence_id,lock=True)
            if occurrence["status"]!="Active":
                raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_STALE")
            model=self._occurrence_model(db,scope,occurrence)
            resolved=PostgresApplicationWorkflows._validate_references(
                db,scope,model,available_functions,
                state["metadata_revision"])
            activity=self._activity(model,activity_id)
            if activity.kind!="Review" or activity.return_to is None:
                raise ValueError("APPLICATION_WORKFLOW_RETURN_UNAVAILABLE")
            now=db.execute("SELECT transaction_timestamp() AS now").fetchone()["now"]
            assignment=self._assignment(db,scope,activity,
                resolved["members"],require_entitlement=True,now=now,
                groups=access.groups)
            rows=db.execute("""SELECT * FROM
                epm.application_workflow_activity WHERE workspace_id=%s
                  AND application_id=%s AND occurrence_id=%s
                ORDER BY activity_id FOR UPDATE""",(scope.workspace_id,
                scope.application_id,occurrence_id)).fetchall()
            by_id={row["activity_id"]:row for row in rows}
            review=by_id.get(activity_id);target=by_id.get(activity.return_to)
            if (review is None or review["status"]!="Ready"
                    or review["state_token"]!=expected):
                raise ValueError("APPLICATION_WORKFLOW_ACTIVITY_STALE")
            if target is None or target["status"]!="Completed":
                raise ValueError("APPLICATION_WORKFLOW_RETURN_TARGET_STALE")
            return_target,invalidated=_review_return_invalidation(
                model,activity_id,rows)
            ordinal=occurrence["last_event_ordinal"]+1
            occurrence_token=new_state_token()
            target_token=new_state_token();review_token=new_state_token()
            invalidated_seed=new_state_token()
            revision=state["commit_revision"]+1
            evidence={"kind":"ReviewReturn","reason":reason,
                "targetActivityId":return_target,
                "actor":{"issuer":self.identity.issuer,
                    "subjectId":self.identity.subject_id},
                "returnedAt":now.isoformat(),
                "assignmentResolution":assignment}
            evidence_digest=_canonical_digest(evidence)
            result={"operationId":operation_id,"function":RETURN,
                "status":"Active","occurrenceId":occurrence_id,
                "occurrenceStateToken":occurrence_token,"activityId":activity_id,
                "activityStateToken":review_token,
                "returnedToActivityId":return_target,
                "invalidatedActivityIds":invalidated,
                "evidenceDigest":evidence_digest,
                "committedRevision":revision}
            self._receipt(db,scope,operation_id,digest,revision,result)
            db.execute("""UPDATE epm.application_workflow_activity SET
                status='Ready',transition_ordinal=transition_ordinal+1,
                state_token=%s,
                operation_id=NULL,completed_by_issuer=NULL,
                completed_by_subject_id=NULL,completed_at=NULL,
                returned_to_activity_id=NULL WHERE workspace_id=%s
                  AND application_id=%s AND occurrence_id=%s
                  AND activity_id=%s""",(target_token,scope.workspace_id,
                scope.application_id,occurrence_id,return_target))
            db.execute("""UPDATE epm.application_workflow_activity SET
                status='Returned',transition_ordinal=transition_ordinal+1,
                state_token=%s,
                operation_id=%s,completed_by_issuer=NULL,
                completed_by_subject_id=NULL,completed_at=NULL,
                returned_to_activity_id=%s WHERE workspace_id=%s
                  AND application_id=%s AND occurrence_id=%s
                  AND activity_id=%s""",(review_token,operation_id,return_target,
                scope.workspace_id,scope.application_id,occurrence_id,
                activity_id))
            if invalidated:
                db.execute("""UPDATE epm.application_workflow_activity SET
                    status='Blocked',transition_ordinal=transition_ordinal+1,
                    state_token=encode(sha256(convert_to(%s||E'\n'||activity_id,
                      'UTF8')),'hex'),
                    operation_id=NULL,completed_by_issuer=NULL,
                    completed_by_subject_id=NULL,completed_at=NULL,
                    returned_to_activity_id=NULL WHERE workspace_id=%s
                      AND application_id=%s AND occurrence_id=%s
                      AND activity_id=ANY(%s::text[])""",(invalidated_seed,scope.workspace_id,
                    scope.application_id,occurrence_id,invalidated))
            db.execute("""UPDATE epm.application_workflow_occurrence SET
                last_event_ordinal=%s,state_token=%s,last_operation_id=%s
                WHERE workspace_id=%s AND application_id=%s
                  AND occurrence_id=%s""",(ordinal,occurrence_token,operation_id,
                scope.workspace_id,scope.application_id,occurrence_id))
            self._event(db,scope,occurrence_id,ordinal,"ActivityReturned",
                activity_id,operation_id,digest,revision,evidence=evidence,
                evidence_digest=evidence_digest)
            db.execute("""UPDATE epm.application_state SET commit_revision=%s
                WHERE workspace_id=%s AND application_id=%s""",(revision,
                scope.workspace_id,scope.application_id))
            self._recheck_authority(db, scope, RETURN, access)
            return result

    def execute_program(self,scope: ApplicationScope,program: dict,*,
                        idempotency_key: str|None,
                        available_functions: Collection[str],replay_only: bool=False)->dict|None:
        """Validate the public transport envelope and delegate to fixed core."""
        function,arguments=_program(program)
        if replay_only and function not in MUTATIONS:
            raise ValueError("OPERATION_ADMISSION_EXPIRED")
        replay={"replay_only":True} if replay_only else {}
        if function in MUTATIONS:
            if idempotency_key is None:
                raise ValueError(
                    "APPLICATION_WORKFLOW_OCCURRENCE_IDEMPOTENCY_REQUIRED")
        elif idempotency_key is not None:
            raise ValueError(
                "APPLICATION_WORKFLOW_OCCURRENCE_READ_KEY_FORBIDDEN")
        if function==START:
            expected={"flowId","expectedStateToken",
                "expectedMetadataRevision","expectedPolicyRevision",
                "expectedSchemaEpoch"}
            if set(arguments)!=expected:
                raise ValueError("APPLICATION_WORKFLOW_START_ARGUMENTS_INVALID")
            return self.start(scope,flow_id=arguments["flowId"],
                expected_state_token=arguments["expectedStateToken"],
                expected_metadata_revision=arguments["expectedMetadataRevision"],
                expected_policy_revision=arguments["expectedPolicyRevision"],
                expected_schema_epoch=arguments["expectedSchemaEpoch"],
                idempotency_key=idempotency_key,
                available_functions=available_functions,**replay)
        if function==READ:
            if not {"occurrenceId"}<=set(arguments)<= {
                    "occurrenceId","eventLimit","afterEventOrdinal","includeCurrentReturns"}:
                raise ValueError("APPLICATION_WORKFLOW_READ_ARGUMENTS_INVALID")
            return self.read(scope,arguments["occurrenceId"],
                event_limit=arguments.get("eventLimit",100),
                after_event_ordinal=arguments.get("afterEventOrdinal",0),
                include_current_returns=arguments.get("includeCurrentReturns",False))
        if function==WORKLIST:
            if not set(arguments)<= {"limit","occurrenceId","afterOccurrenceId",
                                      "afterActivityId","includeBlocked","includeWaiting"} or (
                    "occurrenceId" in arguments and arguments["occurrenceId"] is None):
                raise ValueError(
                    "APPLICATION_WORKFLOW_WORKLIST_ARGUMENTS_INVALID")
            return self.worklist(scope,limit=arguments.get("limit",100),
                occurrence_id=arguments.get("occurrenceId"),
                after_occurrence_id=arguments.get("afterOccurrenceId"),
                after_activity_id=arguments.get("afterActivityId"),
                include_blocked=arguments.get("includeBlocked",False),
                include_waiting=arguments.get("includeWaiting",False),
                available_functions=available_functions)
        if function==EVIDENCE_OPTIONS:
            if not {"occurrenceId","activityId"}<=set(arguments)<= {
                    "occurrenceId","activityId","limit",
                    "beforeCommittedRevision"}:
                raise ValueError(
                    "APPLICATION_WORKFLOW_EVIDENCE_LIST_ARGUMENTS_INVALID")
            return self.evidence_options(scope,
                occurrence_id=arguments["occurrenceId"],
                activity_id=arguments["activityId"],
                limit=arguments.get("limit",50),
                before_committed_revision=arguments.get(
                    "beforeCommittedRevision"),
                available_functions=available_functions)
        if function==EVIDENCE_ASSESSMENT:
            if set(arguments)!={"occurrenceId","activityId"}:
                raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_READ_ARGUMENTS_INVALID")
            return self.assess_evidence(scope,occurrence_id=arguments["occurrenceId"],
                activity_id=arguments["activityId"])
        if function==COMPLETE:
            if set(arguments)!={"occurrenceId","activityId",
                    "expectedActivityStateToken","evidence"}:
                raise ValueError(
                    "APPLICATION_WORKFLOW_COMPLETE_ARGUMENTS_INVALID")
            return self.complete(scope,occurrence_id=arguments["occurrenceId"],
                activity_id=arguments["activityId"],
                expected_activity_state_token=arguments["expectedActivityStateToken"],
                evidence=arguments["evidence"],idempotency_key=idempotency_key,
                available_functions=available_functions,**replay)
        if function==RETURN:
            if set(arguments)!={"occurrenceId","activityId",
                    "expectedActivityStateToken","reason"}:
                raise ValueError(
                    "APPLICATION_WORKFLOW_RETURN_ARGUMENTS_INVALID")
            return self.return_review(scope,
                occurrence_id=arguments["occurrenceId"],
                activity_id=arguments["activityId"],
                expected_activity_state_token=arguments["expectedActivityStateToken"],
                reason=arguments["reason"],idempotency_key=idempotency_key,
                available_functions=available_functions,**replay)
        if set(arguments)!={"occurrenceId","expectedOccurrenceStateToken"}:
            raise ValueError("APPLICATION_WORKFLOW_CANCEL_ARGUMENTS_INVALID")
        return self.cancel(scope,occurrence_id=arguments["occurrenceId"],
            expected_occurrence_state_token=arguments["expectedOccurrenceStateToken"],
            idempotency_key=idempotency_key,**replay)

    def _event(self,db,scope: ApplicationScope,occurrence_id: str,
               ordinal: int,event_type: str,activity_id: str|None,
               operation_id: str,command_digest: str,revision: int,*,
               evidence: dict|None=None,evidence_digest: str|None=None)->None:
        db.execute("""INSERT INTO epm.application_workflow_event(workspace_id,
            application_id,occurrence_id,event_ordinal,event_type,activity_id,
            operation_id,actor_issuer,actor_subject_id,command_digest,
            evidence,evidence_digest,committed_revision)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",(
            scope.workspace_id,scope.application_id,occurrence_id,ordinal,
            event_type,activity_id,operation_id,self.identity.issuer,
            self.identity.subject_id,command_digest,
            Jsonb(evidence) if evidence is not None else None,
            evidence_digest,revision))

    @staticmethod
    def _result(occurrence: dict,activities: list[dict],
                events: list[dict])->dict:
        def instant(value):
            if isinstance(value, str):
                # SQL aggregate timestamps use the same wire representation as
                # the native timestamp columns in the occurrence header.
                value = datetime.fromisoformat(value)
            return value.isoformat() if value is not None else None
        return {"occurrenceId":occurrence["occurrence_id"],
            "flowId":occurrence["flow_id"],
            "flowStateToken":occurrence["flow_state_token"],
            "definitionDigest":occurrence["flow_digest"],
            "status":occurrence["status"],
            "occurrenceStateToken":occurrence["state_token"],
            "lastEventOrdinal":occurrence["last_event_ordinal"],
            "startedRevision":occurrence["started_revision"],
            "startedAt":instant(occurrence["started_at"]),
            "completedAt":instant(occurrence["completed_at"]),
            "cancelledAt":instant(occurrence["cancelled_at"]),
            "activities":[{"activityId":row["activity_id"],
                "kind":row["kind"],"status":row["status"],
                "activityStateToken":row["state_token"],
                "operationId":row["operation_id"],
                "completedAt":instant(row["completed_at"]),
                "returnedToActivityId":row["returned_to_activity_id"]}
                for row in activities],
            "events":[PostgresApplicationWorkflowOccurrences._event_result(row) for row in events]}

    @staticmethod
    def _event_result(row: dict)->dict:
        created=row["created_at"]
        if isinstance(created,str):
            created=datetime.fromisoformat(created)
        return {"ordinal":row["event_ordinal"],
                "eventType":row["event_type"],
                "activityId":row["activity_id"],
                "operationId":row["operation_id"],
                "actor":{"issuer":row["actor_issuer"],
                    "subjectId":row["actor_subject_id"]},
                "evidence":row["evidence"],
                "evidenceDigest":row["evidence_digest"],
                "committedRevision":row["committed_revision"],
                "createdAt":created.isoformat()}
