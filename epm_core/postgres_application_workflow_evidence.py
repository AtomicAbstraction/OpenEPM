"""Server-owned evidence validators for generic application workflows.

Callers identify an opaque receipt or confirm a configured attestation. They
never declare the authoritative function, result, actor, revision, compiler,
plan or currentness. Unsupported receipt families fail closed.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
import re

from .application_workflow import Activity
from .cube_view_contract import canonical_cube_view
from .persistence_contract import ApplicationScope
from .dimensional_security_policy import AccessKind
from .postgres_access import AccessDenied, VerifiedIdentity
from .postgres_definition_lifecycle import current_state, read_owner, resolution_context
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_jobs import (_NUMERIC_COMPILER,_NUMERIC_PLAN_DIGEST,
                            _canonical_digest, _decode_numeric_program)
from .postgres_selection_preview import resolve_selection_in_transaction
from .python_plan_runner import SealedPlanRunner


_OPERATION=re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_NUMERIC_FUNCTION="facts.numeric.batch"
_NUMERIC_VALIDATOR="workflow.numeric-job-receipt"
_RULE_FUNCTION="application.rule.run"
_RULE_VALIDATOR="workflow.application-rule-parent-receipt"
_VIEW_VALIDATOR="workflow.cube-view-numeric-receipt"
CALCULATION_FUNCTION="facts.expression.calculate"
CALCULATION_IMPACT_PENDING="APPLICATION_WORKFLOW_EVIDENCE_IMPACT_PENDING"
_CALCULATION_VALIDATOR="workflow.cube-view-calculation-receipt"
_MANUAL_VALIDATOR="workflow.manual-attestation"
_RECEIPT_FUNCTIONS=frozenset((_NUMERIC_FUNCTION,_RULE_FUNCTION))
_VIEW_RECEIPT_FUNCTIONS={"raw":_NUMERIC_FUNCTION,"calculated":CALCULATION_FUNCTION}
RECEIPT_CONTRACT_UNSUPPORTED="APPLICATION_WORKFLOW_RECEIPT_CONTRACT_UNSUPPORTED"
VIEW_SCOPE_MISMATCH="APPLICATION_WORKFLOW_EVIDENCE_VIEW_SCOPE_MISMATCH"
_RECEIPT_ASSESSMENT_BASIS={
    _NUMERIC_VALIDATOR:"ExactNumericEffects",
    _VIEW_VALIDATOR:"ExactNumericEffects",
    _RULE_VALIDATOR:"RulePublication",
    _CALCULATION_VALIDATOR:"CalculationPublication",
}
RECEIPT_ASSESSMENT_BASES=tuple(dict.fromkeys(_RECEIPT_ASSESSMENT_BASIS.values()))


def validate_workflow_receipt_contract(destination: dict, allowed_functions, *, view_source_kind: str|None) -> None:
    """Require every advertised choice to have a validator for this destination."""
    expected = None
    if destination["kind"] == "Function" and destination["function"] in _RECEIPT_FUNCTIONS:
        expected = destination["function"]
    if destination["kind"] == "CubeView":
        expected = _VIEW_RECEIPT_FUNCTIONS.get(view_source_kind)
    if expected is None or set(allowed_functions) != {expected}:
        raise ValueError(RECEIPT_CONTRACT_UNSUPPORTED)


def completion_evidence_schema() -> dict:
    from .postgres_numeric_catalog import obj

    receipt = {"type": "string", "pattern": "^" + _OPERATION.pattern.removesuffix(r"\Z") + r"(?![\s\S])"}
    return {"oneOf": [
        obj({"kind": {"const": "ManualAttestation"},
             "confirmed": {"type": "boolean", "const": True}}),
        obj({"kind": {"const": "OperationReceipt"}, "operationId": receipt}),
    ]}


@dataclass(frozen=True,slots=True)
class WorkflowEvidence:
    normalized: dict
    digest: str
    validator_id: str
    validator_version: int
    evidence_operation_id: str|None=None
    evidence_committed_revision: int|None=None
    current_assessment: bool|None=None


def _mapping(value: tuple[tuple[str,object],...])->dict:
    return {key:list(item) if isinstance(item,tuple) else item
            for key,item in value}


def _certificate(normalized: dict,validator_id: str,*,
                 operation_id: str|None=None,
                 committed_revision: int|None=None,
                 current_assessment: bool|None=None)->WorkflowEvidence:
    return WorkflowEvidence(normalized,_canonical_digest(normalized),
        validator_id,1,operation_id,committed_revision,current_assessment)


def _manual_certificate(issuer: str,subject: str,contract: dict,
                        now: datetime)->WorkflowEvidence:
    if not isinstance(now,datetime):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_TIME_INVALID")
    normalized={"kind":"ManualAttestation",
        "statementDigest":sha256(
            contract["statement"].encode("utf-8")).hexdigest(),
        "actor":{"issuer":issuer,"subjectId":subject},
        "confirmedAt":now.isoformat(),"confirmed":True,
        "validator":{"id":_MANUAL_VALIDATOR,"version":1}}
    return _certificate(normalized,_MANUAL_VALIDATOR)


def _manual(db,identity: VerifiedIdentity,contract: dict,evidence: object
            )->WorkflowEvidence:
    if (type(evidence) is not dict
            or evidence!={"kind":"ManualAttestation","confirmed":True}
            or evidence["confirmed"] is not True):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_INVALID")
    now=db.execute("SELECT transaction_timestamp() AS now").fetchone()["now"]
    return _manual_certificate(identity.issuer,identity.subject_id,contract,now)


def matches_completed_attestation(activity: Activity,normalized: dict,*,
                                  issuer: str,subject: str,completed_at: datetime)->bool:
    contract=_mapping(activity.evidence_contract)
    if contract.get("kind")!="ManualAttestation":
        return False
    return normalized==_manual_certificate(
        issuer,subject,contract,completed_at).normalized


def _numeric_effects(db,scope: ApplicationScope,row: dict,
                     *,reader: VerifiedIdentity,require_current: bool,
                     assessment: bool)->tuple[list[dict],bool]:
    try:
        mutations=_decode_numeric_program(row["normalized_program"])
    except ValueError as error:
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_UNSUPPORTED") from error
    try:
        # These coordinates come from the fixed, digest-bound job plan.
        # Prove whole-collection access before reading facts or currentness.
        authorize_coordinates(db,reader,scope,
            (mutation.coordinate for mutation in mutations),kind=AccessKind.READ)
    except AccessDenied:
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_UNAVAILABLE") from None
    effects=db.execute("""SELECT e.line_ordinal,e.kind,e.present,
        e.resulting_amount,e.change_id,e.committed_revision,c.members,
        p.present AS current_present,p.amount AS current_amount,
        p.change_id AS current_change_id,p.last_revision AS current_revision
        FROM epm.numeric_fact_event e
        JOIN epm.coordinate c ON c.workspace_id=e.workspace_id
          AND c.application_id=e.application_id
          AND c.coordinate_id=e.coordinate_id
        LEFT JOIN epm.numeric_cell_current p
          ON p.workspace_id=e.workspace_id
         AND p.application_id=e.application_id
         AND p.coordinate_id=e.coordinate_id
        WHERE e.workspace_id=%s AND e.application_id=%s
          AND e.operation_id=%s ORDER BY e.line_ordinal LIMIT %s""",(
        scope.workspace_id,scope.application_id,row["operation_id"],
        len(mutations)+1)).fetchall()
    if (len(effects)!=len(mutations)
            or row["result"].get("changedCount")!=len(effects)):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_EFFECT_MISMATCH")
    for ordinal,(mutation,effect) in enumerate(zip(mutations,effects),1):
        if (effect["line_ordinal"]!=ordinal
                or effect["members"]!=dict(mutation.coordinate.members)
                or effect["kind"]!=mutation.kind.value
                or effect["committed_revision"]!=row["committed_revision"]
                or effect["change_id"]!=
                    f'{row["committed_revision"]}:{ordinal}'):
            raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_EFFECT_MISMATCH")
    current=all(
        effect["current_change_id"]==effect["change_id"]
        and effect["current_revision"]==effect["committed_revision"]
        and effect["current_present"] is effect["present"]
        and effect["current_amount"]==effect["resulting_amount"]
        for effect in effects)
    if require_current and not current and not assessment:
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_NOT_CURRENT")
    return effects,current


def _bound_view_definition(view, destination, resolved_selection, *, source_kind):
    if (type(resolved_selection) is not dict
            or resolved_selection.get("format")!=
               "openepm-resolved-selection-v1"
            or type(resolved_selection.get("members")) is not dict
            or type(resolved_selection.get("resolutionDigest")) is not str):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_SCOPE_REQUIRED")
    if (view is None or view["canonical_digest"]!=destination["digest"]):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_VIEW_MISMATCH")
    members=resolved_selection["members"]
    try:
        definition=canonical_cube_view(
            view["definition"],active_dimensions=members)
    except ValueError as error:
        raise ValueError(
            "APPLICATION_WORKFLOW_EVIDENCE_VIEW_UNSUPPORTED") from error
    if (definition["dataSource"]["kind"]!=source_kind
            or definition["selection"]["metadataRevision"]!=
               view["metadata_revision"]):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_VIEW_UNSUPPORTED")
    return definition


def _evidence_view(db, scope, destination, resolved_selection, *, source_kind):
    view=db.execute("""SELECT definition,canonical_digest,metadata_revision
        FROM epm.saved_grid_definition WHERE workspace_id=%s
          AND application_id=%s AND grid_id=%s""",(
        scope.workspace_id,scope.application_id,destination["viewId"],
        )).fetchone()
    return _bound_view_definition(view,destination,resolved_selection,source_kind=source_kind)


def _raw_view_members(db,scope,definition,resolved_selection):
    selection=definition["selection"]
    try:
        view_members=resolve_selection_in_transaction(db,scope,selection,
            selection["metadataRevision"])["members"]
    except ValueError:
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_VIEW_UNSUPPORTED") from None
    if view_members!=resolved_selection["members"] or any(not members for members in view_members.values()):
        raise ValueError(VIEW_SCOPE_MISMATCH)
    return view_members


def validate_workflow_view_evidence_scope(db,scope,view,destination,resolved_selection,*,require_current):
    """Check that the authored view and workflow resolve to an eligible receipt scope."""
    kind=view["source_kind"]
    try:
        definition=_bound_view_definition(view,destination,resolved_selection,source_kind=kind)
        revision=resolved_selection["metadataRevision"]
        if (require_current or kind=="calculated") and definition["selection"]["metadataRevision"]!=revision:
            raise ValueError(VIEW_SCOPE_MISMATCH)
        if kind=="raw":
            _raw_view_members(db,scope,definition,resolved_selection)
            return
        # Match the calculation publication owner's effective selection and pins.
        view_scope=resolve_selection_in_transaction(db,scope,definition["selection"],revision,
            require_current_layout=True)
        if (view_scope["resolutionDigest"]!=resolved_selection["resolutionDigest"]
                or any(not members for members in view_scope["members"].values())):
            raise ValueError(VIEW_SCOPE_MISMATCH)
    except ValueError:
        raise ValueError(VIEW_SCOPE_MISMATCH) from None


def _cube_view_numeric(db,scope: ApplicationScope,row: dict,
        destination: dict,resolved_selection: dict|None,*,
        reader: VerifiedIdentity,require_current: bool,
        assessment: bool,include_currentness: bool)->WorkflowEvidence:
    """Prove the original effects under the current view and READ policy."""
    definition=_evidence_view(db,scope,destination,resolved_selection,source_kind="raw")
    members=_raw_view_members(db,scope,definition,resolved_selection)
    effects,current=_numeric_effects(db,scope,row,require_current=require_current,
        reader=reader,assessment=assessment)
    allowed={dimension:frozenset(selected)
             for dimension,selected in members.items()}
    for effect in effects:
        coordinate=effect["members"]
        if (type(coordinate) is not dict
                or set(coordinate)!=set(allowed)
                or any(member not in allowed[dimension]
                       for dimension,member in coordinate.items())):
            raise ValueError(VIEW_SCOPE_MISMATCH)
    if require_current or assessment or include_currentness:
        state=db.execute("""SELECT metadata_revision
            FROM epm.application_state WHERE workspace_id=%s
              AND application_id=%s""",(
            scope.workspace_id,scope.application_id)).fetchone()
        metadata_current=(state is not None
                          and state["metadata_revision"]==definition["selection"]["metadataRevision"])
        if require_current and not metadata_current and not assessment:
            raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_NOT_CURRENT")
        current=current and metadata_current
    normalized={"kind":"OperationReceipt",
        "operationId":row["operation_id"],
        "committedRevision":row["committed_revision"],
        "function":_NUMERIC_FUNCTION,
        "programDigest":row["program_digest"],
        "compilerVersion":row["compiler_version"],
        "planDigest":row["plan_digest"],
        "resultDigest":_canonical_digest(row["result"]),
        "view":{"viewId":destination["viewId"],
            "digest":destination["digest"]},
        "selectionResolutionDigest":resolved_selection["resolutionDigest"],
        "effectCount":len(effects),
        "currentAtValidation":require_current,
        "validator":{"id":_VIEW_VALIDATOR,"version":1}}
    return _certificate(normalized,_VIEW_VALIDATOR,
        operation_id=row["operation_id"],committed_revision=row["committed_revision"],
        current_assessment=current if assessment or include_currentness else None)


def _cube_view_calculation(db, scope, row, destination, resolved_selection, *,
                           reader, require_current, assessment, include_currentness):
    from .postgres_calculation_scan import PostgresCalculationScan

    definition = _evidence_view(db,scope,destination,resolved_selection,source_kind="calculated")
    receipt = row['result']
    if (row['status'] != 'published' or row['receipt_revision'] != row['committed_revision']
            or type(receipt) is not dict or row['job_result'] != receipt
            or receipt.get('resultKey') != definition['dataSource']['resultKey']
            or row['program_digest'] != row['command_digest'] or row['subject_id'] != row['actor_id']
            or _canonical_digest(row['normalized_program']) != row['program_digest']):
        raise ValueError('APPLICATION_WORKFLOW_EVIDENCE_RECEIPT_MISMATCH')
    freshness = PostgresCalculationScan.expression_evidence_freshness(db, scope, reader,
        receipt=receipt, operation_id=row['operation_id'], committed_revision=row['committed_revision'],
        compiler=row['compiler_version'], program=row['normalized_program'],
        selection=definition['selection'], resolved_selection=resolved_selection)
    if freshness == 'unavailable':
        raise ValueError('APPLICATION_WORKFLOW_EVIDENCE_UNAVAILABLE')
    if freshness == 'impact_coverage_pending' and (require_current or assessment):
        raise ValueError(CALCULATION_IMPACT_PENDING)
    current = freshness == 'current'
    if require_current and not current and not assessment:
        raise ValueError('APPLICATION_WORKFLOW_EVIDENCE_NOT_CURRENT')
    normalized = {'kind': 'OperationReceipt', 'operationId': row['operation_id'],
        'committedRevision': row['committed_revision'], 'function': CALCULATION_FUNCTION,
        'programDigest': row['program_digest'], 'resultDigest': _canonical_digest(receipt),
        'view': {'viewId': destination['viewId'], 'digest': destination['digest']},
        'selectionResolutionDigest': resolved_selection['resolutionDigest'],
        'currentAtValidation': require_current, 'validator': {'id': _CALCULATION_VALIDATOR, 'version': 1}}
    return _certificate(normalized, _CALCULATION_VALIDATOR,
        operation_id=row['operation_id'], committed_revision=row['committed_revision'],
        current_assessment=current if assessment or include_currentness else None)


def _rule_parent(db,scope: ApplicationScope,row: dict,destination: dict,
                 *,require_current: bool,include_currentness: bool,
                 assessment: bool)->WorkflowEvidence:
    parent=db.execute("""SELECT * FROM epm.application_rule_workflow
        WHERE workspace_id=%s AND application_id=%s AND workflow_id=%s""",(
        scope.workspace_id,scope.application_id,row["operation_id"])).fetchone()
    receipt=row["result"]
    if (parent is None or parent["status"]!="published"
            or parent["request_digest"]!=row["command_digest"]
            or parent["subject_id"]!=row["actor_id"]
            or type(receipt) is not dict
            or receipt.get("status")!="Published"
            or receipt.get("function")!=_RULE_FUNCTION
            or receipt.get("workflowId")!=parent["workflow_id"]
            or receipt.get("ruleId")!=parent["rule_id"]
            or receipt.get("stateToken")!=parent["rule_state_token"]
            or receipt.get("argumentsDigest")!=
               parent["result"].get("argumentsDigest")
            or receipt.get("planDigest")!=parent["plan_digest"]
            or receipt.get("committedRevision")!=row["committed_revision"]
            or destination.get("argumentsDigest")!=
               receipt.get("argumentsDigest")):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_RECEIPT_MISMATCH")
    canonical=parent["sealed_plan"]
    raw=json.dumps(canonical,sort_keys=True,separators=(",",":"),
        ensure_ascii=True,allow_nan=False).encode("ascii")
    units=canonical.get("units") if type(canonical) is dict else None
    checkpoints=parent["result"].get("checkpoints")
    if (sha256(raw).hexdigest()!=parent["plan_digest"]
            or type(units) is not list or not units
            or type(checkpoints) is not list
            or len(units)!=parent["result"].get("unitCount")
            or len(checkpoints)!=len(units)):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_RECEIPT_MISMATCH")
    children=db.execute("""SELECT c.unit_ordinal,c.job_id,
        j.function_name,j.status,j.normalized_program,j.program_digest,
        j.plan_digest,j.receipt_revision,j.subject_id,
        o.command_digest,o.actor_id,o.committed_revision,o.result
        AS receipt_result FROM epm.application_rule_workflow_child c
        JOIN epm.job j ON j.workspace_id=c.workspace_id
          AND j.application_id=c.application_id AND j.job_id=c.job_id
        JOIN epm.operation_receipt o ON o.workspace_id=j.workspace_id
          AND o.application_id=j.application_id AND o.operation_id=j.job_id
        WHERE c.workspace_id=%s AND c.application_id=%s
          AND c.workflow_id=%s ORDER BY c.unit_ordinal""",(
        scope.workspace_id,scope.application_id,parent["workflow_id"]
    )).fetchall()
    job_ids=[child["job_id"] for child in children]
    dependencies=(db.execute("""SELECT job_id,depends_on_job_id
        FROM epm.job_dependency WHERE workspace_id=%s AND application_id=%s
          AND job_id=ANY(%s::text[]) ORDER BY job_id,depends_on_job_id""",(
        scope.workspace_id,scope.application_id,job_ids)).fetchall()
        if job_ids else [])
    dependency_map={job_id:[] for job_id in job_ids}
    for dependency in dependencies:
        dependency_map[dependency["job_id"]].append(
            dependency["depends_on_job_id"])
    child_receipts=[];prior=None
    if len(children)!=len(units):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_RECEIPT_MISMATCH")
    for ordinal,(unit,checkpoint,child) in enumerate(
            zip(units,checkpoints,children),1):
        operation=SealedPlanRunner._atomic_operation(unit)
        if (child["unit_ordinal"]!=ordinal
                or checkpoint.get("ordinal")!=ordinal
                or checkpoint.get("jobId")!=child["job_id"]
                or checkpoint.get("committed") is not True
                or checkpoint.get("receiptId")!=child["job_id"]
                or child["function_name"]!=operation["function"]
                or child["status"]!="published"
                or child["receipt_revision"]!=child["committed_revision"]
                or child["command_digest"]!=child["program_digest"]
                or child["actor_id"]!=child["subject_id"]
                or _canonical_digest(child["normalized_program"])!=
                   child["program_digest"]
                or dependency_map[child["job_id"]]!=([] if prior is None
                    else [prior])):
            raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_RECEIPT_MISMATCH")
        child_receipts.append({"ordinal":ordinal,
            "operationId":child["job_id"],
            "committedRevision":child["committed_revision"],
            "function":child["function_name"],
            "programDigest":child["program_digest"],
            "planDigest":child["plan_digest"],
            "resultDigest":_canonical_digest(child["receipt_result"])})
        prior=child["job_id"]
    if receipt.get("childReceipts")!=[
            child["operationId"] for child in child_receipts]:
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_RECEIPT_MISMATCH")
    current=None
    if require_current or include_currentness or assessment:
        state=db.execute("""SELECT metadata_revision,policy_revision,
            schema_epoch FROM epm.application_state WHERE workspace_id=%s
              AND application_id=%s""",(
            scope.workspace_id,scope.application_id)).fetchone()
        publication=read_owner(db,scope,
            {"kind":"ApplicationRule","definitionId":parent["rule_id"]})
        publication_current=(publication is not None
            and publication["state_token"]==parent["rule_state_token"]
            and publication["program_digest"]==parent["program_digest"]
            and current_state(publication,resolution_context(
                db,scope,[publication]))["executable"])
        current=(state is not None and publication_current and
            (state["metadata_revision"],state["policy_revision"],
             state["schema_epoch"])==
            (parent["expected_metadata_revision"],
             parent["expected_policy_revision"],
             parent["expected_schema_epoch"]))
        if require_current and not current and not assessment:
            raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_NOT_CURRENT")
    normalized={"kind":"OperationReceipt",
        "operationId":parent["workflow_id"],
        "committedRevision":row["committed_revision"],
        "function":_RULE_FUNCTION,
        "argumentsDigest":receipt["argumentsDigest"],
        "ruleId":parent["rule_id"],
        "stateToken":parent["rule_state_token"],
        "planDigest":parent["plan_digest"],
        "childReceipts":child_receipts,
        "currentAtValidation":require_current,
        "validator":{"id":_RULE_VALIDATOR,"version":1}}
    return _certificate(normalized,_RULE_VALIDATOR,
        operation_id=parent["workflow_id"],
        committed_revision=row["committed_revision"],
        current_assessment=current if include_currentness or assessment else None)


def _operation_receipt(db,scope: ApplicationScope,activity: Activity,
                       contract: dict,evidence: object,*,
                       resolved_selection: dict|None,reader: VerifiedIdentity,
                       assessment: bool=False,include_currentness: bool=False)->WorkflowEvidence:
    if (type(evidence) is not dict
            or set(evidence)!={"kind","operationId"}
            or evidence.get("kind")!="OperationReceipt"
            or type(evidence.get("operationId")) is not str
            or _OPERATION.fullmatch(evidence["operationId"]) is None):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_INVALID")
    destination=_mapping(activity.destination)
    row=db.execute("""SELECT o.operation_id,o.command_digest,o.actor_id,
        o.committed_revision,o.result,j.function_name,j.normalized_program,
        j.compiler_version,j.program_digest,j.plan_digest,j.status,
        j.receipt_revision,j.result AS job_result,j.subject_id
        FROM epm.operation_receipt o
        LEFT JOIN epm.job j ON j.workspace_id=o.workspace_id
          AND j.application_id=o.application_id AND j.job_id=o.operation_id
        WHERE o.workspace_id=%s AND o.application_id=%s
          AND o.operation_id=%s""",(scope.workspace_id,scope.application_id,
        evidence["operationId"])).fetchone()
    if row is None:
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_UNAVAILABLE")
    function=(row["function_name"] if row["function_name"] is not None
              else row["result"].get("function")
              if type(row["result"]) is dict else None)
    if (function not in contract["allowedFunctions"]
            or (destination.get("kind")=="Function"
                and destination.get("function")!=function)):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_DESTINATION_MISMATCH")
    if destination.get("kind")=="CubeView":
        if function == _VIEW_RECEIPT_FUNCTIONS["calculated"]:
            return _cube_view_calculation(db,scope,row,destination,resolved_selection,
                reader=reader,require_current=contract["requireCurrent"],assessment=assessment,
                include_currentness=include_currentness)
        if (function!=_VIEW_RECEIPT_FUNCTIONS["raw"]
                or row["status"]!="published"
                or row["receipt_revision"]!=row["committed_revision"]
                or type(row["job_result"]) is not dict
                or row["job_result"].get("committedRevision")!=
                   row["committed_revision"]
                or row["job_result"].get("changedCount")!=
                   row["result"].get("changedCount")
                or type(row["result"].get("payloadDigest")) is not str
                or len(row["result"]["payloadDigest"])!=64
                or row["program_digest"]!=row["command_digest"]
                or row["subject_id"]!=row["actor_id"]
                or _canonical_digest(row["normalized_program"])!=
                   row["program_digest"]
                or row["compiler_version"]!=_NUMERIC_COMPILER
                or row["plan_digest"]!=_NUMERIC_PLAN_DIGEST):
            raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_RECEIPT_MISMATCH")
        return _cube_view_numeric(db,scope,row,destination,
            resolved_selection,require_current=contract["requireCurrent"],
            reader=reader,assessment=assessment,include_currentness=include_currentness)
    if destination.get("kind")!="Function":
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_UNSUPPORTED")
    if function==_RULE_FUNCTION:
        return _rule_parent(db,scope,row,destination,
                            require_current=contract["requireCurrent"],
                            include_currentness=include_currentness,assessment=assessment)
    if destination.get("argumentsDigest")!=row["program_digest"]:
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_DESTINATION_MISMATCH")
    if (row["status"]!="published"
            or row["receipt_revision"]!=row["committed_revision"]
            or type(row["job_result"]) is not dict
            or row["job_result"].get("committedRevision")!=
               row["committed_revision"]
            or row["job_result"].get("changedCount")!=
               row["result"].get("changedCount")
            or type(row["result"].get("payloadDigest")) is not str
            or len(row["result"]["payloadDigest"])!=64
            or row["program_digest"]!=row["command_digest"]
            or row["subject_id"]!=row["actor_id"]
            or _canonical_digest(row["normalized_program"])!=
               row["program_digest"]):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_RECEIPT_MISMATCH")
    if (function not in _RECEIPT_FUNCTIONS
            or row["compiler_version"]!=_NUMERIC_COMPILER
            or row["plan_digest"]!=_NUMERIC_PLAN_DIGEST):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_UNSUPPORTED")
    _,current=_numeric_effects(db,scope,row,
        require_current=contract["requireCurrent"],reader=reader,assessment=assessment)
    normalized={"kind":"OperationReceipt",
        "operationId":row["operation_id"],
        "committedRevision":row["committed_revision"],
        "function":function,"programDigest":row["program_digest"],
        "compilerVersion":row["compiler_version"],
        "planDigest":row["plan_digest"],
        "resultDigest":_canonical_digest(row["result"]),
        "currentAtValidation":contract["requireCurrent"],
        "validator":{"id":_NUMERIC_VALIDATOR,"version":1}}
    return _certificate(normalized,_NUMERIC_VALIDATOR,
        operation_id=row["operation_id"],committed_revision=row["committed_revision"],
        current_assessment=current if assessment or include_currentness else None)


def validate_workflow_evidence(db,scope: ApplicationScope,
        identity: VerifiedIdentity,activity: Activity,
        evidence: object,*,resolved_selection: dict|None=None,
        include_currentness: bool=False,
        )->WorkflowEvidence:
    """Validate one caller reference using only fixed server-owned profiles."""
    if not isinstance(scope,ApplicationScope) or not isinstance(
            identity,VerifiedIdentity) or not isinstance(activity,Activity):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_CONTEXT_INVALID")
    contract=_mapping(activity.evidence_contract)
    if contract.get("kind")=="ManualAttestation":
        return _manual(db,identity,contract,evidence)
    if contract.get("kind")=="OperationReceipt":
        return _operation_receipt(db,scope,activity,contract,evidence,
            resolved_selection=resolved_selection,reader=identity,
            include_currentness=include_currentness)
    raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_UNSUPPORTED")


def assess_completed_basis(db,scope: ApplicationScope,
        identity: VerifiedIdentity,activity: Activity,completed: WorkflowEvidence,
        *,resolved_selection: dict|None=None)->tuple[str,bool]|None:
    """Check one stored completion under current READ authority.

    The occurrence owner must supply the validated historical completion and
    verify that its activity, original definition and application pins remain
    stable across this read. None withholds an unavailable or hidden basis.
    """
    basis=_RECEIPT_ASSESSMENT_BASIS.get(completed.validator_id)
    if basis is None:
        return None
    contract=_mapping(activity.evidence_contract)
    if contract.get("kind")!="OperationReceipt" or completed.validator_version!=1:
        return None
    try:
        current=_operation_receipt(db,scope,activity,contract,
            {"kind":"OperationReceipt","operationId":completed.evidence_operation_id},
            resolved_selection=resolved_selection,reader=identity,assessment=True)
    except ValueError as error:
        if str(error)==CALCULATION_IMPACT_PENDING:
            raise
        if str(error).startswith("APPLICATION_WORKFLOW_EVIDENCE_"):
            return None
        raise
    if (current.digest!=completed.digest or current.normalized!=completed.normalized
            or current.evidence_committed_revision!=completed.evidence_committed_revision
            or current.validator_id!=completed.validator_id
            or type(current.current_assessment) is not bool):
        return None
    return basis,current.current_assessment
