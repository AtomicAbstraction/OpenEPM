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
from .postgres_access import VerifiedIdentity
from .postgres_jobs import (_NUMERIC_COMPILER,_NUMERIC_PLAN_DIGEST,
                            _canonical_digest)
from .python_plan_runner import SealedPlanRunner


_OPERATION=re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_NUMERIC_FUNCTION="facts.numeric.batch"
_NUMERIC_VALIDATOR="workflow.numeric-job-receipt"
_RULE_FUNCTION="application.rule.run"
_RULE_VALIDATOR="workflow.application-rule-parent-receipt"
_VIEW_VALIDATOR="workflow.cube-view-numeric-receipt"
_MANUAL_VALIDATOR="workflow.manual-attestation"


@dataclass(frozen=True,slots=True)
class WorkflowEvidence:
    normalized: dict
    digest: str
    validator_id: str
    validator_version: int
    evidence_operation_id: str|None=None
    evidence_committed_revision: int|None=None


def _mapping(value: tuple[tuple[str,object],...])->dict:
    return {key:list(item) if isinstance(item,tuple) else item
            for key,item in value}


def _certificate(normalized: dict,validator_id: str,*,
                 operation_id: str|None=None,
                 committed_revision: int|None=None)->WorkflowEvidence:
    return WorkflowEvidence(normalized,_canonical_digest(normalized),
        validator_id,1,operation_id,committed_revision)


def _manual(db,identity: VerifiedIdentity,contract: dict,evidence: object
            )->WorkflowEvidence:
    if evidence!={"kind":"ManualAttestation","confirmed":True}:
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_INVALID")
    now=db.execute("SELECT transaction_timestamp() AS now").fetchone()["now"]
    if not isinstance(now,datetime):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_TIME_INVALID")
    normalized={"kind":"ManualAttestation",
        "statementDigest":sha256(
            contract["statement"].encode("utf-8")).hexdigest(),
        "actor":{"issuer":identity.issuer,
            "subjectId":identity.subject_id},
        "confirmedAt":now.isoformat(),"confirmed":True,
        "validator":{"id":_MANUAL_VALIDATOR,"version":1}}
    return _certificate(normalized,_MANUAL_VALIDATOR)


def _numeric_effects(db,scope: ApplicationScope,row: dict,
                     *,require_current: bool)->list[dict]:
    program=row["normalized_program"]
    if (type(program) is not dict
            or set(program)!={"version","function","mutations"}
            or program["version"]!=1
            or program["function"]!=_NUMERIC_FUNCTION
            or type(program["mutations"]) is not list
            or not program["mutations"]):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_UNSUPPORTED")
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
          AND e.operation_id=%s ORDER BY e.line_ordinal""",(
        scope.workspace_id,scope.application_id,row["operation_id"])).fetchall()
    mutations=program["mutations"]
    if (len(effects)!=len(mutations)
            or row["result"].get("changedCount")!=len(effects)):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_EFFECT_MISMATCH")
    for ordinal,(mutation,effect) in enumerate(zip(mutations,effects),1):
        if (type(mutation) is not dict
                or effect["line_ordinal"]!=ordinal
                or effect["members"]!=mutation.get("members")
                or effect["kind"]!=mutation.get("kind")
                or effect["committed_revision"]!=row["committed_revision"]
                or effect["change_id"]!=
                    f'{row["committed_revision"]}:{ordinal}'):
            raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_EFFECT_MISMATCH")
        if require_current and (effect["current_change_id"]!=effect["change_id"]
                or effect["current_revision"]!=effect["committed_revision"]
                or effect["current_present"] is not effect["present"]
                or effect["current_amount"]!=effect["resulting_amount"]):
            raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_NOT_CURRENT")
    return effects


def _cube_view_numeric(db,scope: ApplicationScope,row: dict,
        destination: dict,resolved_selection: dict|None,*,
        require_current: bool)->WorkflowEvidence:
    """Prove that one exact numeric receipt is bounded by a pinned cube view.

    A saved view is presentation metadata, not evidence by itself. This
    profile therefore verifies its immutable digest, the workflow's current
    server-resolved complete-grain selection and every authoritative event
    produced by the referenced receipt. The caller cannot supply members or
    a view definition as evidence.
    """
    if (type(resolved_selection) is not dict
            or resolved_selection.get("format")!=
               "openepm-resolved-selection-v1"
            or type(resolved_selection.get("members")) is not dict
            or type(resolved_selection.get("resolutionDigest")) is not str):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_SCOPE_REQUIRED")
    view=db.execute("""SELECT definition,canonical_digest,metadata_revision
        FROM epm.saved_grid_definition WHERE workspace_id=%s
          AND application_id=%s AND grid_id=%s""",(
        scope.workspace_id,scope.application_id,destination["viewId"],
        )).fetchone()
    if (view is None or view["canonical_digest"]!=destination["digest"]):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_VIEW_MISMATCH")
    members=resolved_selection["members"]
    try:
        definition=canonical_cube_view(
            view["definition"],active_dimensions=members)
    except ValueError as error:
        raise ValueError(
            "APPLICATION_WORKFLOW_EVIDENCE_VIEW_UNSUPPORTED") from error
    if (definition["dataSource"]["kind"]!="raw"
            or definition["selection"]["metadataRevision"]!=
               view["metadata_revision"]):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_VIEW_UNSUPPORTED")
    fixed={item["dimensionId"]:item["include"]["memberId"]
           for item in definition["selection"]["dimensions"]
           if item["include"]["kind"]=="member"}
    explicit={item["dimensionId"]:item["include"]["memberIds"]
              for item in definition["selection"]["dimensions"]
              if item["include"]["kind"]=="members"}
    if (len(fixed)+len(explicit)!=len(
            definition["selection"]["dimensions"])):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_VIEW_UNSUPPORTED")
    if (any(type(selected) is not list or not selected
            for selected in members.values())
            or any(members.get(dimension)!=[member]
                   for dimension,member in fixed.items())
            or any(members.get(dimension)!=selected
                   for dimension,selected in explicit.items())):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_VIEW_SCOPE_MISMATCH")
    effects=_numeric_effects(db,scope,row,require_current=require_current)
    allowed={dimension:frozenset(selected)
             for dimension,selected in members.items()}
    for effect in effects:
        coordinate=effect["members"]
        if (type(coordinate) is not dict
                or set(coordinate)!=set(allowed)
                or any(member not in allowed[dimension]
                       for dimension,member in coordinate.items())
                or any(coordinate[dimension]!=member
                       for dimension,member in fixed.items())):
            raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_VIEW_SCOPE_MISMATCH")
    if require_current:
        state=db.execute("""SELECT metadata_revision
            FROM epm.application_state WHERE workspace_id=%s
              AND application_id=%s""",(
            scope.workspace_id,scope.application_id)).fetchone()
        if (state is None or state["metadata_revision"]!=
                view["metadata_revision"]):
            raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_NOT_CURRENT")
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
        operation_id=row["operation_id"],
        committed_revision=row["committed_revision"])


def _rule_parent(db,scope: ApplicationScope,row: dict,destination: dict,
                 *,require_current: bool)->WorkflowEvidence:
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
    current=require_current
    if require_current:
        state=db.execute("""SELECT metadata_revision,policy_revision,
            schema_epoch FROM epm.application_state WHERE workspace_id=%s
              AND application_id=%s""",(
            scope.workspace_id,scope.application_id)).fetchone()
        publication=db.execute("""SELECT state_token,status,program_digest
            FROM epm.expression_rule_definition
            WHERE workspace_id=%s AND application_id=%s AND rule_id=%s""",(
            scope.workspace_id,scope.application_id,
            parent["rule_id"])).fetchone()
        publication_current=(publication is not None
            and publication["status"]=="Active"
            and publication["state_token"]==parent["rule_state_token"]
            and publication["program_digest"]==parent["program_digest"])
        current=(state is not None and publication_current and
            (state["metadata_revision"],state["policy_revision"],
             state["schema_epoch"])==
            (parent["expected_metadata_revision"],
             parent["expected_policy_revision"],
             parent["expected_schema_epoch"]))
        if not current:
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
        "currentAtValidation":current,
        "validator":{"id":_RULE_VALIDATOR,"version":1}}
    return _certificate(normalized,_RULE_VALIDATOR,
        operation_id=parent["workflow_id"],
        committed_revision=row["committed_revision"])


def _operation_receipt(db,scope: ApplicationScope,activity: Activity,
                       contract: dict,evidence: object,*,
                       resolved_selection: dict|None)->WorkflowEvidence:
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
        if (function!=_NUMERIC_FUNCTION
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
            resolved_selection,require_current=contract["requireCurrent"])
    if destination.get("kind")!="Function":
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_UNSUPPORTED")
    if function==_RULE_FUNCTION:
        return _rule_parent(db,scope,row,destination,
                            require_current=contract["requireCurrent"])
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
    if (function!=_NUMERIC_FUNCTION
            or row["compiler_version"]!=_NUMERIC_COMPILER
            or row["plan_digest"]!=_NUMERIC_PLAN_DIGEST):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_UNSUPPORTED")
    _numeric_effects(db,scope,row,
                     require_current=contract["requireCurrent"])
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
        operation_id=row["operation_id"],
        committed_revision=row["committed_revision"])


def validate_workflow_evidence(db,scope: ApplicationScope,
        identity: VerifiedIdentity,activity: Activity,
        evidence: object,*,resolved_selection: dict|None=None
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
            resolved_selection=resolved_selection)
    raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_UNSUPPORTED")
