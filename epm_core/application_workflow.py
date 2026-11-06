"""Pure domain-neutral contract for assignment-backed application workflows.

The contract describes responsibility, dependency order, destinations and the
kind of authoritative evidence required to complete an activity.  It grants
no cube access, executes no function and accepts no caller-authored identity.
Fixed core must resolve the pinned assignment, embedded canonical selection,
destination and evidence against current authorization when an occurrence is
started or advanced.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re

from .persistence_contract import ApplicationScope
from .selection_contract import canonical_selection


FORMAT="openepm-application-task-flow-v2"
MAX_ACTIVITIES=50
MAX_ALLOWED_FUNCTIONS=20
_ID=re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299}\Z")
_FUNCTION=re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_-]*)+\Z")
_DIGEST=re.compile(r"[0-9a-f]{64}\Z")


def _identifier(value: object,field: str)->str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError(f"APPLICATION_WORKFLOW_{field}_INVALID")
    return value


def _digest(value: object,field: str)->str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"APPLICATION_WORKFLOW_{field}_INVALID")
    return value


def _name(value: object,field: str,maximum: int=200)->str:
    if (type(value) is not str or not 1<=len(value)<=maximum
            or value!=value.strip() or "\x00" in value):
        raise ValueError(f"APPLICATION_WORKFLOW_{field}_INVALID")
    return value


@dataclass(frozen=True,slots=True)
class AssignmentRef:
    assignment_set_id: str
    version: int
    digest: str
    assignment_id: str

    def normalized(self)->dict:
        return {"assignmentSetId":self.assignment_set_id,
            "version":self.version,"digest":self.digest,
            "assignmentId":self.assignment_id}


def _freeze(value: object)->object:
    if isinstance(value,dict):
        return tuple((key,_freeze(item)) for key,item in sorted(value.items()))
    if isinstance(value,list):return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: object)->object:
    if (isinstance(value,tuple) and value
            and all(isinstance(item,tuple) and len(item)==2
                    and isinstance(item[0],str) for item in value)):
        return {key:_thaw(item) for key,item in value}
    if isinstance(value,tuple):return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True,slots=True)
class Activity:
    activity_id: str
    name: str
    kind: str
    depends_on: tuple[str,...]
    return_to: str|None
    assignment_ref: AssignmentRef
    destination: tuple[tuple[str,object],...]
    evidence_contract: tuple[tuple[str,object],...]

    @staticmethod
    def _mapping(value: tuple[tuple[str,object],...])->dict:
        return {key:list(item) if isinstance(item,tuple) else item
                for key,item in value}

    def normalized(self)->dict:
        return {"activityId":self.activity_id,"name":self.name,
            "kind":self.kind,"dependsOn":list(self.depends_on),
            "returnTo":self.return_to,
            "assignmentRef":self.assignment_ref.normalized(),
            "destination":self._mapping(self.destination),
            "evidenceContract":self._mapping(self.evidence_contract)}


@dataclass(frozen=True,slots=True)
class ApplicationWorkflow:
    scope: ApplicationScope
    flow_id: str
    version: int
    name: str
    selection: tuple[tuple[str,object],...]
    activities: tuple[Activity,...]
    digest: str

    @property
    def start_activity_ids(self)->tuple[str,...]:
        return tuple(item.activity_id for item in self.activities
                     if not item.depends_on)

    def normalized(self)->dict:
        return {"format":FORMAT,"workspaceId":self.scope.workspace_id,
            "applicationId":self.scope.application_id,
            "flowId":self.flow_id,"version":self.version,"name":self.name,
            "selection":_thaw(self.selection),
            "activities":[item.normalized() for item in self.activities]}


def _assignment_ref(raw: object)->AssignmentRef:
    if (type(raw) is not dict or set(raw)!={"assignmentSetId","version",
            "digest","assignmentId"} or type(raw["version"]) is not int
            or raw["version"]<1):
        raise ValueError("APPLICATION_WORKFLOW_ASSIGNMENT_REF_INVALID")
    return AssignmentRef(_identifier(raw["assignmentSetId"],"ASSIGNMENT_REF"),
        raw["version"],_digest(raw["digest"],"ASSIGNMENT_DIGEST"),
        _identifier(raw["assignmentId"],"ASSIGNMENT_REF"))


def _destination(raw: object)->tuple[tuple[str,object],...]:
    if type(raw) is not dict or raw.get("kind") not in (
            "CubeView","Function","Artifact"):
        raise ValueError("APPLICATION_WORKFLOW_DESTINATION_INVALID")
    if raw["kind"]=="CubeView":
        if (set(raw)!={"kind","viewId","version","digest"}
                or type(raw["version"]) is not int or raw["version"]<1):
            raise ValueError("APPLICATION_WORKFLOW_DESTINATION_INVALID")
        normalized={"kind":"CubeView",
            "viewId":_identifier(raw["viewId"],"VIEW_ID"),
            "version":raw["version"],
            "digest":_digest(raw["digest"],"VIEW_DIGEST")}
    elif raw["kind"]=="Function":
        if (set(raw)!={"kind","function","argumentsDigest"}
                or type(raw["function"]) is not str
                or _FUNCTION.fullmatch(raw["function"]) is None):
            raise ValueError("APPLICATION_WORKFLOW_DESTINATION_INVALID")
        normalized={"kind":"Function","function":raw["function"],
            "argumentsDigest":_digest(
                raw["argumentsDigest"],"ARGUMENTS_DIGEST")}
    else:
        if (set(raw)!={"kind","artifactKind","artifactId","version","digest"}
                or raw.get("artifactKind") not in (
                    "ApplicationRule","CalculatedMember",
                    "ApplicationSequence","ApplicationSchedule")
                or type(raw.get("version")) is not int
                or raw["version"]<1):
            raise ValueError("APPLICATION_WORKFLOW_DESTINATION_INVALID")
        normalized={"kind":"Artifact","artifactKind":raw["artifactKind"],
            "artifactId":_identifier(raw["artifactId"],"ARTIFACT_ID"),
            "version":raw["version"],
            "digest":_digest(raw["digest"],"ARTIFACT_DIGEST")}
    return tuple(sorted(normalized.items()))


def _evidence_contract(raw: object)->tuple[tuple[str,object],...]:
    if type(raw) is not dict or raw.get("kind") not in (
            "ManualAttestation","OperationReceipt"):
        raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_CONTRACT_INVALID")
    if raw["kind"]=="ManualAttestation":
        if set(raw)!={"kind","statement"}:
            raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_CONTRACT_INVALID")
        normalized={"kind":"ManualAttestation",
            "statement":_name(raw["statement"],"ATTESTATION",500)}
    else:
        if (set(raw)!={"kind","allowedFunctions","requireCurrent"}
                or type(raw["allowedFunctions"]) is not list
                or not 1<=len(raw["allowedFunctions"])<=MAX_ALLOWED_FUNCTIONS
                or any(type(item) is not str
                       or _FUNCTION.fullmatch(item) is None
                       for item in raw["allowedFunctions"])
                or type(raw["requireCurrent"]) is not bool):
            raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_CONTRACT_INVALID")
        functions=tuple(sorted(raw["allowedFunctions"]))
        if len(functions)!=len(set(functions)):
            raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_CONTRACT_INVALID")
        normalized={"kind":"OperationReceipt",
            "allowedFunctions":functions,
            "requireCurrent":raw["requireCurrent"]}
    return tuple(sorted(normalized.items()))


def _activity(raw: object)->Activity:
    expected={"activityId","name","kind","dependsOn","returnTo",
        "assignmentRef","destination","evidenceContract"}
    if (type(raw) is not dict or set(raw)!=expected
            or raw.get("kind") not in ("Action","Review")
            or type(raw.get("dependsOn")) is not list
            or len(raw["dependsOn"])>=MAX_ACTIVITIES
            or any(type(item) is not str for item in raw["dependsOn"])):
        raise ValueError("APPLICATION_WORKFLOW_ACTIVITY_INVALID")
    dependencies=tuple(sorted(
        _identifier(item,"DEPENDENCY") for item in raw["dependsOn"]))
    if len(dependencies)!=len(set(dependencies)):
        raise ValueError("APPLICATION_WORKFLOW_DEPENDENCIES_INVALID")
    return_to=raw["returnTo"]
    if (raw["kind"]=="Action" and return_to is not None
            or raw["kind"]=="Review" and return_to is None):
        raise ValueError("APPLICATION_WORKFLOW_RETURN_TARGET_INVALID")
    if return_to is not None:return_to=_identifier(return_to,"RETURN_TARGET")
    return Activity(_identifier(raw["activityId"],"ACTIVITY_ID"),
        _name(raw["name"],"ACTIVITY_NAME"),raw["kind"],dependencies,return_to,
        _assignment_ref(raw["assignmentRef"]),_destination(raw["destination"]),
        _evidence_contract(raw["evidenceContract"]))


def _validate_graph(activities: tuple[Activity,...])->None:
    by_id={item.activity_id:item for item in activities}
    if len(by_id)!=len(activities):
        raise ValueError("APPLICATION_WORKFLOW_ACTIVITY_ID_DUPLICATE")
    for item in activities:
        if (item.activity_id in item.depends_on
                or not set(item.depends_on)<=set(by_id)):
            raise ValueError("APPLICATION_WORKFLOW_DEPENDENCY_INVALID")
    visiting:set[str]=set();visited:set[str]=set()
    def visit(activity_id: str)->None:
        if activity_id in visited:return
        if activity_id in visiting:raise ValueError("APPLICATION_WORKFLOW_CYCLE")
        visiting.add(activity_id)
        for predecessor in by_id[activity_id].depends_on:visit(predecessor)
        visiting.remove(activity_id);visited.add(activity_id)
    for activity_id in by_id:visit(activity_id)
    def ancestors(activity_id: str)->set[str]:
        result=set(by_id[activity_id].depends_on)
        for predecessor in tuple(result):result.update(ancestors(predecessor))
        return result
    for item in activities:
        if item.return_to is not None and item.return_to not in ancestors(
                item.activity_id):
            raise ValueError("APPLICATION_WORKFLOW_RETURN_TARGET_INVALID")


def compile_application_workflow(definition: object)->ApplicationWorkflow:
    expected={"format","workspaceId","applicationId","flowId","version",
        "name","selection","activities"}
    if (type(definition) is not dict or set(definition)!=expected
            or definition.get("format")!=FORMAT):
        raise ValueError("APPLICATION_WORKFLOW_DEFINITION_INVALID")
    version=definition["version"]
    if type(version) is not int or version<1:
        raise ValueError("APPLICATION_WORKFLOW_VERSION_INVALID")
    raw=definition["activities"]
    if type(raw) is not list or not 1<=len(raw)<=MAX_ACTIVITIES:
        raise ValueError("APPLICATION_WORKFLOW_ACTIVITY_COUNT_INVALID")
    activities=tuple(sorted((_activity(item) for item in raw),
        key=lambda item:item.activity_id))
    _validate_graph(activities)
    model=ApplicationWorkflow(ApplicationScope(
        _identifier(definition["workspaceId"],"WORKSPACE"),
        _identifier(definition["applicationId"],"APPLICATION")),
        _identifier(definition["flowId"],"FLOW_ID"),version,
        _name(definition["name"],"NAME"),
        _freeze(canonical_selection(definition["selection"])),activities,"")
    canonical=json.dumps(model.normalized(),sort_keys=True,separators=(",",":"),
        ensure_ascii=False,allow_nan=False).encode()
    return ApplicationWorkflow(model.scope,model.flow_id,model.version,
        model.name,model.selection,model.activities,
        sha256(canonical).hexdigest())
