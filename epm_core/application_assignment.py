"""Domain-neutral immutable human assignment contract.

Assignments establish who may perform or review an application task over a
bounded multidimensional member scope.  They do not grant cube access, execute
business logic, define a workflow state machine, or infer a planning domain.
The fixed core must still authorize every read, write and task transition.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime,timezone
from hashlib import sha256
import json
import re

from .persistence_contract import ApplicationScope


FORMAT="openepm-application-assignment-set-v1"
MAX_ASSIGNMENTS=1000
MAX_PRINCIPALS=100
MAX_REVIEWERS=20
MAX_SCOPE_DIMENSIONS=32
MAX_MEMBERS_PER_SELECTOR=1000
MAX_TOTAL_MEMBER_REFERENCES=10_000
MAX_DELEGATION_DEPTH=3
MAX_REASSIGNMENTS=20
_ID=re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299}\Z")


def _identifier(value: object,field: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError(f"APPLICATION_ASSIGNMENT_{field}_INVALID")
    return value


def _name(value: object) -> str:
    if (type(value) is not str or not 1<=len(value)<=200
            or value!=value.strip() or "\x00" in value):
        raise ValueError("APPLICATION_ASSIGNMENT_NAME_INVALID")
    return value


def _instant(value: object,field: str) -> datetime:
    if type(value) is not str:
        raise ValueError(f"APPLICATION_ASSIGNMENT_{field}_INVALID")
    try: parsed=datetime.fromisoformat(value.replace("Z","+00:00"))
    except ValueError as error:
        raise ValueError(f"APPLICATION_ASSIGNMENT_{field}_INVALID") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"APPLICATION_ASSIGNMENT_{field}_TIMEZONE_REQUIRED")
    return parsed.astimezone(timezone.utc)


def _optional_instant(value: object,field: str) -> datetime|None:
    return None if value is None else _instant(value,field)


def _identifiers(value: object,field: str,*,maximum: int,
                 allow_empty: bool=True) -> tuple[str,...]:
    if (type(value) is not list or len(value)>maximum
            or (not allow_empty and not value)
            or any(type(item) is not str for item in value)):
        raise ValueError(f"APPLICATION_ASSIGNMENT_{field}_INVALID")
    result=tuple(sorted(_identifier(item,field) for item in value))
    if len(result)!=len(set(result)):
        raise ValueError(f"APPLICATION_ASSIGNMENT_{field}_INVALID")
    return result


@dataclass(frozen=True,slots=True)
class Reviewer:
    kind: str
    identifier: str

    def normalized(self) -> dict:
        return {"kind":self.kind,"id":self.identifier}


@dataclass(frozen=True,slots=True)
class ApplicationAssignment:
    assignment_id: str
    name: str
    subjects: tuple[str,...]
    groups: tuple[str,...]
    member_selectors: tuple[tuple[str,tuple[str,...]],...]
    reviewer_chain: tuple[Reviewer,...]
    due_at: datetime
    reassignable: bool
    max_reassignments: int
    delegation_allowed: bool
    max_delegation_depth: int
    delegation_expires_at: datetime|None

    def principal_matches(self,subject_id: str,groups: tuple[str,...]) -> bool:
        return subject_id in self.subjects or bool(set(groups)&set(self.groups))

    def normalized(self) -> dict:
        return {"assignmentId":self.assignment_id,"name":self.name,
            "subjects":list(self.subjects),"groups":list(self.groups),
            "memberSelectors":{axis:list(members)
                for axis,members in self.member_selectors},
            "reviewerChain":[item.normalized()
                for item in self.reviewer_chain],
            "dueAt":self.due_at.isoformat(),
            "controls":{"reassignable":self.reassignable,
                "maxReassignments":self.max_reassignments,
                "delegationAllowed":self.delegation_allowed,
                "maxDelegationDepth":self.max_delegation_depth,
                "delegationExpiresAt":None if self.delegation_expires_at is None
                    else self.delegation_expires_at.isoformat()}}


@dataclass(frozen=True,slots=True)
class ApplicationAssignmentSet:
    scope: ApplicationScope
    assignment_set_id: str
    version: int
    name: str
    effective_from: datetime
    effective_to: datetime|None
    assignments: tuple[ApplicationAssignment,...]
    digest: str

    def assignment(self,assignment_id: str) -> ApplicationAssignment:
        value=_identifier(assignment_id,"ID")
        for item in self.assignments:
            if item.assignment_id==value:return item
        raise ValueError("APPLICATION_ASSIGNMENT_UNAVAILABLE")

    def normalized(self) -> dict:
        return {"format":FORMAT,"workspaceId":self.scope.workspace_id,
            "applicationId":self.scope.application_id,
            "assignmentSetId":self.assignment_set_id,"version":self.version,
            "name":self.name,"effectiveFrom":self.effective_from.isoformat(),
            "effectiveTo":None if self.effective_to is None
                else self.effective_to.isoformat(),
            "assignments":[item.normalized() for item in self.assignments]}


def _reviewer(raw: object) -> Reviewer:
    if (type(raw) is not dict or set(raw)!={"kind","id"}
            or raw.get("kind") not in ("Subject","Group")):
        raise ValueError("APPLICATION_ASSIGNMENT_REVIEWER_INVALID")
    return Reviewer(raw["kind"],_identifier(raw["id"],"REVIEWER"))


def _assignment(raw: object,set_from: datetime,
                set_to: datetime|None) -> ApplicationAssignment:
    expected={"assignmentId","name","subjects","groups","memberSelectors",
        "reviewerChain","dueAt","controls"}
    if type(raw) is not dict or set(raw)!=expected:
        raise ValueError("APPLICATION_ASSIGNMENT_DEFINITION_INVALID")
    subjects=_identifiers(raw["subjects"],"SUBJECTS",maximum=MAX_PRINCIPALS)
    groups=_identifiers(raw["groups"],"GROUPS",maximum=MAX_PRINCIPALS)
    if not subjects and not groups:
        raise ValueError("APPLICATION_ASSIGNMENT_PRINCIPAL_REQUIRED")
    selectors=raw["memberSelectors"]
    if type(selectors) is not dict or len(selectors)>MAX_SCOPE_DIMENSIONS:
        raise ValueError("APPLICATION_ASSIGNMENT_SELECTORS_INVALID")
    normalized=[];references=0
    for dimension,members in selectors.items():
        selected=_identifiers(members,"MEMBERS",
            maximum=MAX_MEMBERS_PER_SELECTOR,allow_empty=False)
        normalized.append((_identifier(dimension,"DIMENSION"),selected))
        references+=len(selected)
    if references>MAX_TOTAL_MEMBER_REFERENCES:
        raise ValueError("APPLICATION_ASSIGNMENT_MEMBER_REFERENCE_LIMIT")
    raw_reviewers=raw["reviewerChain"]
    if (type(raw_reviewers) is not list
            or not 1<=len(raw_reviewers)<=MAX_REVIEWERS):
        raise ValueError("APPLICATION_ASSIGNMENT_REVIEWER_INVALID")
    reviewers=tuple(_reviewer(item) for item in raw_reviewers)
    if len({(item.kind,item.identifier) for item in reviewers})!=len(reviewers):
        raise ValueError("APPLICATION_ASSIGNMENT_REVIEWER_INVALID")
    controls=raw["controls"]
    control_fields={"reassignable","maxReassignments","delegationAllowed",
        "maxDelegationDepth","delegationExpiresAt"}
    if (type(controls) is not dict or set(controls)!=control_fields
            or type(controls["reassignable"]) is not bool
            or type(controls["delegationAllowed"]) is not bool
            or type(controls["maxReassignments"]) is not int
            or not 0<=controls["maxReassignments"]<=MAX_REASSIGNMENTS
            or type(controls["maxDelegationDepth"]) is not int
            or not 0<=controls["maxDelegationDepth"]<=MAX_DELEGATION_DEPTH
            or ((controls["maxReassignments"]>0)
                !=controls["reassignable"])
            or ((controls["maxDelegationDepth"]>0)
                !=controls["delegationAllowed"])):
        raise ValueError("APPLICATION_ASSIGNMENT_CONTROLS_INVALID")
    delegation_expires=_optional_instant(
        controls["delegationExpiresAt"],"DELEGATION_EXPIRES_AT")
    if (delegation_expires is None)!= (not controls["delegationAllowed"]):
        raise ValueError("APPLICATION_ASSIGNMENT_CONTROLS_INVALID")
    due=_instant(raw["dueAt"],"DUE_AT")
    if due<set_from or set_to is not None and due>set_to:
        raise ValueError("APPLICATION_ASSIGNMENT_DUE_RANGE_INVALID")
    if (delegation_expires is not None
            and (delegation_expires<set_from or delegation_expires>due)):
        raise ValueError("APPLICATION_ASSIGNMENT_DELEGATION_RANGE_INVALID")
    return ApplicationAssignment(_identifier(raw["assignmentId"],"ID"),
        _name(raw["name"]),subjects,groups,tuple(sorted(normalized)),reviewers,
        due,controls["reassignable"],controls["maxReassignments"],
        controls["delegationAllowed"],controls["maxDelegationDepth"],
        delegation_expires)


def compile_application_assignment_set(
        definition: object) -> ApplicationAssignmentSet:
    expected={"format","workspaceId","applicationId","assignmentSetId",
        "version","name","effectiveFrom","effectiveTo","assignments"}
    if (type(definition) is not dict or set(definition)!=expected
            or definition.get("format")!=FORMAT):
        raise ValueError("APPLICATION_ASSIGNMENT_SET_INVALID")
    version=definition["version"]
    if type(version) is not int or version<1:
        raise ValueError("APPLICATION_ASSIGNMENT_VERSION_INVALID")
    start=_instant(definition["effectiveFrom"],"EFFECTIVE_FROM")
    end=_optional_instant(definition["effectiveTo"],"EFFECTIVE_TO")
    if end is not None and end<start:
        raise ValueError("APPLICATION_ASSIGNMENT_EFFECTIVE_RANGE_INVALID")
    raw=definition["assignments"]
    if type(raw) is not list or not 1<=len(raw)<=MAX_ASSIGNMENTS:
        raise ValueError("APPLICATION_ASSIGNMENT_COUNT_INVALID")
    assignments=tuple(sorted((_assignment(item,start,end) for item in raw),
        key=lambda item:item.assignment_id))
    if len({item.assignment_id for item in assignments})!=len(assignments):
        raise ValueError("APPLICATION_ASSIGNMENT_ID_DUPLICATE")
    model=ApplicationAssignmentSet(ApplicationScope(
        _identifier(definition["workspaceId"],"WORKSPACE"),
        _identifier(definition["applicationId"],"APPLICATION")),
        _identifier(definition["assignmentSetId"],"SET_ID"),version,
        _name(definition["name"]),start,end,assignments,"")
    normalized=model.normalized()
    digest=sha256(json.dumps(normalized,sort_keys=True,separators=(",",":"),
        ensure_ascii=False,allow_nan=False).encode()).hexdigest()
    return ApplicationAssignmentSet(model.scope,model.assignment_set_id,
        model.version,model.name,model.effective_from,model.effective_to,
        model.assignments,digest)
