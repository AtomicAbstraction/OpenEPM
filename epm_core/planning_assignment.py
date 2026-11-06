"""Pure immutable assignment contract for generic multidimensional planning."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
import re

from .persistence_contract import ApplicationScope, Coordinate


_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299}\Z')
_DIGEST=re.compile(r'[0-9a-f]{64}\Z')
MAX_ASSIGNMENTS=1000
MAX_SELECTOR_MEMBERS=1000
MAX_TOTAL_MEMBER_REFERENCES=10_000
MAX_REVIEWERS=20
MAX_DELEGATION_DEPTH=3
MAX_REASSIGNMENTS=20


def _id(value,field):
    if not isinstance(value,str) or not _ID.fullmatch(value):
        raise ValueError(f'PLANNING_ASSIGNMENT_{field}_INVALID')
    return value


def _instant(value,field):
    if not isinstance(value,str):
        raise ValueError(f'PLANNING_ASSIGNMENT_{field}_INVALID')
    try:
        parsed=datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f'PLANNING_ASSIGNMENT_{field}_INVALID') from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f'PLANNING_ASSIGNMENT_{field}_TIMEZONE_REQUIRED')
    return parsed


def _optional_instant(value,field):
    return None if value is None else _instant(value,field)


def _ids(value,field,*,maximum=1000,allow_empty=False):
    if (not isinstance(value,list) or len(value)>maximum
            or not allow_empty and not value
            or any(not isinstance(item,str) or not _ID.fullmatch(item)
                   for item in value)
            or len(value)!=len(set(value))):
        raise ValueError(f'PLANNING_ASSIGNMENT_{field}_INVALID')
    return tuple(sorted(value))


@dataclass(frozen=True,slots=True)
class PolicyLink:
    policy_id: str
    version: int
    digest: str


@dataclass(frozen=True,slots=True)
class Reviewer:
    kind: str
    identifier: str


@dataclass(frozen=True,slots=True)
class Assignment:
    assignment_id: str
    priority: int
    subjects: tuple[str,...]
    groups: tuple[str,...]
    workflow_role: str
    member_selectors: tuple[tuple[str,tuple[str,...]],...]
    reviewer_chain: tuple[Reviewer,...]
    due_at: datetime
    escalation_after_due_minutes: int
    escalation_reviewer_ordinal: int
    reassignable: bool
    max_reassignments: int
    delegation_allowed: bool
    max_delegation_depth: int
    delegation_expires_at: datetime|None
    effective_from: datetime
    effective_to: datetime|None

    @property
    def required_dimensions(self):
        return frozenset(dimension for dimension,_ in self.member_selectors)

    def principal_matches(self,subject_id,groups):
        return subject_id in self.subjects or bool(set(groups)&set(self.groups))

    def coordinate_matches(self,coordinate):
        members=dict(coordinate.members)
        return all(members.get(axis) in selected
                   for axis,selected in self.member_selectors)


@dataclass(frozen=True,slots=True)
class AssignmentResolution:
    assignment_id: str
    workflow_role: str
    policy_link: PolicyLink
    reviewer_chain: tuple[Reviewer,...]
    due_at: datetime
    escalation_after_due_minutes: int
    escalation_reviewer_ordinal: int
    reassignable: bool
    max_reassignments: int
    delegation_allowed: bool
    max_delegation_depth: int
    delegation_expires_at: datetime|None
    assignment_set_version: int
    assignment_set_digest: str


@dataclass(frozen=True,slots=True)
class PlanningAssignmentSet:
    scope: ApplicationScope
    assignment_set_id: str
    version: int
    effective_from: datetime
    effective_to: datetime|None
    policy_link: PolicyLink
    assignments: tuple[Assignment,...]
    digest: str

    def resolve(self,scope,coordinate,*,subject_id,groups,workflow_role,
                at,expected_version,expected_digest=None):
        if scope!=self.scope:
            raise ValueError('PLANNING_ASSIGNMENT_SCOPE_MISMATCH')
        if type(expected_version) is not int or expected_version!=self.version:
            raise ValueError('PLANNING_ASSIGNMENT_VERSION_STALE')
        if expected_digest is not None and expected_digest!=self.digest:
            raise ValueError('PLANNING_ASSIGNMENT_DIGEST_STALE')
        _id(subject_id,'SUBJECT')
        group_ids=_ids(list(groups),'GROUPS',allow_empty=True)
        _id(workflow_role,'WORKFLOW_ROLE')
        if not isinstance(at,datetime) or at.tzinfo is None or at.utcoffset() is None:
            raise ValueError('PLANNING_ASSIGNMENT_RESOLUTION_TIME_INVALID')
        if at<self.effective_from or self.effective_to and at>self.effective_to:
            return None
        relevant=[item for item in self.assignments
            if item.workflow_role==workflow_role
            and item.principal_matches(subject_id,group_ids)
            and item.effective_from<=at
            and (item.effective_to is None or at<=item.effective_to)]
        missing=sorted(set().union(*(item.required_dimensions
            for item in relevant))-dict(coordinate.members).keys()) if relevant else []
        if missing:
            raise ValueError('PLANNING_ASSIGNMENT_REQUIRED_DIMENSION_MISSING')
        matches=[item for item in relevant if item.coordinate_matches(coordinate)]
        if not matches:return None
        priority=max(item.priority for item in matches)
        winners=[item for item in matches if item.priority==priority]
        if len(winners)!=1:
            raise ValueError('PLANNING_ASSIGNMENT_PRIORITY_AMBIGUOUS')
        item=winners[0]
        return AssignmentResolution(item.assignment_id,item.workflow_role,
            self.policy_link,item.reviewer_chain,item.due_at,
            item.escalation_after_due_minutes,
            item.escalation_reviewer_ordinal,item.reassignable,
            item.max_reassignments,item.delegation_allowed,
            item.max_delegation_depth,item.delegation_expires_at,
            self.version,self.digest)


def compile_planning_assignment_set(definition):
    expected={'workspaceId','applicationId','assignmentSetId','version',
        'effectiveFrom','effectiveTo','policyLink','assignments'}
    if not isinstance(definition,dict) or set(definition)!=expected:
        raise ValueError('PLANNING_ASSIGNMENT_DEFINITION_INVALID')
    scope=ApplicationScope(_id(definition['workspaceId'],'WORKSPACE'),
        _id(definition['applicationId'],'APPLICATION'))
    version=definition['version']
    if type(version) is not int or version<1:
        raise ValueError('PLANNING_ASSIGNMENT_VERSION_INVALID')
    effective_from=_instant(definition['effectiveFrom'],'EFFECTIVE_FROM')
    effective_to=_optional_instant(definition['effectiveTo'],'EFFECTIVE_TO')
    if effective_to and effective_to<effective_from:
        raise ValueError('PLANNING_ASSIGNMENT_EFFECTIVE_RANGE_INVALID')
    policy=_compile_policy_link(definition['policyLink'])
    raw=definition['assignments']
    if not isinstance(raw,list) or not 1<=len(raw)<=MAX_ASSIGNMENTS:
        raise ValueError('PLANNING_ASSIGNMENT_COUNT_INVALID')
    assignments=tuple(_compile_assignment(item,effective_from,effective_to)
                      for item in raw)
    if len({item.assignment_id for item in assignments})!=len(assignments):
        raise ValueError('PLANNING_ASSIGNMENT_ID_DUPLICATE')
    references=sum(sum(len(members) for _,members in item.member_selectors)
                   for item in assignments)
    if references>MAX_TOTAL_MEMBER_REFERENCES:
        raise ValueError('PLANNING_ASSIGNMENT_MEMBER_REFERENCE_LIMIT')
    canonical_definition=json.loads(json.dumps(definition))
    canonical_definition['assignments'].sort(key=lambda item:item['assignmentId'])
    for item in canonical_definition['assignments']:
        item['subjects'].sort();item['groups'].sort()
        item['memberSelectors']={axis:sorted(members) for axis,members
            in sorted(item['memberSelectors'].items())}
    canonical=json.dumps(canonical_definition,sort_keys=True,separators=(',',':'),
                         ensure_ascii=False,allow_nan=False)
    return PlanningAssignmentSet(scope,
        _id(definition['assignmentSetId'],'SET_ID'),version,effective_from,
        effective_to,policy,tuple(sorted(assignments,
            key=lambda item:item.assignment_id)),
        sha256(canonical.encode()).hexdigest())


def _compile_policy_link(raw):
    if (not isinstance(raw,dict) or set(raw)!={'policyId','version','digest'}
            or type(raw['version']) is not int or raw['version']<1
            or not isinstance(raw['digest'],str)
            or not _DIGEST.fullmatch(raw['digest'])):
        raise ValueError('PLANNING_ASSIGNMENT_POLICY_LINK_INVALID')
    return PolicyLink(_id(raw['policyId'],'POLICY_ID'),raw['version'],raw['digest'])


def _compile_assignment(raw,set_from,set_to):
    expected={'assignmentId','priority','subjects','groups','workflowRole',
        'memberSelectors','reviewerChain','dueAt','escalation','reassignment',
        'delegation','effectiveFrom','effectiveTo'}
    if not isinstance(raw,dict) or set(raw)!=expected:
        raise ValueError('PLANNING_ASSIGNMENT_ITEM_INVALID')
    priority=raw['priority']
    if type(priority) is not int or not 0<=priority<=1_000_000:
        raise ValueError('PLANNING_ASSIGNMENT_PRIORITY_INVALID')
    subjects=_ids(raw['subjects'],'SUBJECTS',allow_empty=True)
    groups=_ids(raw['groups'],'GROUPS',allow_empty=True)
    if not subjects and not groups:
        raise ValueError('PLANNING_ASSIGNMENT_PRINCIPAL_REQUIRED')
    selectors=raw['memberSelectors']
    if (not isinstance(selectors,dict) or not selectors
            or len(selectors)>100 or any(not isinstance(values,list)
            or not 1<=len(values)<=MAX_SELECTOR_MEMBERS for values in selectors.values())):
        raise ValueError('PLANNING_ASSIGNMENT_SELECTORS_INVALID')
    compiled_selectors=tuple(sorted((_id(axis,'DIMENSION'),
        _ids(values,'SELECTOR_MEMBERS',maximum=MAX_SELECTOR_MEMBERS))
        for axis,values in selectors.items()))
    reviewers=_compile_reviewers(raw['reviewerChain'],subjects,groups)
    due=_instant(raw['dueAt'],'DUE_AT')
    effective_from=_instant(raw['effectiveFrom'],'ITEM_EFFECTIVE_FROM')
    effective_to=_optional_instant(raw['effectiveTo'],'ITEM_EFFECTIVE_TO')
    if (effective_from<set_from or set_to and (effective_to is None or effective_to>set_to)
            or effective_to and effective_to<effective_from
            or due<effective_from or effective_to and due>effective_to):
        raise ValueError('PLANNING_ASSIGNMENT_ITEM_TIME_RANGE_INVALID')
    escalation=raw['escalation']
    if (not isinstance(escalation,dict)
            or set(escalation)!={'afterDueMinutes','reviewerOrdinal'}
            or type(escalation['afterDueMinutes']) is not int
            or not 0<=escalation['afterDueMinutes']<=525_600
            or type(escalation['reviewerOrdinal']) is not int
            or not 1<=escalation['reviewerOrdinal']<=len(reviewers)):
        raise ValueError('PLANNING_ASSIGNMENT_ESCALATION_INVALID')
    reassignment=raw['reassignment']
    if (not isinstance(reassignment,dict)
            or set(reassignment)!={'allowed','maxReassignments'}
            or type(reassignment['allowed']) is not bool
            or type(reassignment['maxReassignments']) is not int
            or not 0<=reassignment['maxReassignments']<=MAX_REASSIGNMENTS
            or not reassignment['allowed'] and reassignment['maxReassignments']!=0):
        raise ValueError('PLANNING_ASSIGNMENT_REASSIGNMENT_INVALID')
    delegation=raw['delegation']
    if (not isinstance(delegation,dict)
            or set(delegation)!={'allowed','maxDepth','expiresAt'}
            or type(delegation['allowed']) is not bool
            or type(delegation['maxDepth']) is not int
            or not 0<=delegation['maxDepth']<=MAX_DELEGATION_DEPTH
            or not delegation['allowed'] and delegation['maxDepth']!=0):
        raise ValueError('PLANNING_ASSIGNMENT_DELEGATION_INVALID')
    delegation_expiry=_optional_instant(delegation['expiresAt'],
                                        'DELEGATION_EXPIRES_AT')
    if (delegation['allowed'] and delegation_expiry is None
            or not delegation['allowed'] and delegation_expiry is not None
            or delegation_expiry and (delegation_expiry<effective_from
                or delegation_expiry>due
                or effective_to and delegation_expiry>effective_to)):
        raise ValueError('PLANNING_ASSIGNMENT_DELEGATION_RANGE_INVALID')
    return Assignment(_id(raw['assignmentId'],'ID'),priority,subjects,groups,
        _id(raw['workflowRole'],'WORKFLOW_ROLE'),compiled_selectors,reviewers,due,
        escalation['afterDueMinutes'],escalation['reviewerOrdinal'],
        reassignment['allowed'],reassignment['maxReassignments'],
        delegation['allowed'],delegation['maxDepth'],delegation_expiry,
        effective_from,effective_to)


def _compile_reviewers(raw,subjects,groups):
    if not isinstance(raw,list) or not 1<=len(raw)<=MAX_REVIEWERS:
        raise ValueError('PLANNING_ASSIGNMENT_REVIEWER_CHAIN_INVALID')
    reviewers=[]
    for item in raw:
        if (not isinstance(item,dict) or set(item)!={'kind','id'}
                or item['kind'] not in ('Subject','Group')):
            raise ValueError('PLANNING_ASSIGNMENT_REVIEWER_INVALID')
        reviewers.append(Reviewer(item['kind'],_id(item['id'],'REVIEWER_ID')))
    principals={(item.kind,item.identifier) for item in reviewers}
    if len(principals)!=len(reviewers):
        raise ValueError('PLANNING_ASSIGNMENT_REVIEWER_CYCLE')
    if principals & ({('Subject',item) for item in subjects}
                     | {('Group',item) for item in groups}):
        raise ValueError('PLANNING_ASSIGNMENT_REVIEWER_CYCLE')
    return tuple(reviewers)
