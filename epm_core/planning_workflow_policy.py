"""Pure current editability policy for generic planning applications.

This module deliberately owns no persistence or transport.  It provides the
canonical contract that repositories and every business-data publisher can
share later without making ordinary FP&A depend on financial dimensions.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from hashlib import sha256
import json
import re
from typing import Mapping

from .persistence_contract import ApplicationScope,Coordinate


_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z')
_DIGEST=re.compile(r'[0-9a-f]{64}\Z')
_EFFECTS=frozenset(('Allow','Deny'))
_LOCK_STATES=frozenset(('Open','Locked','Submitted','Approved'))
MAX_RULES=500
MAX_MEMBERS_PER_SELECTOR=1000
MAX_TOTAL_MEMBER_REFERENCES=10_000
FORMAT_V2='openepm-planning-workflow-policy-v2'


def level_resolution_digest(value: dict) -> str:
    return sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
                             ensure_ascii=False).encode()).hexdigest()


def _identifier(value: object,field: str) -> str:
    if not isinstance(value,str) or not _ID.fullmatch(value):
        raise ValueError(f'PLANNING_POLICY_{field}_INVALID')
    return value


def _date(value: object,field: str) -> date:
    if not isinstance(value,str):
        raise ValueError(f'PLANNING_POLICY_{field}_INVALID')
    try:
        parsed=date.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f'PLANNING_POLICY_{field}_INVALID') from error
    if parsed.isoformat()!=value:
        raise ValueError(f'PLANNING_POLICY_{field}_INVALID')
    return parsed


def _string_set(value: object,field: str,*,maximum: int=100) -> tuple[str,...]:
    if (not isinstance(value,list) or not value or len(value)>maximum
            or any(not isinstance(item,str) or not _ID.fullmatch(item)
                   for item in value)
            or len(set(value))!=len(value)):
        raise ValueError(f'PLANNING_POLICY_{field}_INVALID')
    return tuple(sorted(value))


@dataclass(frozen=True,slots=True)
class PlanningPolicyDecision:
    allowed: bool
    reason_code: str
    policy_id: str
    policy_digest: str
    matched_rule_ids: tuple[str,...]


@dataclass(frozen=True,slots=True)
class PeriodBound:
    dimension_id: str
    ordered_members: tuple[str,...]
    start_member_id: str
    end_member_id: str

    def includes(self,member_id: str) -> bool:
        start=self.ordered_members.index(self.start_member_id)
        end=self.ordered_members.index(self.end_member_id)
        return start<=self.ordered_members.index(member_id)<=end


@dataclass(frozen=True,slots=True)
class LevelSelector:
    dimension_id: str
    hierarchy_state_token: str
    root_member_id: str
    depth: int
    metadata_revision: int
    schema_epoch: int
    resolved_members: tuple[str,...]
    resolution_digest: str


@dataclass(frozen=True,slots=True)
class PlanningPolicyRule:
    rule_id: str
    priority: int
    effect: str
    actions: tuple[str,...]
    workflow_roles: tuple[str,...]
    member_selectors: tuple[tuple[str,tuple[str,...]],...]
    scenario_dimension_id: str|None
    scenario_members: tuple[str,...]
    period_bound: PeriodBound|None
    effective_from: date|None
    effective_to: date|None
    level_selector: LevelSelector|None=None

    @property
    def required_dimensions(self) -> frozenset[str]:
        dimensions={dimension for dimension,_ in self.member_selectors}
        if self.scenario_dimension_id:
            dimensions.add(self.scenario_dimension_id)
        if self.period_bound:
            dimensions.add(self.period_bound.dimension_id)
        if self.level_selector:
            dimensions.add(self.level_selector.dimension_id)
        return frozenset(dimensions)

    def matches(self,members: Mapping[str,str],*,action: str,
                workflow_role: str,on_date: date) -> bool:
        if action not in self.actions or workflow_role not in self.workflow_roles:
            return False
        if self.effective_from and on_date<self.effective_from:
            return False
        if self.effective_to and on_date>self.effective_to:
            return False
        if any(members.get(axis) not in selected
               for axis,selected in self.member_selectors):
            return False
        if (self.level_selector and members.get(
                self.level_selector.dimension_id)
                not in self.level_selector.resolved_members):
            return False
        if (self.scenario_dimension_id
                and members.get(self.scenario_dimension_id)
                    not in self.scenario_members):
            return False
        if self.period_bound:
            member=members.get(self.period_bound.dimension_id)
            if (member not in self.period_bound.ordered_members
                    or not self.period_bound.includes(member)):
                return False
        return True


@dataclass(frozen=True,slots=True)
class PlanningWorkflowPolicy:
    scope: ApplicationScope
    policy_id: str
    effective_from: date
    effective_to: date|None
    rules: tuple[PlanningPolicyRule,...]
    digest: str
    format_version: int=1
    authored_intent_digest: str|None=None

    def evaluate(self,scope: ApplicationScope,coordinate: Coordinate,*,
                 action: str,workflow_role: str,on_date: date,
                 lock_state: str,
                 expected_digest: str|None=None) -> PlanningPolicyDecision:
        if scope!=self.scope:
            raise ValueError('PLANNING_POLICY_SCOPE_MISMATCH')
        if (expected_digest is not None
                and (not isinstance(expected_digest,str)
                     or not _DIGEST.fullmatch(expected_digest)
                     or expected_digest!=self.digest)):
            raise ValueError('PLANNING_POLICY_DIGEST_STALE')
        _identifier(action,'ACTION')
        _identifier(workflow_role,'WORKFLOW_ROLE')
        if not isinstance(on_date,date):
            raise ValueError('PLANNING_POLICY_EVALUATION_DATE_INVALID')
        if lock_state not in _LOCK_STATES:
            raise ValueError('PLANNING_POLICY_LOCK_STATE_INVALID')
        if lock_state!='Open':
            return self._decision(False,'PLANNING_INTERSECTION_LOCKED',())
        if on_date<self.effective_from or (
                self.effective_to and on_date>self.effective_to):
            return self._decision(False,'PLANNING_POLICY_NOT_EFFECTIVE',())
        members=dict(coordinate.members)
        relevant=[rule for rule in self.rules
                  if action in rule.actions and workflow_role in rule.workflow_roles
                  and (not rule.effective_from or on_date>=rule.effective_from)
                  and (not rule.effective_to or on_date<=rule.effective_to)]
        missing=sorted(set().union(
            *(rule.required_dimensions for rule in relevant))-members.keys())
        if missing:
            return self._decision(
                False,'PLANNING_POLICY_REQUIRED_DIMENSION_MISSING',())
        matching=[rule for rule in relevant if rule.matches(
            members,action=action,workflow_role=workflow_role,on_date=on_date)]
        if not matching:
            return self._decision(False,'PLANNING_POLICY_NO_ALLOW_RULE',())
        priority=max(rule.priority for rule in matching)
        winners=tuple(sorted(
            (rule for rule in matching if rule.priority==priority),
            key=lambda rule:rule.rule_id))
        effects={rule.effect for rule in winners}
        if len(effects)!=1:
            raise ValueError('PLANNING_POLICY_AMBIGUOUS_MATCH')
        effect=effects.pop()
        return self._decision(
            effect=='Allow',
            ('PLANNING_POLICY_ALLOW' if effect=='Allow'
             else 'PLANNING_POLICY_EXPLICIT_DENY'),
            tuple(rule.rule_id for rule in winners))

    def _decision(self,allowed: bool,reason: str,
                  rule_ids: tuple[str,...]) -> PlanningPolicyDecision:
        return PlanningPolicyDecision(
            allowed,reason,self.policy_id,self.digest,rule_ids)


def compile_planning_workflow_policy(definition: object) -> PlanningWorkflowPolicy:
    """Validate and canonicalize one immutable policy definition."""
    v2=isinstance(definition,dict) and definition.get('format')==FORMAT_V2
    expected={'workspaceId','applicationId','policyId',
              'effectiveFrom','effectiveTo','rules'}
    if v2:expected.update(('format','authoredIntentDigest'))
    if not isinstance(definition,dict) or set(definition)!=expected:
        raise ValueError('PLANNING_POLICY_DEFINITION_INVALID')
    scope=ApplicationScope(
        _identifier(definition['workspaceId'],'WORKSPACE_ID'),
        _identifier(definition['applicationId'],'APPLICATION_ID'))
    policy_id=_identifier(definition['policyId'],'ID')
    authored_digest=(definition['authoredIntentDigest'] if v2 else None)
    if v2 and (not isinstance(authored_digest,str)
            or not _DIGEST.fullmatch(authored_digest)):
        raise ValueError('PLANNING_POLICY_AUTHORED_INTENT_DIGEST_INVALID')
    effective_from=_date(definition['effectiveFrom'],'EFFECTIVE_FROM')
    effective_to=(None if definition['effectiveTo'] is None
                  else _date(definition['effectiveTo'],'EFFECTIVE_TO'))
    if effective_to and effective_to<effective_from:
        raise ValueError('PLANNING_POLICY_EFFECTIVE_RANGE_INVALID')
    raw_rules=definition['rules']
    if not isinstance(raw_rules,list) or not 1<=len(raw_rules)<=MAX_RULES:
        raise ValueError('PLANNING_POLICY_RULE_COUNT_INVALID')
    rules=tuple(_compile_rule(rule,v2=v2) for rule in raw_rules)
    if len({rule.rule_id for rule in rules})!=len(rules):
        raise ValueError('PLANNING_POLICY_RULE_ID_DUPLICATE')
    references=sum(sum(len(members) for _,members in rule.member_selectors)
                   +len(rule.scenario_members)
                   +(len(rule.period_bound.ordered_members)
                     if rule.period_bound else 0)
                   +(len(rule.level_selector.resolved_members)
                     if rule.level_selector else 0) for rule in rules)
    if references>MAX_TOTAL_MEMBER_REFERENCES:
        raise ValueError('PLANNING_POLICY_MEMBER_BUDGET_EXCEEDED')
    canonical={
        'workspaceId':scope.workspace_id,'applicationId':scope.application_id,
        'policyId':policy_id,
        'effectiveFrom':effective_from.isoformat(),
        'effectiveTo':effective_to.isoformat() if effective_to else None,
        'rules':[_canonical_rule(rule) for rule in sorted(
            rules,key=lambda item:item.rule_id)]}
    if v2:
        canonical['format']=FORMAT_V2
        canonical['authoredIntentDigest']=authored_digest
    digest=sha256(json.dumps(canonical,sort_keys=True,separators=(',',':'),
                             ensure_ascii=False).encode()).hexdigest()
    return PlanningWorkflowPolicy(
        scope,policy_id,effective_from,effective_to,
        tuple(sorted(rules,key=lambda item:item.rule_id)),digest,
        2 if v2 else 1,authored_digest)


def _compile_rule(raw: object,*,v2: bool=False) -> PlanningPolicyRule:
    expected={'ruleId','priority','effect','actions','workflowRoles',
              'memberSelectors','scenarioBound','periodBound',
              'effectiveFrom','effectiveTo'}
    if v2:expected.add('levelSelector')
    if not isinstance(raw,dict) or set(raw)!=expected:
        raise ValueError('PLANNING_POLICY_RULE_INVALID')
    priority=raw['priority']
    if type(priority) is not int or not 0<=priority<=10_000:
        raise ValueError('PLANNING_POLICY_PRIORITY_INVALID')
    if raw['effect'] not in _EFFECTS:
        raise ValueError('PLANNING_POLICY_EFFECT_INVALID')
    selectors=raw['memberSelectors']
    if not isinstance(selectors,dict) or len(selectors)>32:
        raise ValueError('PLANNING_POLICY_MEMBER_SELECTORS_INVALID')
    compiled_selectors=[]
    for dimension,members in selectors.items():
        compiled_selectors.append((
            _identifier(dimension,'DIMENSION_ID'),
            _string_set(members,'MEMBER_SELECTOR',
                        maximum=MAX_MEMBERS_PER_SELECTOR)))
    selector_dimensions={dimension for dimension,_ in compiled_selectors}
    level=None
    if v2 and raw['levelSelector'] is not None:
        level=_compile_level_selector(raw['levelSelector'])
    scenario_dimension=None
    scenario_members=()
    scenario=raw['scenarioBound']
    if scenario is not None:
        if not isinstance(scenario,dict) or set(scenario)!={'dimensionId','members'}:
            raise ValueError('PLANNING_POLICY_SCENARIO_BOUND_INVALID')
        scenario_dimension=_identifier(scenario['dimensionId'],'DIMENSION_ID')
        scenario_members=_string_set(
            scenario['members'],'SCENARIO_MEMBERS',
            maximum=MAX_MEMBERS_PER_SELECTOR)
    period=None
    raw_period=raw['periodBound']
    if raw_period is not None:
        if (not isinstance(raw_period,dict)
                or set(raw_period)!={'dimensionId','orderedMembers',
                                     'startMemberId','endMemberId'}):
            raise ValueError('PLANNING_POLICY_PERIOD_BOUND_INVALID')
        dimension=_identifier(raw_period['dimensionId'],'DIMENSION_ID')
        ordered=_string_set(raw_period['orderedMembers'],'PERIOD_MEMBERS',
                            maximum=MAX_MEMBERS_PER_SELECTOR)
        # Period order is semantic and must not be canonicalized alphabetically.
        ordered=tuple(raw_period['orderedMembers'])
        start=_identifier(raw_period['startMemberId'],'PERIOD_MEMBER')
        end=_identifier(raw_period['endMemberId'],'PERIOD_MEMBER')
        if (start not in ordered or end not in ordered
                or ordered.index(start)>ordered.index(end)):
            raise ValueError('PLANNING_POLICY_PERIOD_RANGE_INVALID')
        period=PeriodBound(dimension,ordered,start,end)
    bounded={item for item in (
        scenario_dimension,period.dimension_id if period else None,
        level.dimension_id if level else None) if item}
    if (len(bounded)!=(int(scenario_dimension is not None)
                       +int(period is not None)+int(level is not None))
            or selector_dimensions & bounded):
        raise ValueError('PLANNING_POLICY_DIMENSION_BOUND_DUPLICATE')
    effective_from=(None if raw['effectiveFrom'] is None
                    else _date(raw['effectiveFrom'],'RULE_EFFECTIVE_FROM'))
    effective_to=(None if raw['effectiveTo'] is None
                  else _date(raw['effectiveTo'],'RULE_EFFECTIVE_TO'))
    if effective_from and effective_to and effective_to<effective_from:
        raise ValueError('PLANNING_POLICY_RULE_EFFECTIVE_RANGE_INVALID')
    return PlanningPolicyRule(
        _identifier(raw['ruleId'],'RULE_ID'),priority,raw['effect'],
        _string_set(raw['actions'],'ACTIONS'),
        _string_set(raw['workflowRoles'],'WORKFLOW_ROLES'),
        tuple(sorted(compiled_selectors)),scenario_dimension,
        scenario_members,period,effective_from,effective_to,level)


def _compile_level_selector(raw: object) -> LevelSelector:
    expected={'dimensionId','hierarchyStateToken','rootMemberId','depth',
              'metadataRevision','schemaEpoch','resolvedMemberIds',
              'resolutionDigest'}
    if not isinstance(raw,dict) or set(raw)!=expected:
        raise ValueError('PLANNING_POLICY_LEVEL_SELECTOR_INVALID')
    integers=('depth','metadataRevision','schemaEpoch')
    if any(type(raw[name]) is not int for name in integers):
        raise ValueError('PLANNING_POLICY_LEVEL_SELECTOR_INVALID')
    if (not isinstance(raw['hierarchyStateToken'],str)
            or not re.fullmatch(r'[0-9a-f]{64}',raw['hierarchyStateToken'])
            or not 0<=raw['depth']<=1000
            or raw['metadataRevision']<0 or raw['schemaEpoch']<0):
        raise ValueError('PLANNING_POLICY_LEVEL_SELECTOR_INVALID')
    members=_string_set(raw['resolvedMemberIds'],'LEVEL_MEMBERS',
                        maximum=MAX_MEMBERS_PER_SELECTOR)
    digest=raw['resolutionDigest']
    payload={'dimensionId':raw['dimensionId'],
             'hierarchyStateToken':raw['hierarchyStateToken'],
             'rootMemberId':raw['rootMemberId'],'depth':raw['depth'],
             'metadataRevision':raw['metadataRevision'],
             'schemaEpoch':raw['schemaEpoch'],
             'resolvedMemberIds':list(members)}
    expected_digest=level_resolution_digest(payload)
    if not isinstance(digest,str) or digest!=expected_digest:
        raise ValueError('PLANNING_POLICY_LEVEL_RESOLUTION_DIGEST_INVALID')
    return LevelSelector(_identifier(raw['dimensionId'],'DIMENSION_ID'),
        raw['hierarchyStateToken'],_identifier(raw['rootMemberId'],'ROOT_MEMBER'),
        raw['depth'],raw['metadataRevision'],raw['schemaEpoch'],members,digest)


def _canonical_rule(rule: PlanningPolicyRule) -> dict:
    return {
        'ruleId':rule.rule_id,'priority':rule.priority,'effect':rule.effect,
        'actions':list(rule.actions),'workflowRoles':list(rule.workflow_roles),
        'memberSelectors':{axis:list(members)
                           for axis,members in rule.member_selectors},
        **({'levelSelector':None if rule.level_selector is None else {
            'dimensionId':rule.level_selector.dimension_id,
            'hierarchyStateToken':rule.level_selector.hierarchy_state_token,
            'rootMemberId':rule.level_selector.root_member_id,
            'depth':rule.level_selector.depth,
            'metadataRevision':rule.level_selector.metadata_revision,
            'schemaEpoch':rule.level_selector.schema_epoch,
            'resolvedMemberIds':list(rule.level_selector.resolved_members),
            'resolutionDigest':rule.level_selector.resolution_digest}}
           if rule.level_selector is not None else {}),
        'scenarioBound':(
            {'dimensionId':rule.scenario_dimension_id,
             'members':list(rule.scenario_members)}
            if rule.scenario_dimension_id else None),
        'periodBound':(
            {'dimensionId':rule.period_bound.dimension_id,
             'orderedMembers':list(rule.period_bound.ordered_members),
             'startMemberId':rule.period_bound.start_member_id,
             'endMemberId':rule.period_bound.end_member_id}
            if rule.period_bound else None),
        'effectiveFrom':(
            rule.effective_from.isoformat() if rule.effective_from else None),
        'effectiveTo':(
            rule.effective_to.isoformat() if rule.effective_to else None)}


def canonical_policy_definition(policy: PlanningWorkflowPolicy) -> dict:
    value={'workspaceId':policy.scope.workspace_id,
           'applicationId':policy.scope.application_id,
           'policyId':policy.policy_id,
           'effectiveFrom':policy.effective_from.isoformat(),
           'effectiveTo':(policy.effective_to.isoformat()
                          if policy.effective_to else None),
           'rules':[_canonical_rule(rule) for rule in policy.rules]}
    if policy.format_version==2:
        value['format']=FORMAT_V2
        value['authoredIntentDigest']=policy.authored_intent_digest
        for rule in value['rules']:
            rule.setdefault('levelSelector',None)
    return value
