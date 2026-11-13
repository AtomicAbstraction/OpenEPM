"""Transport-neutral batch guard for configurable planning editability.

The guard is deliberately pure.  A publisher loads the current policy and
lock states inside its publication transaction, then uses this contract before
creating effects.  Applications without an active policy retain their normal
grant-based write behavior; activating a policy makes every targeted point an
explicit fail-closed decision.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from hashlib import sha256
import json
from typing import Mapping,Sequence

from .persistence_contract import ApplicationScope,Coordinate
from .planning_workflow_policy import PlanningWorkflowPolicy


MAX_GUARDED_WRITES=10_000
_LOCK_STATES=frozenset(('Open','Locked','Submitted','Approved'))


@dataclass(frozen=True,slots=True)
class PlanningWrite:
    coordinate: Coordinate
    action: str
    lock_state: str='Open'

    def __post_init__(self) -> None:
        if not isinstance(self.coordinate,Coordinate):
            raise ValueError('PLANNING_WRITE_COORDINATE_INVALID')
        if (not isinstance(self.action,str) or not self.action
                or len(self.action)>200):
            raise ValueError('PLANNING_WRITE_ACTION_INVALID')
        if self.lock_state not in _LOCK_STATES:
            raise ValueError('PLANNING_WRITE_LOCK_STATE_INVALID')


@dataclass(frozen=True,slots=True)
class PlanningWriteGuardEvidence:
    configured: bool
    allowed: bool
    reason_code: str
    policy_id: str|None
    policy_digest: str|None
    write_count: int
    decision_digest: str
    matched_rule_ids: tuple[str,...]


def guard_planning_writes(*,scope: ApplicationScope,
                          policy: PlanningWorkflowPolicy|None,
                          writes: Sequence[PlanningWrite],
                          workflow_role: str,on_date: date,
                          expected_policy_digest: str|None=None,
                          ordered_actions: bool=False
                          ) -> PlanningWriteGuardEvidence:
    """Evaluate a bounded publication unit against one pinned active policy.

    ``None`` means the optional workflow/editability feature is not configured,
    not that authorization is bypassed.  Publishers must still perform their
    ordinary current grant, application-state and revision checks.
    """
    if not isinstance(scope,ApplicationScope):
        raise ValueError('PLANNING_WRITE_SCOPE_INVALID')
    if (not isinstance(writes,Sequence) or isinstance(writes,(str,bytes))
            or not 1<=len(writes)<=MAX_GUARDED_WRITES
            or any(not isinstance(item,PlanningWrite) for item in writes)):
        raise ValueError('PLANNING_WRITE_BATCH_INVALID')
    if (not isinstance(workflow_role,str) or not workflow_role
            or len(workflow_role)>200 or not isinstance(on_date,date)):
        raise ValueError('PLANNING_WRITE_CONTEXT_INVALID')
    if type(ordered_actions) is not bool:
        raise ValueError('PLANNING_WRITE_ORDERED_FLAG_INVALID')
    identities=[(item.coordinate.members,item.action) for item in writes]
    if not ordered_actions and len(set(identities))!=len(identities):
        raise ValueError('PLANNING_WRITE_DUPLICATE_TARGET')
    if policy is None:
        if expected_policy_digest is not None:
            raise ValueError('PLANNING_WRITE_POLICY_PIN_WITHOUT_POLICY')
        return _evidence(False,True,'PLANNING_POLICY_NOT_CONFIGURED',None,
                         writes,())
    if not isinstance(policy,PlanningWorkflowPolicy):
        raise ValueError('PLANNING_WRITE_POLICY_INVALID')
    if policy.scope!=scope:
        raise ValueError('PLANNING_WRITE_POLICY_SCOPE_MISMATCH')
    if (not isinstance(expected_policy_digest,str)
            or expected_policy_digest!=policy.digest):
        raise ValueError('PLANNING_WRITE_POLICY_DIGEST_STALE')
    matched=set()
    for ordinal,item in enumerate(writes):
        decision=policy.evaluate(
            scope,item.coordinate,action=item.action,
            workflow_role=workflow_role,on_date=on_date,
            lock_state=item.lock_state,
            expected_digest=expected_policy_digest)
        matched.update(decision.matched_rule_ids)
        if not decision.allowed:
            raise ValueError(
                f'PLANNING_WRITE_DENIED:{ordinal}:{decision.reason_code}')
    return _evidence(True,True,'PLANNING_POLICY_ALLOW',policy,writes,
                     tuple(sorted(matched)))


def _evidence(configured: bool,allowed: bool,reason: str,
              policy: PlanningWorkflowPolicy|None,
              writes: Sequence[PlanningWrite],
              matched: tuple[str,...]) -> PlanningWriteGuardEvidence:
    payload={
        'configured':configured,'allowed':allowed,'reasonCode':reason,
        'policy':None if policy is None else {
            'policyId':policy.policy_id,
            'digest':policy.digest},
        'writes':[{'members':list(item.coordinate.members),
                   'action':item.action,'lockState':item.lock_state}
                  for item in writes],
        'matchedRuleIds':list(matched),
    }
    digest=sha256(json.dumps(payload,sort_keys=True,separators=(',',':'),
                             ensure_ascii=False).encode()).hexdigest()
    return PlanningWriteGuardEvidence(
        configured,allowed,reason,
        policy.policy_id if policy else None,
        policy.digest if policy else None,len(writes),digest,matched)
