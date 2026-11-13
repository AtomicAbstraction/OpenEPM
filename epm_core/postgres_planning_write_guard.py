"""In-transaction loader and evaluator for active planning write policy."""
from __future__ import annotations

from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope,Coordinate
from .planning_workflow_policy import compile_planning_workflow_policy
from .planning_write_guard import PlanningWrite,guard_planning_writes
from .postgres_planning_workflow_level_selector import validate_level_selector_pins


def enforce_active_planning_policy(db,scope: ApplicationScope,*,
                                   writes: tuple[tuple[Coordinate,str],...],
                                   workflow_role: str,
                                   ordered_actions: bool=False) -> dict:
    """Evaluate a publication unit using the caller's existing transaction.

    The caller already owns the application-state publication lock.  Planning
    policy mutation takes that same lock, so the active state cannot change
    between this read and the fact commit.
    """
    row=db.execute('''SELECT policy_id,state_token,definition,canonical_digest,
        CURRENT_DATE AS evaluation_date FROM epm.cube_write_policy_definition
        WHERE workspace_id=%s AND application_id=%s AND status='Active' ''',
        (scope.workspace_id,scope.application_id)).fetchone()
    lock_states=_lock_states(db,scope,tuple(point for point,_ in writes))
    guarded=tuple(PlanningWrite(point,action,lock_states[index])
                  for index,(point,action) in enumerate(writes))
    for ordinal,item in enumerate(guarded):
        if item.lock_state!='Open':
            raise ValueError(
                f'PLANNING_WRITE_DENIED:{ordinal}:'
                'PLANNING_INTERSECTION_LOCKED')
    if row is None:
        evidence=guard_planning_writes(
            scope=scope,policy=None,
            writes=guarded,
            workflow_role=workflow_role,
            ordered_actions=ordered_actions,
            on_date=db.execute('SELECT CURRENT_DATE AS evaluation_date')
                      .fetchone()['evaluation_date'])
        return _evidence(evidence)
    try:
        policy=compile_planning_workflow_policy(row['definition'])
    except (TypeError,ValueError) as error:
        raise ValueError('PLANNING_WRITE_ACTIVE_POLICY_INVALID') from error
    if (policy.scope!=scope
            or policy.policy_id!=row['policy_id']
            or policy.digest!=row['canonical_digest']):
        raise ValueError('PLANNING_WRITE_ACTIVE_POLICY_DIGEST_MISMATCH')
    validate_level_selector_pins(db,scope,policy)
    evidence=guard_planning_writes(
        scope=scope,policy=policy,writes=guarded,
        workflow_role=workflow_role,on_date=row['evaluation_date'],
        expected_policy_digest=policy.digest,
        ordered_actions=ordered_actions)

    return _evidence(evidence,state_token=row['state_token'],policy=policy)


def _lock_states(db,scope,coordinates: tuple[Coordinate,...]) -> dict[int,str]:
    payload=[{'ordinal':index,'members':dict(point.members)}
             for index,point in enumerate(coordinates)]
    rows=db.execute('''WITH input AS (
        SELECT ordinal,members FROM jsonb_to_recordset(%s::jsonb)
        AS item(ordinal integer,members jsonb))
        SELECT input.ordinal,
          CASE max(CASE
            WHEN s.status='Approved' THEN 3
            WHEN s.status='Submitted' THEN 2
            WHEN l.status='Locked' THEN 1 ELSE 0 END)
          WHEN 3 THEN 'Approved' WHEN 2 THEN 'Submitted'
          WHEN 1 THEN 'Locked' ELSE 'Open' END AS lock_state
        FROM input LEFT JOIN epm.cube_write_scope_lock l
          ON l.workspace_id=%s AND l.application_id=%s
          AND l.status='Locked'
          AND (l.scope_all OR input.members @> l.scope_members)
        LEFT JOIN epm.cube_write_scope_submission s
          ON s.workspace_id=l.workspace_id
          AND s.application_id=l.application_id AND s.lock_id=l.lock_id
        GROUP BY input.ordinal ORDER BY input.ordinal''',
        (Jsonb(payload),scope.workspace_id,scope.application_id)).fetchall()
    states={row['ordinal']:row['lock_state'] for row in rows}
    if set(states)!=set(range(len(coordinates))):
        raise ValueError('PLANNING_WRITE_LOCK_STATE_INCOMPLETE')
    return states


def _evidence(evidence,*,state_token: str|None=None,policy=None) -> dict:
    result={'configured':evidence.configured,'allowed':evidence.allowed,
            'reasonCode':evidence.reason_code,
            'policyId':evidence.policy_id,
            'policyDigest':evidence.policy_digest,
            'policyStateToken':state_token,
            'writeCount':evidence.write_count,
            'decisionDigest':evidence.decision_digest,
            'matchedRuleIds':list(evidence.matched_rule_ids)}
    if policy is not None and policy.format_version==2:
        result['levelResolutions']=[{
            'dimensionId':item.dimension_id,
            'hierarchyStateToken':item.hierarchy_state_token,
            'rootMemberId':item.root_member_id,'depth':item.depth,
            'metadataRevision':item.metadata_revision,
            'schemaEpoch':item.schema_epoch,
            'memberCount':len(item.resolved_members),
            'resolutionDigest':item.resolution_digest}
            for item in (rule.level_selector for rule in policy.rules)
            if item is not None]
    return result


class PlanningReceiptEvidenceConnection:
    """Narrow connection facade that enriches the batch's initial receipt.

    Runtime has INSERT but deliberately lacks general UPDATE authority on
    immutable receipts.  The existing relational batches own receipt INSERT;
    this facade adds server-produced policy evidence to that same statement.
    """
    def __init__(self,db,evidence: dict):
        self._db=db
        self._evidence=evidence

    def execute(self,query,params=None):
        if ('INSERT INTO epm.operation_receipt' in query
                and isinstance(params,(tuple,list)) and params
                and isinstance(params[-1],Jsonb)):
            result=params[-1].obj
            if not isinstance(result,dict) or 'planningPolicy' in result:
                raise ValueError('PLANNING_RECEIPT_RESULT_INVALID')
            params=(*params[:-1],Jsonb({**result,
                'planningPolicy':self._evidence}))
        return self._db.execute(query,params)

    def __getattr__(self,name):
        return getattr(self._db,name)
