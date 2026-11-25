"""In-transaction loader and evaluator for active planning write policy."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope,Coordinate
from .planning_workflow_policy import PlanningWorkflowPolicy, compile_planning_workflow_policy
from .planning_write_guard import MAX_GUARDED_WRITES, WORKFLOW_ROLE_UNBOUND, PlanningWrite, guard_planning_writes
from .postgres_planning_workflow_level_selector import validate_level_selector_pins


@dataclass(frozen=True, slots=True)
class PlanningWriteContext:
    """Verified policy, date and locks for the selected coordinates in one transaction."""
    scope: ApplicationScope
    policy: PlanningWorkflowPolicy | None
    state_token: str | None
    group_policy: bool
    on_date: date
    lock_states: dict

    def evaluate(self, writes, *, workflow_role, matched_write_rows=(),
                 coordinate_duties=None, ordered_actions=False):
        guarded = tuple(PlanningWrite(point, action, self.lock_states[point]) for point, action in writes)
        for ordinal, item in enumerate(guarded):
            if item.lock_state != 'Open':
                raise ValueError(f'PLANNING_WRITE_DENIED:{ordinal}:PLANNING_INTERSECTION_LOCKED')
        if self.group_policy and coordinate_duties is None:
            # Access reviewers already evaluated the subject's complete write
            # assignments on this exact point, under their review authority.
            if len(guarded) == 1:
                duties = frozenset(d for row in matched_write_rows if row.action == 'facts.write'
                                   for d in row.workflow_duties)
                coordinate_duties = {guarded[0].coordinate: duties}
            else:
                coordinate_duties = {}
        evidence = guard_planning_writes(scope=self.scope, policy=self.policy, writes=guarded,
            workflow_role=workflow_role, on_date=self.on_date, coordinate_duties=coordinate_duties,
            ordered_actions=ordered_actions, expected_policy_digest=self.policy.digest if self.policy else None)
        return _evidence(evidence, state_token=self.state_token, policy=self.policy)


def load_planning_write_context(db, scope: ApplicationScope, coordinates) -> PlanningWriteContext:
    if not 1 <= len(coordinates) <= MAX_GUARDED_WRITES:
        raise ValueError('PLANNING_WRITE_BATCH_INVALID')
    row = db.execute('''SELECT p.policy_id,p.state_token,p.definition,p.canonical_digest,
        a.authorization_model,CURRENT_DATE AS evaluation_date FROM epm.cube_write_policy_definition p
        JOIN epm.application a USING(workspace_id,application_id)
        WHERE p.workspace_id=%s AND p.application_id=%s AND p.status='Active' ''',
        (scope.workspace_id,scope.application_id)).fetchone()
    locks = _lock_states(db, scope, coordinates)
    states = {point: locks[index] for index, point in enumerate(coordinates)}
    if row is None:
        today = db.execute('SELECT CURRENT_DATE AS evaluation_date').fetchone()['evaluation_date']
        return PlanningWriteContext(scope, None, None, False, today, states)
    try:
        policy = compile_planning_workflow_policy(row['definition'])
    except (TypeError, ValueError) as error:
        raise ValueError('PLANNING_WRITE_ACTIVE_POLICY_INVALID') from error
    if (policy.scope != scope or policy.policy_id != row['policy_id'] or policy.digest != row['canonical_digest']):
        raise ValueError('PLANNING_WRITE_ACTIVE_POLICY_DIGEST_MISMATCH')
    validate_level_selector_pins(db, scope, policy)
    return PlanningWriteContext(scope, policy, row['state_token'], row['authorization_model'] == 'group_assignments',
                                row['evaluation_date'], states)


def enforce_active_planning_policy(db, scope: ApplicationScope, *, writes: tuple[tuple[Coordinate,str],...],
                                   workflow_role: str, ordered_actions: bool=False, identity=None,
                                   matched_write_rows=()) -> dict:
    """Recheck the actor's complete write assignments and the policy on the publication cut."""
    points = tuple(point for point, _ in writes)
    context = load_planning_write_context(db, scope, points)
    duties = None
    if context.group_policy and identity is not None and all(state == 'Open' for state in context.lock_states.values()):
        from .dimensional_security_policy import AccessKind
        from .postgres_dimensional_security import PostgresDimensionalSecurityResolver
        duties = {}
        unique_points = tuple(context.lock_states)
        for offset in range(0, len(unique_points), 1000):
            batch = unique_points[offset:offset + 1000]
            resolved = PostgresDimensionalSecurityResolver.resolve_many_active_in_transaction(
                db, identity, scope, kind=AccessKind.WRITE, coordinates=tuple(dict(point.members) for point in batch))
            if resolved is None or len(resolved) != len(batch):
                raise ValueError(WORKFLOW_ROLE_UNBOUND)
            duties.update((point, frozenset(item.workflow_duties)) for point, item in zip(batch, resolved))
    return context.evaluate(writes, workflow_role=workflow_role, matched_write_rows=matched_write_rows,
                            coordinate_duties=duties, ordered_actions=ordered_actions)


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


def planning_write_evidence_schema() -> dict:
    """Describe successful public policy evidence, not permission to write.

    The transaction and pure policy owners above still decide the outcome.
    Version-two level resolutions disclose counts and pins, never resolved
    member lists. Return fresh schema objects for each composing catalogue.
    """
    from .planning_write_guard import MAX_GUARDED_WRITES
    from .planning_workflow_policy import MAX_MEMBERS_PER_SELECTOR, MAX_RULES

    identifier = {'type': 'string',
        'pattern': r'^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}(?![\s\S])'}
    digest = {'type': 'string', 'pattern': r'^[0-9a-f]{64}(?![\s\S])'}
    revision = {'type': 'integer', 'minimum': 0}
    level = {
        'dimensionId': identifier, 'hierarchyStateToken': digest,
        'rootMemberId': identifier,
        'depth': {'type': 'integer', 'minimum': 0, 'maximum': 1000},
        'metadataRevision': revision, 'schemaEpoch': revision,
        'memberCount': {'type': 'integer', 'minimum': 1,
                        'maximum': MAX_MEMBERS_PER_SELECTOR},
        'resolutionDigest': digest}
    fields = {
        'configured': {'type': 'boolean'}, 'allowed': {'const': True},
        'reasonCode': {'enum': ['PLANNING_POLICY_NOT_CONFIGURED',
                              'PLANNING_POLICY_ALLOW']},
        'policyId': {'anyOf': [identifier, {'type': 'null'}]},
        'policyDigest': {'anyOf': [digest, {'type': 'null'}]},
        'policyStateToken': {'anyOf': [digest, {'type': 'null'}]},
        'writeCount': {'type': 'integer', 'minimum': 1,
                       'maximum': MAX_GUARDED_WRITES},
        'decisionDigest': digest,
        'matchedRuleIds': {'type': 'array', 'items': identifier,
                           'maxItems': MAX_RULES, 'uniqueItems': True},
        'levelResolutions': {'type': 'array', 'maxItems': MAX_RULES,
            'items': {'type': 'object', 'properties': level,
                      'required': list(level), 'additionalProperties': False}}}
    return {'$schema': 'https://json-schema.org/draft/2020-12/schema',
        'type': 'object', 'properties': fields,
        'required': [key for key in fields if key != 'levelResolutions'],
        'additionalProperties': False}


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
