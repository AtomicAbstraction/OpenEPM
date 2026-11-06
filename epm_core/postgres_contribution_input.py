"""Fixed PostgreSQL admission, publication and lineage for contribution inputs."""
from __future__ import annotations

import re
from decimal import Decimal

from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .consolidation_contribution_input import (
    COMPILER, FUNCTION, PLAN_DIGEST, ContributionInputPlan,
    compile_full_contribution_input)
from .dimensional_security_policy import AccessKind
from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_consolidation_full import enforce_consolidation_target_policy
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_jobs import (PostgresJobQueue, _canonical_digest,
                            _job_request_descriptor,
                            _verify_job_replay_authorization)
from .postgres_numeric_store import PostgresNumericFactStore


AUTH_FUNCTION='consolidation.full.contribute'
PUBLIC_FUNCTION='consolidation.full.contribute.certified'
_JOB=re.compile(r'[0-9a-f]{32}\Z')
_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')


def calculate_and_materialize(db, scope, plan: ContributionInputPlan,
                              *, generation_id: str, job_id: str,
                              source_coordinate_id: int,
                              target_coordinate_id: int,
                              source_commit_revision: int,
                              source_metadata_revision: int,
                              source_policy_revision: int,
                              published_revision: int) -> dict:
    """Materialize one already validated/fenced Full contribution.

    The caller owns authorization, job lease, application-state and publication
    pointer fences. This helper owns only exact arithmetic and immutable result
    lineage, making it reusable by a later fully fenced publisher.
    """
    doc = plan.document
    amount = db.execute('''SELECT epm.round_half_even(
        %s::numeric * %s::numeric,8) AS amount''',
        (doc['sourceAmount'], doc['coefficient']['decimal'])).fetchone()['amount']
    db.execute('''INSERT INTO epm.calculation_generation
        (workspace_id,application_id,generation_id,job_id,result_key,
         source_commit_revision,source_metadata_revision,
         source_policy_revision,function_name,factor,row_count,
         published_revision) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,1,%s)''',
        (scope.workspace_id,scope.application_id,generation_id,job_id,
         doc['resultKey'],source_commit_revision,source_metadata_revision,
         source_policy_revision,AUTH_FUNCTION,published_revision))
    db.execute('''INSERT INTO epm.calculation_result
        (workspace_id,application_id,generation_id,coordinate_id,
         source_amount,source_change_id,amount)
        VALUES (%s,%s,%s,%s,%s,%s,%s)''',
        (scope.workspace_id,scope.application_id,generation_id,
         target_coordinate_id,doc['sourceAmount'],doc['sourceChangeId'],amount))
    return {'generationId':generation_id,'resultKey':doc['resultKey'],
        'method':'Full','sourceProfile':doc['sourceProfile'],
        'sourceCoordinateId':source_coordinate_id,
        'targetCoordinateId':target_coordinate_id,
        'sourceMembers':doc['sourceMembers'],'targetMembers':doc['targetMembers'],
        'sourceAmount':doc['sourceAmount'],'coefficient':doc['coefficient'],
        'amount':format(amount,'.8f'),'sourceChangeId':doc['sourceChangeId'],
        'methodPreviewDigest':doc['methodPreviewDigest'],
        'policy':doc['policy'],'ownership':doc['ownership'],
        'programDigest':plan.digest,'accountingPolicyStatus':'Unreviewed',
        'engine':'postgres_exact_sql','rounding':'half-even-final-8',
        'relationshipId':doc['relationshipId'],
        'parentEntityId':next(value for axis,value in doc['targetMembers'].items()
                              if doc['sourceMembers'][axis]!=value),
        'childEntityId':next(value for axis,value in doc['sourceMembers'].items()
                             if doc['targetMembers'][axis]!=value),
        'pown':format(Decimal(doc['ownership']['POWN']['amount']),'.8f'),
        'effectivePcon':format(Decimal(doc['ownership']['PCON']['amount']),'.8f'),
        'pconFallback':False,
        'accountingStage':'pre_nci_untranslated_uneliminated'}


def _validate_inputs(db,scope,plan,state):
    doc=plan.document
    if state['commit_revision'] < doc['methodPreviewCommitRevision']:
        raise ValueError('STALE_CONTRIBUTION_METHOD_PREVIEW')
    draft=db.execute('''SELECT family,effective_from,effective_before,
        required_elections,source_refs,created_revision
        FROM epm.policy_pack_draft WHERE workspace_id=%s AND application_id=%s
        AND policy_id=%s AND version=%s AND effective_from<=%s
        AND effective_before>%s''',(scope.workspace_id,scope.application_id,
        doc['policy']['policyId'],doc['policy']['version'],doc['policy']['effectiveOn'],
        doc['policy']['effectiveOn'])).fetchone()
    if not draft:raise ValueError('CONTRIBUTION_POLICY_UNAVAILABLE')
    digest=_canonical_digest({'policyId':doc['policy']['policyId'],
        'version':doc['policy']['version'],'family':draft['family'],
        'effectiveFrom':draft['effective_from'].isoformat(),
        'effectiveBefore':draft['effective_before'].isoformat(),
        'requiredElections':draft['required_elections'],'sourceRefs':draft['source_refs'],
        'createdRevision':draft['created_revision']})
    if digest!=doc['policy']['digest']:raise ValueError('STALE_CONTRIBUTION_POLICY')
    rows=db.execute('''SELECT account_name,amount,change_id
        FROM epm.ownership_value_current WHERE workspace_id=%s
        AND application_id=%s AND relationship_id=%s
        AND scenario_member_id=%s AND year_member_id=%s AND period_member_id=%s
        AND present AND account_name IN ('POWN','PCON','PCTRL','Active','Method')''',
        (scope.workspace_id,scope.application_id,doc['relationshipId'],
         doc['scenarioId'],doc['yearId'],doc['periodId'])).fetchall()
    current={row['account_name']:(format(row['amount'],'f'),row['change_id']) for row in rows}
    expected={name:(value['amount'],value['changeId']) for name,value in doc['ownership'].items()}
    if current!=expected:raise ValueError('STALE_CONTRIBUTION_OWNERSHIP')
    placement=db.execute('''SELECT r.parent_member_id,r.child_member_id
        FROM epm.relationship r JOIN epm.dimension d
        ON d.workspace_id=r.workspace_id AND d.application_id=r.application_id
        AND d.dimension_id=r.dimension_id AND d.model_role='Entity'
        WHERE r.workspace_id=%s AND r.application_id=%s AND r.relationship_id=%s
        AND r.status='Active' AND d.status='Active' ''',(scope.workspace_id,
        scope.application_id,doc['relationshipId'])).fetchone()
    if not placement:raise ValueError('CONTRIBUTION_ENTITY_PLACEMENT_UNAVAILABLE')
    changed=[axis for axis in doc['sourceMembers']
             if doc['sourceMembers'][axis]!=doc['targetMembers'][axis]]
    if (len(changed)!=1 or doc['sourceMembers'][changed[0]]!=placement['child_member_id']
            or doc['targetMembers'][changed[0]]!=placement['parent_member_id']):
        raise ValueError('CONTRIBUTION_INPUT_GRAIN_INVALID')
    preview_ownership={name:{'amount':format(Decimal(value['amount']),'.8f'),
                              'changeId':value['changeId']}
                       for name,value in sorted(doc['ownership'].items())}
    preview_digest=_canonical_digest({'scope':[scope.workspace_id,scope.application_id],
        'context':{key:doc[key] for key in ('parentEntityId','scenarioId','yearId','periodId')}
            if 'parentEntityId' in doc else {'parentEntityId':placement['parent_member_id'],
                'scenarioId':doc['scenarioId'],'yearId':doc['yearId'],'periodId':doc['periodId']},
        'effectiveOn':doc['policy']['effectiveOn'],'policyId':doc['policy']['policyId'],
        'policyVersion':doc['policy']['version'],'policyDigest':doc['policy']['digest'],
        'revisions':{'metadata_revision':state['metadata_revision'],
                     'policy_revision':state['policy_revision'],
                     # The preview digest identifies the admitted method
                     # decision.  Later unrelated commits are safe only after
                     # the publisher rechecks every policy, ownership,
                     # placement, source and result-pointer dependency below.
                     'commit_revision':doc['methodPreviewCommitRevision']},
        'placements':[{'relationshipId':doc['relationshipId'],
            'childEntityId':placement['child_member_id'],'method':'Full',
            'methodCode':'1.00000000','controlConfirmed':True,
            'ownership':preview_ownership,'issues':[],'executionSupported':True}]})
    if preview_digest!=doc['methodPreviewDigest']:
        raise ValueError('STALE_CONTRIBUTION_METHOD_PREVIEW')
    source=Coordinate.from_mapping(doc['sourceMembers'])
    source_row=db.execute('''SELECT c.coordinate_id,c.members,n.amount,n.change_id
        FROM epm.coordinate c JOIN epm.numeric_cell_current n USING
        (workspace_id,application_id,coordinate_id)
        WHERE c.workspace_id=%s AND c.application_id=%s AND c.series_key=%s
        AND n.present''',(scope.workspace_id,scope.application_id,source.series_key)).fetchone()
    if (not source_row or source_row['members']!=doc['sourceMembers']
            or source_row['change_id']!=doc['sourceChangeId']
            or format(source_row['amount'],'f')!=doc['sourceAmount']):
        raise ValueError('STALE_CONTRIBUTION_SOURCE')
    pointer=db.execute('''SELECT published_revision FROM epm.calculation_publication
        WHERE workspace_id=%s AND application_id=%s AND result_key=%s''',
        (scope.workspace_id,scope.application_id,doc['resultKey'])).fetchone()
    if (pointer['published_revision'] if pointer else 0)!=doc['expectedPublicationRevision']:
        raise ValueError('STALE_PUBLICATION_POINTER')
    return source_row


def enforce_contribution_input_dimensional_security(
        db, identity: VerifiedIdentity, scope: ApplicationScope,
        plan: ContributionInputPlan) -> None:
    """Authorize the exact certified child source and parent output.

    This boundary is intentionally local to the certified Full contribution
    route.  Equity and Proportional publishers have different contracts and
    must qualify their own complete source and target sets.
    """
    authorize_coordinates(db, identity, scope, (
        Coordinate.from_mapping(plan.document['sourceMembers']),),
        kind=AccessKind.READ)
    authorize_coordinates(db, identity, scope, (
        Coordinate.from_mapping(plan.document['targetMembers']),),
        kind=AccessKind.WRITE)


class PostgresContributionInputPrivate:
    def __init__(self,dsn,*,identity):
        if not isinstance(identity,VerifiedIdentity):raise ValueError('A verified identity is required')
        self.dsn,self.identity=dsn,identity

    def admit(self,scope,document,*,idempotency_key):
        plan=compile_full_contribution_input(document)
        if not isinstance(idempotency_key,str) or not _KEY.fullmatch(idempotency_key):
            raise ValueError('Idempotency key needs 8–128 safe characters')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state=db.execute('''SELECT s.metadata_revision,s.data_revision,
                    s.policy_revision,s.commit_revision,s.processing_mode,
                    a.status AS application_status FROM epm.application_state s
                    JOIN epm.application a USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s FOR SHARE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if not state or state['application_status']!='Active' or state['processing_mode']!='Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write',function=AUTH_FUNCTION)
                previous=db.execute('''SELECT job_id,status,request_digest,
                    expected_metadata_revision,expected_data_revision,
                    expected_policy_revision,normalized_program,
                    compiler_version,plan_digest,function_name,verified_groups,
                    authorization_scope_digest
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',
                    (scope.workspace_id,scope.application_id,self.identity.issuer,
                     self.identity.subject_id,idempotency_key)).fetchone()
                if previous:
                    auth_scope=_verify_job_replay_authorization(db,scope,
                        self.identity,previous,access=access,
                        function_name=FUNCTION,
                        authorization_function=AUTH_FUNCTION)
                    descriptor=_job_request_descriptor(scope,self.identity,
                      function_name=FUNCTION,program_digest=plan.digest,
                      compiler_version=COMPILER,plan_digest=PLAN_DIGEST,
                      revisions=(previous['expected_metadata_revision'],
                        previous['expected_data_revision'],previous['expected_policy_revision']),
                      resource_class='short',dependencies=(),
                      authorization_scope_digest=auth_scope,
                      authorization_function=AUTH_FUNCTION)
                    if (previous['function_name']!=FUNCTION
                            or previous['compiler_version']!=COMPILER
                            or previous['plan_digest']!=PLAN_DIGEST
                            or previous['normalized_program']!=plan.document
                            or previous['request_digest']!=_canonical_digest(descriptor)):
                        raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT')
                    return {'jobId':previous['job_id'],'status':previous['status'],
                            'duplicate':True}
                _validate_inputs(db,scope,plan,state)
                enforce_contribution_input_dimensional_security(
                    db,self.identity,scope,plan)
                revisions=tuple(state[k] for k in ('metadata_revision','data_revision','policy_revision'))
        return PostgresJobQueue(self.dsn,identity=self.identity).submit(scope,
            idempotency_key=idempotency_key,function_name=FUNCTION,
            normalized_program=plan.document,compiler_version=COMPILER,
            plan_digest=PLAN_DIGEST,expected_metadata_revision=revisions[0],
            expected_data_revision=revisions[1],expected_policy_revision=revisions[2],
            resource_class='short',authorization_function=AUTH_FUNCTION)

    def inspect(self,scope,document):
        plan=compile_full_contribution_input(document)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state=db.execute('''SELECT s.metadata_revision,s.data_revision,
                    s.policy_revision,s.commit_revision,s.processing_mode,
                    a.status AS application_status FROM epm.application_state s
                    JOIN epm.application a USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s FOR SHARE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if not state or state['application_status']!='Active' or state['processing_mode']!='Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'write',
                    function=PUBLIC_FUNCTION)
                source=_validate_inputs(db,scope,plan,state)
                enforce_contribution_input_dimensional_security(
                    db,self.identity,scope,plan)
                return {'plan':plan,'sourceCoordinateId':source['coordinate_id'],
                    'revisionVector':{key:state[key] for key in
                      ('metadata_revision','data_revision','policy_revision')},
                    'commitRevision':state['commit_revision']}

    def publish(self,claim):
        if (not isinstance(claim,dict) or not _JOB.fullmatch(claim.get('job_id',''))
                or type(claim.get('claim_generation')) is not int
                or not isinstance(claim.get('claimant'),str)):
            raise ValueError('INVALID_WORKER_CLAIM')
        scope=ApplicationScope(claim['workspace_id'],claim['application_id'])
        # Build a no-effect candidate without the application mutation row.
        # The final transaction repeats every authoritative dependency before
        # inserting any generation/result/receipt state.
        with connect_postgres(self.dsn,row_factory=dict_row) as before:
            with before.transaction():
                configure_statement_timeout(before,5000)
                PostgresNumericFactStore._set_scope(before,scope)
                PostgresAccessChecker.lock_workspace(before,scope.workspace_id)
                state_before=before.execute('''SELECT s.metadata_revision,
                    s.data_revision,s.policy_revision,s.commit_revision,
                    s.processing_mode,a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING(workspace_id,application_id) WHERE s.workspace_id=%s
                    AND s.application_id=%s''',(scope.workspace_id,
                    scope.application_id)).fetchone()
                access_before=PostgresAccessChecker.check_in_transaction(
                    before,self.identity,scope,'write')
                PostgresAccessChecker.require_capability_in_transaction(
                    before,scope,AUTH_FUNCTION,lock_state=False)
                job_before=before.execute('''SELECT * FROM epm.job
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',
                    (scope.workspace_id,scope.application_id,
                     claim['job_id'])).fetchone()
                receipt=before.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',(
                    scope.workspace_id,scope.application_id,
                    claim['job_id'])).fetchone()
                if receipt:
                    if (job_before is None
                            or receipt['command_digest']!=job_before['program_digest']
                            or receipt['actor_id']!=job_before['subject_id']):
                        raise ValueError('CONTRIBUTION_RECEIPT_CONFLICT')
                    return receipt['result']
                if (state_before is None
                        or state_before['application_status']!='Active'
                        or state_before['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (job_before is None
                        or job_before['issuer']!=self.identity.issuer
                        or job_before['subject_id']!=self.identity.subject_id
                        or job_before['status']!='running'
                        or job_before['claim_generation']!=claim['claim_generation']
                        or job_before['claimant']!=claim['claimant']
                        or not before.execute(
                          'SELECT %s::timestamptz>clock_timestamp() ok',(
                          job_before['lease_until'],)).fetchone()['ok']):
                    raise ValueError('STALE_WORKER_FENCE')
                if (job_before['function_name']!=FUNCTION
                        or job_before['compiler_version']!=COMPILER
                        or job_before['plan_digest']!=PLAN_DIGEST
                        or job_before['program_digest']!=_canonical_digest(
                            job_before['normalized_program'])):
                    raise ValueError('UNSUPPORTED_CONTRIBUTION_INPUT_JOB')
                if any(state_before[k]!=job_before['expected_'+k] for k in
                       ('metadata_revision','data_revision','policy_revision')):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                plan_before=compile_full_contribution_input(
                    job_before['normalized_program'])
                source_before=_validate_inputs(
                    before,scope,plan_before,state_before)
                enforce_contribution_input_dimensional_security(
                    before,self.identity,scope,plan_before)
                target_before=Coordinate.from_mapping(
                    plan_before.document['targetMembers'])
                policy_before=enforce_consolidation_target_policy(
                    before,scope,target_before,access_before.role)
                amount_before=before.execute('''SELECT epm.round_half_even(
                    %s::numeric * %s::numeric,8) amount''',(
                    plan_before.document['sourceAmount'],
                    plan_before.document['coefficient']['decimal']
                    )).fetchone()['amount']
                candidate_digest=_canonical_digest({'plan':plan_before.document,
                    'sourceCoordinateId':source_before['coordinate_id'],
                    'targetMembers':dict(target_before.members),
                    'amount':format(amount_before,'.8f'),
                    'planningPolicy':policy_before})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000);PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state=db.execute('''SELECT s.metadata_revision,s.data_revision,
                    s.policy_revision,s.commit_revision,s.processing_mode,
                    a.status AS application_status FROM epm.application_state s
                    JOIN epm.application a USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write',function=AUTH_FUNCTION)
                job=db.execute('''SELECT * FROM epm.job WHERE workspace_id=%s
                    AND application_id=%s AND job_id=%s FOR UPDATE''',
                    (scope.workspace_id,scope.application_id,claim['job_id'])).fetchone()
                receipt=db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s AND application_id=%s
                    AND operation_id=%s''',(scope.workspace_id,scope.application_id,claim['job_id'])).fetchone()
                if receipt:
                    if (job is None or receipt['command_digest']!=job['program_digest']
                            or receipt['actor_id']!=job['subject_id']):
                        raise ValueError('CONTRIBUTION_RECEIPT_CONFLICT')
                    return receipt['result']
                if job is None:
                    raise ValueError('STALE_WORKER_FENCE')
                unexpired=db.execute('SELECT %s::timestamptz>clock_timestamp() ok',
                    (job['lease_until'],)).fetchone()['ok']
                if (job['status']!='running' or job['claim_generation']!=claim['claim_generation']
                        or job['claimant']!=claim['claimant'] or not unexpired):
                    raise ValueError('STALE_WORKER_FENCE')
                if (job['function_name']!=FUNCTION or job['compiler_version']!=COMPILER
                        or job['plan_digest']!=PLAN_DIGEST
                        or job['program_digest']!=_canonical_digest(job['normalized_program'])):
                    raise ValueError('UNSUPPORTED_CONTRIBUTION_INPUT_JOB')
                immutable=('issuer','subject_id','function_name',
                    'normalized_program','program_digest','compiler_version',
                    'plan_digest','expected_metadata_revision',
                    'expected_data_revision','expected_policy_revision')
                if any(job[key]!=job_before[key] for key in immutable):
                    raise ValueError('STALE_WORKER_FENCE')
                plan=compile_full_contribution_input(job['normalized_program'])
                if (state['application_status']!='Active' or state['processing_mode']!='Active'
                        or any(state[k]!=job['expected_'+k] for k in
                               ('metadata_revision','data_revision','policy_revision'))):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                source=_validate_inputs(db,scope,plan,state)
                enforce_contribution_input_dimensional_security(
                    db,self.identity,scope,plan)
                target=Coordinate.from_mapping(plan.document['targetMembers'])
                policy=enforce_consolidation_target_policy(db,scope,target,
                    access.role)
                amount=db.execute('''SELECT epm.round_half_even(
                    %s::numeric * %s::numeric,8) amount''',(
                    plan.document['sourceAmount'],
                    plan.document['coefficient']['decimal']
                    )).fetchone()['amount']
                if _canonical_digest({'plan':plan.document,
                        'sourceCoordinateId':source['coordinate_id'],
                        'targetMembers':dict(target.members),
                        'amount':format(amount,'.8f'),
                        'planningPolicy':policy})!=candidate_digest:
                    raise ValueError('CONTRIBUTION_INPUT_CANDIDATE_CHANGED')
                db.execute('''INSERT INTO epm.coordinate(workspace_id,application_id,series_key,members)
                    VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING''',(scope.workspace_id,
                    scope.application_id,target.series_key,Jsonb(dict(target.members))))
                target_row=db.execute('''SELECT coordinate_id,members FROM epm.coordinate
                    WHERE workspace_id=%s AND application_id=%s AND series_key=%s''',
                    (scope.workspace_id,scope.application_id,target.series_key)).fetchone()
                if target_row['members']!=dict(target.members):raise ValueError('COORDINATE_HASH_COLLISION')
                revision=state['commit_revision']+1
                result=calculate_and_materialize(db,scope,plan,generation_id=claim['job_id'],
                    job_id=claim['job_id'],source_coordinate_id=source['coordinate_id'],
                    target_coordinate_id=target_row['coordinate_id'],
                    source_commit_revision=state['commit_revision'],
                    source_metadata_revision=state['metadata_revision'],
                    source_policy_revision=state['policy_revision'],published_revision=revision)
                result.update({'committedRevision':revision,'planningPolicy':policy})
                db.execute('''INSERT INTO epm.calculation_publication(workspace_id,application_id,
                    result_key,generation_id,published_revision) VALUES(%s,%s,%s,%s,%s)
                    ON CONFLICT(workspace_id,application_id,result_key) DO UPDATE SET
                    generation_id=EXCLUDED.generation_id,published_revision=EXCLUDED.published_revision,
                    updated_at=transaction_timestamp()''',(scope.workspace_id,scope.application_id,
                    plan.document['resultKey'],claim['job_id'],revision))
                db.execute('''UPDATE epm.application_state SET commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',(revision,scope.workspace_id,scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,
                    operation_id,command_digest,actor_id,committed_revision,result)
                    VALUES(%s,%s,%s,%s,%s,%s,%s)''',(scope.workspace_id,scope.application_id,
                    claim['job_id'],job['program_digest'],job['subject_id'],revision,Jsonb(result)))
                changed=db.execute('''UPDATE epm.job SET status='published',receipt_revision=%s,result=%s,
                    claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s
                    AND status='running' AND claim_generation=%s AND claimant=%s
                    AND lease_until>clock_timestamp()''',(revision,Jsonb(result),
                    scope.workspace_id,scope.application_id,claim['job_id'],
                    claim['claim_generation'],claim['claimant'])).rowcount
                if changed!=1:raise ValueError('STALE_WORKER_FENCE')
                return result
