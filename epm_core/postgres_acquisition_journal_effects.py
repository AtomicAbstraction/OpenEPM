"""Governed acquisition source resolution and atomic worker effects.

V2 preview/admission reuse this validator; only the fixed worker publishes.
Raw/manual data stay separate from the same-functional-currency offset layer.
"""
from decimal import Decimal, localcontext
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate, NumericCell
from .dimensional_security_policy import AccessKind
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_acquisition_journal import (
    FUNCTION, COMPILER, SINGLE, STEP, _STEP_FIELDS, ACCOUNT_TYPES, compile_program, balanced_entries)
from .postgres_acquisition_nci import (_program as _single_program, _step_program,
    _evaluate_in_transaction, _evaluate_step_in_transaction)
from .postgres_jobs import _canonical_digest
from .postgres_manual_journal import PostgresManualJournal
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_planning_write_guard import enforce_active_planning_policy
from .postgres_policy_activation import resolve_in_transaction

PLAN_DIGEST = _canonical_digest({'function':FUNCTION,'compiler':COMPILER,
    'effect':'same-functional-currency acquisition investment offset',
    'sources':'raw pinned signed balances, no current adjustments',
    'publication':'atomic sealed separate layer'})


def _point(db, scope, members, axes):
    """Read-only coordinate check; preview must not create coordinates."""
    if set(members)!=axes:
        raise ValueError('ACQUISITION_COORDINATE_GRAIN_MISMATCH')
    coordinate=Coordinate.from_mapping(members)
    if db.execute('''SELECT 1 FROM jsonb_each_text(%s::jsonb) i
        LEFT JOIN epm.member m ON m.workspace_id=%s AND m.application_id=%s
        AND m.dimension_id=i.key AND m.member_id=i.value AND m.status='Active'
        WHERE m.member_id IS NULL LIMIT 1''',
        (Jsonb(members),scope.workspace_id,scope.application_id)).fetchone():
        raise ValueError('ACQUISITION_COORDINATE_MEMBER_UNAVAILABLE')
    point=db.execute('''SELECT coordinate_id,members FROM epm.coordinate
        WHERE workspace_id=%s AND application_id=%s AND series_key=%s''',
        (scope.workspace_id,scope.application_id,coordinate.series_key)).fetchone()
    if point and point['members']!=members:
        raise ValueError('COORDINATE_HASH_COLLISION')
    return coordinate,point


def _raw(db,scope,members,axes,change_id):
    coordinate,point=_point(db,scope,members,axes)
    cell=(None if point is None else db.execute('''SELECT present,amount,change_id,last_revision
        FROM epm.numeric_cell_current WHERE workspace_id=%s AND application_id=%s
        AND coordinate_id=%s''',(scope.workspace_id,scope.application_id,
            point['coordinate_id'])).fetchone())
    if cell is None or not cell['present']:
        raise ValueError('ACQUISITION_RAW_SOURCE_REQUIRED')
    if db.execute('''SELECT 1 FROM epm.text_cell_current WHERE workspace_id=%s
        AND application_id=%s AND coordinate_id=%s AND present UNION ALL
        SELECT 1 FROM epm.line_detail_current WHERE workspace_id=%s
        AND application_id=%s AND coordinate_id=%s LIMIT 1''',
        (scope.workspace_id,scope.application_id,point['coordinate_id'])*2).fetchone():
        raise ValueError('ACQUISITION_NUMERIC_SOURCE_ONLY')
    if cell['change_id']!=change_id:
        raise ValueError('ACQUISITION_SOURCE_CHANGED')
    return {'members':members,'coordinateId':point['coordinate_id'],
        'amount':format(cell['amount'],'.8f'),'changeId':cell['change_id'],
        'lastRevision':cell['last_revision']}


def validate_in_transaction(db,scope,program,state):
    """Caller holds the application-state SHARE/UPDATE fence and verified grant.

    This function performs SELECTs only, including target-coordinate validation.
    It resolves operational facts rather than copying reviewed fixture amounts.
    """
    program=compile_program(program)
    args=program['arguments']
    keys=(scope.workspace_id,scope.application_id)
    dimensions=db.execute('''SELECT dimension_id,model_role FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active' ''',keys).fetchall()
    roles={}; axes=set()
    for row in dimensions:
        role=row['model_role']
        if role!='Currency': axes.add(row['dimension_id'])
        if role and role!='Custom':
            if role in roles: raise ValueError('ACQUISITION_MODEL_ROLE_AMBIGUOUS')
            roles[role]=row['dimension_id']
    if not {'Scenario','Year','Period','Entity','Account','Currency'}<=roles.keys():
        raise ValueError('ACQUISITION_FINANCIAL_ROLES_REQUIRED')
    if 'Method' in roles:
        raise ValueError('ACQUISITION_METHOD_AXIS_UNSUPPORTED')
    target=args['targetMembers']
    if set(target)!=axes-{roles['Account']}:
        raise ValueError('ACQUISITION_TARGET_GRAIN_INVALID')
    if 'Value' in roles or 'View' in roles:
        settings=state.get('currency_settings')
        if (not {'Value','View'}<=roles.keys() or not settings
                or settings.get('validatedMetadataRevision')!=state['metadata_revision']
                or target[roles['Value']]!=settings.get('entityCurrencyValueMemberId')
                or target[roles['View']]!=settings.get('ytdViewMemberId')):
            raise ValueError('ACQUISITION_ENTITY_CURRENCY_YTD_REQUIRED')
    parent=target[roles['Entity']]
    placement=db.execute('''SELECT child_member_id,hierarchy_id FROM epm.relationship
        WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s
        AND relationship_id=%s AND parent_member_id=%s AND status='Active'  AND EXISTS(SELECT 1 FROM epm.hierarchy_definition hierarchy
          WHERE hierarchy.workspace_id=relationship.workspace_id AND hierarchy.application_id=relationship.application_id
            AND hierarchy.dimension_id=relationship.dimension_id AND hierarchy.hierarchy_id=relationship.hierarchy_id
            AND hierarchy.status='Active') ''',
        (*keys,roles['Entity'],args['relationshipId'],parent)).fetchone()
    if placement is None: raise ValueError('ACQUISITION_PARENT_PLACEMENT_MISMATCH')
    child=placement['child_member_id']
    if db.execute('''SELECT count(*) AS count FROM epm.relationship
        WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s
        AND parent_member_id=%s AND child_member_id=%s AND hierarchy_id=%s AND status='Active' ''',
        (*keys,roles['Entity'],parent,child,placement['hierarchy_id'])).fetchone()['count']!=1:
        raise ValueError('ACQUISITION_ENTITY_PLACEMENT_AMBIGUOUS')
    currency=args['currencyMemberId']
    if not db.execute('''SELECT 1 FROM epm.member WHERE workspace_id=%s AND application_id=%s
        AND dimension_id=%s AND member_id=%s AND status='Active' ''',
        (*keys,roles['Currency'],currency)).fetchone():
        raise ValueError('ACQUISITION_CURRENCY_UNAVAILABLE')
    for entity in (parent,child):
        row=db.execute('''SELECT entity_default_currency_member_id FROM epm.member
            WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s
            AND member_id=%s AND status='Active' ''',(*keys,roles['Entity'],entity)).fetchone()
        if row is None or row['entity_default_currency_member_id']!=currency:
            raise ValueError('ACQUISITION_SAME_FUNCTIONAL_CURRENCY_REQUIRED')
    governed=resolve_in_transaction(db,scope,{
        **{key:args[key] for key in ('policyId','policyStateToken','candidateFunction',
                                     'selections','effectiveOn')},
        'expectedPolicyRevision':state['policy_revision']},state)
    if governed['activationId']!=args['activationId']:
        raise ValueError('ACQUISITION_ACTIVATION_CHANGED')
    if db.execute('''SELECT 1 FROM epm.acquisition_journal WHERE workspace_id=%s
        AND application_id=%s AND acquisition_key=%s AND reversal_of IS NULL''',
        (*keys,args['acquisitionKey'])).fetchone():
        raise ValueError('ACQUISITION_ALREADY_POSTED')
    inputs={}; amounts={}
    baseline={key:value for key,value in target.items() if key!=roles['Entity']}
    for field,source in args['sources'].items():
        members=source['members']
        entity=child if field in ('identifiableNetAssets','nciFairValue') else parent
        if (members.get(roles['Entity'])!=entity
                or {key:value for key,value in members.items()
                    if key not in (roles['Entity'],roles['Account'])}!=baseline):
            raise ValueError('ACQUISITION_SOURCE_CONTEXT_MISMATCH')
        if field=='identifiableNetAssets' and members.get(roles['Account'])!=args['accounts']['netAssetsOffset']:
            raise ValueError('ACQUISITION_NET_ASSETS_ACCOUNT_MISMATCH')
        inputs[field]=_raw(db,scope,members,axes,source['expectedChangeId'])
        account=db.execute('''SELECT financial_account_type FROM epm.member
            WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s AND member_id=%s''',
            (*keys,roles['Account'],members[roles['Account']])).fetchone()
        if not account or account['financial_account_type'] not in (
                'ASSET','LIABILITY','BALANCE','BALANCERECURRING','REVENUE','EXPENSE','FLOW'):
            raise ValueError('ACQUISITION_SOURCE_ACCOUNT_TYPE_INVALID')
        value=Decimal(inputs[field]['amount'])
        amounts[field]=value.copy_negate() if field=='identifiableNetAssets' else value
    PostgresManualJournal._validate_financial_context(db,scope,[
        (Coordinate.from_mapping(row['members']),None,None) for row in inputs.values()])
    context={'relationshipId':args['relationshipId'],'scenarioId':target[roles['Scenario']],
        'yearId':target[roles['Year']],'periodId':target[roles['Period']]}
    ownership=db.execute('''SELECT amount FROM epm.ownership_value_current
        WHERE workspace_id=%s AND application_id=%s AND relationship_id=%s
        AND scenario_member_id=%s AND year_member_id=%s AND period_member_id=%s
        AND account_name='POWN' AND present''',(*keys,*context.values())).fetchone()
    if ownership is None: raise ValueError('ACQUISITION_POWN_UNAVAILABLE')
    common={**context,'policyId':args['policyId'],'effectiveOn':args['effectiveOn'],
        'selections':args['selections'],'expectedPolicyRevision':state['policy_revision'],
        'controlConfirmed':True}
    if args['candidateFunction']==SINGLE:
        raw={'languageVersion':2,'function':SINGLE,'arguments':{**common,
            'acquisitionType':'single_step',
            'nciInstrumentClass':'present_ownership_proportionate_liquidation',
            'ownershipPercent':format(ownership['amount'],'.8f'),
            'considerationTransferred':format(amounts['considerationTransferred'],'.8f'),
            'identifiableNetAssets':format(amounts['identifiableNetAssets'],'.8f'),
            'nciFairValue':format(amounts['nciFairValue'],'.8f') if 'nciFairValue' in amounts else None}}
        policy,values=_single_program(raw)
        measured=_evaluate_in_transaction(db,scope,policy,values,state)
        source_amounts={key:amounts[key] for key in ('considerationTransferred','identifiableNetAssets')}
        book=amounts['considerationTransferred']
    else:
        raw={'languageVersion':2,'function':STEP,'arguments':{**common,
            'priorControlConfirmed':False,'finalOwnershipPercent':format(ownership['amount'],'.8f'),
            **{key:format(amounts[key],'.8f') for key in _STEP_FIELDS if key!='priorOciBalance'}}}
        parsed,policy,values=_step_program(raw)
        measured=_evaluate_step_in_transaction(db,scope,parsed,policy,values,state)
        source_amounts={key:amounts[key] for key in ('considerationTransferred',
            'identifiableNetAssets','priorInterestCarryingAmount','priorInterestFairValue','priorOciBalance')}
        with localcontext() as precision:
            precision.prec=80
            book=amounts['considerationTransferred']+amounts['priorInterestCarryingAmount']
        NumericCell(True,book,'')
    entries=balanced_entries(args['candidateFunction'],source_amounts,measured)
    investment={**target,roles['Account']:args['accounts']['investmentOffset']}
    inputs['bookInvestment']=_raw(db,scope,investment,axes,args['expectedInvestmentChangeId'])
    if Decimal(inputs['bookInvestment']['amount'])!=book:
        raise ValueError('ACQUISITION_BOOK_INVESTMENT_MISMATCH')
    # This compiler explicitly consumes raw values, not adjusted/IC/FX layers.
    # Reject live adjustments rather than silently mislabelling them as inputs.
    for point_id in {row['coordinateId'] for row in inputs.values()}:
        adjusted=db.execute('''SELECT
            coalesce((SELECT sum(signed_amount) FROM epm.manual_journal_line
                WHERE workspace_id=%s AND application_id=%s AND coordinate_id=%s),0)<>0 OR
            coalesce((SELECT sum(l.signed_amount) FROM epm.acquisition_journal_line l
                JOIN epm.acquisition_journal j USING(workspace_id,application_id,journal_id)
                WHERE l.workspace_id=%s AND l.application_id=%s AND l.coordinate_id=%s
                AND j.currency_dimension_id=%s AND j.currency_member_id=%s),0)<>0 OR
            EXISTS(SELECT 1 FROM epm.ic_elimination_current_line l
                JOIN epm.ic_elimination_state s USING(
                  workspace_id,application_id,parent_entity_member_id,pair_key)
                WHERE l.workspace_id=%s AND l.application_id=%s AND l.coordinate_id=%s)
            AS adjusted''',(*keys,point_id,*keys,point_id,roles['Currency'],currency,*keys,point_id)).fetchone()
        if adjusted['adjusted']: raise ValueError('ACQUISITION_ADJUSTED_SOURCE_UNSUPPORTED')
    # Validate even accounts whose exact zero amount is omitted from publication.
    coordinates={}
    for role,account in args['accounts'].items():
        row=db.execute('''SELECT financial_account_type FROM epm.member WHERE workspace_id=%s
            AND application_id=%s AND dimension_id=%s AND member_id=%s AND status='Active' ''',
            (*keys,roles['Account'],account)).fetchone()
        if not row or row['financial_account_type'] not in ACCOUNT_TYPES[role]:
            raise ValueError('ACQUISITION_ACCOUNT_TYPE_MISMATCH')
        coordinate,point=_point(db,scope,{**target,roles['Account']:account},axes)
        coordinates[role]=coordinate
        if point and db.execute('''SELECT 1 FROM epm.text_cell_current
            WHERE workspace_id=%s AND application_id=%s AND coordinate_id=%s AND present
            UNION ALL SELECT 1 FROM epm.line_detail_current
            WHERE workspace_id=%s AND application_id=%s AND coordinate_id=%s LIMIT 1''',
            (*keys,point['coordinate_id'],*keys,point['coordinate_id'])).fetchone():
            raise ValueError('ACQUISITION_TARGET_TYPE_CONFLICT')
    PostgresManualJournal._validate_financial_context(db,scope,[
        (point,None,None) for point in coordinates.values()])
    lines=tuple((coordinates[role],amount,role) for role,amount in entries)
    if db.execute('''SELECT 1 FROM jsonb_to_recordset(%s::jsonb) AS input(members jsonb)
        JOIN epm.cube_write_scope_lock l ON l.workspace_id=%s AND l.application_id=%s
        AND l.status='Locked' AND (l.scope_all OR input.members @> l.scope_members) LIMIT 1''',
        (Jsonb([{'members':dict(point.members)} for point,_,_ in lines]),*keys)).fetchone():
        raise ValueError('PLANNING_SLICE_LOCKED')
    manifest={'stage':'AcquisitionInvestmentOffset','compilerVersion':COMPILER,
        'governedPolicy':governed,'candidateFunction':args['candidateFunction'],
        'currencyDimensionId':roles['Currency'],'currencyMemberId':currency,
        'relationshipId':args['relationshipId'],'parentEntityId':parent,'childEntityId':child,
        'inputs':inputs,'ownershipSource':measured['ownershipSource'],
        'calendarSource':measured['calendarSource'],
        'measurement':{key:measured[key] for key in ('nciAtAcquisition','goodwillCandidate',
            'remeasurementGainOrLossCandidate') if key in measured},
        'controlAssessment':'CallerConfirmed','fairValueBasis':'CallerConfirmed',
        'sourceLayer':'raw_unadjusted','fullFinancialCloseSupported':False,
        'sourceRevisions':{key:state[key] for key in ('metadata_revision','data_revision',
            'policy_revision','commit_revision')}}
    return lines,manifest


def _candidate_identity(lines, manifest):
    """Canonical semantic identity for privately prepared acquisition effects.

    Global data/commit revisions are deliberately excluded: a publication on a
    disjoint POV may advance them while this candidate waits.  The manifest's
    exact raw change IDs, ownership/calendar evidence, governed policy and
    resolved targets are retained, so a changed dependency still invalidates
    the candidate at the final fence.
    """
    stable_manifest={key:value for key,value in manifest.items()
                     if key!='sourceRevisions'}
    return _canonical_digest({
        'lines':[{'members':dict(point.members),
                  'amount':format(amount,'.8f'),'role':role}
                 for point,amount,role in lines],
        'manifest':stable_manifest})


def enforce_acquisition_journal_dimensional_security(
        db, identity, scope, lines, manifest):
    """Authorize trusted acquisition inputs separately from journal outputs."""
    inputs = manifest.get('inputs')
    if (not isinstance(inputs, dict) or not inputs
            or any(not isinstance(item, dict)
                   or not isinstance(item.get('members'), dict)
                   for item in inputs.values())):
        raise ValueError('ACQUISITION_SECURITY_COORDINATES_INVALID')
    sources = tuple(Coordinate.from_mapping(item['members'])
                    for item in inputs.values())
    targets = tuple(point for point, _, _ in lines)
    if not targets:
        raise ValueError('ACQUISITION_SECURITY_COORDINATES_INVALID')
    authorize_coordinates(db, identity, scope, sources, kind=AccessKind.READ)
    authorize_coordinates(db, identity, scope, targets, kind=AccessKind.WRITE)


def _read_candidate_state(db, scope):
    """Read lifecycle/revisions without taking the application mutation row."""
    row=db.execute('''SELECT s.metadata_revision,s.policy_revision,
        s.data_revision,s.commit_revision,s.processing_mode,s.currency_settings,
        a.status AS application_status
        FROM epm.application_state s JOIN epm.application a
          USING(workspace_id,application_id)
        WHERE s.workspace_id=%s AND s.application_id=%s''',
        (scope.workspace_id,scope.application_id)).fetchone()
    if not row:
        raise ValueError('APPLICATION_UNAVAILABLE')
    if row['application_status']!='Active' or row['processing_mode']!='Active':
        raise ValueError('APPLICATION_NOT_WRITABLE')
    return dict(row)


class PostgresAcquisitionJournalPublisher:
    def __init__(self,dsn,*,identity):
        if not isinstance(dsn,str) or not dsn or not isinstance(identity,VerifiedIdentity):
            raise ValueError('A runtime DSN and verified identity are required')
        self.dsn,self.identity=dsn,identity

    def publish(self,claim):
        if (not isinstance(claim,dict) or not isinstance(claim.get('job_id'),str)
                or not re.fullmatch(r'[0-9a-f]{32}',claim['job_id'])
                or not isinstance(claim.get('claimant'),str)
                or type(claim.get('claim_generation')) is not int):
            raise ValueError('INVALID_WORKER_CLAIM')
        scope=ApplicationScope(claim['workspace_id'],claim['application_id'])
        keys=(scope.workspace_id,scope.application_id)
        # Private preparation: authorization and all source/arithmetic work run
        # without the application mutation row.  The transaction still holds
        # the workspace security fence for its own current-authority snapshot.
        with connect_postgres(self.dsn,row_factory=dict_row) as before:
            with before.transaction():
                configure_statement_timeout(before,10000)
                PostgresNumericFactStore._set_scope(before,scope)
                access=PostgresAccessChecker.check_in_transaction(
                    before,self.identity,scope,'admin',function=FUNCTION)
                state=_read_candidate_state(before,scope)
                job=before.execute('''SELECT *,lease_until>clock_timestamp() AS unexpired
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s''',(*keys,claim['job_id'])).fetchone()
                receipt=before.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (*keys,claim['job_id'])).fetchone()
                if receipt:
                    if (not job or receipt['command_digest']!=job['request_digest']
                            or receipt['actor_id']!=job['subject_id']):
                        raise ValueError('ACQUISITION_RECEIPT_CONFLICT')
                    PostgresNumericFactStore._require_replay_impact(
                        before,scope,claim['job_id'],receipt)
                    return receipt['result']
                if (job is None or job['issuer']!=self.identity.issuer
                        or job['subject_id']!=self.identity.subject_id):
                    raise ValueError('JOB_UNAVAILABLE')
                if (job['status']!='running' or not job['unexpired']
                        or job['claim_generation']!=claim['claim_generation']
                        or job['claimant']!=claim['claimant']):
                    raise ValueError('STALE_WORKER_FENCE')
                if (job['function_name']!=FUNCTION or job['compiler_version']!=COMPILER
                        or job['plan_digest']!=PLAN_DIGEST
                        or job['program_digest']!=_canonical_digest(job['normalized_program'])):
                    raise ValueError('ACQUISITION_JOB_PROGRAM_MISMATCH')
                for column in ('metadata_revision','data_revision','policy_revision'):
                    if job['expected_'+column]!=state[column]:
                        raise ValueError('STALE_ACQUISITION_REVISION')
                program=compile_program(job['normalized_program'])
                lines,manifest=validate_in_transaction(before,scope,program,state)
                enforce_acquisition_journal_dimensional_security(
                    before,self.identity,scope,lines,manifest)
                enforce_active_planning_policy(before,scope,
                    writes=tuple((point,'Add') for point,_,_ in lines),
                    workflow_role=access.role,ordered_actions=True)
                initial_identity=_candidate_identity(lines,manifest)
                initial_job=dict(job)

        # Short final publication fence.  Re-resolve every exact dependency and
        # compare the semantic candidate before creating any durable effect.
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,10000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state=PostgresManualJournal._state(db,scope)
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'admin',function=FUNCTION)
                job=db.execute('''SELECT *,lease_until>clock_timestamp() AS unexpired
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s FOR UPDATE''',(*keys,claim['job_id'])).fetchone()
                receipt=db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (*keys,claim['job_id'])).fetchone()
                if receipt:
                    if (not job or receipt['command_digest']!=job['request_digest']
                            or receipt['actor_id']!=job['subject_id']):
                        raise ValueError('ACQUISITION_RECEIPT_CONFLICT')
                    return receipt['result']
                immutable=('issuer','subject_id','function_name','normalized_program',
                    'request_digest','program_digest','compiler_version','plan_digest',
                    'expected_metadata_revision','expected_data_revision',
                    'expected_policy_revision')
                if (not job or any(job[name]!=initial_job[name]
                                   for name in immutable)):
                    raise ValueError('STALE_WORKER_FENCE')
                if (job['status']!='running' or not job['unexpired']
                        or job['claim_generation']!=claim['claim_generation']
                        or job['claimant']!=claim['claimant']):
                    raise ValueError('STALE_WORKER_FENCE')
                if (job['function_name']!=FUNCTION or job['compiler_version']!=COMPILER
                        or job['plan_digest']!=PLAN_DIGEST
                        or job['program_digest']!=_canonical_digest(job['normalized_program'])):
                    raise ValueError('ACQUISITION_JOB_PROGRAM_MISMATCH')
                # Metadata/policy changes can reinterpret coordinates or the
                # governed treatment.  Unrelated data publication is allowed;
                # exact raw change IDs and candidate identity fence dependencies.
                for column in ('metadata_revision','policy_revision'):
                    if job['expected_'+column]!=state[column]:
                        raise ValueError('STALE_ACQUISITION_REVISION')
                if state['data_revision']<job['expected_data_revision']:
                    raise ValueError('STALE_ACQUISITION_REVISION')
                lines,manifest=validate_in_transaction(db,scope,program,state)
                if _candidate_identity(lines,manifest)!=initial_identity:
                    raise ValueError('STALE_ACQUISITION_CANDIDATE')
                enforce_acquisition_journal_dimensional_security(
                    db,self.identity,scope,lines,manifest)
                policy_evidence=enforce_active_planning_policy(
                    db,scope,writes=tuple((point,'Add')
                        for point,_,_ in lines),workflow_role=access.role,
                    ordered_actions=True)
                revision=state['commit_revision']+1
                result={'journalId':job['job_id'],'acquisitionKey':program['arguments']['acquisitionKey'],
                    'status':'Posted','layer':'acquisition_journal','lineCount':len(lines),
                    'activationId':manifest['governedPolicy']['activationId'],
                    'currencyMemberId':manifest['currencyMemberId'],
                    'dataRevision':state['data_revision']+1,'committedRevision':revision,
                    'planningPolicy':policy_evidence}
                from .postgres_calculation_impact import journal_impact
                impact=journal_impact(operation_id=job['job_id'],
                    causal_revision=revision,
                    member_sets=[dict(point.members) for point,_,_ in lines])
                result['impactDigest']=impact.digest
                db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,
                    operation_id,command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',(*keys,job['job_id'],job['request_digest'],
                        self.identity.subject_id,revision,Jsonb(result)))
                from .postgres_calculation_impact import record_calculation_impact
                record_calculation_impact(db,scope,
                    operation_id=job['job_id'],impact=impact)
                db.execute('''INSERT INTO epm.acquisition_journal(workspace_id,application_id,
                    journal_id,acquisition_key,job_id,activation_id,currency_dimension_id,
                    currency_member_id,reason,manifest,issuer,subject_id,metadata_revision,
                    policy_revision,committed_revision) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys,job['job_id'],program['arguments']['acquisitionKey'],job['job_id'],
                     manifest['governedPolicy']['activationId'],manifest['currencyDimensionId'],
                     manifest['currencyMemberId'],program['arguments']['reason'],Jsonb(manifest),
                     self.identity.issuer,self.identity.subject_id,state['metadata_revision'],
                     state['policy_revision'],revision))
                db.cursor().executemany('''INSERT INTO epm.acquisition_journal_line
                    (workspace_id,application_id,journal_id,line_ordinal,coordinate_id,signed_amount,line_role)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',[
                        (*keys,job['job_id'],ordinal,PostgresNumericFactStore._coordinate_id(db,scope,point),amount,role)
                        for ordinal,(point,amount,role) in enumerate(lines,1)])
                db.execute("UPDATE epm.acquisition_journal SET status='Posted' "
                    'WHERE workspace_id=%s AND application_id=%s AND journal_id=%s',(*keys,job['job_id']))
                db.execute('''UPDATE epm.application_state SET data_revision=data_revision+1,
                    commit_revision=%s WHERE workspace_id=%s AND application_id=%s''',(revision,*keys))
                committed=db.execute("""UPDATE epm.job SET status='published',claimant=NULL,lease_until=NULL,
                    receipt_revision=%s,result=%s,updated_at=clock_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s
                    AND lease_until>clock_timestamp() RETURNING job_id""",
                    (revision,Jsonb(result),*keys,job['job_id'])).fetchone()
                if committed is None: raise ValueError('STALE_WORKER_FENCE')
                return result
