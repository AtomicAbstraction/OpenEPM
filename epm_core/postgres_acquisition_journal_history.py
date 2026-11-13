"""Scoped acquisition history, explicit snapshot balances and exact correction."""
from decimal import Decimal

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate, NumericCell
from .dimensional_security_policy import AccessKind
from .postgres_access import VerifiedIdentity, PostgresAccessChecker
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_acquisition_journal import _KEY, _id, _coordinate
from .postgres_jobs import _canonical_digest
from .postgres_manual_journal import PostgresManualJournal
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_planning_write_guard import enforce_active_planning_policy

READ='consolidation.acquisition.journal.read'
BALANCE='consolidation.acquisition.journal.balance.read'
REVERSE='consolidation.acquisition.journal.reverse'


def compile_history(program):
    if (not isinstance(program,dict) or set(program)!={'languageVersion','function','arguments'}
            or type(program['languageVersion']) is not int or program['languageVersion']!=2
            or not isinstance(program['function'],str) or not isinstance(program['arguments'],dict)):
        raise ValueError('ACQUISITION_HISTORY_PROGRAM_INVALID')
    function,args=program['function'],program['arguments']
    if function==READ:
        if set(args)!={'journalId'} or not isinstance(args['journalId'],str) or not _KEY.fullmatch(args['journalId']):
            raise ValueError('ACQUISITION_HISTORY_ARGUMENTS_INVALID')
    elif function==BALANCE:
        if (set(args)-{'snapshotRevision'}!={'members','currencyDimensionId','currencyMemberId'}
                or not _id(args['currencyDimensionId']) or not _id(args['currencyMemberId'])
                or 'snapshotRevision' in args and (type(args['snapshotRevision']) is not int
                    or args['snapshotRevision']<0)):
            raise ValueError('ACQUISITION_HISTORY_ARGUMENTS_INVALID')
        _coordinate(args['members'])
    elif function==REVERSE:
        if (set(args)!={'journalId','reason','expectedMetadataRevision','expectedDataRevision','expectedPolicyRevision'}
                or not isinstance(args['journalId'],str) or not _KEY.fullmatch(args['journalId'])
                or not isinstance(args['reason'],str) or not 1<=len(args['reason'])<=500
                or args['reason']!=args['reason'].strip() or '\0' in args['reason']
                or any(type(args[key]) is not int or args[key]<0 for key in (
                    'expectedMetadataRevision','expectedDataRevision','expectedPolicyRevision'))):
            raise ValueError('ACQUISITION_HISTORY_ARGUMENTS_INVALID')
    else: raise ValueError('ACQUISITION_HISTORY_FUNCTION_UNSUPPORTED')
    return function,args


def _revisions(state):
    return {key:state[key] for key in ('metadata_revision','data_revision','policy_revision')}


def _reversal_candidate(db,scope,args,*,workflow_role,lock_original,identity):
    """Resolve one immutable posted journal and its current reversal guard."""
    keys=(scope.workspace_id,scope.application_id)
    original=db.execute('''SELECT * FROM epm.acquisition_journal
        WHERE workspace_id=%s AND application_id=%s AND journal_id=%s
        AND status='Posted' '''+('FOR UPDATE' if lock_original else ''),
        (*keys,args['journalId'])).fetchone()
    if not original:raise ValueError('ACQUISITION_JOURNAL_UNAVAILABLE')
    if original['reversal_of'] is not None:
        raise ValueError('ACQUISITION_REVERSAL_OF_REVERSAL_DENIED')
    if db.execute('''SELECT 1 FROM epm.acquisition_journal
        WHERE workspace_id=%s AND application_id=%s AND reversal_of=%s''',
        (*keys,args['journalId'])).fetchone():
        raise ValueError('ACQUISITION_ALREADY_REVERSED')
    lines=db.execute('''SELECT l.coordinate_id,l.signed_amount,
        l.line_role,l.line_ordinal,c.members
        FROM epm.acquisition_journal_line l JOIN epm.coordinate c
          ON c.workspace_id=l.workspace_id
          AND c.application_id=l.application_id
          AND c.coordinate_id=l.coordinate_id
        WHERE l.workspace_id=%s AND l.application_id=%s
        AND l.journal_id=%s ORDER BY l.line_ordinal''',
        (*keys,args['journalId'])).fetchall()
    if not lines:raise ValueError('ACQUISITION_JOURNAL_LINES_UNAVAILABLE')
    points=tuple(Coordinate.from_mapping(line['members']) for line in lines)
    authorize_coordinates(db,identity,scope,points,kind=AccessKind.WRITE)
    policy_evidence=enforce_active_planning_policy(
        db,scope,writes=tuple((point,'Add') for point in points),
        workflow_role=workflow_role,ordered_actions=True)
    identity={'journalId':original['journal_id'],
        'acquisitionKey':original['acquisition_key'],
        'activationId':original['activation_id'],
        'currencyDimensionId':original['currency_dimension_id'],
        'currencyMemberId':original['currency_member_id'],
        'manifest':original['manifest'],
        'lines':tuple((line['line_ordinal'],line['coordinate_id'],
            line['signed_amount'],line['line_role'],line['members'])
            for line in lines)}
    return {'identity':identity,'original':original,'lines':lines,
        'planningPolicy':policy_evidence}


class PostgresAcquisitionJournalHistory:
    def __init__(self,dsn,*,identity):
        if not isinstance(dsn,str) or not dsn or not isinstance(identity,VerifiedIdentity):
            raise ValueError('A runtime DSN and verified identity are required')
        self.dsn,self.identity=dsn,identity

    def read(self,scope,program):
        function,args=compile_history(program)
        if function not in (READ,BALANCE): raise ValueError('ACQUISITION_HISTORY_READ_REQUIRED')
        keys=(scope.workspace_id,scope.application_id)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read')
                state=db.execute('''SELECT metadata_revision,data_revision,policy_revision,commit_revision
                    FROM epm.application_state WHERE workspace_id=%s AND application_id=%s FOR SHARE''',keys).fetchone()
                if not state: raise ValueError('APPLICATION_UNAVAILABLE')
                common={'layer':'acquisition_journal','revisionVector':_revisions(state),
                    'observedCommitRevision':state['commit_revision']}
                if function==BALANCE:
                    snapshot=args.get('snapshotRevision',state['commit_revision'])
                    if snapshot>state['commit_revision']: raise ValueError('SNAPSHOT_REVISION_INVALID')
                    point=_coordinate(args['members'])
                    authorize_coordinates(db,self.identity,scope,(point,),
                                          kind=AccessKind.READ)
                    # Existing coordinates identify their historical grain exactly;
                    # current metadata may have retired a dimension/member since posting.
                    row=db.execute('''SELECT members,coordinate_id FROM epm.coordinate
                        WHERE workspace_id=%s AND application_id=%s AND series_key=%s''',
                        (*keys,point.series_key)).fetchone()
                    if row and row['members']!=args['members']: raise ValueError('COORDINATE_HASH_COLLISION')
                    if not db.execute('''SELECT 1 FROM epm.member m JOIN epm.dimension d
                        USING(workspace_id,application_id,dimension_id) WHERE m.workspace_id=%s
                        AND m.application_id=%s AND m.dimension_id=%s AND m.member_id=%s
                        AND (d.model_role='Currency' OR EXISTS(SELECT 1 FROM epm.acquisition_journal j
                            WHERE j.workspace_id=m.workspace_id AND j.application_id=m.application_id
                            AND j.currency_dimension_id=m.dimension_id AND j.currency_member_id=m.member_id))''',
                        (*keys,args['currencyDimensionId'],args['currencyMemberId'])).fetchone():
                        raise ValueError('ACQUISITION_CURRENCY_UNAVAILABLE')
                    amount=Decimal(0); count=0
                    if row:
                        totals=db.execute('''SELECT coalesce(sum(l.signed_amount),0) AS amount,count(*) AS count
                            FROM epm.acquisition_journal_line l JOIN epm.acquisition_journal j
                            USING(workspace_id,application_id,journal_id) WHERE l.workspace_id=%s
                            AND l.application_id=%s AND l.coordinate_id=%s AND j.currency_dimension_id=%s
                            AND j.currency_member_id=%s AND j.committed_revision<=%s AND j.status='Posted' ''',
                            (*keys,row['coordinate_id'],args['currencyDimensionId'],args['currencyMemberId'],snapshot)).fetchone()
                        amount,count=totals['amount'],totals['count']
                    try: NumericCell(True,amount,'')
                    except ValueError as error: raise ValueError('ACQUISITION_BALANCE_OUT_OF_RANGE') from error
                    return {**common,'members':args['members'],'currencyDimensionId':args['currencyDimensionId'],
                        'currencyMemberId':args['currencyMemberId'],'snapshotRevision':snapshot,
                        'adjustmentAmount':format(amount,'.8f'),'contributingLineCount':count}
                header=db.execute('''SELECT * FROM epm.acquisition_journal WHERE workspace_id=%s
                    AND application_id=%s AND journal_id=%s AND status='Posted' ''',(*keys,args['journalId'])).fetchone()
                if not header: raise ValueError('ACQUISITION_JOURNAL_UNAVAILABLE')
                lines=db.execute('''SELECT l.line_ordinal,l.line_role,l.signed_amount,c.members
                    FROM epm.acquisition_journal_line l JOIN epm.coordinate c
                    USING(workspace_id,application_id,coordinate_id) WHERE l.workspace_id=%s
                    AND l.application_id=%s AND l.journal_id=%s ORDER BY l.line_ordinal''',
                    (*keys,args['journalId'])).fetchall()
                output_points=tuple(Coordinate.from_mapping(line['members'])
                                    for line in lines)
                authorize_coordinates(db,self.identity,scope,output_points,
                                      kind=AccessKind.READ)
                reversal=db.execute('''SELECT journal_id FROM epm.acquisition_journal WHERE workspace_id=%s
                    AND application_id=%s AND reversal_of=%s''',(*keys,args['journalId'])).fetchone()
                manifest=header['manifest']; governed=manifest.get('governedPolicy',{})
                inputs=manifest.get('inputs')
                if isinstance(inputs,dict):
                    source_points=tuple(Coordinate.from_mapping(item['members'])
                        for item in inputs.values() if isinstance(item,dict)
                        and isinstance(item.get('members'),dict))
                    if source_points:
                        authorize_coordinates(db,self.identity,scope,
                                              source_points,
                                              kind=AccessKind.READ)
                active=(None if not isinstance(governed,dict) or not governed.get('variantKey') else
                    db.execute('''SELECT activation_id,status FROM epm.policy_activation_current
                        WHERE workspace_id=%s AND application_id=%s AND variant_key=%s''',
                        (*keys,governed['variantKey'])).fetchone())
                inputs=manifest.get('inputs'); source_current=None
                if isinstance(inputs,dict) and inputs and all(isinstance(value,dict)
                        and type(value.get('coordinateId')) is int and isinstance(value.get('changeId'),str)
                        for value in inputs.values()):
                    source_current=True
                    for source in inputs.values():
                        current=db.execute('''SELECT present,change_id FROM epm.numeric_cell_current
                            WHERE workspace_id=%s AND application_id=%s AND coordinate_id=%s''',
                            (*keys,source['coordinateId'])).fetchone()
                        source_current=source_current and bool(current and current['present']
                            and current['change_id']==source['changeId'])
                return {**common,'journalId':header['journal_id'],'acquisitionKey':header['acquisition_key'],
                    'status':'Reversed' if reversal else 'Posted','reversalOf':header['reversal_of'],
                    'reversedBy':reversal['journal_id'] if reversal else None,
                    'activationId':header['activation_id'],'currencyDimensionId':header['currency_dimension_id'],
                    'currencyMemberId':header['currency_member_id'],'reason':header['reason'],
                    'committedRevision':header['committed_revision'],'postedAt':header['posted_at'].isoformat(),
                    'actor':{'issuer':header['issuer'],'subjectId':header['subject_id']},
                    'metadataCurrent':state['metadata_revision']==header['metadata_revision'],
                    'rawSourceChangeIdsCurrent':source_current,
                    'policyActivationCurrent':bool(active and active['status']=='Active'
                        and active['activation_id']==header['activation_id']),
                    'manifest':manifest,'lines':[{'ordinal':line['line_ordinal'],'role':line['line_role'],
                        'members':line['members'],'signedAmount':format(line['signed_amount'],'.8f')} for line in lines]}

    def reverse(self,scope,program,*,idempotency_key):
        function,args=compile_history(program)
        if function!=REVERSE: raise ValueError('ACQUISITION_REVERSAL_REQUIRED')
        if not isinstance(idempotency_key,str) or not _KEY.fullmatch(idempotency_key):
            raise ValueError('ACQUISITION_REVERSAL_KEY_INVALID')
        keys=(scope.workspace_id,scope.application_id)
        digest=_canonical_digest({'scope':list(keys),'program':program,
            'identity':[self.identity.issuer,self.identity.subject_id]})
        # Perform immutable history/line resolution and the first current
        # policy check before taking the application publication row. The
        # final transaction locks the original and repeats every mutable
        # authority, lifecycle, reversal and target-policy check.
        with connect_postgres(self.dsn,row_factory=dict_row) as before:
            with before.transaction():
                configure_statement_timeout(before,10000)
                PostgresNumericFactStore._set_scope(before,scope)
                PostgresAccessChecker.lock_workspace(
                    before,scope.workspace_id)
                initial_access=PostgresAccessChecker.check_in_transaction(
                    before,self.identity,scope,'admin',function=REVERSE)
                prior=before.execute('''SELECT command_digest,result FROM
                    epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (*keys,idempotency_key)).fetchone()
                if prior:
                    if prior['command_digest']!=digest:
                        raise ValueError('ACQUISITION_REVERSAL_KEY_CONFLICT')
                    return prior['result']
                initial_state=before.execute('''SELECT
                    s.metadata_revision,s.data_revision,s.policy_revision,
                    s.commit_revision,s.processing_mode,
                    a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    keys).fetchone()
                if (not initial_state
                        or initial_state['processing_mode']!='Active'
                        or initial_state['application_status']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                PostgresManualJournal._validate_revisions(
                    initial_state,args)
                candidate=_reversal_candidate(
                    before,scope,args,workflow_role=initial_access.role,
                    lock_original=False,identity=self.identity)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db,scope)
                state=PostgresManualJournal._state(db,scope)
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'admin',function=REVERSE)
                prior=db.execute('''SELECT command_digest,result FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',(*keys,idempotency_key)).fetchone()
                if prior:
                    if prior['command_digest']!=digest: raise ValueError('ACQUISITION_REVERSAL_KEY_CONFLICT')
                    PostgresNumericFactStore._require_replay_impact(
                        db,scope,idempotency_key,prior)
                    return prior['result']
                # Metadata and policy still define the governed target. Data
                # revision may advance through an unrelated disjoint reversal;
                # this journal's immutable identity is rechecked below.
                for expected,column in (
                        ('expectedMetadataRevision','metadata_revision'),
                        ('expectedPolicyRevision','policy_revision')):
                    if args[expected]!=state[column]:
                        raise ValueError('STALE_JOURNAL_REVISION')
                final_candidate=_reversal_candidate(
                    db,scope,args,workflow_role=access.role,
                    lock_original=True,identity=self.identity)
                if final_candidate['identity']!=candidate['identity']:
                    raise ValueError('ACQUISITION_REVERSAL_CANDIDATE_STALE')
                original=final_candidate['original']
                lines=final_candidate['lines']
                policy_evidence=final_candidate['planningPolicy']
                manifest={**original['manifest'],'reversalOf':args['journalId'],
                    'authorizationKind':'ExactHistoricalCorrection',
                    'reversalSourceRevisions':{**_revisions(state),'commit_revision':state['commit_revision']}}
                revision=state['commit_revision']+1
                result={'journalId':idempotency_key,'acquisitionKey':original['acquisition_key'],
                    'status':'Posted','layer':'acquisition_journal','reversalOf':args['journalId'],
                    'lineCount':len(lines),'activationId':original['activation_id'],
                    'currencyDimensionId':original['currency_dimension_id'],
                    'currencyMemberId':original['currency_member_id'],
                    'dataRevision':state['data_revision']+1,'committedRevision':revision,
                    'planningPolicy':policy_evidence}
                from .postgres_calculation_impact import journal_impact
                impact=journal_impact(operation_id=idempotency_key,
                    causal_revision=revision,
                    member_sets=[line['members'] for line in lines])
                result['impactDigest']=impact.digest
                db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,
                    command_digest,actor_id,committed_revision,result) VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys,idempotency_key,digest,self.identity.subject_id,revision,Jsonb(result)))
                from .postgres_calculation_impact import record_calculation_impact
                record_calculation_impact(db,scope,
                    operation_id=idempotency_key,impact=impact)
                db.execute('''INSERT INTO epm.acquisition_journal(workspace_id,application_id,journal_id,
                    acquisition_key,reversal_of,activation_id,currency_dimension_id,currency_member_id,
                    reason,manifest,issuer,subject_id,metadata_revision,policy_revision,committed_revision)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys,idempotency_key,original['acquisition_key'],args['journalId'],original['activation_id'],
                     original['currency_dimension_id'],original['currency_member_id'],args['reason'],Jsonb(manifest),
                     self.identity.issuer,self.identity.subject_id,state['metadata_revision'],state['policy_revision'],revision))
                # Exact historical negation retains coordinate IDs/currency.  The
                # current editability policy is evaluated against their retained
                # coordinate members without remapping the historical amounts.
                db.cursor().executemany('''INSERT INTO epm.acquisition_journal_line(workspace_id,application_id,
                    journal_id,line_ordinal,coordinate_id,signed_amount,line_role) VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    [(*keys,idempotency_key,line['line_ordinal'],line['coordinate_id'],
                        line['signed_amount'].copy_negate(),line['line_role']) for line in lines])
                db.execute("UPDATE epm.acquisition_journal SET status='Posted' WHERE workspace_id=%s "
                    'AND application_id=%s AND journal_id=%s',(*keys,idempotency_key))
                db.execute('''UPDATE epm.application_state SET data_revision=data_revision+1,
                    commit_revision=%s WHERE workspace_id=%s AND application_id=%s''',(revision,*keys))
                return result
