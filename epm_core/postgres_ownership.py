"""Exact, period-sensitive ownership inputs for a direct Entity placement.

This fixed core records declared values. It does not infer control, select an
accounting method, or calculate a consolidated balance from percentages.
"""
from __future__ import annotations

import re
import uuid

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, NumericCell
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore


WRITE_FUNCTION = 'consolidation.ownership.value.set'
READ_FUNCTION = 'consolidation.ownership.value.read'
SCOPE_READ_FUNCTION = 'consolidation.ownership.scope.read'
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_ACCOUNTS = {'POWN','PCON','PCTRL','DOWN','Active','Method',
             'Consol1','Consol2','Consol3'}
_BOUNDS = {'POWN':(0,100),'PCON':(-100,100),'PCTRL':(0,100),
           'DOWN':(0,100),'Active':(0,1),'Method':(0,None),
           'Consol1':(0,255),'Consol2':(0,255),'Consol3':(0,255)}


def _account(value: object) -> str:
    if not isinstance(value,str):
        raise ValueError('OWNERSHIP_ACCOUNT_UNSUPPORTED')
    normalized=value[1:-1] if value.startswith('[') and value.endswith(']') else value
    if normalized not in _ACCOUNTS:
        raise ValueError('OWNERSHIP_ACCOUNT_UNSUPPORTED')
    return normalized


def _context(program: object, function: str) -> dict:
    if (not isinstance(program,dict)
            or set(program)!={'languageVersion','function','arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion']!=2
            or program['function']!=function
            or not isinstance(program['arguments'],dict)):
        raise ValueError('V2_OWNERSHIP_FUNCTION_INVALID')
    args=program['arguments']
    required={'relationshipId','scenarioId','yearId','periodId','account'}
    extras=({'op','value','expectedChangeId','expectedMetadataRevision',
             'expectedPolicyRevision'} if function==WRITE_FUNCTION else set())
    if (not required<=set(args) or set(args)-required-extras
            or any(not isinstance(args[name],str)
                   or not 1<=len(args[name])<=200
                   for name in required-{'account'})):
        raise ValueError('V2_OWNERSHIP_ARGUMENTS_INVALID')
    result={name:args[name] for name in required-{'account'}}
    result['account']=_account(args['account'])
    return result


def compile_ownership_write(program: object) -> dict:
    result=_context(program,WRITE_FUNCTION)
    args=program['arguments']
    if (set(args)!={'relationshipId','scenarioId','yearId','periodId',
                   'account','op','expectedChangeId',
                   'expectedMetadataRevision','expectedPolicyRevision'}
            and set(args)!={'relationshipId','scenarioId','yearId','periodId',
                            'account','op','value','expectedChangeId',
                            'expectedMetadataRevision',
                            'expectedPolicyRevision'}):
        raise ValueError('V2_OWNERSHIP_ARGUMENTS_INVALID')
    if (args['op'] not in ('Set','Clear')
            or not isinstance(args['expectedChangeId'],str)
            or len(args['expectedChangeId'])>200
            or any(type(args[key]) is not int or args[key]<0 for key in (
                'expectedMetadataRevision','expectedPolicyRevision'))):
        raise ValueError('V2_OWNERSHIP_ARGUMENTS_INVALID')
    if args['op']=='Clear':
        if 'value' in args:
            raise ValueError('OWNERSHIP_CLEAR_HAS_VALUE')
        amount=None
    else:
        value=args.get('value')
        if (not isinstance(value,dict)
                or set(value)!={'type','decimal'}
                or value['type']!='AmountLiteral'):
            raise ValueError('OWNERSHIP_AMOUNT_LITERAL_REQUIRED')
        amount=NumericCell.from_wire(
            present=True,amount=value['decimal']).amount
        lower,upper=_BOUNDS[result['account']]
        if amount<lower or (upper is not None and amount>upper):
            raise ValueError('OWNERSHIP_VALUE_OUT_OF_RANGE')
        if (result['account'] in {'Active','Method','Consol1','Consol2','Consol3'}
                and amount!=amount.to_integral_value()):
            raise ValueError('OWNERSHIP_WHOLE_NUMBER_REQUIRED')
    return {**result,'op':args['op'],'amount':amount,
            'expectedChangeId':args['expectedChangeId'],
            'expectedMetadataRevision':args['expectedMetadataRevision'],
            'expectedPolicyRevision':args['expectedPolicyRevision']}


def compile_ownership_read(program: object) -> dict:
    result=_context(program,READ_FUNCTION)
    if set(program['arguments'])!={
            'relationshipId','scenarioId','yearId','periodId','account'}:
        raise ValueError('V2_OWNERSHIP_ARGUMENTS_INVALID')
    return result


class PostgresOwnershipValues:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity):
        if not isinstance(dsn,str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn,self.identity=dsn,identity

    @staticmethod
    def _active_context(db,scope: ApplicationScope,query: dict) -> dict:
        roles={}
        for row in db.execute('''SELECT dimension_id,model_role
            FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
            AND model_role IN ('Scenario','Year','Period','Entity')
            AND status='Active' ''',
            (scope.workspace_id,scope.application_id)).fetchall():
            role=row['model_role']
            if role in roles:
                raise ValueError('OWNERSHIP_MODEL_ROLE_AMBIGUOUS')
            roles[role]=row['dimension_id']
        if set(roles)!={'Scenario','Year','Period','Entity'}:
            raise ValueError('OWNERSHIP_MODEL_ROLES_REQUIRED')
        placement=db.execute('''SELECT 1 FROM epm.relationship r
            JOIN epm.member parent ON parent.workspace_id=r.workspace_id
            AND parent.application_id=r.application_id
            AND parent.dimension_id=r.dimension_id
            AND parent.member_id=r.parent_member_id
            JOIN epm.member child ON child.workspace_id=r.workspace_id
            AND child.application_id=r.application_id
            AND child.dimension_id=r.dimension_id
            AND child.member_id=r.child_member_id
            WHERE r.workspace_id=%s AND r.application_id=%s
            AND r.relationship_id=%s AND r.dimension_id=%s
            AND r.status='Active' AND parent.status='Active'
            AND child.status='Active'  AND EXISTS(SELECT 1 FROM epm.hierarchy_definition hierarchy
          WHERE hierarchy.workspace_id=r.workspace_id AND hierarchy.application_id=r.application_id
            AND hierarchy.dimension_id=r.dimension_id AND hierarchy.hierarchy_id=r.hierarchy_id
            AND hierarchy.status='Active') ''',
            (scope.workspace_id,scope.application_id,
             query['relationshipId'],roles['Entity'])).fetchone()
        if not placement:
            raise ValueError('OWNERSHIP_ENTITY_PLACEMENT_UNAVAILABLE')
        for role,name in (('Scenario','scenarioId'),('Year','yearId'),
                          ('Period','periodId')):
            found=db.execute('''SELECT 1 FROM epm.member
                WHERE workspace_id=%s AND application_id=%s
                AND dimension_id=%s AND member_id=%s AND status='Active' ''',
                (scope.workspace_id,scope.application_id,
                 roles[role],query[name])).fetchone()
            if not found:
                raise ValueError('OWNERSHIP_CONTEXT_MEMBER_UNAVAILABLE')
        return roles

    @staticmethod
    def _key(scope: ApplicationScope,query: dict) -> tuple:
        return (scope.workspace_id,scope.application_id,
                query['relationshipId'],query['scenarioId'],
                query['yearId'],query['periodId'],query['account'])

    def read(self,scope: ApplicationScope,program: object) -> dict:
        query=compile_ownership_read(program)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'read', function=READ_FUNCTION)
                self._active_context(db,scope,query)
                current=db.execute('''SELECT present,amount,change_id,
                    last_revision FROM epm.ownership_value_current
                    WHERE workspace_id=%s AND application_id=%s
                    AND relationship_id=%s AND scenario_member_id=%s
                    AND year_member_id=%s AND period_member_id=%s
                    AND account_name=%s''',self._key(scope,query)).fetchone()
                return {'relationshipId':query['relationshipId'],
                        'scenarioId':query['scenarioId'],
                        'yearId':query['yearId'],
                        'periodId':query['periodId'],
                        'account':query['account'],
                        'present':bool(current and current['present']),
                        'amount':format(current['amount'],'f')
                            if current and current['present'] else None,
                        'changeId':current['change_id'] if current else '',
                        'lastRevision':current['last_revision']
                            if current else 0}

    def read_scope(self,scope: ApplicationScope,program: object) -> dict:
        """Page direct active Entity placements and declared ownership inputs.

        This is an input-coverage read, not a control or method assessment.
        Revisions on later pages fence concurrent metadata and policy edits.
        """
        if (not isinstance(program,dict)
                or set(program)!={'languageVersion','function','arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion']!=2
                or program['function']!=SCOPE_READ_FUNCTION
                or not isinstance(program['arguments'],dict)):
            raise ValueError('V2_OWNERSHIP_SCOPE_ARGUMENTS_INVALID')
        args=program['arguments']
        required={'parentEntityId','scenarioId','yearId','periodId'}
        optional={'afterRelationshipId','limit','expectedMetadataRevision',
                  'expectedPolicyRevision'}
        if (not required<=set(args) or set(args)-required-optional
                or any(not isinstance(args[key],str)
                       or not 1<=len(args[key])<=200 for key in required)
                or ('afterRelationshipId' in args and
                    (not isinstance(args['afterRelationshipId'],str)
                     or len(args['afterRelationshipId'])>200))
                or type(args.get('limit',100)) is not int
                or not 1<=args.get('limit',100)<=200
                or (('expectedMetadataRevision' in args)!=
                    ('expectedPolicyRevision' in args))
                or any(type(args[key]) is not int or args[key]<0
                       for key in ('expectedMetadataRevision',
                                   'expectedPolicyRevision') if key in args)):
            raise ValueError('V2_OWNERSHIP_SCOPE_ARGUMENTS_INVALID')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state=db.execute('''SELECT metadata_revision,
                    policy_revision,commit_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s FOR SHARE''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'read', function=SCOPE_READ_FUNCTION)
                if ('expectedMetadataRevision' in args and
                    (args['expectedMetadataRevision']!=state['metadata_revision']
                     or args['expectedPolicyRevision']!=state['policy_revision'])):
                    raise ValueError('STALE_OWNERSHIP_SCOPE_REVISION')
                roles={}
                for row in db.execute('''SELECT dimension_id,model_role
                    FROM epm.dimension WHERE workspace_id=%s
                    AND application_id=%s AND status='Active'
                    AND model_role IN ('Scenario','Year','Period','Entity')''',
                    (scope.workspace_id,scope.application_id)).fetchall():
                    if row['model_role'] in roles:
                        raise ValueError('OWNERSHIP_MODEL_ROLE_AMBIGUOUS')
                    roles[row['model_role']]=row['dimension_id']
                if set(roles)!={'Scenario','Year','Period','Entity'}:
                    raise ValueError('OWNERSHIP_MODEL_ROLES_REQUIRED')
                for role,member_id in (('Scenario',args['scenarioId']),
                                       ('Year',args['yearId']),
                                       ('Period',args['periodId']),
                                       ('Entity',args['parentEntityId'])):
                    found=db.execute('''SELECT 1 FROM epm.member
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND member_id=%s
                        AND status='Active' ''',
                        (scope.workspace_id,scope.application_id,
                         roles[role],member_id)).fetchone()
                    if not found:
                        raise ValueError('OWNERSHIP_CONTEXT_MEMBER_UNAVAILABLE')
                rows=db.execute('''SELECT r.relationship_id,
                    r.child_member_id,pown.amount AS pown_amount,
                    pown.change_id AS pown_change_id,
                    pcon.amount AS pcon_amount,
                    pcon.change_id AS pcon_change_id,
                    pctrl.amount AS pctrl_amount,
                    pctrl.change_id AS pctrl_change_id
                    FROM epm.relationship r
                    JOIN epm.member child ON child.workspace_id=r.workspace_id
                      AND child.application_id=r.application_id
                      AND child.dimension_id=r.dimension_id
                      AND child.member_id=r.child_member_id
                    LEFT JOIN epm.ownership_value_current pown
                      ON pown.workspace_id=r.workspace_id
                      AND pown.application_id=r.application_id
                      AND pown.relationship_id=r.relationship_id
                      AND pown.scenario_member_id=%s
                      AND pown.year_member_id=%s
                      AND pown.period_member_id=%s
                      AND pown.account_name='POWN' AND pown.present
                    LEFT JOIN epm.ownership_value_current pcon
                      ON pcon.workspace_id=r.workspace_id
                      AND pcon.application_id=r.application_id
                      AND pcon.relationship_id=r.relationship_id
                      AND pcon.scenario_member_id=%s
                      AND pcon.year_member_id=%s
                      AND pcon.period_member_id=%s
                      AND pcon.account_name='PCON' AND pcon.present
                    LEFT JOIN epm.ownership_value_current pctrl
                      ON pctrl.workspace_id=r.workspace_id
                      AND pctrl.application_id=r.application_id
                      AND pctrl.relationship_id=r.relationship_id
                      AND pctrl.scenario_member_id=%s
                      AND pctrl.year_member_id=%s
                      AND pctrl.period_member_id=%s
                      AND pctrl.account_name='PCTRL' AND pctrl.present
                    WHERE r.workspace_id=%s AND r.application_id=%s
                      AND r.dimension_id=%s AND r.parent_member_id=%s
                      AND r.relationship_id>%s AND r.hierarchy_id=epm.default_hierarchy_id(r.workspace_id,r.application_id,r.dimension_id) AND r.status='Active'
                      AND child.status='Active'
                    ORDER BY r.relationship_id LIMIT %s''',
                    (args['scenarioId'],args['yearId'],args['periodId'])*3+
                    (scope.workspace_id,scope.application_id,
                     roles['Entity'],args['parentEntityId'],
                     args.get('afterRelationshipId',''),args.get('limit',100)+1)
                    ).fetchall()
                has_more=len(rows)>args.get('limit',100)
                shown=rows[:args.get('limit',100)]
                values=[]
                for row in shown:
                    values.append({
                        'relationshipId':row['relationship_id'],
                        'childEntityId':row['child_member_id'],
                        **{account:{'present':row[alias+'_amount'] is not None,
                                    'amount':format(row[alias+'_amount'],'.8f')
                                        if row[alias+'_amount'] is not None else None,
                                    'changeId':row[alias+'_change_id'] or ''}
                           for account,alias in (('POWN','pown'),
                                                 ('PCON','pcon'),
                                                 ('PCTRL','pctrl'))}})
                return {'parentEntityId':args['parentEntityId'],
                        'scenarioId':args['scenarioId'],
                        'yearId':args['yearId'],
                        'periodId':args['periodId'],
                        'metadataRevision':state['metadata_revision'],
                        'policyRevision':state['policy_revision'],
                        'commitRevision':state['commit_revision'],
                        'relationships':values,
                        'nextAfterRelationshipId':
                            shown[-1]['relationship_id'] if has_more else None}

    def apply(self,scope: ApplicationScope,program: object,*,
              idempotency_key: str) -> dict:
        query=compile_ownership_write(program)
        if (not isinstance(idempotency_key,str)
                or not _KEY.fullmatch(idempotency_key)):
            raise ValueError('OWNERSHIP_IDEMPOTENCY_KEY_INVALID')
        digest=_canonical_digest({
            'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],
            'query':{**query,'amount':format(query['amount'],'.8f')
                     if query['amount'] is not None else None}})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state=db.execute('''SELECT s.metadata_revision,
                    s.policy_revision,s.commit_revision,s.processing_mode,
                    a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'admin', function=WRITE_FUNCTION)
                previous=db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id,scope.application_id,
                     idempotency_key)).fetchone()
                if previous:
                    if (previous['command_digest']!=digest
                            or previous['actor_id']!=self.identity.subject_id):
                        raise ValueError('OWNERSHIP_IDEMPOTENCY_CONFLICT')
                    PostgresNumericFactStore._require_replay_impact(
                        db,scope,idempotency_key,previous)
                    return previous['result']
                if (state['application_status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['metadata_revision']!=
                        query['expectedMetadataRevision']
                        or state['policy_revision']!=
                        query['expectedPolicyRevision']):
                    raise ValueError('STALE_OWNERSHIP_REVISION')
                roles=self._active_context(db,scope,query)
                current=db.execute('''SELECT change_id FROM
                    epm.ownership_value_current
                    WHERE workspace_id=%s AND application_id=%s
                    AND relationship_id=%s AND scenario_member_id=%s
                    AND year_member_id=%s AND period_member_id=%s
                    AND account_name=%s''',self._key(scope,query)).fetchone()
                if (current['change_id'] if current else '') != (
                        query['expectedChangeId']):
                    raise ValueError('STALE_OWNERSHIP_CHANGE_ID')
                change_id=uuid.uuid4().hex
                revision=state['commit_revision']+1
                result={'operationId':idempotency_key,
                        'relationshipId':query['relationshipId'],
                        'scenarioId':query['scenarioId'],
                        'yearId':query['yearId'],
                        'periodId':query['periodId'],
                        'account':query['account'],
                        'present':query['op']=='Set',
                        'amount':format(query['amount'],'.8f')
                            if query['amount'] is not None else None,
                        'changeId':change_id,
                        'committedRevision':revision,
                        'policyRevision':state['policy_revision']+1}
                from .calculation_impact_contract import (
                    compile_calculation_impact)
                impact=compile_calculation_impact({
                    'format':'openepm-calculation-impact-v1',
                    'sourceKind':'ownership','sourceId':idempotency_key,
                    'causalRevision':revision,'effects':[{
                        'domain':'ownership','change':(
                            'set' if query['op']=='Set' else 'clear'),
                        'objectType':'ownership-value','objectId':':'.join((
                            query['relationshipId'],query['scenarioId'],
                            query['yearId'],query['periodId'],query['account'])),
                        'scope':[
                            {'dimensionId':roles['Scenario'],
                             'memberId':query['scenarioId']},
                            {'dimensionId':roles['Year'],
                             'memberId':query['yearId']},
                            {'dimensionId':roles['Period'],
                             'memberId':query['periodId']}],
                        'reason':'unit_policy_changed',
                        'oldPresence':(
                            'present' if current else 'absent'),
                        'newPresence':(
                            'present' if query['op']=='Set' else 'absent')} ]})
                result['impactDigest']=impact.digest
                db.execute('''UPDATE epm.application_state SET
                    policy_revision=policy_revision+1,
                    commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (revision,scope.workspace_id,scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                     command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id,scope.application_id,
                     idempotency_key,digest,self.identity.subject_id,
                     revision,Jsonb(result)))
                db.execute('''INSERT INTO epm.ownership_value_event
                    (workspace_id,application_id,operation_id,
                     relationship_id,scenario_dimension_id,
                     scenario_member_id,year_dimension_id,year_member_id,
                     period_dimension_id,period_member_id,account_name,
                     kind,amount,previous_change_id,change_id,
                     committed_revision)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                            %s,%s,%s,%s)''',
                    (scope.workspace_id,scope.application_id,
                     idempotency_key,query['relationshipId'],
                     roles['Scenario'],query['scenarioId'],
                     roles['Year'],query['yearId'],
                     roles['Period'],query['periodId'],
                     query['account'],query['op'],query['amount'],
                     query['expectedChangeId'],change_id,revision))
                db.execute('''INSERT INTO epm.ownership_value_current
                    (workspace_id,application_id,relationship_id,
                     scenario_dimension_id,scenario_member_id,
                     year_dimension_id,year_member_id,
                     period_dimension_id,period_member_id,account_name,
                     present,amount,change_id,last_revision)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (workspace_id,application_id,relationship_id,
                        scenario_member_id,year_member_id,period_member_id,
                        account_name) DO UPDATE SET
                    present=EXCLUDED.present,amount=EXCLUDED.amount,
                    change_id=EXCLUDED.change_id,
                    last_revision=EXCLUDED.last_revision''',
                    (scope.workspace_id,scope.application_id,
                     query['relationshipId'],roles['Scenario'],
                     query['scenarioId'],roles['Year'],query['yearId'],
                     roles['Period'],query['periodId'],query['account'],
                     query['op']=='Set',query['amount'],change_id,revision))
                from .postgres_calculation_impact import record_calculation_impact
                record_calculation_impact(db,scope,
                    operation_id=idempotency_key,impact=impact)
                return result
