"""Authorized partial-disposal retaining-control candidate."""
from __future__ import annotations
from psycopg.rows import dict_row
from .consolidation_retained_control_disposal import RetainedControlDisposal
from .persistence_contract import ApplicationScope,Coordinate
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_ownership import PostgresOwnershipValues
from .postgres_processing_limits import configure_statement_timeout
from .postgres_source_batch import PostgresSourceBatch

FUNCTION='consolidation.disposal.retain_control.inspect'

class PostgresRetainedControlDisposal:
    def __init__(self,dsn:str,*,identity:VerifiedIdentity):
        if not isinstance(dsn,str) or not dsn:raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity,VerifiedIdentity):raise ValueError('A verified identity is required')
        self.dsn,self.identity=dsn,identity
    def inspect(self,scope:ApplicationScope,program:object)->dict:
        if (not isinstance(program,dict) or set(program)!={'languageVersion','function','arguments'}
          or program.get('languageVersion')!=2 or program.get('function')!=FUNCTION
          or not isinstance(program.get('arguments'),dict) or set(program['arguments'])!={'definition'}):
            raise ValueError('RETAINED_CONTROL_PROGRAM_INVALID')
        definition=RetainedControlDisposal.parse(program['arguments']['definition']);keys=(scope.workspace_id,scope.application_id)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            configure_statement_timeout(db,10000);PostgresNumericFactStore._set_scope(db,scope)
            PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read',function=FUNCTION)
            state=db.execute('''SELECT metadata_revision,data_revision,policy_revision,commit_revision
              FROM epm.application_state WHERE workspace_id=%s AND application_id=%s FOR SHARE''',keys).fetchone()
            if state is None:raise ValueError('APPLICATION_UNAVAILABLE')
            if (state['metadata_revision']!=definition.expected_metadata_revision
              or state['data_revision']!=definition.expected_data_revision
              or state['policy_revision']!=definition.expected_policy_revision):raise ValueError('RETAINED_CONTROL_SOURCE_REVISION_STALE')
            currency=db.execute('''SELECT 1 FROM epm.dimension d JOIN epm.member m
              ON m.workspace_id=d.workspace_id AND m.application_id=d.application_id AND m.dimension_id=d.dimension_id
              WHERE d.workspace_id=%s AND d.application_id=%s AND d.dimension_id=%s AND d.model_role='Currency'
              AND d.status='Active' AND m.member_id=%s AND m.status='Active' ''',(*keys,definition.currency_dimension_id,definition.currency_member_id)).fetchone()
            if currency is None:raise ValueError('RETAINED_CONTROL_CURRENCY_UNAVAILABLE')
            context={'relationshipId':definition.relationship_id,'scenarioId':definition.scenario_id,
              'yearId':definition.year_id,'periodId':definition.period_id,'account':'POWN'}
            PostgresOwnershipValues._active_context(db,scope,context)
            ownership=db.execute('''SELECT present,amount,change_id,last_revision FROM epm.ownership_value_current
              WHERE workspace_id=%s AND application_id=%s AND relationship_id=%s AND scenario_member_id=%s
              AND year_member_id=%s AND period_member_id=%s AND account_name='POWN' ''',(*keys,
              definition.relationship_id,definition.scenario_id,definition.year_id,definition.period_id)).fetchone()
            if ownership is None or not ownership['present'] or ownership['amount']!=definition.retained_ownership_percent:
                raise ValueError('RETAINED_CONTROL_FINAL_POWN_MISMATCH')
            if ownership['change_id']!=definition.ownership_change_id:raise ValueError('RETAINED_CONTROL_OWNERSHIP_CHANGE_STALE')
            period=db.execute('''SELECT starts_on,ends_before,change_id,last_revision FROM epm.calendar_period_current
              WHERE workspace_id=%s AND application_id=%s AND year_member_id=%s AND period_member_id=%s''',
              (*keys,definition.year_id,definition.period_id)).fetchone()
            if period is None or not(period['starts_on']<=definition.effective_on<period['ends_before']):raise ValueError('RETAINED_CONTROL_PERIOD_DATE_MISMATCH')
            if period['change_id']!=definition.calendar_change_id:raise ValueError('RETAINED_CONTROL_CALENDAR_CHANGE_STALE')
            values={};lineage=[]
            for pin in definition.pins:
              members=dict(pin.members);PostgresSourceBatch._check_scope_members(db,scope,members)
              coordinate=Coordinate.from_mapping(members)
              row=db.execute('''SELECT c.members,n.amount,n.change_id,n.last_revision FROM epm.coordinate c
                JOIN epm.numeric_cell_current n ON n.workspace_id=c.workspace_id AND n.application_id=c.application_id
                AND n.coordinate_id=c.coordinate_id WHERE c.workspace_id=%s AND c.application_id=%s
                AND c.series_key=%s AND n.present''',(*keys,coordinate.series_key)).fetchone()
              if row is None:raise ValueError('RETAINED_CONTROL_SOURCE_MISSING')
              if row['members']!=members:raise ValueError('COORDINATE_HASH_COLLISION')
              if row['change_id']!=pin.change_id:raise ValueError('RETAINED_CONTROL_SOURCE_CHANGE_STALE')
              values[pin.change_id]=format(row['amount'],'f');lineage.append({'members':members,'changeId':pin.change_id,'lastRevision':row['last_revision']})
        result=definition.calculate(values)
        return {**result,'commitRevision':state['commit_revision'],'lineage':lineage,
          'ownershipSource':{**context,'changeId':ownership['change_id'],'lastRevision':ownership['last_revision']},
          'calendarSource':{'startsOn':period['starts_on'].isoformat(),'endsBefore':period['ends_before'].isoformat(),
            'changeId':period['change_id'],'lastRevision':period['last_revision']},
          'controlAssessmentStatus':'CallerDeclaredUnverified',
          'effects':{'businessRevisionChanged':False,'published':False,'rawFactsChanged':False},
          'limitations':['Unreviewed retaining-control reattribution arithmetic only',
            'No control, policy, valuation, gain/loss, currency conversion, or posting inference']}
