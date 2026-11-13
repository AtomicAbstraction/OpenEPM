"""Authorized, pinned intercompany mismatch-resolution inspection."""
from __future__ import annotations
from psycopg.rows import dict_row
from .consolidation_ic_residual_resolution import IntercompanyResidualResolution
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_ic_pair_inspect import PostgresIntercompanyPairInspector
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout

FUNCTION='consolidation.ic.residual.resolve.inspect'
class PostgresIntercompanyResidualResolution:
    def __init__(self,dsn:str,*,identity:VerifiedIdentity):
        if not isinstance(dsn,str) or not dsn:raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity,VerifiedIdentity):raise ValueError('A verified identity is required')
        self.dsn,self.identity=dsn,identity
    def inspect(self,scope:ApplicationScope,program:object)->dict:
        if (not isinstance(scope,ApplicationScope) or not isinstance(program,dict)
          or set(program)!={'languageVersion','function','arguments'} or program.get('languageVersion')!=2
          or program.get('function')!=FUNCTION or not isinstance(program.get('arguments'),dict)
          or set(program['arguments'])!={'definition'}):raise ValueError('IC_RESIDUAL_PROGRAM_INVALID')
        definition=IntercompanyResidualResolution.parse(program['arguments']['definition'])
        pair=PostgresIntercompanyPairInspector(self.dsn,identity=self.identity).inspect(scope,{
          'languageVersion':2,'function':'consolidation.ic.pair.inspect','arguments':{
            'leftMembers':definition.left_members,'rightMembers':definition.right_members}})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            configure_statement_timeout(db,5000);PostgresNumericFactStore._set_scope(db,scope)
            PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read',function=FUNCTION)
            state=db.execute('''SELECT metadata_revision,data_revision,policy_revision,commit_revision
              FROM epm.application_state WHERE workspace_id=%s AND application_id=%s FOR SHARE''',
              (scope.workspace_id,scope.application_id)).fetchone()
            if state is None:raise ValueError('APPLICATION_UNAVAILABLE')
            current={'metadataRevision':state['metadata_revision'],'dataRevision':state['data_revision'],
              'policyRevision':state['policy_revision'],'commitRevision':state['commit_revision']}
            if any(pair[key]!=value for key,value in current.items()):raise ValueError('IC_RESIDUAL_SOURCE_REVISION_STALE')
            currency=db.execute('''SELECT 1 FROM epm.dimension d JOIN epm.member m
              ON m.workspace_id=d.workspace_id AND m.application_id=d.application_id AND m.dimension_id=d.dimension_id
              WHERE d.workspace_id=%s AND d.application_id=%s AND d.dimension_id=%s AND d.model_role='Currency'
              AND d.status='Active' AND m.member_id=%s AND m.status='Active' ''',
              (scope.workspace_id,scope.application_id,definition.currency_dimension_id,definition.currency_member_id)).fetchone()
            if currency is None:raise ValueError('IC_RESIDUAL_CURRENCY_UNAVAILABLE')
        result=definition.calculate(pair)
        return {**result,'sourcePair':pair,'revisionPins':current,
          'lineage':[{'side':side,'members':pair[side]['members'],'changeId':pair[side]['changeId']}
            for side in ('left','right')],
          'effects':{'businessRevisionChanged':False,'published':False,'rawFactsChanged':False},
          'limitations':['Unreviewed caller-directed residual candidate only','No cause, policy, FX, posting or close inference']}
