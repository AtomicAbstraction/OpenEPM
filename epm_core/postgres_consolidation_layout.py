"""Versioned server-owned financial consolidation coordinate layout."""
from hashlib import sha256
import json

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_manual_journal import valid_idempotency_key
from .postgres_numeric_store import PostgresNumericFactStore

CONFIGURE='consolidation.layout.configure'
READ='consolidation.layout.read'


def _digest(document):
    return sha256(json.dumps(document,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def compile_layout_program(program):
    if (not isinstance(program,dict) or set(program)!={'languageVersion','function','arguments'}
            or program.get('languageVersion')!=2 or program.get('function') not in (CONFIGURE,READ)
            or not isinstance(program.get('arguments'),dict)):
        raise ValueError('CONSOLIDATION_LAYOUT_PROGRAM_INVALID')
    args=program['arguments']
    if program['function']==READ:
        if args:raise ValueError('CONSOLIDATION_LAYOUT_ARGUMENTS_INVALID')
        return program['function'],{}
    if (set(args)!={'stageDimensionId','movementDimensionId','expectedMetadataRevision','expectedPolicyRevision'}
            or any(not isinstance(args[name],str) or not 1<=len(args[name])<=200
                   for name in ('stageDimensionId','movementDimensionId'))
            or args['stageDimensionId']==args['movementDimensionId']
            or any(type(args[name]) is not int or args[name]<0 for name in
                   ('expectedMetadataRevision','expectedPolicyRevision'))):
        raise ValueError('CONSOLIDATION_LAYOUT_ARGUMENTS_INVALID')
    return program['function'],dict(args)


def resolve_active_layout(db,scope,*,expected_version=None,expected_digest=None):
    row=db.execute('''SELECT v.*,s.active_layout_version,s.active_layout_digest,
        a.metadata_revision AS current_metadata_revision,
        a.policy_revision AS current_policy_revision
        FROM epm.consolidation_layout_state s
        JOIN epm.consolidation_layout_version v ON v.workspace_id=s.workspace_id
          AND v.application_id=s.application_id
          AND v.layout_version=s.active_layout_version
          AND v.layout_digest=s.active_layout_digest
        JOIN epm.application_state a ON a.workspace_id=s.workspace_id
          AND a.application_id=s.application_id
        WHERE s.workspace_id=%s AND s.application_id=%s''',(
        scope.workspace_id,scope.application_id)).fetchone()
    if (row is None or row['metadata_revision']!=row['current_metadata_revision']
            or row['policy_revision']!=row['current_policy_revision']
            or (expected_version is not None and row['layout_version']!=expected_version)
            or (expected_digest is not None and row['layout_digest']!=expected_digest)):
        raise ValueError('CONSOLIDATION_LAYOUT_STALE_OR_UNAVAILABLE')
    return dict(row)


class PostgresConsolidationLayout:
    def __init__(self,dsn,*,identity):
        if not isinstance(identity,VerifiedIdentity):raise ValueError('A verified identity is required')
        self.dsn,self.identity=dsn,identity

    @staticmethod
    def catalog():
        return {CONFIGURE:{'mode':'versioned_configuration','permission':'admin',
          'arguments':{'stageDimensionId':'active Custom dimension','movementDimensionId':'different active Custom dimension','expectedMetadataRevision':'current revision','expectedPolicyRevision':'current revision'},
          'result':'immutable layout version and active pointer','previewRequired':False,'idempotencyRequired':True,'workClass':'short'},
          READ:{'mode':'read','permission':'read','arguments':{},'result':'active pinned server-owned consolidation layout','previewRequired':False,'idempotencyRequired':False,'workClass':'short'}}

    def configure(self,scope,program,*,idempotency_key):
        name,args=compile_layout_program(program)
        if name!=CONFIGURE:raise ValueError('CONSOLIDATION_LAYOUT_CONFIGURE_REQUIRED')
        if not valid_idempotency_key(idempotency_key):raise ValueError('CONSOLIDATION_LAYOUT_IDEMPOTENCY_KEY_INVALID')
        command=_canonical_digest({'scope':[scope.workspace_id,scope.application_id],'identity':[self.identity.issuer,self.identity.subject_id],'program':program})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            PostgresNumericFactStore._set_scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=CONFIGURE)
            prior=db.execute('''SELECT command_digest,actor_id,result FROM epm.operation_receipt WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',(scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
            if prior:
                if prior['command_digest']!=command or prior['actor_id']!=self.identity.subject_id:raise ValueError('CONSOLIDATION_LAYOUT_IDEMPOTENCY_CONFLICT')
                return prior['result']
            state=db.execute('''SELECT metadata_revision,policy_revision,commit_revision,enabled_capabilities FROM epm.application_state WHERE workspace_id=%s AND application_id=%s FOR UPDATE''',(scope.workspace_id,scope.application_id)).fetchone()
            if state is None or 'financial_consolidation' not in state['enabled_capabilities']:raise ValueError('APPLICATION_CAPABILITY_DISABLED')
            if state['metadata_revision']!=args['expectedMetadataRevision'] or state['policy_revision']!=args['expectedPolicyRevision']:raise ValueError('STALE_CONSOLIDATION_LAYOUT_PINS')
            rows=db.execute('''SELECT dimension_id,model_role FROM epm.dimension WHERE workspace_id=%s AND application_id=%s AND status='Active' AND (model_role IN('Account','Entity','Currency') OR dimension_id=ANY(%s::text[])) ORDER BY dimension_id''',(scope.workspace_id,scope.application_id,[args['stageDimensionId'],args['movementDimensionId']])).fetchall()
            roles={};custom={}
            for row in rows:
                if row['model_role'] in ('Account','Entity','Currency'):
                    if row['model_role'] in roles:raise ValueError('CONSOLIDATION_LAYOUT_ROLE_AMBIGUOUS')
                    roles[row['model_role']]=row['dimension_id']
                if row['dimension_id'] in (args['stageDimensionId'],args['movementDimensionId']):custom[row['dimension_id']]=row['model_role']
            if set(roles)!={'Account','Entity','Currency'} or custom!={args['stageDimensionId']:'Custom',args['movementDimensionId']:'Custom'}:raise ValueError('CONSOLIDATION_LAYOUT_UNSUPPORTED')
            document={'accountDimensionId':roles['Account'],'entityDimensionId':roles['Entity'],'currencyDimensionId':roles['Currency'],'stageDimensionId':args['stageDimensionId'],'movementDimensionId':args['movementDimensionId'],'metadataRevision':state['metadata_revision'],'policyRevision':state['policy_revision']+1}
            digest=_digest(document);version=db.execute('''SELECT COALESCE(max(layout_version),0)+1 AS version FROM epm.consolidation_layout_version WHERE workspace_id=%s AND application_id=%s''',(scope.workspace_id,scope.application_id)).fetchone()['version'];revision=state['commit_revision']+1
            db.execute('''INSERT INTO epm.consolidation_layout_version(workspace_id,application_id,layout_version,layout_digest,account_dimension_id,entity_dimension_id,currency_dimension_id,stage_dimension_id,movement_dimension_id,metadata_revision,policy_revision,issuer,subject_id) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',(scope.workspace_id,scope.application_id,version,digest,roles['Account'],roles['Entity'],roles['Currency'],args['stageDimensionId'],args['movementDimensionId'],state['metadata_revision'],state['policy_revision']+1,self.identity.issuer,self.identity.subject_id))
            db.execute('''INSERT INTO epm.consolidation_layout_state(workspace_id,application_id,active_layout_version,active_layout_digest) VALUES(%s,%s,%s,%s) ON CONFLICT(workspace_id,application_id) DO UPDATE SET active_layout_version=EXCLUDED.active_layout_version,active_layout_digest=EXCLUDED.active_layout_digest''',(scope.workspace_id,scope.application_id,version,digest))
            db.execute('''UPDATE epm.application_state SET policy_revision=policy_revision+1,commit_revision=%s WHERE workspace_id=%s AND application_id=%s''',(revision,scope.workspace_id,scope.application_id))
            result={**document,'layoutVersion':version,'layoutDigest':digest,'committedRevision':revision,'status':'Configured'}
            db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)''',(scope.workspace_id,scope.application_id,idempotency_key,command,self.identity.subject_id,revision,Jsonb(result)))
            return result

    def read(self,scope,program):
        name,_=compile_layout_program(program)
        if name!=READ:raise ValueError('CONSOLIDATION_LAYOUT_READ_REQUIRED')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            PostgresNumericFactStore._set_scope(db,scope);PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read',function=READ)
            row=resolve_active_layout(db,scope)
            return {'layoutVersion':row['layout_version'],'layoutDigest':row['layout_digest'],'accountDimensionId':row['account_dimension_id'],'entityDimensionId':row['entity_dimension_id'],'currencyDimensionId':row['currency_dimension_id'],'stageDimensionId':row['stage_dimension_id'],'movementDimensionId':row['movement_dimension_id'],'metadataRevision':row['metadata_revision'],'policyRevision':row['policy_revision'],'status':'Active'}
