"""Current saved-grid definitions shared by the browser and MCP clients."""
from __future__ import annotations

import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .current_object_contract import collection_token, new_state_token, require_state_token
from .cube_view_contract import canonical_cube_view, cube_view_digest
from .postgres_access import PostgresAccessChecker,VerifiedIdentity,assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout


SAVE='grid.definition.save'
DELETE='grid.definition.delete'
READ='grid.definition.read'
LIST='grid.definition.list'
_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{2,127}\Z')


def catalog() -> dict:
    return {
        SAVE:{'mode':'current_definition_write','permission':'write',
              'previewRequired':False,'idempotencyRequired':True,
              'workClass':'short',
              'arguments':{'gridId':'stable grid ID',
                  'definition':'canonical openepm-cube-view-v1 definition',
                  'expectedMetadataRevision':'current metadata revision'},
              'optionalArguments':{'expectedStateToken':'required when replacing an existing grid'},
              'result':'verified current saved-grid definition'},
        DELETE:{'mode':'current_definition_delete','permission':'write',
              'previewRequired':False,'idempotencyRequired':True,
              'workClass':'short',
              'arguments':{'gridId':'stable grid ID',
                  'expectedStateToken':'current grid state token'},
              'result':'verified current saved-grid deletion'},
        READ:{'mode':'read','permission':'read','previewRequired':False,
              'idempotencyRequired':False,'workClass':'short',
              'arguments':{'gridId':'stable grid ID'},
              'result':'one verified current saved-grid definition'},
        LIST:{'mode':'read','permission':'read','previewRequired':False,
              'idempotencyRequired':False,'workClass':'short',
              'arguments':{'limit':'optional 1-100','afterGridId':'optional stable cursor',
                  'expectedCollectionToken':'required with cursor'},
              'result':'current saved grids in stable order'}}


def _canonical(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(',',':'),
                      ensure_ascii=False,allow_nan=False).encode()


class PostgresSavedGrids:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity):
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError('A verified identity is required')
        assert_nonowner_role(dsn,'epm_runtime',('saved_grid_definition',))
        self.dsn=dsn;self.identity=identity

    @staticmethod
    def _program(program: object,functions: set[str]) -> tuple[str,dict]:
        if (not isinstance(program,dict)
                or set(program)!={'languageVersion','function','arguments'}
                or program.get('languageVersion')!=2
                or program.get('function') not in functions
                or type(program.get('arguments')) is not dict):
            raise ValueError('SAVED_GRID_PROGRAM_INVALID')
        return program['function'],program['arguments']

    @staticmethod
    def _target(grid_id: object) -> None:
        if not isinstance(grid_id,str) or not _ID.fullmatch(grid_id):
            raise ValueError('SAVED_GRID_ID_INVALID')

    def _prepare(self,db,scope: ApplicationScope,permission: str,function: str) -> None:
        if not isinstance(scope,ApplicationScope):
            raise ValueError('SAVED_GRID_SCOPE_INVALID')
        configure_lock_wait(db);configure_statement_timeout(db,5000)
        PostgresNumericFactStore._set_scope(db,scope)
        PostgresAccessChecker.check_in_transaction(
            db,self.identity,scope,permission,function=function)

    @staticmethod
    def _definition(value: object, *, active_dimensions=None) -> dict:
        definition=canonical_cube_view(value,active_dimensions=active_dimensions)
        if len(_canonical(definition))>1_000_000:
            raise ValueError('SAVED_GRID_DEFINITION_TOO_LARGE')
        return definition

    @staticmethod
    def _validate_metadata(db,scope: ApplicationScope,definition: dict,
                           expected_revision: int) -> tuple[dict,list[str]]:
        state=db.execute('''SELECT metadata_revision FROM epm.application_state
            WHERE workspace_id=%s AND application_id=%s FOR SHARE''',
            (scope.workspace_id,scope.application_id)).fetchone()
        if not state or state['metadata_revision']!=expected_revision:
            raise ValueError('SAVED_GRID_METADATA_STALE')
        rows=db.execute('''SELECT dimension_id FROM epm.dimension
            WHERE workspace_id=%s AND application_id=%s AND status='Active'
            ORDER BY dimension_id''',
            (scope.workspace_id,scope.application_id)).fetchall()
        dimensions=[row['dimension_id'] for row in rows]
        canonical=PostgresSavedGrids._definition(
            definition,active_dimensions=dimensions)
        if canonical['selection']['metadataRevision']!=expected_revision:
            raise ValueError('SAVED_GRID_METADATA_REVISION_MISMATCH')
        return canonical,dimensions

    @staticmethod
    def _result(row: dict,*,include_definition: bool=True) -> dict:
        value={'gridId':row['grid_id'],'stateToken':row['state_token'],'name':row['name'],
               'canonicalDigest':row['canonical_digest'],
               'metadataRevision':row['metadata_revision'],
               'creator':{'issuer':row['creator_issuer'],
                          'subjectId':row['creator_subject_id']},
               'updatedAt':row['updated_at'].isoformat()}
        if include_definition:value['definition']=row['definition']
        return value

    def save(self,scope: ApplicationScope,program: object,*,idempotency_key: str) -> dict:
        _,args=self._program(program,{SAVE})
        required={'gridId','definition','expectedMetadataRevision'}
        if not required<=set(args) or set(args)-required-{'expectedStateToken'}:
            raise ValueError('SAVED_GRID_ARGUMENTS_INVALID')
        self._target(args['gridId'])
        if 'expectedStateToken' in args:
            require_state_token(args['expectedStateToken'],error='SAVED_GRID_STATE_TOKEN_INVALID')
        if (not isinstance(idempotency_key,str)
                or re.fullmatch(r'[A-Za-z0-9._-]{8,128}',idempotency_key) is None):
            raise ValueError('SAVED_GRID_IDEMPOTENCY_KEY_INVALID')
        if type(args['expectedMetadataRevision']) is not int or args['expectedMetadataRevision']<1:
            raise ValueError('SAVED_GRID_METADATA_REVISION_INVALID')
        definition=self._definition(args['definition'])
        if definition['viewId']!=args['gridId']:
            raise ValueError('SAVED_GRID_VIEW_ID_MISMATCH')
        command_digest=_canonical_digest({'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],'program':program})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                self._prepare(db,scope,'write',SAVE)
                state=db.execute('''SELECT s.metadata_revision,s.commit_revision,
                    s.processing_mode,a.status FROM epm.application_state s
                    JOIN epm.application a USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:raise ValueError('APPLICATION_UNAVAILABLE')
                prior=db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
                if prior:
                    if (prior['command_digest']!=command_digest
                            or prior['actor_id']!=self.identity.subject_id):
                        raise ValueError('SAVED_GRID_IDEMPOTENCY_CONFLICT')
                    return prior['result']
                if state['status']!='Active' or state['processing_mode']!='Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                definition,dimensions=self._validate_metadata(
                    db,scope,definition,args['expectedMetadataRevision'])
                digest=cube_view_digest(definition,active_dimensions=dimensions)
                existing=db.execute('''SELECT * FROM epm.saved_grid_definition
                    WHERE workspace_id=%s AND application_id=%s AND grid_id=%s
                    FOR UPDATE''',(scope.workspace_id,scope.application_id,
                    args['gridId'])).fetchone()
                if existing is None and 'expectedStateToken' in args:
                    raise ValueError('SAVED_GRID_NOT_FOUND')
                if existing is not None:
                    if 'expectedStateToken' not in args:
                        raise ValueError('SAVED_GRID_STATE_TOKEN_REQUIRED')
                    if args['expectedStateToken']!=existing['state_token']:
                        raise ValueError('SAVED_GRID_STATE_CONFLICT')
                state_token=new_state_token();revision=state['commit_revision']+1
                result={'gridId':args['gridId'],'stateToken':state_token,
                    'name':definition['name'],'definition':definition,
                    'canonicalDigest':digest,
                    'metadataRevision':args['expectedMetadataRevision'],
                    'creator':{'issuer':self.identity.issuer,
                               'subjectId':self.identity.subject_id}}
                db.execute('''UPDATE epm.application_state SET commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (revision,scope.workspace_id,scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt(workspace_id,
                    application_id,operation_id,command_digest,actor_id,
                    committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id,scope.application_id,idempotency_key,
                     command_digest,self.identity.subject_id,revision,Jsonb(result)))
                db.execute('''INSERT INTO epm.saved_grid_definition
                    (workspace_id,application_id,grid_id,name,definition,
                     canonical_digest,state_token,metadata_revision,creator_issuer,
                     creator_subject_id,updated_operation_id)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT(workspace_id,application_id,grid_id) DO UPDATE SET
                      name=EXCLUDED.name,definition=EXCLUDED.definition,
                      canonical_digest=EXCLUDED.canonical_digest,
                      state_token=EXCLUDED.state_token,
                      metadata_revision=EXCLUDED.metadata_revision,
                      creator_issuer=EXCLUDED.creator_issuer,
                      creator_subject_id=EXCLUDED.creator_subject_id,
                      updated_operation_id=EXCLUDED.updated_operation_id,
                      updated_at=transaction_timestamp()''',
                    (scope.workspace_id,scope.application_id,args['gridId'],
                     definition['name'],Jsonb(definition),digest,state_token,
                     args['expectedMetadataRevision'],self.identity.issuer,
                     self.identity.subject_id,idempotency_key))
                return result

    def delete(self,scope: ApplicationScope,program: object,*,idempotency_key: str) -> dict:
        _,args=self._program(program,{DELETE})
        if set(args)!={'gridId','expectedStateToken'}:
            raise ValueError('SAVED_GRID_ARGUMENTS_INVALID')
        self._target(args['gridId'])
        require_state_token(args['expectedStateToken'],error='SAVED_GRID_STATE_TOKEN_INVALID')
        if (not isinstance(idempotency_key,str)
                or re.fullmatch(r'[A-Za-z0-9._-]{8,128}',idempotency_key) is None):
            raise ValueError('SAVED_GRID_IDEMPOTENCY_KEY_INVALID')
        command_digest=_canonical_digest({'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],'program':program})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                self._prepare(db,scope,'write',DELETE)
                state=db.execute('''SELECT s.commit_revision,s.processing_mode,a.status
                    FROM epm.application_state s JOIN epm.application a
                    USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:raise ValueError('APPLICATION_UNAVAILABLE')
                prior=db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
                if prior:
                    if (prior['command_digest']!=command_digest
                            or prior['actor_id']!=self.identity.subject_id):
                        raise ValueError('SAVED_GRID_IDEMPOTENCY_CONFLICT')
                    return prior['result']
                if state['status']!='Active' or state['processing_mode']!='Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                existing=db.execute('''SELECT state_token FROM epm.saved_grid_definition
                    WHERE workspace_id=%s AND application_id=%s AND grid_id=%s
                    FOR UPDATE''',(scope.workspace_id,scope.application_id,
                    args['gridId'])).fetchone()
                if existing is None:raise ValueError('SAVED_GRID_NOT_FOUND')
                if existing['state_token']!=args['expectedStateToken']:
                    raise ValueError('SAVED_GRID_STATE_CONFLICT')
                revision=state['commit_revision']+1
                result={'operationId':idempotency_key,'gridId':args['gridId'],
                    'status':'Deleted'}
                db.execute('''UPDATE epm.application_state SET commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (revision,scope.workspace_id,scope.application_id))
                db.execute('''DELETE FROM epm.saved_grid_definition
                    WHERE workspace_id=%s AND application_id=%s AND grid_id=%s''',
                    (scope.workspace_id,scope.application_id,args['gridId']))
                db.execute('''INSERT INTO epm.operation_receipt(workspace_id,
                    application_id,operation_id,command_digest,actor_id,
                    committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id,scope.application_id,idempotency_key,
                     command_digest,self.identity.subject_id,revision,Jsonb(result)))
                return result

    def read(self,scope: ApplicationScope,program: object) -> dict:
        function,args=self._program(program,{READ,LIST})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                self._prepare(db,scope,'read',function)
                if function==READ:
                    if set(args)!={'gridId'}:raise ValueError('SAVED_GRID_ARGUMENTS_INVALID')
                    self._target(args['gridId'])
                    row=db.execute('''SELECT * FROM epm.saved_grid_definition
                        WHERE workspace_id=%s AND application_id=%s AND grid_id=%s
                        ''',(scope.workspace_id,scope.application_id,
                        args['gridId'])).fetchone()
                    if not row:raise ValueError('SAVED_GRID_NOT_FOUND')
                    return self._result(row)
                if set(args)-{'limit','afterGridId','expectedCollectionToken'}:
                    raise ValueError('SAVED_GRID_ARGUMENTS_INVALID')
                limit=args.get('limit',100);after=args.get('afterGridId')
                if type(limit) is not int or not 1<=limit<=100:raise ValueError('SAVED_GRID_LIMIT_INVALID')
                if after is not None:self._target(after)
                if after is not None and 'expectedCollectionToken' not in args:
                    raise ValueError('SAVED_GRID_CONTINUATION_PIN_REQUIRED')
                if 'expectedCollectionToken' in args:
                    require_state_token(args['expectedCollectionToken'],
                                        error='SAVED_GRID_COLLECTION_TOKEN_INVALID')
                token_rows=db.execute('''SELECT grid_id,state_token
                    FROM epm.saved_grid_definition WHERE workspace_id=%s
                    AND application_id=%s ORDER BY grid_id''',
                    (scope.workspace_id,scope.application_id)).fetchall()
                current_token=collection_token((row['grid_id'],row['state_token'])
                                               for row in token_rows)
                if ('expectedCollectionToken' in args
                        and args['expectedCollectionToken']!=current_token):
                    raise ValueError('SAVED_GRID_LIST_STALE')
                rows=db.execute('''SELECT *
                    FROM epm.saved_grid_definition WHERE workspace_id=%s
                    AND application_id=%s AND (%s::text IS NULL OR grid_id>%s)
                    ORDER BY grid_id LIMIT %s''',
                    (scope.workspace_id,scope.application_id,after,after,limit+1)).fetchall()
                values=[self._result(row) for row in rows[:limit]]
                return {'grids':values,'nextAfterGridId':(
                    values[-1]['gridId'] if len(rows)>limit else None),
                    'collectionToken':current_token}
