"""Versioned saved-grid definitions shared by the browser and MCP clients."""
from __future__ import annotations

from hashlib import sha256
import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker,VerifiedIdentity,assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout


SAVE='grid.definition.save'
READ='grid.definition.read'
LIST='grid.definition.list'
_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{2,127}\Z')


def catalog() -> dict:
    return {
        SAVE:{'mode':'immutable_definition_write','permission':'write',
              'previewRequired':False,'idempotencyRequired':False,
              'workClass':'short',
              'arguments':{'gridId':'stable grid ID','version':'positive immutable version',
                  'name':'display name','definition':'bounded row/column/POV definition',
                  'expectedMetadataRevision':'current metadata revision'},
              'result':'verified immutable saved-grid version'},
        READ:{'mode':'read','permission':'read','previewRequired':False,
              'idempotencyRequired':False,'workClass':'short',
              'arguments':{'gridId':'stable grid ID','version':'positive immutable version'},
              'result':'one verified saved-grid definition'},
        LIST:{'mode':'read','permission':'read','previewRequired':False,
              'idempotencyRequired':False,'workClass':'short',
              'arguments':{'limit':'optional 1-100','afterGridId':'optional stable cursor'},
              'result':'latest version of each saved grid in stable order'}}


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
    def _target(grid_id: object,version: object|None=None) -> None:
        if not isinstance(grid_id,str) or not _ID.fullmatch(grid_id):
            raise ValueError('SAVED_GRID_ID_INVALID')
        if version is not None and (type(version) is not int or version<1):
            raise ValueError('SAVED_GRID_VERSION_INVALID')

    def _prepare(self,db,scope: ApplicationScope,permission: str,function: str) -> None:
        if not isinstance(scope,ApplicationScope):
            raise ValueError('SAVED_GRID_SCOPE_INVALID')
        configure_lock_wait(db);configure_statement_timeout(db,5000)
        PostgresNumericFactStore._set_scope(db,scope)
        PostgresAccessChecker.check_in_transaction(
            db,self.identity,scope,permission,function=function)

    @staticmethod
    def _definition(value: object) -> dict:
        fields={'rowDimensions','columnDimensions','pov','dataLayer','pageSize'}
        if not isinstance(value,dict) or set(value)-({'resultKey'}|fields) or not fields<=set(value):
            raise ValueError('SAVED_GRID_DEFINITION_INVALID')
        rows=value['rowDimensions'];columns=value['columnDimensions'];pov=value['pov']
        if (not isinstance(rows,list) or not isinstance(columns,list)
                or any(not isinstance(v,str) or not v or len(v)>200 for v in rows+columns)
                or len(set(rows+columns))!=len(rows+columns)
                or not rows or not columns or len(rows)+len(columns)>20):
            raise ValueError('SAVED_GRID_AXES_INVALID')
        if (not isinstance(pov,dict) or len(pov)>50
                or any(not isinstance(k,str) or not k or len(k)>200
                       or not isinstance(v,str) or not v or len(v)>200
                       for k,v in pov.items())
                or set(pov)&set(rows+columns)):
            raise ValueError('SAVED_GRID_POV_INVALID')
        if value['dataLayer'] not in ('raw','calculated'):
            raise ValueError('SAVED_GRID_LAYER_INVALID')
        if type(value['pageSize']) is not int or not 1<=value['pageSize']<=500:
            raise ValueError('SAVED_GRID_PAGE_SIZE_INVALID')
        result_key=value.get('resultKey')
        if ((value['dataLayer']=='calculated') !=
                (isinstance(result_key,str) and 1<=len(result_key)<=200)):
            raise ValueError('SAVED_GRID_RESULT_KEY_INVALID')
        if len(_canonical(value))>1_000_000:
            raise ValueError('SAVED_GRID_DEFINITION_TOO_LARGE')
        return value

    @staticmethod
    def _validate_metadata(db,scope: ApplicationScope,definition: dict,
                           expected_revision: int) -> None:
        state=db.execute('''SELECT metadata_revision FROM epm.application_state
            WHERE workspace_id=%s AND application_id=%s FOR SHARE''',
            (scope.workspace_id,scope.application_id)).fetchone()
        if not state or state['metadata_revision']!=expected_revision:
            raise ValueError('SAVED_GRID_METADATA_STALE')
        dimensions=set(definition['rowDimensions'])|set(definition['columnDimensions'])|set(definition['pov'])
        rows=db.execute('''SELECT dimension_id FROM epm.dimension
            WHERE workspace_id=%s AND application_id=%s AND status='Active'
            AND dimension_id=ANY(%s)''',
            (scope.workspace_id,scope.application_id,list(dimensions))).fetchall()
        if {row['dimension_id'] for row in rows}!=dimensions:
            raise ValueError('SAVED_GRID_DIMENSION_INVALID')
        for dimension_id,member_id in definition['pov'].items():
            exists=db.execute('''SELECT 1 FROM epm.member WHERE workspace_id=%s
                AND application_id=%s AND dimension_id=%s AND member_id=%s
                AND status='Active' ''',
                (scope.workspace_id,scope.application_id,dimension_id,member_id)).fetchone()
            if not exists:raise ValueError('SAVED_GRID_MEMBER_INVALID')

    @staticmethod
    def _result(row: dict,*,include_definition: bool=True) -> dict:
        value={'gridId':row['grid_id'],'version':row['version'],'name':row['name'],
               'canonicalDigest':row['canonical_digest'],
               'metadataRevision':row['metadata_revision'],
               'creator':{'issuer':row['creator_issuer'],
                          'subjectId':row['creator_subject_id']},
               'createdAt':row['created_at'].isoformat()}
        if include_definition:value['definition']=row['definition']
        return value

    def save(self,scope: ApplicationScope,program: object) -> dict:
        _,args=self._program(program,{SAVE})
        if set(args)!={'gridId','version','name','definition','expectedMetadataRevision'}:
            raise ValueError('SAVED_GRID_ARGUMENTS_INVALID')
        self._target(args['gridId'],args['version'])
        if (not isinstance(args['name'],str) or args['name']!=args['name'].strip()
                or not 1<=len(args['name'])<=200 or any(ord(c)<32 for c in args['name'])):
            raise ValueError('SAVED_GRID_NAME_INVALID')
        if type(args['expectedMetadataRevision']) is not int or args['expectedMetadataRevision']<1:
            raise ValueError('SAVED_GRID_METADATA_REVISION_INVALID')
        definition=self._definition(args['definition'])
        digest=sha256(_canonical({'name':args['name'],'definition':definition,
            'metadataRevision':args['expectedMetadataRevision']})).hexdigest()
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                self._prepare(db,scope,'write',SAVE)
                self._validate_metadata(db,scope,definition,args['expectedMetadataRevision'])
                existing=db.execute('''SELECT * FROM epm.saved_grid_definition
                    WHERE workspace_id=%s AND application_id=%s AND grid_id=%s
                    AND version=%s''',(scope.workspace_id,scope.application_id,
                    args['gridId'],args['version'])).fetchone()
                if existing:
                    if existing['canonical_digest']!=digest:
                        raise ValueError('SAVED_GRID_VERSION_CONFLICT')
                    return self._result(existing)
                latest=db.execute('''SELECT max(version) AS version
                    FROM epm.saved_grid_definition WHERE workspace_id=%s
                    AND application_id=%s AND grid_id=%s''',
                    (scope.workspace_id,scope.application_id,args['gridId'])).fetchone()['version']
                if args['version']!=(1 if latest is None else latest+1):
                    raise ValueError('SAVED_GRID_VERSION_NOT_NEXT')
                row=db.execute('''INSERT INTO epm.saved_grid_definition
                    (workspace_id,application_id,grid_id,version,name,definition,
                     canonical_digest,metadata_revision,creator_issuer,creator_subject_id)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *''',
                    (scope.workspace_id,scope.application_id,args['gridId'],args['version'],
                     args['name'],Jsonb(definition),digest,args['expectedMetadataRevision'],
                     self.identity.issuer,self.identity.subject_id)).fetchone()
                return self._result(row)

    def read(self,scope: ApplicationScope,program: object) -> dict:
        function,args=self._program(program,{READ,LIST})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                self._prepare(db,scope,'read',function)
                if function==READ:
                    if set(args)!={'gridId','version'}:raise ValueError('SAVED_GRID_ARGUMENTS_INVALID')
                    self._target(args['gridId'],args['version'])
                    row=db.execute('''SELECT * FROM epm.saved_grid_definition
                        WHERE workspace_id=%s AND application_id=%s AND grid_id=%s
                        AND version=%s''',(scope.workspace_id,scope.application_id,
                        args['gridId'],args['version'])).fetchone()
                    if not row:raise ValueError('SAVED_GRID_NOT_FOUND')
                    return self._result(row)
                if set(args)-{'limit','afterGridId'}:raise ValueError('SAVED_GRID_ARGUMENTS_INVALID')
                limit=args.get('limit',100);after=args.get('afterGridId')
                if type(limit) is not int or not 1<=limit<=100:raise ValueError('SAVED_GRID_LIMIT_INVALID')
                if after is not None:self._target(after)
                rows=db.execute('''SELECT DISTINCT ON (grid_id) *
                    FROM epm.saved_grid_definition WHERE workspace_id=%s
                    AND application_id=%s AND (%s::text IS NULL OR grid_id>%s)
                    ORDER BY grid_id,version DESC LIMIT %s''',
                    (scope.workspace_id,scope.application_id,after,after,limit+1)).fetchall()
                values=[self._result(row) for row in rows[:limit]]
                return {'grids':values,'nextAfterGridId':(
                    values[-1]['gridId'] if len(rows)>limit else None)}
