"""Current saved-grid definitions shared by the browser and MCP clients."""
from __future__ import annotations

import json
import re

from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .current_object_contract import STATE_TOKEN_PATTERN, collection_token, new_state_token, require_state_token
from .cube_view_contract import FORMAT as VIEW_FORMAT, canonical_cube_view, cube_view_digest, structural_schema
from .postgres_access import AccessDenied,PostgresAccessChecker,VerifiedIdentity,assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import (
    metadata_selection_visible_sql,
    reject_mixed_metadata_reads, resolve_effective_dimensional_scope,
)
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout
from .selection_contract import FORMAT as SELECTION_FORMAT, structural_schema_definitions


SAVE='grid.definition.save'
DELETE='grid.definition.delete'
READ='grid.definition.read'
LIST='grid.definition.list'
FUNCTIONS = frozenset((SAVE, DELETE, READ, LIST))
_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{2,127}\Z')
_OPERATION_ID = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_AUTHORITY_STALE = 'SAVED_GRID_AUTHORIZATION_STALE'
_OBSERVED_REVISIONS = ('current_metadata_revision', 'policy_revision', 'security_revision', 'schema_epoch')


def _view_visible_sql(authority, alias='g'):
    return metadata_selection_visible_sql(authority, alias,
        sql.SQL("{}.definition->'selection'").format(sql.Identifier(alias)))


def _object_visible_sql(authority, action, alias='g'):
    if authority.privileges is None:
        return sql.SQL('TRUE')
    targets = authority.privileges.object_targets(action, 'saved_view')
    if targets is None:
        return sql.SQL('TRUE')
    return sql.SQL('{}=ANY({}::text[])').format(sql.Identifier(alias,'grid_id'), sql.Literal(sorted(targets)))


def _require_view_target(authority, action, grid_id):
    if authority.privileges is not None:
        targets = authority.privileges.object_targets(action, 'saved_view')
        if targets is not None and grid_id not in targets:
            raise ValueError('SAVED_GRID_NOT_FOUND')


def saved_grid_program_contract(function: str) -> dict:
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj

    def exact_string(pattern):
        return {'type': 'string', 'pattern': '^' + pattern.pattern.removesuffix(r'\Z') + r'(?![\s\S])'}

    identifier = exact_string(_ID)
    nullable_identifier = {'anyOf': [identifier, {'type': 'null'}]}
    token = exact_string(STATE_TOKEN_PATTERN)
    revision = {'type': 'integer', 'minimum': 1}
    view = structural_schema()
    record = {'gridId': identifier, 'stateToken': token, 'canonicalDigest': token,
              'name': {'type': 'string', 'minLength': 1, 'maxLength': 200},
              'metadataRevision': revision, 'definition': view,
              'creator': obj({'issuer': {'type': 'string'}, 'subjectId': {'type': 'string'}})}
    stored = obj({**record, 'updatedAt': {'type': 'string', 'format': 'date-time'}})
    grid_id, example_token = 'comparison', 'a' * 64
    target = {'gridId': grid_id}
    if function == LIST:
        arguments = obj({'limit': {'type': 'integer', 'minimum': 1, 'maximum': 100, 'default': 100},
                         'afterGridId': nullable_identifier, 'expectedCollectionToken': token}, [])
        arguments['allOf'] = [{'if': {'required': ['afterGridId'],
                                      'properties': {'afterGridId': {'type': 'string'}}},
                               'then': {'required': ['expectedCollectionToken']}}]
        result = obj({'grids': {'type': 'array', 'items': stored, 'maxItems': 100},
                      'nextAfterGridId': nullable_identifier, 'collectionToken': token})
        examples = [
            read_example(function, {'limit': 1}, name='Read the first saved view page',
                         binding='Choose a currently readable application. An empty list is a successful result.'),
            read_example(function, {'limit': 1, 'afterGridId': grid_id, 'expectedCollectionToken': example_token},
                         name='Read the next page of the same collection',
                         binding='Copy nextAfterGridId and collectionToken from the preceding response. Stop when the cursor is null.')]
        rules = ['The collection token and page describe one visible database snapshot. Under active dimensional policy, definitions are projected before pagination and the token binds the current actor and scope.',
                 'A policy that rejects mixed selections can refuse the entire collection with SAVED_GRID_SCOPE_UNAVAILABLE.']
    elif function == READ:
        arguments, result = obj({'gridId': identifier}), stored
        examples = [read_example(function, target, name='Open a current saved view definition',
            binding='Use a gridId from grid.definition.list in the same application. Use the definition with facts.cube.resolved.read to evaluate visible values separately.')]
        rules = ['The definition describes the saved selection and layout. The complete definition requires current access to typed references in both include and exclude selectors. Protected and absent views return SAVED_GRID_NOT_FOUND.',
                 'Evaluating the view requires a separate current authorized cube read.']
    elif function == SAVE:
        fields = {'gridId': identifier, 'definition': view, 'expectedMetadataRevision': revision}
        arguments = obj({**fields, 'expectedStateToken': token}, list(fields))
        definition = {'format': VIEW_FORMAT, 'viewId': grid_id, 'name': 'Comparison',
            'selection': {'format': SELECTION_FORMAT, 'metadataRevision': 1,
                'dimensions': [{'dimensionId': axis, 'include': {'kind': 'member', 'memberId': member},
                                'exclude': None} for axis, member in (('custom-axis', 'member-a'), ('Region', 'East'))]},
            'layout': {'rows': ['custom-axis'], 'columns': ['Region'], 'pages': [], 'filters': []},
            'dataSource': {'kind': 'raw', 'resultKey': None},
            'suppression': {'missing': False, 'zero': False}, 'pageSize': 1}
        create = {**target, 'definition': definition, 'expectedMetadataRevision': 1}
        binding = ('This example uses a two-axis fixture. Bind selectors and layout to the full active fact grain, '
                   'and copy the current metadata revision into both revision fields.')
        examples = [read_example(function, create, name='Save a new view', binding=binding),
            read_example(function, {**create, 'expectedStateToken': example_token}, name='Replace a current view',
                binding=binding + ' Read the existing definition and its stateToken before editing.')]
        result = obj(record)
        rules = ['gridId and definition.viewId must match. The fixed core validates the active fact layout, selection, references, and current metadata revision.',
                 'Omit expectedStateToken to create. Replace only with the exact current stateToken from a read. A successful save returns a fresh token.']
    elif function == DELETE:
        arguments = obj({'gridId': identifier, 'expectedStateToken': token})
        result = obj({'operationId': exact_string(_OPERATION_ID), 'gridId': identifier, 'status': {'const': 'Deleted'}})
        examples = [read_example(function, {**target, 'expectedStateToken': example_token}, name='Delete an exact saved view',
            binding='Use the current gridId and stateToken from grid.definition.read after explicitly confirming which saved view to delete.')]
        rules = ['Delete removes the current saved definition. In a group-assigned application, the views.delete duty is application-wide. Retire every exact access scope referencing this view before deletion.']
    else:
        raise ValueError('SAVED_GRID_PROGRAM_INVALID')
    if function in (SAVE, DELETE):
        rules.append('Obtain signed operation admission and send the unchanged program through execute_v2_metadata_program. The fixed transaction rechecks current write authority and access to the stored or proposed selection. A replay discloses a prior definition only under current read authority for its references.')
        recovery = ('After a stale definition or metadata conflict, reread the current state before composing a new intent. '
                    'If the acknowledgement was lost, use application.operation.receipt.read with the original admitted operation ID. '
                    'Any retry uses the exact original admitted packet.')
    else:
        rules.append('Use read_v2_program. The fixed core rechecks current application and dimensional READ.')
        recovery = ('On SAVED_GRID_LIST_STALE, restart at the first page. On SAVED_GRID_NOT_FOUND, '
                    'list the currently available saved views and use an exact returned ID.')
    contract = read_contract(function, arguments, result, owner='PostgresSavedGrids',
        examples=examples, semantic_rules=rules,
        definitions=structural_schema_definitions() if function != DELETE else None)
    contract['programContract']['recovery'] = recovery
    return contract


def catalog() -> dict:
    functions = {
        SAVE:{'mode':'current_definition_write','permission':'write',
              'previewRequired':False,'idempotencyRequired':True,
              'workClass':'short',
              'arguments':{'gridId':'stable grid ID',
                  'definition':'canonical openepm-cube-view-v1 definition over the active fact layout',
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
              'arguments':{},
              'optionalArguments':{'limit':'optional 1-100','afterGridId':'optional stable cursor',
                  'expectedCollectionToken':'required with cursor'},
              'result':'current saved grids in stable order'}}
    for function, specification in functions.items():
        specification.update(saved_grid_program_contract(function))
    return functions


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

    def _prepare(self,db,scope: ApplicationScope,permission: str,function: str):
        if not isinstance(scope,ApplicationScope):
            raise ValueError('SAVED_GRID_SCOPE_INVALID')
        configure_lock_wait(db);configure_statement_timeout(db,5000)
        PostgresNumericFactStore._set_scope(db,scope)
        return PostgresAccessChecker.check_in_transaction(
            db,self.identity,scope,permission,function=function)

    def _recheck_authority(self, db, scope, permission, function, authority):
        access = PostgresAccessChecker.check_in_transaction(db, self.identity, scope, permission, function=function)
        if access != authority.access or resolve_effective_dimensional_scope(
                db, self.identity, scope, access=access).scope_digest != authority.scope_digest:
            raise ValueError(_AUTHORITY_STALE)

    @staticmethod
    def _require_visible_definition(db, scope, authority, definition):
        if authority.policy is None or authority.administrator_bypass:
            return
        row = db.execute(sql.SQL('''SELECT {} AS visible FROM
            (VALUES (%s::text,%s::text,%s::jsonb)) g(workspace_id,application_id,definition)''').format(
                _view_visible_sql(authority)),
            (scope.workspace_id, scope.application_id, Jsonb(definition))).fetchone()
        if row['visible'] is not True:
            raise AccessDenied('SAVED_GRID_SCOPE_UNAVAILABLE')

    def _finish_read(self, db, scope, function, authority, observed):
        self._recheck_authority(db, scope, 'read', function, authority)
        if authority.policy is None:
            return
        current = db.execute('''SELECT metadata_revision AS current_metadata_revision,
            policy_revision,security_revision,schema_epoch FROM epm.application_state
            WHERE workspace_id=%s AND application_id=%s''', (scope.workspace_id, scope.application_id)).fetchone()
        if current is None or any(current[key] != observed[key] for key in _OBSERVED_REVISIONS):
            raise ValueError('SAVED_GRID_LIST_STALE' if function == LIST else 'SAVED_GRID_READ_STALE')

    @staticmethod
    def _definition(value: object, *, active_dimensions=None) -> dict:
        definition=canonical_cube_view(value,active_dimensions=active_dimensions)
        if len(_canonical(definition))>1_000_000:
            raise ValueError('SAVED_GRID_DEFINITION_TOO_LARGE')
        return definition

    @staticmethod
    def _validate_metadata(db,scope: ApplicationScope,definition: dict,
                           expected_revision: int) -> tuple[dict,list[str]]:
        state=db.execute('''SELECT s.metadata_revision, l.dimensions
            FROM epm.application_state s LEFT JOIN epm.coordinate_layout l
              USING(workspace_id,application_id,schema_epoch)
            WHERE s.workspace_id=%s AND s.application_id=%s FOR SHARE OF s''',
            (scope.workspace_id,scope.application_id)).fetchone()
        if not state or state['metadata_revision']!=expected_revision:
            raise ValueError('SAVED_GRID_METADATA_STALE')
        if state['dimensions'] is None:
            raise ValueError('COORDINATE_LAYOUT_UNAVAILABLE')
        dimensions=list(state['dimensions'])
        canonical=PostgresSavedGrids._definition(
            definition,active_dimensions=dimensions)
        if canonical['selection']['metadataRevision']!=expected_revision:
            raise ValueError('SAVED_GRID_METADATA_REVISION_MISMATCH')
        references = {(item['dimensionId'], selector['listId'])
            for item in canonical['selection']['dimensions']
            for selector in (item['include'], item['exclude'])
            if selector is not None and selector['kind'] == 'member_list'}
        if references:
            rows = db.execute('''
                SELECT dimension_id,list_id FROM epm.member_list_definition
                WHERE workspace_id=%s AND application_id=%s AND list_id=ANY(%s)''',
                (scope.workspace_id, scope.application_id,
                 sorted({list_id for _, list_id in references}))).fetchall()
            if not references <= {(row['dimension_id'], row['list_id']) for row in rows}:
                raise ValueError('SAVED_GRID_MEMBER_LIST_REFERENCE_UNAVAILABLE')
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
        if not isinstance(idempotency_key, str) or not _OPERATION_ID.fullmatch(idempotency_key):
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
                access = self._prepare(db,scope,'write',SAVE)
                state=db.execute('''SELECT s.metadata_revision,s.commit_revision,
                    s.processing_mode,a.status FROM epm.application_state s
                    JOIN epm.application a USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:raise ValueError('APPLICATION_UNAVAILABLE')
                authority = resolve_effective_dimensional_scope(db, self.identity, scope, access=access)
                _require_view_target(authority,'views.save',args['gridId'])
                prior=db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
                if prior:
                    if (prior['command_digest']!=command_digest
                            or prior['actor_id']!=self.identity.subject_id):
                        raise ValueError('SAVED_GRID_IDEMPOTENCY_CONFLICT')
                    self._require_visible_definition(db, scope, authority, prior['result'].get('definition'))
                    self._recheck_authority(db, scope, 'write', SAVE, authority)
                    return prior['result']
                if state['status']!='Active' or state['processing_mode']!='Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                self._require_visible_definition(db, scope, authority, definition)
                definition,dimensions=self._validate_metadata(
                    db,scope,definition,args['expectedMetadataRevision'])
                digest=cube_view_digest(definition,active_dimensions=dimensions)
                existing=db.execute(sql.SQL('''SELECT g.state_token,{} AS visible FROM epm.saved_grid_definition g
                    WHERE workspace_id=%s AND application_id=%s AND grid_id=%s
                    FOR UPDATE''').format(_view_visible_sql(authority)),(scope.workspace_id,scope.application_id,
                    args['gridId'])).fetchone()
                if existing is None and 'expectedStateToken' in args:
                    raise ValueError('SAVED_GRID_NOT_FOUND')
                if existing is not None:
                    if existing['visible'] is not True:
                        if 'expectedStateToken' in args:
                            raise ValueError('SAVED_GRID_NOT_FOUND')
                        raise AccessDenied('SAVED_GRID_SCOPE_UNAVAILABLE')
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
                self._recheck_authority(db, scope, 'write', SAVE, authority)
                return result

    def delete(self,scope: ApplicationScope,program: object,*,idempotency_key: str) -> dict:
        _,args=self._program(program,{DELETE})
        if set(args)!={'gridId','expectedStateToken'}:
            raise ValueError('SAVED_GRID_ARGUMENTS_INVALID')
        self._target(args['gridId'])
        require_state_token(args['expectedStateToken'],error='SAVED_GRID_STATE_TOKEN_INVALID')
        if not isinstance(idempotency_key, str) or not _OPERATION_ID.fullmatch(idempotency_key):
            raise ValueError('SAVED_GRID_IDEMPOTENCY_KEY_INVALID')
        command_digest=_canonical_digest({'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],'program':program})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                access = self._prepare(db,scope,'write',DELETE)
                state=db.execute('''SELECT s.commit_revision,s.processing_mode,a.status
                    FROM epm.application_state s JOIN epm.application a
                    USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:raise ValueError('APPLICATION_UNAVAILABLE')
                authority = resolve_effective_dimensional_scope(db, self.identity, scope, access=access)
                _require_view_target(authority,'views.delete',args['gridId'])
                prior=db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
                if prior:
                    if (prior['command_digest']!=command_digest
                            or prior['actor_id']!=self.identity.subject_id):
                        raise ValueError('SAVED_GRID_IDEMPOTENCY_CONFLICT')
                    self._recheck_authority(db, scope, 'write', DELETE, authority)
                    return prior['result']
                if state['status']!='Active' or state['processing_mode']!='Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                existing=db.execute(sql.SQL('''SELECT g.state_token,{} AS visible FROM epm.saved_grid_definition g
                    WHERE workspace_id=%s AND application_id=%s AND grid_id=%s
                    FOR UPDATE''').format(_view_visible_sql(authority)),(scope.workspace_id,scope.application_id,
                    args['gridId'])).fetchone()
                if existing is None or existing['visible'] is not True:raise ValueError('SAVED_GRID_NOT_FOUND')
                if existing['state_token']!=args['expectedStateToken']:
                    raise ValueError('SAVED_GRID_STATE_CONFLICT')
                revision=state['commit_revision']+1
                result={'operationId':idempotency_key,'gridId':args['gridId'],
                    'status':'Deleted'}
                db.execute('''UPDATE epm.application_state SET commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (revision,scope.workspace_id,scope.application_id))
                from psycopg.errors import ForeignKeyViolation
                try:
                    db.execute('''DELETE FROM epm.saved_grid_definition
                        WHERE workspace_id=%s AND application_id=%s AND grid_id=%s''',
                        (scope.workspace_id,scope.application_id,args['gridId']))
                except ForeignKeyViolation as error:
                    if error.diag.message_primary == 'SAVED_GRID_AUTHORIZATION_SCOPE_IN_USE':
                        raise ValueError('SAVED_GRID_AUTHORIZATION_SCOPE_IN_USE') from error
                    raise
                db.execute('''INSERT INTO epm.operation_receipt(workspace_id,
                    application_id,operation_id,command_digest,actor_id,
                    committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id,scope.application_id,idempotency_key,
                     command_digest,self.identity.subject_id,revision,Jsonb(result)))
                self._recheck_authority(db, scope, 'write', DELETE, authority)
                return result

    def read(self,scope: ApplicationScope,program: object) -> dict:
        function,args=self._program(program,{READ,LIST})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                access = self._prepare(db,scope,'read',function)
                authority = resolve_effective_dimensional_scope(db, self.identity, scope, access=access)
                object_visible = _object_visible_sql(authority, 'views.read')
                visible = sql.SQL('({} AND {})').format(object_visible,_view_visible_sql(authority))
                if function==READ:
                    if set(args)!={'gridId'}:raise ValueError('SAVED_GRID_ARGUMENTS_INVALID')
                    self._target(args['gridId'])
                    row=db.execute(sql.SQL('''SELECT g.*,s.metadata_revision AS current_metadata_revision,
                        s.policy_revision,s.security_revision,s.schema_epoch FROM epm.application_state s
                        LEFT JOIN epm.saved_grid_definition g
                          ON g.workspace_id=s.workspace_id AND g.application_id=s.application_id
                           AND g.grid_id=%s AND {}
                        WHERE s.workspace_id=%s AND s.application_id=%s''').format(visible),
                        (args['gridId'],scope.workspace_id,scope.application_id)).fetchone()
                    if row is None:raise ValueError('APPLICATION_UNAVAILABLE')
                    self._finish_read(db, scope, function, authority, row)
                    if row['grid_id'] is None:raise ValueError('SAVED_GRID_NOT_FOUND')
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
                hidden = sql.SQL('FALSE')
                if reject_mixed_metadata_reads(authority):
                    hidden = sql.SQL('''EXISTS (SELECT 1 FROM epm.saved_grid_definition hidden
                        WHERE hidden.workspace_id=%(workspace)s AND hidden.application_id=%(application)s
                          AND {} AND NOT EXISTS(SELECT 1 FROM visible WHERE grid_id=hidden.grid_id))''').format(
                              _object_visible_sql(authority,'views.read','hidden'))
                # Authorization precedes pagination. Both readers in this
                # statement share the same cut, including an empty collection.
                rows = db.execute(sql.SQL('''WITH visible AS MATERIALIZED (
                    SELECT g.grid_id,g.state_token FROM epm.saved_grid_definition g
                    WHERE g.workspace_id=%(workspace)s AND g.application_id=%(application)s AND {visible}
                ), page AS (
                    SELECT g.* FROM epm.saved_grid_definition g JOIN visible USING (grid_id)
                    WHERE g.workspace_id=%(workspace)s AND g.application_id=%(application)s
                      AND (%(after)s::text IS NULL OR g.grid_id>%(after)s)
                    ORDER BY g.grid_id LIMIT %(limit)s
                )
                SELECT v.grid_id,v.state_token,page.grid_id IS NOT NULL AS on_page,
                    page.name,page.canonical_digest,page.metadata_revision,page.creator_issuer,
                    page.creator_subject_id,page.updated_at,page.definition,
                    s.metadata_revision AS current_metadata_revision,s.policy_revision,s.security_revision,
                    s.schema_epoch,{hidden} AS hidden_exists
                FROM epm.application_state s LEFT JOIN visible v ON TRUE LEFT JOIN page ON page.grid_id=v.grid_id
                WHERE s.workspace_id=%(workspace)s AND s.application_id=%(application)s
                ORDER BY v.grid_id''').format(visible=visible, hidden=hidden), {'workspace': scope.workspace_id,
                    'application': scope.application_id, 'after': after, 'limit': limit+1}).fetchall()
                if not rows:raise ValueError('APPLICATION_UNAVAILABLE')
                observed = rows[0]
                self._finish_read(db, scope, function, authority, observed)
                if observed['hidden_exists']:
                    raise AccessDenied('SAVED_GRID_SCOPE_UNAVAILABLE')
                current_token=collection_token((row['grid_id'],row['state_token']) for row in rows if row['grid_id'] is not None)
                if authority.policy is not None:
                    current_token = _canonical_digest([scope.workspace_id, scope.application_id, current_token,
                        self.identity.issuer, self.identity.subject_id, authority.scope_digest,
                        *(observed[key] for key in _OBSERVED_REVISIONS)])
                if ('expectedCollectionToken' in args
                        and args['expectedCollectionToken']!=current_token):
                    raise ValueError('SAVED_GRID_LIST_STALE')
                page = [row for row in rows if row['on_page']]
                values=[self._result(row) for row in page[:limit]]
                return {'grids':values,'nextAfterGridId':(
                    values[-1]['gridId'] if len(page)>limit else None),
                    'collectionToken':current_token}
