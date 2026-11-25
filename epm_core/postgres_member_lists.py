"""Current PostgreSQL member-list registry and bounded evaluator."""
from __future__ import annotations

import re
from contextlib import nullcontext
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .application_schedule import SCHEDULE_ID_PATTERN

from .application_workflow import _ID as _WORKFLOW_ID
from .current_object_contract import collection_token,new_state_token,require_state_token
from .member_list_contract import canonical_member_list_definition,member_list_digest
from .postgres_definition_lifecycle import (
    REFERENCE_CONSUMER_KINDS, DefinitionReferenceBlocked, certificate, current_state, definition_reference_blockers,
    effective_state, replace_references, resolution_context,
)
from .persistence_contract import ApplicationScope
from .postgres_access import AccessDenied,PostgresAccessChecker,VerifiedIdentity,assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import (
    metadata_dimension_reference_read_sql, metadata_expression_visible_sql, reject_mixed_metadata_reads,
    resolve_effective_dimensional_scope,
)
from .postgres_expression_rules import _ID as _RULE_ID
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout
from .postgres_saved_grids import _ID as _SAVED_GRID_ID

SAVE='metadata.member_list.save';READ='metadata.member_list.read';LIST='metadata.member_list.list'
ACTIVATE='metadata.member_list.activate';DEACTIVATE='metadata.member_list.deactivate'
DELETE='metadata.member_list.delete';EVALUATE='metadata.member_list.evaluate'
ADOPT_CONFIGURATION='metadata.member_list.adopt_configuration'
WRITE_FUNCTIONS=frozenset((SAVE,ACTIVATE,DEACTIVATE,DELETE,ADOPT_CONFIGURATION));READ_FUNCTIONS=frozenset((READ,LIST,EVALUATE))
_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z');_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_SLOT=re.compile(r'Custom(0[1-9]|[12][0-9]|30)\Z')
_OBSERVED_REVISIONS = ('current_metadata_revision', 'policy_revision', 'security_revision', 'schema_epoch')
_CONSUMER_PAGE_LIMIT = 100
_CONSUMER_IDS = {'list': _ID, 'rule': _RULE_ID, 'saved-view': _SAVED_GRID_ID,
    'schedule': SCHEDULE_ID_PATTERN, 'workflow': _WORKFLOW_ID}
_CONSUMERS_STALE = 'MEMBER_LIST_RETIREMENT_CONSUMERS_STALE'
_AUTHORITY_STALE = 'MEMBER_LIST_AUTHORIZATION_STALE'

def catalog()->dict:
    common={'previewRequired':False,'workClass':'short'}
    mutation={'mode':'current_definition_activation','permission':'rule_publish','idempotencyRequired':True,
        'arguments':{'listId':'stable list ID','expectedStateToken':'current list token',
            'expectedMetadataRevision':'current metadata revision','expectedPolicyRevision':'current policy revision'}}
    return {
        SAVE:{**common,'mode':'current_definition_write','permission':'rule_design','idempotencyRequired':True,
            'arguments':{'definition':'canonical current member-list definition',
                'expectedMetadataRevision':'current metadata revision','expectedPolicyRevision':'current policy revision'},
            'optionalArguments':{'expectedStateToken':'required when replacing an existing list'},
            'result':'current definition and state token'},
        ACTIVATE:{**common,**mutation,'result':'activated current definition'},
        DEACTIVATE:{**common,**mutation,'result':'inactive current definition'},
        DELETE:{**common,**mutation,'mode':'current_definition_delete','result':'current definition deletion receipt'},
        ADOPT_CONFIGURATION:{**common,'mode':'source_wrapper_retirement',
            'permission':'rule_publish','idempotencyRequired':True,
            'arguments':{'listId':'exact native member-list ID',
                'expectedStateToken':'exact current list token',
                'expectedCanonicalDigest':'exact current list digest',
                'sourceProgramId':'exact legacy wrapper program ID',
                'expectedSourceStateToken':'exact wrapper state token',
                'expectedSourceToken':'exact wrapper source token',
                'expectedSourceDigest':'exact wrapper source digest',
                'reason':'native_object_replaces_python_wrapper',
                'expectedMetadataRevision':'current metadata revision',
                'expectedPolicyRevision':'current policy revision'},
            'result':'configuration-owned native list and retired exact wrapper'},
        READ:{**common,'mode':'read','permission':'read','idempotencyRequired':False,
            'arguments':{'listId':'stable list ID'},
            'optionalArguments':{'retirementConsumers': 'bounded dependency page for authorized publishers'},
            'result':'current definition and, when requested, exact retirement dependencies'},
        LIST:{**common,'mode':'read','permission':'read','idempotencyRequired':False,'arguments':{},
            'optionalArguments':{'limit':'1-100','afterListId':'stable keyset cursor',
                'expectedCollectionToken':'required with cursor'},'result':'bounded current definitions'},
        EVALUATE:{**common,'mode':'read','permission':'read','idempotencyRequired':False,
            'arguments':{'listId':'stable list ID','parameters':'declared typed parameter bindings',
                'expectedMetadataRevision':'current metadata revision'},
            'result':'bounded member IDs from active current definition'}}

def _id(value):
    if not isinstance(value,str) or not _ID.fullmatch(value):raise ValueError('MEMBER_LIST_ID_INVALID')
    return value

def _revision(value,code):
    if type(value) is not int or value<0:raise ValueError(code)
    return value

def _program(raw,functions):
    if (not isinstance(raw,dict) or set(raw)!={'languageVersion','function','arguments'}
            or type(raw['languageVersion']) is not int or raw['languageVersion']!=2
            or type(raw['function']) is not str or raw['function'] not in functions
            or type(raw.get('arguments')) is not dict):raise ValueError('MEMBER_LIST_PROGRAM_INVALID')
    return raw['function'],raw['arguments']


def compile_member_list_write(raw):
    function, args = _program(raw, WRITE_FUNCTIONS)
    revisions = {'expectedMetadataRevision', 'expectedPolicyRevision'}
    definition = None
    if function == SAVE:
        required = revisions | {'definition'}
        if not required <= set(args) or set(args) - required - {'expectedStateToken'}:
            raise ValueError('MEMBER_LIST_ARGUMENTS_INVALID')
        definition = canonical_member_list_definition(args['definition'])
    else:
        required = revisions | {'listId', 'expectedStateToken'}
        if function == ADOPT_CONFIGURATION:
            required |= {'expectedCanonicalDigest', 'sourceProgramId', 'expectedSourceStateToken',
                         'expectedSourceToken', 'expectedSourceDigest', 'reason'}
        if set(args) != required:
            raise ValueError('MEMBER_LIST_ARGUMENTS_INVALID')
        _id(args['listId'])
        if function == ADOPT_CONFIGURATION:
            if (args['reason'] != 'native_object_replaces_python_wrapper'
                    or not isinstance(args['sourceProgramId'], str)
                    or not _ID.fullmatch(args['sourceProgramId'])
                    or any(not isinstance(args[name], str)
                           or not re.fullmatch(r'[0-9a-f]{64}', args[name])
                           for name in ('expectedCanonicalDigest', 'expectedSourceDigest'))):
                raise ValueError('MEMBER_LIST_ARGUMENTS_INVALID')
            require_state_token(args['expectedSourceStateToken'], error='PYTHON_PROGRAM_STATE_TOKEN_INVALID')
            require_state_token(args['expectedSourceToken'], error='PYTHON_PROGRAM_SOURCE_TOKEN_INVALID')
    _revision(args['expectedMetadataRevision'], 'STALE_METADATA_REVISION')
    _revision(args['expectedPolicyRevision'], 'STALE_POLICY_REVISION')
    if args.get('expectedStateToken') is not None:
        require_state_token(args['expectedStateToken'], error='MEMBER_LIST_STATE_TOKEN_INVALID')
    return function, args, definition


def _consumer_page_arguments(page):
    if type(page) is not dict or set(page) - {'limit', 'after', 'expectedCollectionToken'}:
        raise ValueError('MEMBER_LIST_RETIREMENT_CONSUMERS_ARGUMENTS_INVALID')
    limit = page.get('limit', _CONSUMER_PAGE_LIMIT)
    if type(limit) is not int or not 1 <= limit <= _CONSUMER_PAGE_LIMIT:
        raise ValueError('MEMBER_LIST_RETIREMENT_CONSUMERS_LIMIT_INVALID')
    after = page.get('after')
    if 'after' in page:
        if (type(after) is not dict or set(after) != {'kind', 'id'}
                or type(after['kind']) is not str or after['kind'] not in _CONSUMER_IDS
                or type(after['id']) is not str or not _CONSUMER_IDS[after['kind']].fullmatch(after['id'])):
            raise ValueError('MEMBER_LIST_RETIREMENT_CONSUMERS_CURSOR_INVALID')
    if ('after' in page) != ('expectedCollectionToken' in page):
        raise ValueError('MEMBER_LIST_RETIREMENT_CONSUMERS_PIN_REQUIRED')
    token = page.get('expectedCollectionToken')
    if 'expectedCollectionToken' in page:
        require_state_token(token, error='MEMBER_LIST_RETIREMENT_CONSUMERS_TOKEN_INVALID')
    return limit, after, token

def _references(node):
    from .member_list_contract import iter_member_list_nodes
    members, hierarchies, attributes = set(), set(), set()
    for item in iter_member_list_nodes(node):
        kind = item['kind']
        if kind == 'explicit':
            members.update(item['memberIds'])
        elif kind in {'children','parents','descendants','ancestors','siblings','leaves','base'}:
            members.add(item['memberId']); hierarchies.add(item['hierarchyId'])
        elif kind == 'navigation':
            if item['hierarchyId'] is not None:
                hierarchies.add(item['hierarchyId'])
            if item['anchor'] is not None:
                members.add(item['anchor']['memberId'])
        elif kind == 'attribute' or kind == 'order' and item['attributeId'] is not None:
            attributes.add(item['attributeId'])
    return members, hierarchies, attributes


def member_list_definition_visible_sql(authority):
    """Check list references without interpreting its relational result."""
    if authority is None or authority.policy is None or authority.administrator_bypass:
        return sql.SQL('TRUE')
    dimension = sql.SQL('d.dimension_id')
    return sql.SQL('(CASE WHEN d.definition IS NULL THEN {} ELSE {} END)').format(
        metadata_dimension_reference_read_sql(authority, 'd', dimension),
        metadata_expression_visible_sql(authority, 'd', dimension, sql.SQL("d.definition->'expression'")))


def evaluate_definition_in_transaction(db,scope,definition,parameters,*,authority=None):
    """Evaluate the canonical metadata expression from one relevant scope.

    Public reads supply current dimensional authority. Trusted structural
    callers retain their existing authorization boundary and never return
    this internal metadata context directly.
    """
    from .postgres_member_selection import evaluate_member_ids_in_transaction
    return evaluate_member_ids_in_transaction(
        db,scope,authority,definition,parameters)


class PostgresMemberLists:
    def __init__(self,dsn,*,identity):
        if not isinstance(identity,VerifiedIdentity):raise ValueError('A verified identity is required')
        assert_nonowner_role(dsn,'epm_runtime',('member_list_definition',));self.dsn,self.identity=dsn,identity

    @staticmethod
    def _scope(db,scope):
        if not isinstance(scope,ApplicationScope):raise ValueError('MEMBER_LIST_SCOPE_INVALID')
        configure_lock_wait(db);configure_statement_timeout(db,5000);PostgresNumericFactStore._set_scope(db,scope)

    @staticmethod
    def _validate_definition(db,scope,definition):
        if db.execute('''SELECT 1 FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
            AND dimension_id=%s AND status='Active' ''',(scope.workspace_id,scope.application_id,
            definition['dimensionId'])).fetchone() is None:raise ValueError('MEMBER_LIST_DIMENSION_UNAVAILABLE')
        members,hierarchies,attributes=_references(definition['expression'])
        from .postgres_hierarchies import resolve_hierarchy
        for hierarchy in sorted(hierarchies):resolve_hierarchy(db,scope,definition['dimensionId'],hierarchy,allow_alias=True)
        if members:
            found=db.execute('''SELECT member_id FROM epm.member WHERE workspace_id=%s AND application_id=%s
                AND dimension_id=%s AND status='Active' AND member_id=ANY(%s)''',(scope.workspace_id,
                scope.application_id,definition['dimensionId'],list(members))).fetchall()
            if {row['member_id'] for row in found}!=members:raise ValueError('MEMBER_LIST_MEMBER_UNAVAILABLE')
        for attribute in attributes:
            slot=int(attribute[6:]) if _SLOT.fullmatch(attribute) else None
            legacy=db.execute('''SELECT 1 FROM epm.semantic_column WHERE workspace_id=%s AND application_id=%s
                AND dimension_id=%s AND scope='Member' AND ((%s::integer IS NOT NULL AND slot=%s)
                OR (%s::integer IS NULL AND display_name=%s))''',(scope.workspace_id,scope.application_id,
                definition['dimensionId'],slot,slot,slot,attribute)).fetchone()
            current=db.execute('''SELECT 1 FROM epm.attribute_definition WHERE workspace_id=%s AND application_id=%s
                AND scope='Member' AND dimension_id=%s AND attribute_id=%s AND status='Active' ''',
                (scope.workspace_id,scope.application_id,definition['dimensionId'],attribute)).fetchone()
            if legacy is not None and current is not None:raise ValueError('MEMBER_LIST_ATTRIBUTE_AMBIGUOUS')
            if legacy is None and current is None:raise ValueError('MEMBER_LIST_ATTRIBUTE_UNAVAILABLE')

    @staticmethod
    def _result(row,include_definition=True):
        value={'listId':row['list_id'],'stateToken':row['state_token'],'dimensionId':row['dimension_id'],
            'name':row['name'],'canonicalDigest':row['canonical_digest'],**effective_state(row),
            'definitionMetadataRevision':row['metadata_revision'],'sourceBuildId':row.get('source_build_id'),
            'updatedAt':row['updated_at'].isoformat()}
        if include_definition:value['definition']=row['definition']
        return value

    def execute(self,scope,raw,*,idempotency_key,_connection=None,_source_build_id=None):
        function, args, definition = compile_member_list_write(raw)
        if not isinstance(idempotency_key,str) or not _KEY.fullmatch(idempotency_key):raise ValueError('MEMBER_LIST_IDEMPOTENCY_KEY_INVALID')
        list_id = definition['listId'] if function == SAVE else args['listId']
        expected_metadata = args['expectedMetadataRevision']
        expected_policy = args['expectedPolicyRevision']
        expected_token=args.get('expectedStateToken')
        command_digest=_canonical_digest({'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],'program':raw})
        connection=nullcontext(_connection) if _connection is not None else connect_postgres(self.dsn,row_factory=dict_row)
        with connection as db:
            with db.transaction():
                self._scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state=db.execute('''SELECT s.metadata_revision,s.policy_revision,s.commit_revision,s.processing_mode,
                    a.status application_status FROM epm.application_state s JOIN epm.application a
                    USING(workspace_id,application_id) WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:raise ValueError('APPLICATION_UNAVAILABLE')
                access = self._access(db, scope, function)
                prior=db.execute('''SELECT command_digest,actor_id,result FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',(scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
                if prior:
                    if prior['command_digest']!=command_digest or prior['actor_id']!=self.identity.subject_id:raise ValueError('MEMBER_LIST_IDEMPOTENCY_CONFLICT')
                    self._recheck_authority(db, scope, function, access)
                    return prior['result']
                if state['application_status']!='Active' or state['processing_mode']!='Active':raise ValueError('APPLICATION_NOT_WRITABLE')
                if state['metadata_revision']!=expected_metadata:raise ValueError('STALE_METADATA_REVISION')
                if state['policy_revision']!=expected_policy:raise ValueError('STALE_POLICY_REVISION')
                existing=db.execute('''SELECT * FROM epm.member_list_definition WHERE workspace_id=%s
                    AND application_id=%s AND list_id=%s FOR UPDATE''',(scope.workspace_id,scope.application_id,list_id)).fetchone()
                if existing is None and expected_token is not None:raise ValueError('MEMBER_LIST_NOT_FOUND')
                if existing is not None:
                    if expected_token is None:raise ValueError('MEMBER_LIST_STATE_TOKEN_REQUIRED')
                    if expected_token!=existing['state_token']:raise ValueError('MEMBER_LIST_STATE_CONFLICT')
                elif function!=SAVE:raise ValueError('MEMBER_LIST_NOT_FOUND')
                policy=state['policy_revision'];revision=state['commit_revision']+1;token=new_state_token()
                if function==ADOPT_CONFIGURATION:
                    if (existing['ownership_state']!='Source'
                            or existing['canonical_digest']!=args['expectedCanonicalDigest']
                            or existing['definition'] is None
                            or existing['source_program_id']!=args['sourceProgramId']
                            or existing['source_token']!=args['expectedSourceToken']
                            or existing['source_digest']!=args['expectedSourceDigest']):
                        raise ValueError('MEMBER_LIST_SOURCE_ADOPTION_STALE')
                    source=db.execute('''SELECT * FROM epm.python_program_definition
                        WHERE workspace_id=%s AND application_id=%s AND program_id=%s
                        FOR UPDATE''',(scope.workspace_id,scope.application_id,
                        args['sourceProgramId'])).fetchone()
                    declared={'kind':'MemberList','definitionId':list_id,
                        'dimensionId':existing['dimension_id']}
                    if (source is None or source['state_token']!=args['expectedSourceStateToken']
                            or source['source_token']!=args['expectedSourceToken']
                            or source['source_digest']!=args['expectedSourceDigest']
                            or source['declared_output']!=declared):
                        raise ValueError('MEMBER_LIST_SOURCE_ADOPTION_STALE')
                    blockers=[]
                    for row in db.execute('''SELECT build_id,status FROM epm.python_program_build
                        WHERE workspace_id=%s AND application_id=%s AND program_id=%s
                          AND status IN('accepted','ready','running','cancel_requested')
                        ORDER BY build_id''',(scope.workspace_id,scope.application_id,
                        source['program_id'])).fetchall():
                        blockers.append({'kind':'python-build','id':row['build_id'],
                            'state':row['status']})
                    for row in db.execute('''SELECT schedule_id,status
                        FROM epm.python_program_schedule_definition
                        WHERE workspace_id=%s AND application_id=%s AND program_id=%s
                        ORDER BY schedule_id''',(scope.workspace_id,scope.application_id,
                        source['program_id'])).fetchall():
                        blockers.append({'kind':'python-schedule','id':row['schedule_id'],
                            'state':row['status']})
                    if blockers:raise DefinitionReferenceBlocked(blockers)
                    self._validate_definition(db,scope,existing['definition'])
                    if member_list_digest(existing['definition'])!=existing['canonical_digest']:
                        raise ValueError('MEMBER_LIST_DEFINITION_CORRUPT')
                    acceptance=certificate(db,scope,kind='MemberList',definition_id=list_id,
                        digest=existing['canonical_digest'],metadata_revision=expected_metadata,
                        payload=existing['definition'])
                    from .postgres_definition_lifecycle import retire_source_payloads
                    retire_source_payloads(db,scope,source)
                    digest=existing['canonical_digest'];status=existing['status'];policy+=1
                elif function==SAVE:
                    if existing and existing['ownership_state']=='Unresolved':
                        raise ValueError('DEFINITION_OWNERSHIP_UNRESOLVED')
                    if existing and existing['ownership_state']=='Source':
                        from .postgres_definition_lifecycle import source_for_build
                        next_source=source_for_build(db,scope,_source_build_id)
                        if next_source is None or next_source['program_id']!=existing['source_program_id']:
                            raise ValueError('PYTHON_DEFINITION_SOURCE_REQUIRED')
                    self._validate_definition(db,scope,definition);digest=member_list_digest(definition);status='Saved'
                    acceptance=certificate(db,scope,kind='MemberList',definition_id=list_id,digest=digest,
                        metadata_revision=expected_metadata,source_build_id=_source_build_id,payload=definition)
                    if existing and existing['status']=='Published':policy+=1
                elif function==ACTIVATE:
                    if existing['status']=='Published':raise ValueError('MEMBER_LIST_ALREADY_ACTIVE')
                    if existing['metadata_revision']!=expected_metadata:raise ValueError('MEMBER_LIST_METADATA_STALE')
                    if existing['ownership_state']=='Unresolved':
                        raise ValueError('DEFINITION_OWNERSHIP_UNRESOLVED')
                    if existing['definition'] is None:
                        raise ValueError('DEFINITION_CURRENT_VALIDATION_REQUIRED')
                    if existing['ownership_state']=='Source' and (
                            _source_build_id is None or existing['source_build_id']!=_source_build_id):
                        raise ValueError('PYTHON_DEFINITION_SOURCE_ACTIVATION_REQUIRED')
                    self._validate_definition(db,scope,existing['definition'])
                    acceptance=(existing['current_certificate'] if existing['ownership_state']=='Source'
                        else certificate(db,scope,kind='MemberList',definition_id=list_id,
                            digest=existing['canonical_digest'],metadata_revision=expected_metadata,payload=existing['definition']))
                    if acceptance is None:raise ValueError('DEFINITION_CURRENT_VALIDATION_REQUIRED')
                    digest=existing['canonical_digest'];status='Published';policy+=1
                elif function==DEACTIVATE:
                    if existing['status']!='Published':raise ValueError('MEMBER_LIST_NOT_ACTIVE')
                    if existing['ownership_state']=='Source':raise ValueError('PYTHON_DEFINITION_SOURCE_ACTIVATION_REQUIRED')
                    digest=existing['canonical_digest'];status='Inactive';policy+=1
                else:
                    if existing['ownership_state']!='Configuration':
                        raise ValueError('DEFINITION_SOURCE_OR_RECONCILIATION_REQUIRED')
                    blockers = definition_reference_blockers(
                        db, scope, producer_kind='list', producer_id=list_id)
                    if blockers:
                        raise DefinitionReferenceBlocked(blockers)
                    digest=existing['canonical_digest'];status='Deleted';policy+=1
                result={'operationId':idempotency_key,'listId':list_id,'status':status,
                    'canonicalDigest':digest,'stateToken':token if function!=DELETE else None,
                    'metadataRevision':expected_metadata,'policyRevision':policy}
                if function==ADOPT_CONFIGURATION:
                    result.update(ownershipState='Configuration',
                        retiredSourceProgramId=source['program_id'])
                db.execute('''UPDATE epm.application_state SET policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',(policy,revision,scope.workspace_id,scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,
                    command_digest,actor_id,committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id,scope.application_id,idempotency_key,command_digest,
                     self.identity.subject_id,revision,Jsonb(result)))
                if function==ADOPT_CONFIGURATION:
                    adopted=db.execute('''SELECT epm.member_list_adopt_configuration(
                        %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) adopted''',(
                        scope.workspace_id,scope.application_id,list_id,
                        args['expectedStateToken'],args['expectedCanonicalDigest'],
                        source['program_id'],args['expectedSourceStateToken'],
                        args['expectedSourceToken'],args['expectedSourceDigest'],
                        token,Jsonb(acceptance),idempotency_key)).fetchone()['adopted']
                    if adopted is not True:
                        raise ValueError('MEMBER_LIST_SOURCE_ADOPTION_STALE')
                elif function==DELETE:
                    db.execute('''DELETE FROM epm.member_list_definition WHERE workspace_id=%s AND application_id=%s
                        AND list_id=%s''',(scope.workspace_id,scope.application_id,list_id))
                elif function==SAVE:
                    db.execute('''INSERT INTO epm.member_list_definition(workspace_id,application_id,list_id,
                        dimension_id,name,definition,canonical_digest,state_token,status,metadata_revision,creator_issuer,
                        creator_subject_id,source_build_id,updated_operation_id,current_certificate,
                        ownership_state,source_program_id,source_token,source_digest)
                        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT(workspace_id,application_id,list_id) DO UPDATE SET dimension_id=EXCLUDED.dimension_id,
                        name=EXCLUDED.name,definition=EXCLUDED.definition,canonical_digest=EXCLUDED.canonical_digest,
                        state_token=EXCLUDED.state_token,status=EXCLUDED.status,metadata_revision=EXCLUDED.metadata_revision,
                        creator_issuer=EXCLUDED.creator_issuer,creator_subject_id=EXCLUDED.creator_subject_id,
                        source_build_id=EXCLUDED.source_build_id,current_certificate=EXCLUDED.current_certificate,updated_operation_id=EXCLUDED.updated_operation_id,
                        updated_at=transaction_timestamp()''',
                        (scope.workspace_id,scope.application_id,list_id,definition['dimensionId'],definition['name'],Jsonb(definition),
                         digest,token,status,expected_metadata,self.identity.issuer,self.identity.subject_id,_source_build_id,
                         idempotency_key,Jsonb(acceptance),existing['ownership_state'] if existing else 'Configuration',
                         existing.get('source_program_id') if existing else None,
                         existing.get('source_token') if existing else None,
                         existing.get('source_digest') if existing else None))
                else:
                    db.execute('''UPDATE epm.member_list_definition SET status=%s,state_token=%s,current_certificate=%s,updated_operation_id=%s,
                        updated_at=transaction_timestamp() WHERE workspace_id=%s AND application_id=%s
                        AND list_id=%s''',(status,token,Jsonb(acceptance if function==ACTIVATE else existing['current_certificate']),idempotency_key,scope.workspace_id,scope.application_id,list_id))
                if function==SAVE:
                    replace_references(db,scope,kind='MemberList',definition_id=list_id,payload=definition)
                if function!=SAVE or existing and existing['status']=='Published':
                    from .calculation_impact_contract import compile_calculation_impact
                    impact=compile_calculation_impact({'format':'openepm-calculation-impact-v1','sourceKind':'definition',
                        'sourceId':idempotency_key,'causalRevision':revision,'effects':[{'domain':'definition',
                        'change':'delete' if function==DELETE else 'replace','objectType':'member-list','objectId':list_id,
                        'scope':[],'reason':'definition_changed','oldPresence':'present',
                        'newPresence':'absent' if function in (DEACTIVATE,DELETE) else 'present'}]})
                    from .postgres_calculation_impact import record_calculation_impact
                    record_calculation_impact(db,scope,operation_id=idempotency_key,impact=impact)
                self._recheck_authority(db, scope, function, access)
                return result

    @staticmethod
    def _require_current_snapshot(db, scope, observed, owners, *, code, pin_commit=False):
        # The shared lifecycle resolver reads dependencies under READ COMMITTED.
        # Policy/metadata revisions and the returned owner tokens fence those
        # reads without treating unrelated fact commits as owner changes.
        current = db.execute('''SELECT s.metadata_revision AS current_metadata_revision,
            s.policy_revision,s.security_revision,s.schema_epoch,s.commit_revision,
            ARRAY(SELECT state_token FROM epm.member_list_definition
                WHERE workspace_id=s.workspace_id AND application_id=s.application_id
                  AND list_id=ANY(%s::text[]) ORDER BY list_id) AS owner_tokens
            FROM epm.application_state s WHERE s.workspace_id=%s AND s.application_id=%s''',
            ([row['list_id'] for row in owners], scope.workspace_id, scope.application_id)).fetchone()
        if (current is None or any(current[key] != observed[key] for key in _OBSERVED_REVISIONS)
                or pin_commit and current['commit_revision'] != observed['commit_revision']
                or current['owner_tokens'] != [row['state_token'] for row in owners]):
            raise ValueError(code)

    def _access(self, db, scope, function):
        if function in READ_FUNCTIONS:
            return PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, 'read', function=function)
        write = PostgresAccessChecker.check_in_transaction(db, self.identity, scope, 'write')
        rule = PostgresAccessChecker.check_in_transaction(db, self.identity, scope,
            'rule_design' if function == SAVE else 'rule_publish', function=function)
        if write != rule:
            raise ValueError(_AUTHORITY_STALE)
        return rule

    def _recheck_authority(self, db, scope, function, access):
        # A directory update may commit independently of the workspace fence.
        if self._access(db, scope, function) != access:
            raise ValueError(_AUTHORITY_STALE)

    def _recheck_read_authority(self, db, scope, function, access, authority):
        self._recheck_authority(db, scope, function, access)
        current = resolve_effective_dimensional_scope(db, self.identity, scope, access=access)
        if current.scope_digest != authority.scope_digest:
            raise ValueError(_AUTHORITY_STALE)

    def _retirement_consumers(self, db, scope, row, *, limit, after, expected_token, access):
        token = _canonical_digest([scope.workspace_id, scope.application_id, row['list_id'],
            row['state_token'], row['commit_revision'], *(row[key] for key in _OBSERVED_REVISIONS)])
        if expected_token is not None and expected_token != token:
            raise ValueError(_CONSUMERS_STALE)
        candidates = definition_reference_blockers(db, scope, producer_kind='list',
            producer_id=row['list_id'], after=after, limit=limit + 1)
        self._recheck_authority(db, scope, DELETE, access)
        self._require_current_snapshot(db, scope, row, [row], code=_CONSUMERS_STALE, pin_commit=True)
        return {'items': candidates[:limit], 'collectionToken': token,
                'nextAfter': candidates[limit - 1] if len(candidates) > limit else None}

    def _list_current(self, db, scope, args, authority):
        if set(args) - {'limit', 'afterListId', 'expectedCollectionToken'}:
            raise ValueError('MEMBER_LIST_ARGUMENTS_INVALID')
        limit = args.get('limit', 100)
        after = args.get('afterListId')
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('MEMBER_LIST_LIMIT_INVALID')
        if after is not None:
            _id(after)
            if 'expectedCollectionToken' not in args:
                raise ValueError('MEMBER_LIST_CONTINUATION_PIN_REQUIRED')
        if 'expectedCollectionToken' in args:
            require_state_token(args['expectedCollectionToken'], error='MEMBER_LIST_COLLECTION_TOKEN_INVALID')
        denied = sql.SQL('FALSE')
        if reject_mixed_metadata_reads(authority):
            denied = sql.SQL('''EXISTS (SELECT 1 FROM epm.member_list_definition hidden
                WHERE hidden.workspace_id=%(workspace)s AND hidden.application_id=%(application)s
                  AND NOT EXISTS(SELECT 1 FROM visible WHERE list_id=hidden.list_id))''')
        # Only visible identities contribute to the collection. Only the page
        # carries complete definitions and their validation certificates.
        rows = db.execute(sql.SQL('''WITH visible AS MATERIALIZED (
            SELECT d.list_id,d.state_token FROM epm.member_list_definition d
            WHERE d.workspace_id=%(workspace)s AND d.application_id=%(application)s AND {visible}
        ), page AS (
            SELECT d.* FROM epm.member_list_definition d JOIN visible USING (list_id)
            WHERE d.workspace_id=%(workspace)s AND d.application_id=%(application)s
              AND (%(after)s::text IS NULL OR d.list_id>%(after)s)
            ORDER BY d.list_id LIMIT %(limit)s
        )
        SELECT v.list_id,v.state_token,page.list_id IS NOT NULL AS on_page,
            page.dimension_id,page.name,page.definition,page.canonical_digest,page.status,page.metadata_revision,
            page.source_build_id,page.updated_at,page.current_certificate,page.ownership_state,
            page.source_program_id,page.source_token,page.source_digest,
            s.metadata_revision AS current_metadata_revision,s.policy_revision,s.security_revision,s.schema_epoch,
            {denied} AS hidden_exists
        FROM epm.application_state s
        LEFT JOIN visible v ON TRUE
        LEFT JOIN page ON page.list_id=v.list_id
        WHERE s.workspace_id=%(workspace)s AND s.application_id=%(application)s
        ORDER BY v.list_id''').format(visible=member_list_definition_visible_sql(authority), denied=denied),
            {'workspace': scope.workspace_id,
            'application': scope.application_id, 'after': after, 'limit': limit + 1}).fetchall()
        if not rows:
            raise ValueError('APPLICATION_UNAVAILABLE')
        observed = rows[0]
        if observed['hidden_exists']:
            raise AccessDenied('MEMBER_LIST_SCOPE_UNAVAILABLE')
        owner_token = collection_token((row['list_id'], row['state_token'])
                                       for row in rows if row['list_id'] is not None)
        token_parts = [scope.workspace_id, scope.application_id, owner_token,
                       *(observed[key] for key in _OBSERVED_REVISIONS)]
        if authority.policy is not None:
            token_parts.extend((self.identity.issuer, self.identity.subject_id, authority.scope_digest))
        token = _canonical_digest(token_parts)
        if args.get('expectedCollectionToken', token) != token:
            raise ValueError('MEMBER_LIST_LIST_STALE')
        page = [row for row in rows if row['on_page']]
        owners = page[:limit]
        values = []
        if owners:
            context = resolution_context(db, scope, owners)
            values = [{**self._result(row), **current_state(row, context)} for row in owners]
        self._require_current_snapshot(db, scope, observed, owners, code='MEMBER_LIST_LIST_STALE')
        return {'memberLists': values,
            'nextAfterListId': values[-1]['listId'] if len(page) > limit else None,
            'collectionToken': token}

    def read(self, scope, raw):
        function, args = _program(raw, READ_FUNCTIONS)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                self._scope(db, scope)
                access = self._access(db, scope, function)
                authority = resolve_effective_dimensional_scope(db, self.identity, scope, access=access)
                if function == LIST:
                    try:
                        page = self._list_current(db, scope, args, authority)
                    except ValueError:
                        self._recheck_read_authority(db, scope, function, access, authority)
                        raise
                    self._recheck_read_authority(db, scope, function, access, authority)
                    return page
                required = {'listId'} if function == READ else {'listId', 'parameters', 'expectedMetadataRevision'}
                optional = {'retirementConsumers'} if function == READ else set()
                if not required <= set(args) or set(args) - required - optional:
                    raise ValueError('MEMBER_LIST_ARGUMENTS_INVALID')
                consumer_page = None
                if 'retirementConsumers' in args:
                    consumer_page = _consumer_page_arguments(args['retirementConsumers'])
                    if self._access(db, scope, DELETE) != access:
                        raise ValueError(_AUTHORITY_STALE)
                list_id = _id(args['listId'])
                row = db.execute(sql.SQL('''SELECT d.*,s.metadata_revision AS current_metadata_revision,
                    s.policy_revision,s.commit_revision,s.security_revision,s.schema_epoch
                    FROM epm.application_state s
                    LEFT JOIN epm.member_list_definition d
                      ON d.workspace_id=s.workspace_id AND d.application_id=s.application_id
                        AND d.list_id=%s AND {visible}
                    WHERE s.workspace_id=%s AND s.application_id=%s''').format(
                        visible=member_list_definition_visible_sql(authority)),
                    (list_id, scope.workspace_id, scope.application_id)).fetchone()
                if row is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if row['list_id'] is None:
                    self._recheck_read_authority(db, scope, function, access, authority)
                    if function == EVALUATE and authority.policy is not None:
                        raise AccessDenied('METADATA_SELECTION_SCOPE_UNAVAILABLE')
                    raise ValueError('MEMBER_LIST_NOT_FOUND')
                if function == READ:
                    from .postgres_python_definitions import source_binding
                    context = resolution_context(db, scope, [row])
                    result = {**self._result(row), **current_state(row, context), 'source': source_binding(db, scope, row),
                        'currentMetadataRevision': row['current_metadata_revision'], 'policyRevision': row['policy_revision'],
                        'commitRevision': row['commit_revision']}
                    if consumer_page is None:
                        self._require_current_snapshot(db, scope, row, [row], code='MEMBER_LIST_READ_STALE')
                    else:
                        limit, after, token = consumer_page
                        result['retirementConsumers'] = self._retirement_consumers(
                            db, scope, row, limit=limit, after=after, expected_token=token, access=access)
                    self._recheck_read_authority(db, scope, function, access, authority)
                    return result
                if type(args['parameters']) is not dict or len(args['parameters']) > 100:
                    raise ValueError('MEMBER_LIST_PARAMETERS_INVALID')
                expected_metadata = _revision(args['expectedMetadataRevision'], 'STALE_METADATA_REVISION')
                if expected_metadata != row['current_metadata_revision']:
                    raise ValueError('STALE_METADATA_REVISION')
                from .postgres_python_definitions import assert_source_active
                assert_source_active(db, scope, row)
                resolved = evaluate_definition_in_transaction(db, scope, row['definition'], args['parameters'], authority=authority)
                final_access = self._access(db, scope, function)
                if final_access != access:
                    raise ValueError(_AUTHORITY_STALE)
                final_authority = resolve_effective_dimensional_scope(db, self.identity, scope, access=final_access)
                self._require_current_snapshot(db, scope, row, [row], code='METADATA_CHANGED_DURING_MEMBER_LIST_EVALUATION')
                if final_authority.scope_digest != authority.scope_digest:
                    raise ValueError('METADATA_CHANGED_DURING_MEMBER_LIST_EVALUATION')
                return {'listId': list_id, 'stateToken': row['state_token'], 'dimensionId': row['dimension_id'],
                    'memberIds': resolved, 'memberCount': len(resolved), 'canonicalDigest': row['canonical_digest'],
                    'metadataRevision': row['current_metadata_revision'], 'status': 'Published'}


def read_program_contract(function):
    if function not in READ_FUNCTIONS:
        return None
    from .metadata_read_contract import read_contract, read_example, obj
    from .member_list_contract import structural_schema_definitions
    from .member_list_evaluator import MAX_EVALUATED_MEMBERS
    identifier = {'type': 'string', 'pattern': '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'}
    token = {'type': 'string', 'pattern': '^[0-9a-f]{64}$'}
    revision = {'type': 'integer', 'minimum': 0}
    summary = {'listId': identifier, 'stateToken': token, 'dimensionId': identifier,
        'name': {'type': 'string'}, 'canonicalDigest': {'anyOf': [token, {'type': 'null'}]},
        'defined': {'const': True}, 'valid': {'type': 'boolean'},
        'active': {'type': 'boolean'}, 'sourceCurrent': {'type': 'boolean'},
        'resultCurrent': {'type': 'null'}, 'executable': {'type': 'boolean'},
        'reason': {'enum': [None, 'ownership_unresolved', 'validation_required',
            'metadata_stale', 'schema_stale', 'inactive', 'dependency_stale',
            'source_environment_stale', 'compiler_unavailable']},
        'status': {'enum': ['Unavailable', 'Active', 'Inactive']},
        'definitionMetadataRevision': revision, 'sourceBuildId': {'type': ['string', 'null']},
        'updatedAt': {'type': 'string'}, 'definition': {'anyOf': [
            {'$ref': '#/$defs/memberListDefinition'}, {'type': 'null'}]}}
    if function == LIST:
        arguments = obj({'limit': {'type': 'integer', 'minimum': 1, 'maximum': 100},
            'afterListId': {'anyOf': [identifier, {'type': 'null'}]},
            'expectedCollectionToken': token}, [])
        arguments['allOf'] = [{'if': {'required': ['afterListId'],
            'properties': {'afterListId': {'type': 'string'}}},
            'then': {'required': ['expectedCollectionToken']}}]
        result = obj({'memberLists': {'type': 'array', 'maxItems': 100, 'items': obj(summary)},
            'nextAfterListId': {'anyOf': [identifier, {'type': 'null'}]}, 'collectionToken': token})
        example = {'limit': 100}
    elif function == READ:
        consumer = {'anyOf': [obj({'kind': {'const': kind}, 'id': {
            'type': 'string', 'pattern': '^' + _CONSUMER_IDS[kind].pattern.removesuffix(r'\Z') + r'(?![\s\S])'}})
            for kind in REFERENCE_CONSUMER_KINDS]}
        page = obj({'limit': {'type': 'integer', 'minimum': 1, 'maximum': _CONSUMER_PAGE_LIMIT},
            'after': consumer, 'expectedCollectionToken': token}, [])
        page['dependentRequired'] = {'after': ['expectedCollectionToken'], 'expectedCollectionToken': ['after']}
        arguments = obj({'listId': identifier, 'retirementConsumers': page}, ['listId'])
        fields = {**summary, 'source': {'anyOf': [{'type': 'null'}, obj({
            'programId': {'type': 'string'}, 'programSourceToken': {'type': 'string'},
            'sourceDigest': token, 'buildId': {'type': ['string', 'null']},
            'active': {'type': 'boolean'}})]}, 'currentMetadataRevision': revision,
            'policyRevision': revision, 'commitRevision': revision}
        result = obj({**fields, 'retirementConsumers': obj({
            'items': {'type': 'array', 'maxItems': _CONSUMER_PAGE_LIMIT, 'items': consumer},
            'nextAfter': {'anyOf': [consumer, {'type': 'null'}]}, 'collectionToken': token})}, list(fields))
        example = {'listId': 'business-selection'}
    else:
        arguments = obj({'listId': identifier, 'parameters': {'type': 'object',
            'maxProperties': 100, 'additionalProperties': {'type': ['string', 'boolean']}},
            'expectedMetadataRevision': revision})
        result = obj({'listId': identifier, 'stateToken': token, 'dimensionId': identifier,
            'memberIds': {'type': 'array', 'maxItems': MAX_EVALUATED_MEMBERS,
                'uniqueItems': True, 'items': identifier},
            'memberCount': {'type': 'integer', 'minimum': 0, 'maximum': MAX_EVALUATED_MEMBERS},
            'canonicalDigest': token, 'metadataRevision': revision, 'status': {'const': 'Published'}})
        example = {'listId': 'business-selection', 'parameters': {}, 'expectedMetadataRevision': 1}
    contract = read_contract(function, arguments, result, owner='PostgresMemberLists.read',
        definitions=structural_schema_definitions(),
        examples=[read_example(function, example, name='Read or evaluate a current named member list',
            binding='List needs no prior definition. Read uses its returned listId. Evaluate requires a current active executable list, its declared typed parameters and the current metadata revision; the example assumes a parameter-free list.')],
        semantic_rules=['Canonical expression depth/node/member budgets, parameter declarations and current object/source/dependency validity remain native.',
            'Active dimensional policy checks every typed reference in a complete definition before reading '
            'or evaluating it. List filters definitions before paging. A policy that rejects mixed selections '
            'refuses the catalogue with MEMBER_LIST_SCOPE_UNAVAILABLE if any definition is outside current scope.',
            'Each list page and collectionToken refer to the same visible owner set and application metadata, '
            'policy, security and schema revisions. Under active policy the token also binds the actor '
            'and effective dimensional scope. Continue with the returned nextAfterListId and collectionToken. '
            'A null nextAfterListId ends the list.',
            'Member-list reads recheck effective application and dimensional access before disclosure. '
            'Read uses the same MEMBER_LIST_NOT_FOUND response for absent and protected definitions. '
            'Read rechecks the returned definition and the revisions used to resolve its executable state. '
            'State tokens identify current objects, never historical retrieval.',
            'Evaluation rechecks current dimensional authority and metadata/security/schema/policy revisions; no hidden selection or stale owner is silently substituted.'])
    contract['programContract']['recovery'] = (
        'On MEMBER_LIST_LIST_STALE, restart from the first page without the old cursor or collection token. '
        'On MEMBER_LIST_READ_STALE, read the current list again. If evaluation reports changed metadata, '
        'refresh the revision and inspect the current list before trying again. '
        'On MEMBER_LIST_AUTHORIZATION_STALE, refresh the application catalogue and restart the read.')
    if function == READ:
        description = contract['programContract']
        description['examples'].append(read_example(function,
            {'listId': 'business-selection', 'retirementConsumers': {}},
            name='Review the current dependencies before retiring a member list',
            binding='Use an exact listId from current discovery with member-list deletion authority.'))
        description['semanticRules'].extend([
            'retirementConsumers requires current write and rule_publish authority with member-list deletion enabled. '
            'It reads the exact direct consumers checked by deletion, including compiled definitions, saved views, '
            'workflows and schedules with named member-list bindings.',
            'Continue with nextAfter as after and collectionToken as expectedCollectionToken for the same list. '
            'A null nextAfter ends the review. The token binds the current list and application commit.',
            'This read has no effects. Deletion rechecks dependencies under its own transaction fence.'])
        description['recovery'] += (' On MEMBER_LIST_RETIREMENT_CONSUMERS_STALE, restart the dependency review '
            'without the old cursor and collection token.')
    return contract


def write_program_contract(function: str) -> dict:
    from .member_list_contract import FORMAT, structural_schema_definitions
    from .metadata_read_contract import obj, read_contract, read_example

    outcomes = {SAVE: 'Saved', ACTIVATE: 'Published', DEACTIVATE: 'Inactive', DELETE: 'Deleted'}
    if function not in WRITE_FUNCTIONS:
        raise ValueError('MEMBER_LIST_WRITE_FUNCTION_INVALID')

    identifier = {'type': 'string', 'pattern': r'^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}(?![\s\S])'}
    token = {'type': 'string', 'pattern': r'^[0-9a-f]{64}(?![\s\S])'}
    revision = {'type': 'integer', 'minimum': 0}
    fields = {'expectedMetadataRevision': revision, 'expectedPolicyRevision': revision}
    pins = {'expectedMetadataRevision': 1, 'expectedPolicyRevision': 1}
    list_id = 'business-selection'
    request = {**pins, 'listId': list_id, 'expectedStateToken': 'a' * 64}
    binding = ('Read the current list and copy listId, stateToken, currentMetadataRevision '
               'and policyRevision into the matching request fields.')
    rules = ['Use issue_v2_operation_admission for the exact program in the chosen application. '
             'Pass the returned operationId as idempotency_key to execute_v2_metadata_program.',
             'Admission binds the request and identity. The fixed core still checks current '
             'authority, metadata and policy revisions, ownership and any required dependencies.']
    definitions = None
    if function == SAVE:
        definitions = structural_schema_definitions()
        definition_schema = definitions['memberListDefinition']
        definition_schema['required'].remove('limits')
        definition_schema['properties']['name'].pop('maxLength')
        arguments = obj({**fields, 'definition': {'$ref': '#/$defs/memberListDefinition'},
                         'expectedStateToken': {'anyOf': [token, {'type': 'null'}]}},
                        [*fields, 'definition'])
        members = {'kind': 'explicit', 'memberIds': ['example-member']}
        definition = {'format': FORMAT, 'listId': list_id, 'dimensionId': 'example-dimension',
                      'name': 'Business selection', 'parameters': [], 'expression': members}
        create = {**pins, 'definition': definition}
        examples = [
            read_example(function, create, name='Save a new named selection',
                binding=('Use a new listId. Discover the dimension and member IDs in this application. '
                         'Bind the revisions from application.state.read. Omit expectedStateToken for creation.')),
            read_example(function, {**create, 'expectedStateToken': 'a' * 64}, name='Update an existing named selection',
                binding=('Read the current list. Use its listId inside definition. Copy stateToken, '
                         'currentMetadataRevision and policyRevision into the expected fields, then review the replacement.')),
        ]
        rules.extend(['The name is trimmed to a nonempty length of at most 200 characters. The core computes limits '
                      'and rejects supplied limits that differ from the exact node and reference counts.',
                      'Save creates a Saved definition. Activation requires a separate admission and current pins. '
                      'Saving a replacement for a Published list also returns it to Saved.'])
    else:
        arguments = obj({**fields, 'listId': identifier, 'expectedStateToken': token})
        if function == ADOPT_CONFIGURATION:
            arguments = obj({**arguments['properties'], 'expectedCanonicalDigest': token,
                'sourceProgramId': identifier, 'expectedSourceStateToken': token, 'expectedSourceToken': token,
                'expectedSourceDigest': token, 'reason': {'const': 'native_object_replaces_python_wrapper'}})
            request.update(expectedCanonicalDigest='b' * 64, sourceProgramId='legacy-wrapper',
                expectedSourceStateToken='c' * 64, expectedSourceToken='d' * 64,
                expectedSourceDigest='e' * 64, reason='native_object_replaces_python_wrapper')
            binding += (' For an approved wrapper retirement, use the exact canonicalDigest and existing '
                        'source.programId from the list, then get the source state token, source token '
                        'and source digest from python.program.read.')
            rules.append('Adoption preserves the list identity, definition digest and lifecycle status. '
                         'The fixed core checks the exact existing source ownership and outstanding source dependencies.')
        elif function == DELETE:
            binding += (' Review every retirementConsumers page before approving deletion. '
                        'The transaction independently checks for remaining consumers.')
        elif function == ACTIVATE:
            binding += ' Use the current Saved or Inactive configuration-owned definition.'
            rules.append('Activation publishes the named selection. Evaluate it with current metadata and authority to see the exact resolved members.')
        else:
            binding += ' Use the current Published configuration-owned definition.'
        examples = [read_example(function, request,
            name={ACTIVATE: 'Activate the reviewed named selection', DEACTIVATE: 'Deactivate the current named selection',
                  DELETE: 'Delete an approved member list with no consumers',
                  ADOPT_CONFIGURATION: 'Adopt an exact approved source-owned member list'}[function],
            binding=binding)]

    result = {'operationId': {'type': 'string', 'pattern': r'^[A-Za-z0-9._-]{8,128}(?![\s\S])'},
              'listId': identifier, 'canonicalDigest': token, 'metadataRevision': revision, 'policyRevision': revision,
              'status': {'enum': ['Saved', 'Published', 'Inactive']} if function == ADOPT_CONFIGURATION else
                        {'const': outcomes[function]},
              'stateToken': {'type': 'null'} if function == DELETE else token}
    if function == ADOPT_CONFIGURATION:
        result.update(ownershipState={'const': 'Configuration'}, retiredSourceProgramId=identifier)
    contract = read_contract(function, arguments, obj(result), owner='PostgresMemberLists.execute',
        definitions=definitions, examples=examples, semantic_rules=rules)
    contract['programContract']['recovery'] = (
        'On a state-token or revision conflict, read the current list and application state and review the change '
        'before seeking a new admission. After an uncertain response, read application.operation.receipt.read '
        'using the original operationId. Use the exact original program and key for replay under current authority.')
    return contract
