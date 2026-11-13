"""Current PostgreSQL member-list registry and bounded evaluator."""
from __future__ import annotations

import re
from contextlib import nullcontext
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .current_object_contract import collection_token,new_state_token,require_state_token
from .member_list_contract import canonical_member_list_definition,member_list_digest
from .postgres_definition_lifecycle import certificate,effective_state,current_state,resolution_context,replace_references,DefinitionReferenceBlocked
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker,VerifiedIdentity,assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout

SAVE='metadata.member_list.save';READ='metadata.member_list.read';LIST='metadata.member_list.list'
ACTIVATE='metadata.member_list.activate';DEACTIVATE='metadata.member_list.deactivate'
DELETE='metadata.member_list.delete';EVALUATE='metadata.member_list.evaluate'
ADOPT_CONFIGURATION='metadata.member_list.adopt_configuration'
WRITE_FUNCTIONS=frozenset((SAVE,ACTIVATE,DEACTIVATE,DELETE,ADOPT_CONFIGURATION));READ_FUNCTIONS=frozenset((READ,LIST,EVALUATE))
_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z');_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_SLOT=re.compile(r'Custom(0[1-9]|[12][0-9]|30)\Z')

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
            'arguments':{'listId':'stable list ID'},'result':'current definition'},
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
            or raw.get('languageVersion')!=2 or raw.get('function') not in functions
            or type(raw.get('arguments')) is not dict):raise ValueError('MEMBER_LIST_PROGRAM_INVALID')
    return raw['function'],raw['arguments']

def _references(node):
    from .member_list_contract import iter_member_list_nodes
    members, hierarchies, attributes = set(), set(), set()
    for item in iter_member_list_nodes(node):
        kind = item['kind']
        if kind == 'explicit':
            members.update(item['memberIds'])
        elif kind in {'children','parents','descendants','ancestors','siblings','leaves','base'}:
            members.add(item['memberId']); hierarchies.add(item['hierarchyId'])
        elif kind == 'attribute' or kind == 'order' and item['attributeId'] is not None:
            attributes.add(item['attributeId'])
    return members, hierarchies, attributes


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
        function,args=_program(raw,WRITE_FUNCTIONS)
        if not isinstance(idempotency_key,str) or not _KEY.fullmatch(idempotency_key):raise ValueError('MEMBER_LIST_IDEMPOTENCY_KEY_INVALID')
        base={'expectedMetadataRevision','expectedPolicyRevision'}
        if function==SAVE:
            required=base|{'definition'}
            if not required<=set(args) or set(args)-required-{'expectedStateToken'}:raise ValueError('MEMBER_LIST_ARGUMENTS_INVALID')
            definition=canonical_member_list_definition(args['definition']);list_id=definition['listId']
        elif function==ADOPT_CONFIGURATION:
            required=base|{'listId','expectedStateToken','expectedCanonicalDigest',
                'sourceProgramId','expectedSourceStateToken','expectedSourceToken',
                'expectedSourceDigest','reason'}
            if (set(args)!=required
                    or args['reason']!='native_object_replaces_python_wrapper'
                    or not isinstance(args['sourceProgramId'],str)
                    or not _ID.fullmatch(args['sourceProgramId'])
                    or any(not isinstance(args[name],str)
                           or not re.fullmatch(r'[0-9a-f]{64}',args[name])
                           for name in ('expectedCanonicalDigest','expectedSourceDigest'))):
                raise ValueError('MEMBER_LIST_ARGUMENTS_INVALID')
            definition=None;list_id=_id(args['listId'])
            require_state_token(args['expectedSourceStateToken'],
                error='PYTHON_PROGRAM_STATE_TOKEN_INVALID')
            require_state_token(args['expectedSourceToken'],
                error='PYTHON_PROGRAM_SOURCE_TOKEN_INVALID')
        else:
            if set(args)!=base|{'listId','expectedStateToken'}:raise ValueError('MEMBER_LIST_ARGUMENTS_INVALID')
            definition=None;list_id=_id(args['listId'])
        expected_metadata=_revision(args['expectedMetadataRevision'],'STALE_METADATA_REVISION')
        expected_policy=_revision(args['expectedPolicyRevision'],'STALE_POLICY_REVISION')
        expected_token=args.get('expectedStateToken')
        if expected_token is not None:require_state_token(expected_token,error='MEMBER_LIST_STATE_TOKEN_INVALID')
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
                PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'write')
                PostgresAccessChecker.check_in_transaction(db,self.identity,scope,
                    'rule_design' if function==SAVE else 'rule_publish')
                prior=db.execute('''SELECT command_digest,actor_id,result FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',(scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
                if prior:
                    if prior['command_digest']!=command_digest or prior['actor_id']!=self.identity.subject_id:raise ValueError('MEMBER_LIST_IDEMPOTENCY_CONFLICT')
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
                    refs=db.execute('''SELECT consumer_kind,consumer_id FROM epm.current_definition_reference
                        WHERE workspace_id=%s AND application_id=%s AND producer_list_id=%s
                        ORDER BY consumer_kind,consumer_id''',(scope.workspace_id,scope.application_id,list_id)).fetchall()
                    if refs:raise DefinitionReferenceBlocked([{'kind':r['consumer_kind'],'id':r['consumer_id']} for r in refs])
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
                return result

    def read(self,scope,raw):
        function,args=_program(raw,READ_FUNCTIONS)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY');self._scope(db,scope)
                PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read',function=function)
                state=db.execute('''SELECT metadata_revision,policy_revision,commit_revision,security_revision,schema_epoch FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',(scope.workspace_id,scope.application_id)).fetchone()
                if state is None:raise ValueError('APPLICATION_UNAVAILABLE')
                if function==LIST:
                    if set(args)-{'limit','afterListId','expectedCollectionToken'}:raise ValueError('MEMBER_LIST_ARGUMENTS_INVALID')
                    limit=args.get('limit',100);after=args.get('afterListId')
                    if type(limit) is not int or not 1<=limit<=100:raise ValueError('MEMBER_LIST_LIMIT_INVALID')
                    if after is not None:_id(after)
                    if after is not None and 'expectedCollectionToken' not in args:raise ValueError('MEMBER_LIST_CONTINUATION_PIN_REQUIRED')
                    if 'expectedCollectionToken' in args:require_state_token(args['expectedCollectionToken'],error='MEMBER_LIST_COLLECTION_TOKEN_INVALID')
                    token_rows=db.execute('''SELECT list_id,state_token FROM epm.member_list_definition WHERE workspace_id=%s
                        AND application_id=%s ORDER BY list_id''',(scope.workspace_id,scope.application_id)).fetchall()
                    token=collection_token((row['list_id'],row['state_token']) for row in token_rows)
                    if args.get('expectedCollectionToken',token)!=token:raise ValueError('MEMBER_LIST_LIST_STALE')
                    rows=db.execute('''SELECT * FROM epm.member_list_definition WHERE workspace_id=%s AND application_id=%s
                        AND (%s::text IS NULL OR list_id>%s) ORDER BY list_id LIMIT %s''',
                        (scope.workspace_id,scope.application_id,after,after,limit+1)).fetchall()
                    owner_context=resolution_context(db,scope,rows[:limit])
                    values=[{**self._result(row),**current_state(row,owner_context)} for row in rows[:limit]]
                    return {'memberLists':values,'nextAfterListId':values[-1]['listId'] if len(rows)>limit else None,
                        'collectionToken':token}
                required={'listId'} if function==READ else {'listId','parameters','expectedMetadataRevision'}
                if set(args)!=required:raise ValueError('MEMBER_LIST_ARGUMENTS_INVALID')
                list_id=_id(args['listId'])
                row=db.execute('''SELECT * FROM epm.member_list_definition WHERE workspace_id=%s
                    AND application_id=%s AND list_id=%s''',(scope.workspace_id,scope.application_id,list_id)).fetchone()
                if row is None:raise ValueError('MEMBER_LIST_NOT_FOUND')
                if function==READ:
                    from .postgres_python_definitions import source_binding
                    return {**self._result(row),**current_state(row,resolution_context(db,scope,[row])),'source':source_binding(db,scope,row),
                        'currentMetadataRevision':state['metadata_revision'],'policyRevision':state['policy_revision'],
                        'commitRevision':state['commit_revision']}
                if type(args['parameters']) is not dict or len(args['parameters'])>100:raise ValueError('MEMBER_LIST_PARAMETERS_INVALID')
                if args['expectedMetadataRevision']!=state['metadata_revision']:raise ValueError('STALE_METADATA_REVISION')
                from .postgres_python_definitions import assert_source_active
                assert_source_active(db,scope,row)
                from .postgres_dimensional_scope import resolve_effective_dimensional_scope
                authority=resolve_effective_dimensional_scope(db,self.identity,scope,function=EVALUATE)
                resolved=evaluate_definition_in_transaction(db,scope,row['definition'],args['parameters'],authority=authority)
                final_authority=resolve_effective_dimensional_scope(db,self.identity,scope,function=EVALUATE)
                end=db.execute('''SELECT metadata_revision,policy_revision,security_revision,schema_epoch
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',(scope.workspace_id,scope.application_id)).fetchone()
                if (end is None or any(end[key]!=state[key] for key in
                        ('metadata_revision','policy_revision','security_revision','schema_epoch'))
                        or final_authority.scope_digest!=authority.scope_digest):
                    raise ValueError('METADATA_CHANGED_DURING_MEMBER_LIST_EVALUATION')
                return {'listId':list_id,'stateToken':row['state_token'],'dimensionId':row['dimension_id'],
                    'memberIds':resolved,'memberCount':len(resolved),'canonicalDigest':row['canonical_digest'],
                    'metadataRevision':state['metadata_revision'],'status':'Published'}
