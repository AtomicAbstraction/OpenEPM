"""Current lifecycle for application cube-write policies."""
from __future__ import annotations

from hashlib import sha256
import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .current_object_contract import collection_token,new_state_token,require_state_token
from .persistence_contract import ApplicationScope
from .planning_workflow_policy import (
    FORMAT_V2, MAX_RULES, canonical_policy_definition, compile_planning_workflow_policy,
    policy_definition_schema, policy_identifier_schema, policy_level_selector_schema,
)
from .postgres_planning_workflow_level_selector import (
    authored_policy_identity,resolve_level_selectors,validate_level_selector_pins,
)
from .postgres_access import PostgresAccessChecker,VerifiedIdentity,assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore

SAVE='cube.write.policy.save';READ='cube.write.policy.read';LIST='cube.write.policy.list'
ACTIVATE='cube.write.policy.activate';DEACTIVATE='cube.write.policy.deactivate'
FUNCTIONS=frozenset((SAVE,READ,LIST,ACTIVATE,DEACTIVATE))
_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z')
_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z');_DIGEST=re.compile(r'[0-9a-f]{64}\Z')
_DRAFT_FIELDS = ('state_token', 'definition', 'canonical_digest', 'updated_operation_id',
                 'updated_issuer', 'updated_subject_id', 'updated_at')
_SELECT = 'policy_id,status,' + ','.join((*_DRAFT_FIELDS, *('draft_' + f for f in _DRAFT_FIELDS)))


def policy_program_contract(function: str) -> dict:
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj

    identifier = policy_identifier_schema()
    token = {'type': 'string', 'pattern': r'^[0-9a-f]{64}(?![\s\S])'}
    nullable_identifier = {'anyOf': [identifier, {'type': 'null'}]}
    nullable_token = {'anyOf': [token, {'type': 'null'}]}
    identity = {'policyId': identifier, 'stateToken': token, 'canonicalDigest': token}
    example_id = 'example-input-policy'
    example_token = 'a' * 64

    if function in (READ, LIST):
        fields = {**identity, 'status': {'enum': ['Saved', 'Active']}, 'active': {'type': 'boolean'},
                  'actor': obj({'issuer': {'type': 'string'}, 'subjectId': {'type': 'string'}}),
                  'updatedAt': {'type': 'string', 'format': 'date-time'},
                  'operationId': {'type': 'string'}, 'definition': policy_definition_schema(sealed=True)}
        resolution_fields = {'authoredIntentDigest': token, 'levelResolutions': {'type': 'array',
            'maxItems': MAX_RULES, 'items': policy_level_selector_schema(sealed=True, summary=True)}}
        saved_record = obj({**fields, **resolution_fields}, list(fields))
        saved_record['allOf'] = [
            {'if': {'properties': {'definition': {'required': ['format']}}},
             'then': {'required': list(resolution_fields)},
             'else': {'not': {'anyOf': [{'required': [field]} for field in resolution_fields]}}},
            {'if': {'properties': {'status': {'const': 'Active'}}},
             'then': {'properties': {'active': {'const': True}}},
             'else': {'properties': {'active': {'const': False}}}},
        ]
        candidate = {**saved_record, 'properties': {**saved_record['properties'],
                                                    'status': {'const': 'Saved'}}}
        record = {**saved_record, 'properties': {**saved_record['properties'], 'pendingDraft': candidate},
                  'allOf': [*saved_record['allOf'],
                            {'if': {'required': ['pendingDraft']},
                             'then': {'properties': {'status': {'const': 'Active'}}}}]}
        if function == READ:
            arguments, result = obj({'policyId': identifier}), record
            examples = [read_example(function, {'policyId': example_id},
                name='Read a current cube write policy',
                binding='Use a policyId returned by an authorized list in the same application.')]
        else:
            arguments = obj({'limit': {'type': 'integer', 'minimum': 1, 'maximum': 100},
                             'afterPolicyId': nullable_identifier, 'expectedCollectionToken': nullable_token}, [])
            arguments['allOf'] = [
                {'if': {'required': ['expectedCollectionToken']}, 'then': {'required': ['afterPolicyId']}},
                {'if': {'required': ['afterPolicyId']}, 'then': {'required': ['expectedCollectionToken']}},
                {'if': {'required': ['afterPolicyId'], 'properties': {'afterPolicyId': identifier}},
                 'then': {'properties': {'expectedCollectionToken': token}}},
            ]
            result = obj({'policies': {'type': 'array', 'maxItems': 100, 'items': record},
                          'collectionToken': token, 'nextAfterPolicyId': nullable_identifier})
            examples = [read_example(function, {'limit': 1}, name='List the first bounded policy page',
                            binding='Select a currently administered application.'),
                        read_example(function, {'limit': 1, 'afterPolicyId': example_id,
                            'expectedCollectionToken': example_token}, name='Continue the same policy collection',
                            binding='Copy nextAfterPolicyId and collectionToken from the prior page. A null nextAfterPolicyId ends the list.')]
    elif function == SAVE:
        arguments = obj({'definition': policy_definition_schema(sealed=False),
                         'expectedStateToken': nullable_token}, ['definition'])
        rule = {'ruleId': 'planner-input', 'priority': 100, 'effect': 'Allow', 'actions': ['Set'],
                'workflowRoles': ['Planner'], 'memberSelectors': {'example-dimension': ['example-member']},
                'scenarioBound': None, 'periodBound': None, 'effectiveFrom': None, 'effectiveTo': None}
        definition = {'workspaceId': 'example-workspace', 'applicationId': 'example-application',
                      'policyId': example_id, 'effectiveFrom': '2026-01-01', 'effectiveTo': None, 'rules': [rule]}
        level_definition = {**definition, 'format': FORMAT_V2, 'rules': [{**rule, 'memberSelectors': {},
            'levelSelector': {'dimensionId': 'example-dimension', 'rootMemberId': 'example-root', 'depth': 1}}]}
        scope_binding = 'Bind the policy identity, scope, workflow role and member IDs to the intended application.'
        examples = [read_example(function, {'definition': definition}, name='Save a member-scoped policy',
                        binding=scope_binding),
                    read_example(function, {'definition': level_definition}, name='Save an authored level selector',
                        binding=scope_binding + ' Use a root and level in a current built hierarchy. The core supplies the resolution pins.'),
                    read_example(function, {'definition': definition, 'expectedStateToken': example_token},
                        name='Replace the exact current policy', binding=scope_binding +
                        ' Copy pendingDraft.stateToken for an existing candidate, otherwise stateToken.')]
    else:
        arguments = obj({'policyId': identifier, 'expectedStateToken': token, 'canonicalDigest': token})
        examples = [read_example(function, {'policyId': example_id, 'expectedStateToken': example_token,
                    'canonicalDigest': 'b' * 64},
                    name='Activate the exact saved policy' if function == ACTIVATE else 'Deactivate the exact active policy',
                    binding=('Use the stateToken and canonicalDigest of the saved candidate, including pendingDraft when present.'
                             if function == ACTIVATE else
                             'Use the stateToken and canonicalDigest of the active record.'))]
    if function not in (READ, LIST):
        result = obj({**identity, 'status': {'const': 'Active' if function == ACTIVATE else 'Saved'},
                      'policyRevision': {'type': 'integer', 'minimum': 0}})
    contract = read_contract(function, arguments, result, owner='PostgresPlanningWorkflowPolicies',
        examples=examples, semantic_rules=[
            'In group-assigned applications drafting and publication require their respective group-assigned actions. Either action permits inspection. Legacy applications require an administrator.',
            'Save validates dates, ranges and selector budgets. Authored level selectors become sealed against current hierarchy pins.',
            'Saving a group-assigned active policy stages a pendingDraft and preserves its published definition. A legacy administrator saving an active policy returns it to Saved.',
            'Activate publishes the exact reviewed candidate. Deactivate uses the exact active pins and retains any pending proposal as the Saved definition with fresh pins.',
            'Each list page and its collection token share one database snapshot.',
        ])
    contract['programContract']['recovery'] = (
        'Restart the list without its cursor and token on PLANNING_POLICY_LIST_STALE. '
        'Reread the current policy and its hierarchy on stale state or hierarchy pins before proposing another change. '
        'Replay the exact signed admission and program before expiry. After expiry, read the original operation receipt with current authority.')
    return contract


def catalog()->dict:
    common={'permission':'admin','requiredCapabilities':[],
            'previewRequired':False,'workClass':'short'}
    functions = {
        SAVE:{**common,'mode':'current_policy_write','idempotencyRequired':True,
              'arguments':{'definition':'bounded current cube-write policy'},
              'optionalArguments':{'expectedStateToken':'current candidate token, otherwise the current policy token'},
              'result':'saved candidate, its state token, digest and policy revision'},
        READ:{**common,'mode':'read','idempotencyRequired':False,
              'arguments':{'policyId':'stable policy ID'},'result':'verified current policy and any pending draft'},
        LIST:{**common,'mode':'read','idempotencyRequired':False,'arguments':{},
              'optionalArguments':{'limit':'1-100','afterPolicyId':'keyset cursor',
                                   'expectedCollectionToken':'required with cursor'},
              'result':'bounded current policies and collection token'},
        ACTIVATE:{**common,'mode':'atomic_policy_write','idempotencyRequired':True,
                  'arguments':{'policyId':'stable policy ID','expectedStateToken':'current token',
                               'canonicalDigest':'exact current digest'},
                  'result':'active current policy and receipt'},
        DEACTIVATE:{**common,'mode':'atomic_policy_write','idempotencyRequired':True,
                    'arguments':{'policyId':'stable policy ID','expectedStateToken':'current token',
                                 'canonicalDigest':'exact current digest'},
                    'result':'saved current policy and receipt'},
    }
    return {function: {**entry, **policy_program_contract(function)} for function, entry in functions.items()}


def _program(raw):
    if (not isinstance(raw,dict) or set(raw)!={'languageVersion','function','arguments'}
            or raw.get('languageVersion')!=2 or raw.get('function') not in FUNCTIONS
            or not isinstance(raw.get('arguments'),dict)):
        raise ValueError('PLANNING_POLICY_PROGRAM_INVALID')
    return raw['function'],raw['arguments']


class PostgresPlanningWorkflowPolicies:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity):
        if not isinstance(identity,VerifiedIdentity):raise ValueError('A verified identity is required')
        assert_nonowner_role(dsn,'epm_runtime',('cube_write_policy_definition',))
        self.dsn,self.identity=dsn,identity

    def _prepare(self,db,scope,function,*,writable=False):
        if not isinstance(scope,ApplicationScope):raise ValueError('APPLICATION_SCOPE_INVALID')
        PostgresNumericFactStore._set_scope(db,scope)
        PostgresAccessChecker.lock_directory_membership_for_assignment(db)
        PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
        PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=function)
        state=db.execute('''SELECT a.status,a.authorization_model,s.processing_mode,s.policy_revision,
            s.commit_revision FROM epm.application_state s JOIN epm.application a
            USING(workspace_id,application_id) WHERE s.workspace_id=%s AND s.application_id=%s'''+
            (' FOR UPDATE OF s' if writable else ''),
            (scope.workspace_id,scope.application_id)).fetchone()
        if state is None:raise ValueError('APPLICATION_UNAVAILABLE')
        if writable and (state['status']!='Active' or state['processing_mode']!='Active'):
            raise ValueError('APPLICATION_NOT_WRITABLE')
        return state

    @staticmethod
    def _target(policy_id):
        if not isinstance(policy_id,str) or not _ID.fullmatch(policy_id):
            raise ValueError('PLANNING_POLICY_TARGET_INVALID')

    @staticmethod
    def _verify(row):
        if row is None:raise ValueError('PLANNING_POLICY_UNAVAILABLE')
        try:policy=compile_planning_workflow_policy(row['definition'])
        except (TypeError,ValueError) as error:
            raise ValueError('PLANNING_POLICY_PERSISTED_DEFINITION_INVALID') from error
        if policy.policy_id!=row['policy_id'] or policy.digest!=row['canonical_digest']:
            raise ValueError('PLANNING_POLICY_PERSISTED_DIGEST_MISMATCH')
        return policy

    @classmethod
    def _result(cls,row,*,definition=False):
        policy=cls._verify(row)
        value={'policyId':policy.policy_id,'stateToken':row['state_token'],
               'status':row['status'],'active':row['status']=='Active',
               'canonicalDigest':policy.digest,
               'actor':{'issuer':row['updated_issuer'],'subjectId':row['updated_subject_id']},
               'updatedAt':row['updated_at'].isoformat(),'operationId':row['updated_operation_id']}
        if policy.format_version==2:
            value['authoredIntentDigest']=policy.authored_intent_digest
            value['levelResolutions']=cls._level_resolutions(policy)
        if definition:value['definition']=row['definition']
        return value

    @staticmethod
    def _pending(row):
        if row['draft_state_token'] is None:
            return None
        return {'policy_id': row['policy_id'], 'status': 'Saved',
                **{field: row['draft_' + field] for field in _DRAFT_FIELDS}}

    @classmethod
    def _review_record(cls, row):
        record = cls._result(row, definition=True)
        pending = cls._pending(row)
        if pending:
            record['pendingDraft'] = cls._result(pending, definition=True)
        return record

    def save(self,scope,definition,*,expected_state_token=None,idempotency_key):
        _request_key(idempotency_key)
        if expected_state_token is not None:
            require_state_token(expected_state_token,error='PLANNING_POLICY_STATE_TOKEN_INVALID')
        is_v2=isinstance(definition,dict) and definition.get('format')==FORMAT_V2
        if is_v2:
            policy_id,_=authored_policy_identity(definition)
            if (definition.get('workspaceId'),definition.get('applicationId'))!=(
                    scope.workspace_id,scope.application_id):
                raise ValueError('PLANNING_POLICY_SCOPE_MISMATCH')
            authored=definition
        else:
            initial=compile_planning_workflow_policy(definition)
            if initial.scope!=scope:raise ValueError('PLANNING_POLICY_SCOPE_MISMATCH')
            policy_id,authored=initial.policy_id,definition
        command={'scope':[scope.workspace_id,scope.application_id],
                 'actor':[self.identity.issuer,self.identity.subject_id],'function':SAVE,
                 'definition':authored,'expectedStateToken':expected_state_token,
                 'idempotencyKey':idempotency_key};digest=_digest(command)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                app=self._prepare(db,scope,SAVE,writable=True)
                prior=self._replay(db,scope,idempotency_key,digest)
                if prior is not None:return prior
                current=self._row(db,scope,policy_id,optional=True,lock=True)
                if current is None and expected_state_token is not None:
                    raise ValueError('PLANNING_POLICY_UNAVAILABLE')
                if current is not None:
                    if expected_state_token is None:
                        raise ValueError('PLANNING_POLICY_EXPECTED_STATE_TOKEN_REQUIRED')
                    if (current['draft_state_token'] or current['state_token'])!=expected_state_token:
                        raise ValueError('PLANNING_POLICY_STATE_STALE')
                sealed=resolve_level_selectors(db,scope,authored) if is_v2 else authored
                policy=compile_planning_workflow_policy(sealed)
                stored=canonical_policy_definition(policy) if is_v2 else sealed
                revision,token=app['commit_revision']+1,new_state_token()
                ids=(scope.workspace_id,scope.application_id,policy.policy_id)
                active = current is not None and current['status']=='Active'
                staged = active and (app['authorization_model']=='group_assignments'
                                     or current['draft_state_token'] is not None)
                policy_revision = app['policy_revision'] + int(active and not staged)
                if staged:
                    db.execute('''UPDATE epm.cube_write_policy_definition SET
                        draft_state_token=%s,draft_definition=%s,draft_canonical_digest=%s,
                        draft_updated_operation_id=%s,draft_updated_issuer=%s,
                        draft_updated_subject_id=%s,draft_updated_at=clock_timestamp()
                        WHERE workspace_id=%s AND application_id=%s AND policy_id=%s''',
                        (token,Jsonb(stored),policy.digest,idempotency_key,self.identity.issuer,
                         self.identity.subject_id,*ids))
                else:
                    db.execute('''INSERT INTO epm.cube_write_policy_definition(
                        workspace_id,application_id,policy_id,state_token,status,definition,
                        canonical_digest,updated_operation_id,updated_issuer,updated_subject_id)
                        VALUES(%s,%s,%s,%s,'Saved',%s,%s,%s,%s,%s)
                        ON CONFLICT(workspace_id,application_id,policy_id) DO UPDATE SET
                         state_token=EXCLUDED.state_token,status='Saved',definition=EXCLUDED.definition,
                         canonical_digest=EXCLUDED.canonical_digest,
                         updated_operation_id=EXCLUDED.updated_operation_id,
                         updated_issuer=EXCLUDED.updated_issuer,
                         updated_subject_id=EXCLUDED.updated_subject_id,updated_at=clock_timestamp()''',
                        (*ids,token,Jsonb(stored),policy.digest,idempotency_key,
                         self.identity.issuer,self.identity.subject_id))
                db.execute('''UPDATE epm.application_state SET policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (policy_revision,revision,scope.workspace_id,scope.application_id))
                result={'policyId':policy.policy_id,'stateToken':token,'status':'Saved',
                        'canonicalDigest':policy.digest,'policyRevision':policy_revision,
                        }
                self._receipt(db,scope,idempotency_key,digest,revision,result,SAVE,app);return result

    def read(self,scope,policy_id):
        self._target(policy_id)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY');self._prepare(db,scope,READ)
                return self._review_record(self._row(db,scope,policy_id))

    def read_active(self,scope):
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY');self._prepare(db,scope,READ)
                row=db.execute(f'''SELECT {_SELECT} FROM epm.cube_write_policy_definition
                    WHERE workspace_id=%s AND application_id=%s AND status='Active' ''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                return {'active':row is not None,'policy':None if row is None else self._result(row,definition=True)}

    def list(self,scope,*,limit=100,after_policy_id=None,expected_collection_token=None):
        if type(limit) is not int or not 1<=limit<=100:raise ValueError('PLANNING_POLICY_LIST_INVALID')
        if after_policy_id is not None:
            self._target(after_policy_id)
            require_state_token(expected_collection_token,error='PLANNING_POLICY_COLLECTION_TOKEN_INVALID')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY');self._prepare(db,scope,LIST)
                ids=(scope.workspace_id,scope.application_id)
                # The access checker needs READ COMMITTED. Read the page and
                # the complete token inputs in the same statement snapshot.
                observed = db.execute(f'''WITH page AS MATERIALIZED (
                    SELECT {_SELECT} FROM epm.cube_write_policy_definition
                    WHERE workspace_id=%s AND application_id=%s AND policy_id>%s
                    ORDER BY policy_id LIMIT %s
                ) SELECT stored.policy_id AS current_policy_id,
                    COALESCE(stored.draft_state_token,stored.state_token) AS current_state_token, page.*
                    FROM epm.cube_write_policy_definition stored
                    LEFT JOIN page ON page.policy_id=stored.policy_id
                    WHERE stored.workspace_id=%s AND stored.application_id=%s
                    ORDER BY stored.policy_id''', (*ids, after_policy_id or '', limit+1, *ids)).fetchall()
                token = collection_token((row['current_policy_id'], row['current_state_token'])
                                         for row in observed)
                if expected_collection_token is not None and token!=expected_collection_token:
                    raise ValueError('PLANNING_POLICY_LIST_STALE')
                rows = [row for row in observed if row['policy_id'] is not None]
                return {'policies':[self._review_record(row) for row in rows[:limit]],
                        'collectionToken':token,
                        'nextAfterPolicyId':rows[limit-1]['policy_id'] if len(rows)>limit else None}

    def change(self,scope,*,policy_id,expected_state_token,canonical_digest,idempotency_key,deactivate):
        self._target(policy_id);_request_key(idempotency_key)
        require_state_token(expected_state_token,error='PLANNING_POLICY_MUTATION_INVALID')
        if not isinstance(canonical_digest,str) or not _DIGEST.fullmatch(canonical_digest):
            raise ValueError('PLANNING_POLICY_MUTATION_INVALID')
        function=DEACTIVATE if deactivate else ACTIVATE
        command={'scope':[scope.workspace_id,scope.application_id],
                 'actor':[self.identity.issuer,self.identity.subject_id],'function':function,
                 'policyId':policy_id,'expectedStateToken':expected_state_token,
                 'canonicalDigest':canonical_digest,'idempotencyKey':idempotency_key};digest=_digest(command)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                app=self._prepare(db,scope,function,writable=True)
                prior=self._replay(db,scope,idempotency_key,digest)
                if prior is not None:return prior
                current=self._row(db,scope,policy_id,lock=True)
                pending=self._pending(current)
                # Deactivation always reviews the published row. Activation
                # reviews the candidate, which may coexist with that row.
                reviewed = current if deactivate or pending is None else pending
                reviewed_policy=self._verify(reviewed)
                if reviewed['state_token']!=expected_state_token:raise ValueError('PLANNING_POLICY_STATE_STALE')
                if reviewed_policy.digest!=canonical_digest:raise ValueError('PLANNING_POLICY_DIGEST_MISMATCH')
                if deactivate and reviewed['status']!='Active':raise ValueError('PLANNING_POLICY_NOT_ACTIVE')
                if not deactivate and reviewed['status']=='Active':raise ValueError('PLANNING_POLICY_ALREADY_ACTIVE')
                if not deactivate:
                    validate_level_selector_pins(db,scope,reviewed_policy)
                    other=db.execute('''SELECT policy_id FROM epm.cube_write_policy_definition
                        WHERE workspace_id=%s AND application_id=%s AND status='Active'
                        AND policy_id<>%s FOR UPDATE''',
                        (scope.workspace_id,scope.application_id,policy_id)).fetchone()
                    if other is not None:raise ValueError('PLANNING_POLICY_ANOTHER_ACTIVE')
                token,revision=new_state_token(),app['commit_revision']+1
                policy_revision=app['policy_revision']+1;status='Saved' if deactivate else 'Active'
                result_digest = self._verify(pending).digest if deactivate and pending else reviewed_policy.digest
                db.execute('''UPDATE epm.cube_write_policy_definition SET status=%s,state_token=%s,
                    definition=COALESCE(draft_definition,definition),
                    canonical_digest=COALESCE(draft_canonical_digest,canonical_digest),
                    draft_state_token=NULL,draft_definition=NULL,draft_canonical_digest=NULL,
                    draft_updated_operation_id=NULL,draft_updated_issuer=NULL,
                    draft_updated_subject_id=NULL,draft_updated_at=NULL,
                    updated_operation_id=%s,updated_issuer=%s,
                    updated_subject_id=%s,updated_at=clock_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND policy_id=%s''',
                    (status,token,idempotency_key,self.identity.issuer,self.identity.subject_id,
                     scope.workspace_id,scope.application_id,policy_id))
                db.execute('''UPDATE epm.application_state SET policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (policy_revision,revision,scope.workspace_id,scope.application_id))
                result={'policyId':policy_id,'stateToken':token,'status':status,
                        'canonicalDigest':result_digest,'policyRevision':policy_revision,
                        }
                self._receipt(db,scope,idempotency_key,digest,revision,result,function,app);return result

    def execute_program(self,scope,program,*,idempotency_key=None):
        function,args=_program(program)
        if function==SAVE:
            if set(args)-{'definition','expectedStateToken'} or 'definition' not in args or idempotency_key is None:
                raise ValueError('PLANNING_POLICY_ARGUMENTS_INVALID')
            return self.save(scope,args['definition'],expected_state_token=args.get('expectedStateToken'),
                             idempotency_key=idempotency_key)
        if function in (ACTIVATE,DEACTIVATE):
            if set(args)!={'policyId','expectedStateToken','canonicalDigest'} or idempotency_key is None:
                raise ValueError('PLANNING_POLICY_ARGUMENTS_INVALID')
            return self.change(scope,policy_id=args['policyId'],expected_state_token=args['expectedStateToken'],
                canonical_digest=args['canonicalDigest'],idempotency_key=idempotency_key,
                deactivate=function==DEACTIVATE)
        raise ValueError('PLANNING_POLICY_WRITE_FUNCTION_INVALID')

    def read_program(self,scope,program):
        function,args=_program(program)
        if function==READ and set(args)=={'policyId'}:return self.read(scope,args['policyId'])
        if function==LIST and not set(args)-{'limit','afterPolicyId','expectedCollectionToken'}:
            if ('afterPolicyId' in args)!=('expectedCollectionToken' in args):
                raise ValueError('PLANNING_POLICY_LIST_INVALID')
            return self.list(scope,limit=args.get('limit',100),after_policy_id=args.get('afterPolicyId'),
                             expected_collection_token=args.get('expectedCollectionToken'))
        raise ValueError('PLANNING_POLICY_READ_FUNCTION_INVALID')

    @staticmethod
    def _row(db,scope,policy_id,*,optional=False,lock=False):
        row=db.execute(f'''SELECT {_SELECT} FROM epm.cube_write_policy_definition
            WHERE workspace_id=%s AND application_id=%s AND policy_id=%s'''+
            (' FOR UPDATE' if lock else ''),(scope.workspace_id,scope.application_id,policy_id)).fetchone()
        if row is None and not optional:raise ValueError('PLANNING_POLICY_UNAVAILABLE')
        return row

    def _replay(self,db,scope,operation_id,digest):
        row=db.execute('''SELECT command_digest,actor_id,result FROM epm.operation_receipt
            WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',
            (scope.workspace_id,scope.application_id,operation_id)).fetchone()
        if row is None:return None
        if row['command_digest']!=digest or row['actor_id']!=self.identity.subject_id:
            raise ValueError('PLANNING_POLICY_IDEMPOTENCY_CONFLICT')
        return {name: value for name,value in row['result'].items()
                if name not in ('function','actorIssuer')}

    def _receipt(self,db,scope,operation_id,digest,revision,result,function,app):
        stored = result
        if app['authorization_model']=='group_assignments':
            stored = {**result,'function':function,'actorIssuer':self.identity.issuer}
        db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,
            operation_id,command_digest,actor_id,committed_revision,result)
            VALUES(%s,%s,%s,%s,%s,%s,%s)''',
            (scope.workspace_id,scope.application_id,operation_id,digest,
             self.identity.subject_id,revision,Jsonb(stored)))

    @staticmethod
    def _level_resolutions(policy):
        return [{'dimensionId':item.dimension_id,'hierarchyStateToken':item.hierarchy_state_token,
                 'rootMemberId':item.root_member_id,'depth':item.depth,
                 'metadataRevision':item.metadata_revision,'schemaEpoch':item.schema_epoch,
                 'memberCount':len(item.resolved_members),'resolutionDigest':item.resolution_digest}
                for item in (rule.level_selector for rule in policy.rules) if item is not None]


def _request_key(value):
    if not isinstance(value,str) or not _KEY.fullmatch(value):
        raise ValueError('PLANNING_POLICY_IDEMPOTENCY_KEY_INVALID')


def _digest(value):
    return sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
        ensure_ascii=True,allow_nan=False).encode('ascii')).hexdigest()
