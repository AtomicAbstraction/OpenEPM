"""Immutable authored ordered programs, runtime CAS binding and fenced jobs."""
from copy import deepcopy
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from .postgres_connection import connect_postgres
from .postgres_access import PostgresAccessChecker
from .postgres_numeric_store import PostgresNumericFactStore
from .persistence_contract import Coordinate
from .postgres_jobs import (_canonical_digest,PostgresJobQueue,_KEY,_JOB_ID,
    _job_request_descriptor,_verify_job_replay_authorization)
from .postgres_expression import _decimal
from .postgres_expression_rules import PostgresExpressionRules,_ID,_PARAM
from . import postgres_numeric_sequence as sequence
from .postgres_numeric_sequence_expression import COMPILER as EXPRESSION_COMPILER, PLAN_DIGEST as EXPRESSION_PLAN

SAVE='rules.numeric_sequence.version.save'
PUBLISH='rules.numeric_sequence.version.publish'
READ='rules.numeric_sequence.version.read'
LIST='rules.numeric_sequence.version.list'
RUN='rules.numeric_sequence.run'
TEMPLATE='rules.numeric_sequence.template'
COMPILER='saved-ordered-numeric-v1'
PLAN_DIGEST=_canonical_digest({'function':RUN,'compiler':COMPILER,
    'baseCompilers':[(sequence.COMPILER,sequence.PLAN_DIGEST),(EXPRESSION_COMPILER,EXPRESSION_PLAN)],
    'template':'typed_parameters_no_authored_cas','execution':'existing_exact_ordered_sql',
    'publication':'current_version_grants_source_and_lease_fenced','events':'one_atomic_commit'})


def bind_template(stored,bindings=None,*,authoring=False):
    if (not isinstance(stored,dict) or set(stored)!={'languageVersion','function','arguments'}
            or type(stored['languageVersion']) is not int or stored['languageVersion']!=2
            or stored['function']!=TEMPLATE or not isinstance(stored['arguments'],dict)):
        raise ValueError('ORDERED_RULE_TEMPLATE_INVALID')
    definition=stored['arguments']
    if set(definition)-{'statements','parameters','rounding'} or 'statements' not in definition:
        raise ValueError('ORDERED_RULE_TEMPLATE_INVALID')
    parameters=definition.get('parameters',{})
    if not isinstance(parameters,dict) or len(parameters)>8:
        raise ValueError('ORDERED_RULE_PARAMETERS_INVALID')
    values={}
    if not authoring and (not isinstance(bindings if bindings is not None else {},dict)
            or set(bindings or {})!=set(parameters)):
        raise ValueError('ORDERED_RULE_BINDINGS_INVALID')
    for name,kind in parameters.items():
        if not isinstance(name,str) or not _PARAM.fullmatch(name):
            raise ValueError('ORDERED_RULE_PARAMETERS_INVALID')
        if isinstance(kind,dict):
            if (set(kind)!={'type','dimensionId','sampleMemberId'} or kind['type']!='member'
                    or any(not isinstance(kind[k],str) or not 1<=len(kind[k])<=200
                        or kind[k]!=kind[k].strip() or '\x00' in kind[k]
                        for k in ('dimensionId','sampleMemberId'))):
                raise ValueError('ORDERED_RULE_PARAMETERS_INVALID')
            value=kind['sampleMemberId'] if authoring else bindings[name]
            if not isinstance(value,str) or not 1<=len(value)<=200 or value!=value.strip() or '\x00' in value:
                raise ValueError('ORDERED_RULE_MEMBER_BINDING_INVALID')
            values[name]=value
        elif kind in ('amount','ratio'):
            values[name]=_decimal('1' if authoring else bindings[name],amount=kind=='amount')
        else:raise ValueError('ORDERED_RULE_PARAMETERS_INVALID')
    used=set();budget=[0]
    def substitute(node,depth=0):
        budget[0]+=1
        if depth>16 or budget[0]>100_000:raise ValueError('ORDERED_RULE_TEMPLATE_BUDGET')
        if isinstance(node,list):return [substitute(v,depth+1) for v in node]
        if not isinstance(node,dict):return node
        if node.get('op')=='Parameter' or node.get('type')=='AmountParameter':
            expression=node.get('op')=='Parameter'
            if set(node)!=({'op','name'} if expression else {'type','name'}):
                raise ValueError('ORDERED_RULE_PARAMETER_REFERENCE_INVALID')
            name=node['name'];kind=parameters.get(name) if isinstance(name,str) else None
            if kind not in ('amount','ratio') or (not expression and kind!='amount'):
                raise ValueError('ORDERED_RULE_PARAMETER_REFERENCE_INVALID')
            used.add(name)
            return {('op' if expression else 'type'):'AmountLiteral' if kind=='amount' else 'RatioLiteral',
                'decimal':values[name]}
        if node.get('type')=='MemberParameter':raise ValueError('ORDERED_RULE_MEMBER_REFERENCE_INVALID')
        return {k:substitute(v,depth+1) for k,v in node.items()}
    statements=definition['statements']
    if not isinstance(statements,list) or not 1<=len(statements)<=500:
        raise ValueError('NUMERIC_SEQUENCE_STATEMENT_BOUNDS')
    rows=[]
    for raw in statements:
        if not isinstance(raw,dict) or 'expectedChangeId' in raw or not isinstance(raw.get('coordinate'),dict):
            raise ValueError('ORDERED_RULE_AUTHORED_CAS_FORBIDDEN')
        coordinate={}
        for axis,member in raw['coordinate'].items():
            if isinstance(member,dict):
                name=member.get('name');kind=parameters.get(name) if isinstance(name,str) else None
                if (set(member)!={'type','name'} or member['type']!='MemberParameter'
                        or not isinstance(kind,dict) or kind['dimensionId']!=axis):
                    raise ValueError('ORDERED_RULE_MEMBER_REFERENCE_INVALID')
                used.add(name);member=values[name]
            coordinate[axis]=member
        rows.append(substitute({**raw,'coordinate':coordinate}))
    if used!=set(parameters):raise ValueError('ORDERED_RULE_UNUSED_PARAMETER')
    arguments={'statements':rows,**({'rounding':definition['rounding']} if 'rounding' in definition else {})}
    return {'languageVersion':2,'function':sequence.FUNCTION,'arguments':arguments},values


def with_cas(bound,changes):
    raw=deepcopy(bound);seen=set()
    for row in raw['arguments']['statements']:
        point=Coordinate.from_mapping(row['coordinate'])
        if point.series_key not in seen:row['expectedChangeId']=changes.get(point.series_key,'')
        seen.add(point.series_key)
    return raw


def parse(raw,function):
    if (not isinstance(raw,dict) or set(raw)!={'languageVersion','function','arguments'}
            or type(raw['languageVersion']) is not int or raw['languageVersion']!=2
            or raw['function']!=function or not isinstance(raw['arguments'],dict)):
        raise ValueError('ORDERED_RULE_PROGRAM_INVALID')
    args=raw['arguments']
    if function==LIST:
        if (set(args)-{'limit','afterRuleId','expectedMetadataRevision','expectedPolicyRevision'}
                or type(args.get('limit',100)) is not int or not 1<=args.get('limit',100)<=100
                or ('afterRuleId' in args and (not isinstance(args['afterRuleId'],str) or not _ID.fullmatch(args['afterRuleId'])
                    or not {'expectedMetadataRevision','expectedPolicyRevision'}<=set(args)))
                or any(type(args[k]) is not int or args[k]<0 for k in ('expectedMetadataRevision','expectedPolicyRevision') if k in args)):
            raise ValueError('ORDERED_RULE_ARGUMENTS_INVALID')
        return args
    if not isinstance(args.get('ruleId'),str) or not _ID.fullmatch(args['ruleId']):
        raise ValueError('ORDERED_RULE_ARGUMENTS_INVALID')
    if function==READ:
        if set(args) not in ({'ruleId'},{'ruleId','version'}) or ('version' in args and (type(args['version']) is not int or args['version']<1)):
            raise ValueError('ORDERED_RULE_ARGUMENTS_INVALID')
        return args
    required={'ruleId','version','expectedMetadataRevision','expectedPolicyRevision'}|({'definition'} if function==SAVE else set())
    if (function not in (SAVE,PUBLISH) or set(args)!=required or type(args['version']) is not int or args['version']<1
            or any(type(args[k]) is not int or args[k]<0 for k in ('expectedMetadataRevision','expectedPolicyRevision'))):
        raise ValueError('ORDERED_RULE_ARGUMENTS_INVALID')
    if function==SAVE:
        stored={'languageVersion':2,'function':TEMPLATE,'arguments':args['definition']}
        bound,_=bind_template(stored,authoring=True)
        return {**args,'calculation':stored,'plan':sequence.compile_program(with_cas(bound,{}))}
    return args


class PostgresSavedNumericSequences(PostgresExpressionRules):
    SAVE,PUBLISH,READ,LIST=SAVE,PUBLISH,READ,LIST
    STORED_FUNCTION=TEMPLATE
    _parse=staticmethod(parse)
    _validate_definition=staticmethod(sequence.validate_coordinates)

    @staticmethod
    def _summary(definition):
        return {'statementCount':len(definition['statements']),
            'parameterDeclarations':definition.get('parameters',{})}


def intent(raw):
    if (not isinstance(raw,dict) or set(raw)!={'languageVersion','function','arguments'}
            or type(raw['languageVersion']) is not int or raw['languageVersion']!=2
            or raw['function']!=RUN or not isinstance(raw['arguments'],dict)
            or set(raw['arguments']) not in ({'ruleId'},{'ruleId','bindings'})
            or not isinstance(raw['arguments'].get('ruleId'),str) or not _ID.fullmatch(raw['arguments']['ruleId'])
            or not isinstance(raw['arguments'].get('bindings',{}),dict)):
        raise ValueError('ORDERED_RULE_RUN_INVALID')
    value={'ruleId':raw['arguments']['ruleId'],'bindings':raw['arguments'].get('bindings',{})}
    if (len(value['bindings'])>8 or any(not isinstance(k,str) or not _PARAM.fullmatch(k)
            or not isinstance(v,str) or not 1<=len(v)<=200 or '\x00' in v
            for k,v in value['bindings'].items())):
        raise ValueError('ORDERED_RULE_BINDINGS_INVALID')
    _canonical_digest(value)
    return value


def resolve(db,scope,run):
    row=db.execute('''SELECT p.version,p.published_revision,v.program,v.program_digest,v.metadata_revision,
        s.metadata_revision current_metadata FROM epm.expression_rule_publication p
        JOIN epm.expression_rule_version v USING(workspace_id,application_id,rule_id,version)
        JOIN epm.application_state s USING(workspace_id,application_id)
        WHERE p.workspace_id=%s AND p.application_id=%s AND p.rule_id=%s''',
        (scope.workspace_id,scope.application_id,run['ruleId'])).fetchone()
    if row is None or row['program'].get('function')!=TEMPLATE:raise ValueError('ORDERED_RULE_NOT_PUBLISHED')
    if row['metadata_revision']!=row['current_metadata']:raise ValueError('ORDERED_RULE_METADATA_STALE')
    if _canonical_digest(row['program'])!=row['program_digest']:raise ValueError('ORDERED_RULE_DEFINITION_CORRUPT')
    bound,values=bind_template(row['program'],run['bindings'])
    pin={'ruleId':run['ruleId'],'version':row['version'],'programDigest':row['program_digest'],
        'publishedRevision':row['published_revision'],'bindings':values}
    return bound,pin


def normalize(db,scope,run):
    bound,pin=resolve(db,scope,run)
    sample=sequence.compile_program(with_cas(bound,{}))
    unique=sequence.validate_coordinates(db,scope,sample)
    current=db.execute('''SELECT i.series_key,coalesce(n.change_id,'') change_id
        FROM jsonb_to_recordset(%s::jsonb) i(series_key text)
        LEFT JOIN epm.coordinate c ON c.workspace_id=%s AND c.application_id=%s AND c.series_key=i.series_key
        LEFT JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id)''',
        (Jsonb(list(unique.values())),scope.workspace_id,scope.application_id)).fetchall()
    compiled=sequence.compile_program(with_cas(bound,{r['series_key']:r['change_id'] for r in current}))
    return {'version':1,'function':RUN,'intent':run,'pin':pin,'sequence':compiled}


def validate_run(db,scope,normalized):
    if (not isinstance(normalized,dict) or set(normalized)!={'version','function','intent','pin','sequence'}
            or type(normalized['version']) is not int or normalized['version']!=1 or normalized['function']!=RUN):
        raise ValueError('ORDERED_RULE_NORMALIZED_INVALID')
    run=intent({'languageVersion':2,'function':RUN,'arguments':normalized['intent']})
    bound,pin=resolve(db,scope,run)
    if pin!=normalized['pin']:raise ValueError('STALE_ORDERED_RULE_PUBLICATION')
    compiled=sequence.decode_program(normalized['sequence'])
    changes={r['series_key']:r['expected_change_id'] for r in compiled['statements'] if r['expected_change_id'] is not None}
    if sequence.compile_program(with_cas(bound,changes))!=compiled:
        raise ValueError('ORDERED_RULE_BOUND_PROGRAM_MISMATCH')
    return compiled


def preview(language,scope,raw):
    run=intent(raw)
    with connect_postgres(language.dsn,row_factory=dict_row) as db:
        with db.transaction():
            PostgresNumericFactStore._set_scope(db,scope)
            PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            state=db.execute('''SELECT metadata_revision,data_revision,policy_revision FROM epm.application_state
                WHERE workspace_id=%s AND application_id=%s FOR SHARE''',(scope.workspace_id,scope.application_id)).fetchone()
            access=PostgresAccessChecker.check_in_transaction(
                db,language.identity,scope,'write',function=RUN)
            PostgresAccessChecker.check_in_transaction(db,language.identity,scope,'rule_run')
            normalized=normalize(db,scope,run)
            sequence.enforce_sequence_dimensional_security(
                db,language.identity,scope,normalized['sequence'])
            trace=sequence.evaluate(db,scope,normalized['sequence'])
            revisions={k:state[k] for k in ('metadata_revision','data_revision','policy_revision')}
    token,digest=language._sign_preview(scope,RUN,normalized,revisions)
    return {'languageVersion':2,'function':RUN,'previewToken':token,'programDigest':digest,
        'revisionVector':revisions,'savedProgram':normalized['pin'],'statementCount':len(trace),
        'statementResults':[{'statementIndex':i,'present':r['amount'] is not None,
            'amount':format(r['amount'],'.8f') if r['amount'] is not None else None} for i,r in enumerate(trace)]}


def submit(language,scope,raw,token,key,dependencies):
    run=intent(raw)
    if (not isinstance(key,str) or not _KEY.fullmatch(key) or not isinstance(dependencies,tuple)
            or len(dependencies)>16
            or any(not isinstance(d,str) or not _JOB_ID.fullmatch(d) for d in dependencies)
            or len(set(dependencies))!=len(dependencies)):
        raise ValueError('ORDERED_RULE_REQUEST_INVALID')
    with connect_postgres(language.dsn,row_factory=dict_row) as db:
        with db.transaction():
            PostgresNumericFactStore._set_scope(db,scope)
            PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            state=db.execute('''SELECT metadata_revision,data_revision,policy_revision FROM epm.application_state
                WHERE workspace_id=%s AND application_id=%s FOR SHARE''',(scope.workspace_id,scope.application_id)).fetchone()
            access=PostgresAccessChecker.check_in_transaction(db,language.identity,scope,'write',function=RUN)
            PostgresAccessChecker.check_in_transaction(db,language.identity,scope,'rule_run')
            prior=db.execute('''SELECT job_id,status,request_digest,normalized_program,program_digest,
                compiler_version,plan_digest,expected_metadata_revision,expected_data_revision,expected_policy_revision,
                verified_groups,authorization_scope_digest
                FROM epm.job WHERE workspace_id=%s AND application_id=%s AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',
                (scope.workspace_id,scope.application_id,language.identity.issuer,language.identity.subject_id,key)).fetchone()
            if prior:
                auth_scope=_verify_job_replay_authorization(db,scope,
                    language.identity,prior,access=access,function_name=RUN)
                descriptor=_job_request_descriptor(scope,language.identity,
                    function_name=RUN,program_digest=prior['program_digest'],
                    compiler_version=COMPILER,plan_digest=PLAN_DIGEST,
                    revisions=(prior['expected_metadata_revision'],
                        prior['expected_data_revision'],prior['expected_policy_revision']),
                    resource_class='short',dependencies=dependencies,
                    authorization_scope_digest=auth_scope)
                if (prior['normalized_program'].get('intent')!=run
                        or prior['compiler_version']!=COMPILER or prior['plan_digest']!=PLAN_DIGEST
                        or _canonical_digest(prior['normalized_program'])!=prior['program_digest']
                        or _canonical_digest(descriptor)!=prior['request_digest']):
                    raise ValueError('ORDERED_RULE_IDEMPOTENCY_CONFLICT')
                return {'jobId':prior['job_id'],'status':prior['status'],'duplicate':True}
            payload=language._unpack_preview(scope,RUN,token)
            normalized=normalize(db,scope,run)
            revisions={k:state[k] for k in ('metadata_revision','data_revision','policy_revision')}
            if (set(payload)!={'scope','identity','function','programDigest','revisions','expiresAt'}
                    or payload['programDigest']!=_canonical_digest(normalized) or payload['revisions']!=revisions):
                raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
    return PostgresJobQueue(language.dsn,identity=language.identity).submit(scope,idempotency_key=key,
        function_name=RUN,normalized_program=normalized,compiler_version=COMPILER,plan_digest=PLAN_DIGEST,
        expected_metadata_revision=revisions['metadata_revision'],expected_data_revision=revisions['data_revision'],
        expected_policy_revision=revisions['policy_revision'],depends_on_job_ids=dependencies)


def apply(db,scope,job,job_id,identity,*,workflow_role):
    PostgresAccessChecker.check_in_transaction(db,identity,scope,'rule_run')
    compiled=validate_run(db,scope,job['normalized_program'])
    return sequence.apply_in_transaction(db,scope,{**job,'normalized_program':compiled},job_id,
        identity=identity,provenance=job['normalized_program']['pin'],
        workflow_role=workflow_role)


def catalog():
    common={'workClass':'short','idempotencyRequired':True,'previewRequired':False}
    return {
      SAVE:{**common,'mode':'atomic_rule_definition','permission':'rule_design',
        'arguments':{'ruleId':'stable ID','version':'next immutable version','definition':'typed ordered template without CAS',
                     'expectedMetadataRevision':'current revision','expectedPolicyRevision':'current revision'},
        'result':'immutable authored version and digest'},
      PUBLISH:{**common,'mode':'atomic_rule_publication','permission':'rule_publish',
        'arguments':{'ruleId':'stable ID','version':'saved version','expectedMetadataRevision':'current revision','expectedPolicyRevision':'current revision'},
        'result':'atomic publication pointer and policy revision'},
      READ:{'mode':'read','permission':'read','arguments':{'ruleId':'stable ID'},'optionalArguments':{'version':'saved immutable version'},
        'result':'typed authored program, digest and publication state','previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
      LIST:{'mode':'read','permission':'read','arguments':{},'optionalArguments':{'limit':'1–100','afterRuleId':'stable cursor',
        'expectedMetadataRevision':'cursor revision','expectedPolicyRevision':'cursor revision'},'result':'bounded published ordered programs',
        'previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
      RUN:{'mode':'durable_write','permission':'rule_run','arguments':{'ruleId':'published ID'},'optionalArguments':{'bindings':'exact declared typed values'},
        'result':'durable job; ordered exact statement events and saved-program provenance',
        'previewRequired':True,'idempotencyRequired':True,'workClass':'short'}}
