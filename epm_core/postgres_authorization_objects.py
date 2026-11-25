"""Discover exact saved-view targets an application access manager can delegate."""
import hmac
from functools import lru_cache

from jsonschema import Draft202012Validator
from psycopg.rows import dict_row

from .application_authorization_config import EXACT_SAVED_VIEW, TOKEN
from .metadata_read_contract import read_contract, read_example
from .postgres_access import AccessDenied, PostgresAccessChecker
from .postgres_authorization_config import configuration_state
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_numeric_catalog import obj, program_schema

FUNCTION = 'security.application.authorization.objects.list'
_ARGS = obj({'limit':{'type':'integer','minimum':1,'maximum':100},'after':EXACT_SAVED_VIEW,'expectedSnapshot':TOKEN},[])
_ARGS['dependentRequired']={'after':['expectedSnapshot'],'expectedSnapshot':['after']}


@lru_cache(maxsize=1)
def _validator():
    return Draft202012Validator(program_schema(FUNCTION,_ARGS))


def catalog_entry():
    item = obj({**EXACT_SAVED_VIEW['properties'],'objectName':{'type':'string'}})
    result = obj({'workspaceId':{'type':'string'},'applicationId':{'type':'string'},
        'objects':{'type':'array','maxItems':100,'items':item},'snapshotToken':TOKEN,
        'nextAfter':{'oneOf':[EXACT_SAVED_VIEW,{'type':'null'}]}})
    contract = read_contract(FUNCTION,_ARGS,result,owner='PostgresAuthorizationObjects',
        examples=[read_example(FUNCTION,{'limit':25},name='Find saved views eligible for exact scope',
            binding='In the current application, use a returned objectType and objectId in a putScope preview.')],
        semantic_rules=['Only saved-view IDs and labels within the caller’s current delegation are returned.',
            'A selected object does not grant the right to read its saved definition or its source cells.',
            'Continue with nextAfter and expectedSnapshot. Restart the list if the snapshot changes.'])
    return {'mode':'read','permission':'admin','previewRequired':False,'idempotencyRequired':False,
        'workClass':'short','arguments':list(_ARGS['properties']),'result':'eligible saved-view targets',**contract}


def compile_objects(program):
    if not _validator().is_valid(program) or type(program['languageVersion']) is not int:
        raise ValueError('APPLICATION_AUTHORIZATION_OBJECTS_ARGUMENTS_INVALID')
    args = program['arguments']
    if type(args.get('limit',50)) is not int:
        raise ValueError('APPLICATION_AUTHORIZATION_OBJECTS_ARGUMENTS_INVALID')
    return args


def read_objects(dsn, scope, actor, program):
    args = compile_objects(program)
    limit = args.get('limit',50)
    where = {'workspace':scope.workspace_id,'app':scope.application_id,'issuer':actor.issuer}
    with connect_postgres(dsn,row_factory=dict_row) as db:
        with PostgresAccessChecker.application_security_read(db,actor,scope,function=FUNCTION) as decision:
            if decision.authorization_model=='legacy' and not decision.workspace_administrator:
                raise AccessDenied('WORKSPACE_ADMIN_REQUIRED')

            def snapshot():
                commit = db.execute("""SELECT commit_revision FROM epm.application_state
                    WHERE workspace_id=%(workspace)s AND application_id=%(app)s""",where).fetchone()['commit_revision']
                return _canonical_digest([FUNCTION,where,actor.subject_id,list(decision.groups),
                    configuration_state(db,where),commit])

            observed = snapshot()
            if 'after' in args and not hmac.compare_digest(observed,args['expectedSnapshot']):
                raise ValueError('APPLICATION_AUTHORIZATION_OBJECTS_SNAPSHOT_STALE')
            rows = db.execute("""SELECT 'saved_view' AS "objectType",object_id AS "objectId",object_name AS "objectName"
                FROM epm.authorization_saved_view_choices(%s,%s,%s::text[],%s,%s) ORDER BY object_id COLLATE "C" """,
                (actor.issuer,actor.subject_id,list(actor.groups),args.get('after',{}).get('objectId'),limit+1)).fetchall()
            if snapshot()!=observed:
                raise ValueError('APPLICATION_AUTHORIZATION_OBJECTS_SNAPSHOT_STALE')
    page = rows[:limit]
    after = {k:page[-1][k] for k in ('objectType','objectId')} if len(rows)>limit else None
    return {'languageVersion':2,'function':FUNCTION,'result':{'workspaceId':scope.workspace_id,
        'applicationId':scope.application_id,'objects':page,'snapshotToken':observed,'nextAfter':after}}
