"""Person and administrator review within one currently authorized workspace."""
from __future__ import annotations

from hashlib import sha256
import json
import secrets

from psycopg.rows import dict_row

from .metadata_read_contract import read_contract, read_example
from .postgres_access import _ROLE_RANK
from .postgres_connection import connect_postgres
from .postgres_effective_access import _cursor_anchor, _cursor_value
from .postgres_grants import PostgresGrantStore, WORKSPACE_SECURITY_AUTHORIZATION_STALE
from .postgres_numeric_catalog import obj


PEOPLE = 'security.workspace.people.list'
APPLICATIONS = 'security.workspace.person-applications.list'
BOOTSTRAP_GROUPS = 'security.workspace.bootstrap-groups.list'
FUNCTIONS = (PEOPLE, APPLICATIONS, BOOTSTRAP_GROUPS)
# An optional installation without a configured preview key can still inspect
# access. Its read-only cursors expire on workspace listener restart.
PROCESS_REVIEW_KEY = secrets.token_bytes(32)
INVALID = 'WORKSPACE_ACCESS_REVIEW_ARGUMENTS_INVALID'


def catalog():
    text={'type':'string'}
    name={'type':['string','null']}
    subject={**text,'minLength':1,'maxLength':300}
    common={'cursor':{**text,'minLength':1,'maxLength':8192},'limit':{'type':'integer','minimum':1,'maximum':100}}
    envelope={'workspaceId':text,'coverage':{'enum':['complete_in_workspace','partial']},
              'coverageReasons':{'type':'array','items':text},'asOf':{'type':'string','format':'date-time'},
              'nextCursor':name}
    origin=obj({'kind':{'enum':['workspace_direct','workspace_group']},'groupId':name,'groupName':name})
    person=obj({'subjectId':subject,'username':name,'displayName':name,
                'directoryStatus':{'enum':['Active','Inactive','Unresolved']},
                'workspaceAdministrator':{'type':['boolean','null']},
                'origins':{'type':'array','items':origin,'maxItems':100},'originsComplete':{'type':'boolean'}})
    app=obj({'applicationId':text,'applicationName':text,'authorizationMode':{'enum':['legacy','group_assignments']},
             'applicationRole':name,'roleNames':{'type':'array','items':text,'maxItems':100},
             'rolesComplete':{'type':'boolean'},'workspaceInherited':{'type':'boolean'}})
    specs={}
    for function,args,key,row,example in (
        (BOOTSTRAP_GROUPS,obj({**common,'query':{**text,'minLength':1,'maxLength':128}},[]),'groups',
         obj({'groupId':subject,'groupName':name,'displayName':name,'actorMember':{'type':'boolean'}}),{'limit':25}),
        (PEOPLE,obj({**common,'query':{**text,'minLength':1,'maxLength':128},
                     'administratorsOnly':{'type':'boolean'}},[]),'people',person,{'limit':25}),
        (APPLICATIONS,obj({**common,'subjectId':subject},['subjectId']),'applications',app,{'subjectId':'example-person'})):
        specs[function]={'mode':'read','permission':'workspace_admin','idempotencyRequired':False,
            'previewRequired':False,'workClass':'short','arguments':list(args['properties']),
            'result':'bounded person-centric access inspection within the selected workspace',
            **read_contract(function,args,obj({**envelope,key:{'type':'array','maxItems':100,'items':row}}),
                owner='WorkspaceAccessReview',examples=[read_example(function,example,
                    name='Inspect access in a workspace you administer',
                    binding='For a person’s applications, copy the subjectId from the workspace people page.')],
                semantic_rules=['Only current workspace administrators can inspect this workspace.',
                    'Group membership and role assignments describe entitlements, independently of session validity.',
                    'Workspace administrators inherit entry in legacy applications only.',
                    'Use the same subject, filter and limit when continuing a page.'])}
    return specs


def compile_workspace_review(program):
    if (not isinstance(program,dict) or set(program)!={'languageVersion','function','arguments'}
            or type(program['languageVersion']) is not int or program['languageVersion']!=2
            or program['function'] not in FUNCTIONS or not isinstance(program['arguments'],dict)):
        raise ValueError(INVALID)
    args=program['arguments']
    fields={'cursor','limit'}|{PEOPLE:{'query','administratorsOnly'},APPLICATIONS:{'subjectId'},
                               BOOTSTRAP_GROUPS:{'query'}}[program['function']]
    if not set(args)<=fields or (program['function']==APPLICATIONS and 'subjectId' not in args):
        raise ValueError(INVALID)
    limit=args.get('limit',25)
    if type(limit) is not int or not 1<=limit<=100 or type(args.get('administratorsOnly',False)) is not bool:
        raise ValueError(INVALID)
    for field,minimum,maximum in (('cursor',1,8192),('query',1,128),('subjectId',1,300)):
        if field in args:
            value=args[field]
            if (not isinstance(value,str) or not minimum<=len(value)<=maximum or value!=value.strip()
                    or any(ord(char)<32 for char in value)):
                raise ValueError(INVALID)
    return args


_PEOPLE = """
WITH origins AS MATERIALIZED (
    SELECT * FROM epm.workspace_authorization_review_sources(%(issuer)s,NULL)
), people AS (
    SELECT o.person,u.username,u.display_name,u.status,
      bool_or(o.origin IN ('workspace_direct','workspace_group')) AS administrator
    FROM origins o LEFT JOIN epm.identity_user_directory_state u ON u.issuer=%(issuer)s AND u.subject_id=o.person
    WHERE o.person IS NOT NULL AND (%(after)s::text IS NULL OR o.person COLLATE "C">%(after)s)
        AND (%(query)s::text IS NULL OR strpos(lower(u.username),lower(%(query)s))>0
            OR strpos(lower(u.display_name),lower(%(query)s))>0)
    GROUP BY o.person,u.username,u.display_name,u.status
    HAVING NOT %(admins)s::boolean OR
        (u.status='Active' AND bool_or(o.origin IN ('workspace_direct','workspace_group')))
    ORDER BY o.person COLLATE "C" LIMIT %(fetch)s
), rows AS (
    SELECT p.person,p.username,p.display_name,p.status,p.administrator,
        coalesce(jsonb_agg(jsonb_build_object('kind',q.origin,'groupId',q.group_id,'groupName',q.group_name)
            ORDER BY q.origin,q.group_id) FILTER (WHERE q.seq<=100),'[]') AS origins,
        count(q.seq)<=100 AS origins_complete
    FROM people p LEFT JOIN LATERAL (
      SELECT o.origin,o.group_id,o.group_name,row_number() OVER (ORDER BY o.origin,o.group_id) AS seq
      FROM origins o WHERE o.person=p.person AND o.origin IN ('workspace_direct','workspace_group')
      ORDER BY o.origin,o.group_id LIMIT 101
    ) q ON true GROUP BY p.person,p.username,p.display_name,p.status,p.administrator
)
SELECT statement_timestamp() AS as_of,EXISTS(SELECT 1 FROM origins WHERE directory_gap) AS gap,
       coalesce((SELECT jsonb_agg(to_jsonb(rows) ORDER BY person COLLATE "C") FROM rows),'[]') AS rows
"""

_APPS = """
WITH origins AS MATERIALIZED (
    SELECT * FROM epm.workspace_authorization_review_sources(%(issuer)s,%(subject)s)
), active AS (
    SELECT * FROM origins WHERE person=%(subject)s AND epm.identity_subject_active(%(issuer)s,%(subject)s)
), entries AS (
    SELECT application_id,application_name,authorization_model,role_name,admits,false AS inherited
    FROM active WHERE application_id IS NOT NULL
    UNION ALL
    SELECT w.application_id,w.application_name,'legacy','Administrator',true,true
    FROM epm.workspace_authorization_legacy_applications() w
    WHERE EXISTS(SELECT 1 FROM active WHERE origin IN ('workspace_direct','workspace_group'))
), rows AS (
    SELECT application_id,application_name,authorization_model,bool_or(inherited) AS inherited,
       (array_agg(DISTINCT role_name ORDER BY role_name))[1:100] AS roles,
       count(DISTINCT role_name)<=100 AS roles_complete
    FROM entries WHERE %(after)s::text IS NULL OR application_id COLLATE "C">%(after)s
    GROUP BY application_id,application_name,authorization_model HAVING bool_or(admits)
    ORDER BY application_id COLLATE "C" LIMIT %(fetch)s
)
SELECT statement_timestamp() AS as_of,EXISTS(SELECT 1 FROM origins WHERE directory_gap) AS gap,
       coalesce((SELECT jsonb_agg(to_jsonb(rows) ORDER BY application_id COLLATE "C") FROM rows),'[]') AS rows
"""


_GROUPS = """
WITH eligible AS MATERIALIZED (
    SELECT * FROM epm.workspace_bootstrap_groups(%(issuer)s,%(actor)s,%(groups)s::text[])
), rows AS (
    SELECT group_id,group_name,display_name,actor_member FROM eligible
    WHERE (%(after)s::text IS NULL OR group_id COLLATE "C">%(after)s)
      AND (%(query)s::text IS NULL OR strpos(lower(group_name),lower(%(query)s))>0
           OR strpos(lower(display_name),lower(%(query)s))>0)
    ORDER BY group_id COLLATE "C" LIMIT %(fetch)s
)
SELECT statement_timestamp() AS as_of,EXISTS(SELECT 1 FROM eligible WHERE group_name IS NULL) AS gap,
       coalesce((SELECT jsonb_agg(to_jsonb(rows) ORDER BY group_id COLLATE "C") FROM rows),'[]') AS rows
"""


def read(dsn,workspace,actor,program,*,secret):
    args=compile_workspace_review(program)
    limit=args.get('limit',25)
    function=program['function']
    people=function==PEOPLE
    with connect_postgres(dsn,row_factory=dict_row) as db:
        with PostgresGrantStore._workspace_security_transaction(db,workspace,actor,write=False):
            def revision():
                return db.execute('SELECT epm.workspace_authorization_review_state() AS revision').fetchone()['revision']
            current=revision()
            params={'issuer':actor.issuer,'subject':args.get('subjectId'),'query':args.get('query'),
                    'admins':args.get('administratorsOnly',False),'fetch':limit+1,
                    'actor':actor.subject_id,'groups':list(actor.groups)}
            binding=sha256(json.dumps([program['function'],workspace,actor.subject_id,actor.groups,current,params],
                                      sort_keys=True,separators=(',',':')).encode()).digest()
            params['after']=_cursor_anchor(secret,binding,args['cursor']) if 'cursor' in args else None
            data=db.execute({PEOPLE:_PEOPLE,APPLICATIONS:_APPS,BOOTSTRAP_GROUPS:_GROUPS}[function],params).fetchone()
            if revision()!=current:
                raise ValueError(WORKSPACE_SECURITY_AUTHORIZATION_STALE)
    rows=[]
    for row in data['rows'][:limit]:
        if function==BOOTSTRAP_GROUPS:
            rows.append({'groupId':row['group_id'],'groupName':row['group_name'],'displayName':row['display_name'],
                         'actorMember':row['actor_member']})
        elif people:
            status=row['status'] or 'Unresolved'
            rows.append({'subjectId':row['person'],'username':row['username'],'displayName':row['display_name'],
                         'directoryStatus':status,'workspaceAdministrator':(
                             row['administrator'] if status=='Active' else False if status=='Inactive' else None),
                         'origins':row['origins'],'originsComplete':row['origins_complete']})
        else:
            legacy=row['authorization_model']=='legacy'
            rows.append({'applicationId':row['application_id'],'applicationName':row['application_name'],
                         'authorizationMode':row['authorization_model'],'workspaceInherited':row['inherited'],
                         'applicationRole':max(row['roles'],key=_ROLE_RANK.__getitem__) if legacy else None,
                         'roleNames':row['roles'],'rolesComplete':row['roles_complete']})
    next_cursor=None
    if len(data['rows'])>limit:
        next_cursor=_cursor_value(secret,binding,rows[-1][{PEOPLE:'subjectId',APPLICATIONS:'applicationId',BOOTSTRAP_GROUPS:'groupId'}[function]])
    result={'workspaceId':workspace,'coverage':'partial' if data['gap'] else 'complete_in_workspace',
            'coverageReasons':['directory_identity_unresolved'] if data['gap'] else [],
            'asOf':data['as_of'].isoformat(),{PEOPLE:'people',APPLICATIONS:'applications',BOOTSTRAP_GROUPS:'groups'}[function]:rows,'nextCursor':next_cursor}
    return {'languageVersion':2,'function':program['function'],'result':result}
