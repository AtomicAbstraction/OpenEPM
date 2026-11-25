"""Reviewed, transactionally scoped management of group authorization assignments."""
from __future__ import annotations

from hashlib import sha256
from hmac import compare_digest, digest as keyed_digest

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .application_authorization_actions import ACTION_SCOPE_KINDS
from . import application_role_templates as templates
from .authorization_requester_benefit import requester_benefit
from .application_authorization_config import (
    APPLY, COLLECTIONS, FIELDS, INVALID, KEY, OPERATIONS, READ, REVIEW, REVISION,
    compile_config, covers, desired_state,
)
from .postgres_access import AccessDenied, PostgresAccessChecker
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest


_TABLES = {
    'roles': ('application_authorization_role','role_id'),
    'scopes': ('application_authorization_scope','scope_id'),
    'assignments': ('application_authorization_assignment','assignment_id'),
    'eligibleGroups': ('identity_group_directory_state','group_id'),
}
_COLS = {
    'roles': '''a.role_id AS "roleId",a.role_name AS name,a.revision,a.actions,
        a.template_origin AS "templateOrigin",a.workflow_duties AS "workflowDuties"''',
    'scopes': 'a.scope_id AS "scopeId",a.scope_name AS name,a.revision,a.scope_kind AS "scopeKind",a.selector',
    'assignments': '''a.assignment_id AS "assignmentId",a.group_id AS "groupId",a.role_id AS "roleId",
        a.issuer,a.revision,coalesce((SELECT jsonb_agg(jsonb_build_object('action',b.action,'scopeId',b.scope_id)
        ORDER BY b.action,b.scope_id) FROM epm.application_authorization_assignment_scope b
        WHERE (b.workspace_id,b.application_id,b.assignment_id)=
        (a.workspace_id,a.application_id,a.assignment_id)),'[]') AS privileges''',
    'eligibleGroups': 'a.group_id AS "groupId",a.group_name AS "groupName",a.display_name AS "displayName"',
}
_LOCATION = 'a.workspace_id=%(workspace)s AND a.application_id=%(app)s'
_GROUPS = """a.issuer=%(issuer)s AND a.status='Active' AND (
    a.group_id=ANY(%(groups)s::text[]) OR EXISTS (SELECT 1 FROM epm.application_authorization_assignment x
        WHERE x.workspace_id=%(workspace)s AND x.application_id=%(app)s AND x.issuer=a.issuer AND x.group_id=a.group_id)
    OR EXISTS (SELECT 1 FROM epm.workspace_group_access_grant x WHERE x.workspace_id=%(workspace)s
        AND x.issuer=a.issuer AND x.group_id=a.group_id)
    OR EXISTS (SELECT 1 FROM epm.application_group_access_grant x WHERE x.workspace_id=%(workspace)s
        AND x.application_id=%(app)s AND x.issuer=a.issuer AND x.group_id=a.group_id))"""
_MAX_IMPACT = 1000


def _rows(db, kind, params, clause, *, limit=False):
    table,key = _TABLES[kind]
    where = _GROUPS if kind=='eligibleGroups' else _LOCATION
    statement = f'SELECT {_COLS[kind]} FROM epm.{table} a WHERE {where} AND ({clause}) ORDER BY a.{key} COLLATE "C"'
    if limit:
        statement += ' LIMIT %(fetch)s'
    return db.execute(statement,params).fetchall()


def _overview(db,params,state,args,snapshot,decision):
    staging=state['authorization_model']=='legacy'
    actions=set(decision.actions)
    can_manage=staging or 'access.manage' in actions
    if 'expectedSnapshot' in args and not compare_digest(args['expectedSnapshot'],snapshot):
        raise ValueError(REVISION)
    count = args.get('limit',25)
    can_manage_duties=staging or {'access.manage','roles.manage'}<=actions
    # A legacy workspace administrator can clear links retained on reversal.
    # New links are authorized only in the group-assignment model.
    available=([row['duty'] for row in db.execute(
        'SELECT duty FROM epm.authorization_planning_duties(NULL,101)').fetchall()]
        if can_manage_duties and not staging else [])
    result = {'workspaceId':params['workspace'],'applicationId':params['app'],'revision':state['security_revision'],'authorizationMode':state['authorization_model'],
              'snapshotToken':snapshot,'complete':True,'canManageRoles':staging or 'roles.manage' in actions,
              'canManageScopes':can_manage,'canManageAssignments':can_manage,'canManageWorkflowDuties':can_manage_duties,
              'availableWorkflowDuties':available[:100],'workflowDutiesComplete':len(available)<=100,
              'actions':[{'action':action,'scopeKinds':list(kinds),'canDelegate':staging or 'delegate.'+action in actions}
                         for action,kinds in sorted(ACTION_SCOPE_KINDS.items())],
              'roleTemplates':templates.published_templates(),'nextAfter':{}}
    for kind in COLLECTIONS:
        result[kind] = []
        result['nextAfter'][kind] = None
        if 'collection' in args and args['collection']!=kind:
            continue
        clause = '(%(after)s::text IS NULL OR a.'+_TABLES[kind][1]+' COLLATE "C">%(after)s)'
        if kind=='assignments':
            clause += ' AND a.issuer=%(issuer)s'
        rows = _rows(db,kind,{**params,'after':args.get('after'),'fetch':count+1},clause,limit=True)
        for row in rows[:count]:
            row.pop('issuer',None)
            result[kind].append(row)
        if len(rows)>count:
            result['nextAfter'][kind] = rows[count-1][KEY[kind]]
            result['complete'] = False
    return result


def _load_affected(db,params,changes):
    ids={kind:set() for kind in FIELDS}
    for item in changes:
        kind,_=OPERATIONS[item['op']]
        ids[kind].add(item[KEY[kind]])
    # Include every assignment whose meaning or referential integrity could
    # change indirectly through a role or a scope edit, across all issuers.
    affected=_rows(db,'assignments',{**params,**{k:sorted(v) for k,v in ids.items()},'fetch':_MAX_IMPACT+1},
        """a.assignment_id=ANY(%(assignments)s::text[]) OR a.role_id=ANY(%(roles)s::text[])
        OR EXISTS (SELECT 1 FROM epm.application_authorization_assignment_scope b
          WHERE (b.workspace_id,b.application_id,b.assignment_id)=(a.workspace_id,a.application_id,a.assignment_id)
          AND b.scope_id=ANY(%(scopes)s::text[]))""",limit=True)
    if len(affected)>_MAX_IMPACT:
        raise ValueError('APPLICATION_AUTHORIZATION_IMPACT_LIMIT')
    if any(row['issuer']!=params['issuer'] for row in affected):
        raise AccessDenied('APPLICATION_AUTHORIZATION_DELEGATION_REQUIRED')
    before={'assignments':{row['assignmentId']:{k:v for k,v in row.items() if k!='issuer'} for row in affected}}
    for assignment in [*affected,*(c for c in changes if c['op']=='putAssignment')]:
        ids['roles'].add(assignment['roleId'])
        ids['scopes'].update(p['scopeId'] for p in assignment['privileges'])
    for kind in ('roles','scopes'):
        rows=_rows(db,kind,{**params,'ids':sorted(ids[kind])},'a.'+_TABLES[kind][1]+'=ANY(%(ids)s::text[])')
        before[kind]={row[KEY[kind]]:row for row in rows}
    return before


def _validate_targets(db,params,state,changes):
    object_tokens={}
    for item in changes:
        if item['op']=='putAssignment':
            exact={**params,'group':item['groupId']}
            criterion=("a.issuer=%(issuer)s AND a.status='Active'"
                       if state['authorization_model']=='legacy' else _GROUPS)
            row=db.execute(f'''SELECT 1 FROM epm.identity_group_directory_state a
                WHERE a.group_id=%(group)s AND {criterion}''',exact).fetchone()
            if row is None:
                raise ValueError('APPLICATION_AUTHORIZATION_GROUP_UNAVAILABLE')
        if item['op']=='putScope' and item['scopeKind']=='dimension_tags':
            valid=db.execute("""SELECT NOT EXISTS (
                SELECT 1 FROM jsonb_each(%(selector)s::jsonb) axis
                CROSS JOIN LATERAL jsonb_array_elements_text(axis.value) t(tag)
                WHERE NOT EXISTS (SELECT 1 FROM epm.dimension d JOIN epm.security_tag s
                    USING(workspace_id,application_id,dimension_id)
                    WHERE d.workspace_id=%(workspace)s AND d.application_id=%(app)s
                      AND d.dimension_id=axis.key AND d.status='Active'
                      AND s.tag_id=t.tag AND s.status='Active')) AS valid""",
                {**params,'selector':Jsonb(item['selector'])}).fetchone()
            if not valid['valid']:
                raise ValueError('APPLICATION_AUTHORIZATION_SCOPE_UNAVAILABLE')
        if item['op']=='putScope' and item['scopeKind']=='exact_object':
            target=item['selector']['objectId']
            token=db.execute('SELECT epm.authorization_saved_view_token(%s) AS token',(target,)).fetchone()['token']
            if token is None:
                raise ValueError('APPLICATION_AUTHORIZATION_SCOPE_UNAVAILABLE')
            object_tokens[target]=token
    return object_tokens


def _target_authority(db,params,actions,changes,before,after,affected):
    required={'roles.manage' if OPERATIONS[item['op']][0]=='roles' else 'access.manage' for item in changes}
    if not required.issubset(actions):
        raise AccessDenied('APPLICATION_AUTHORIZATION_MANAGEMENT_REQUIRED')
    ceiling_rows=db.execute("""SELECT action,scope_kind AS "scopeKind",selector
        FROM epm.application_authorization_privilege
        WHERE workspace_id=%(workspace)s AND application_id=%(app)s AND issuer=%(issuer)s
          AND group_id=ANY(%(groups)s::text[]) AND starts_with(action,'delegate.')""",params).fetchall()
    ceilings={}
    for row in ceiling_rows:
        action=row['action'].removeprefix('delegate.')
        if row['scopeKind'] in ACTION_SCOPE_KINDS.get(action,()):
            ceilings.setdefault(action,[]).append(row)
    for item in changes:
        if OPERATIONS[item['op']][0]=='roles':
            # A role definition is inert until bound, but defining one still
            # requires ceiling authority over its fixed actions. Delegation
            # powers are seeded externally and are not locally re-delegable.
            for graph in (before,after):
                role=graph['roles'].get(item['roleId'])
                if role and any(a not in ceilings for a in role['actions']):
                    raise AccessDenied('APPLICATION_AUTHORIZATION_DELEGATION_REQUIRED')
        elif item['op'] in ('putScope','removeScope'):
            for graph in (before,after):
                scope=graph['scopes'].get(item['scopeId'])
                if scope and not any(
                    scope['scopeKind'] in ACTION_SCOPE_KINDS.get(action,()) and covers(ceiling,scope)
                    for action,grants in ceilings.items() for ceiling in grants):
                    raise AccessDenied('APPLICATION_AUTHORIZATION_DELEGATION_REQUIRED')
    for key in affected:
        for graph in (before,after):
            assignment=graph['assignments'].get(key)
            if not assignment: continue
            for privilege in assignment['privileges']:
                scope=graph['scopes'][privilege['scopeId']]
                if not any(covers(ceiling,scope) for ceiling in ceilings.get(privilege['action'],())):
                    raise AccessDenied('APPLICATION_AUTHORIZATION_DELEGATION_REQUIRED')


def _impact(before,after,changed):
    affected=set(changed['assignments'])
    for graph in (before,after):
        for key,assignment in graph['assignments'].items():
            if (assignment['roleId'] in changed['roles']
                    or any(p['scopeId'] in changed['scopes'] for p in assignment['privileges'])):
                affected.add(key)
    result={'changed':{kind:sorted(values) for kind,values in changed.items()},
            'affectedAssignments':sorted(affected)}
    duties=[]
    for key in sorted(changed['roles']):
        prior=set(before['roles'].get(key,{}).get('workflowDuties',()))
        current=set(after['roles'].get(key,{}).get('workflowDuties',()))
        if prior!=current:
            duties.append({'roleId':key,'addedDuties':sorted(current-prior),'removedDuties':sorted(prior-current)})
    if duties:
        result['reviewedWorkflowDuties']=duties
    return result


def _validate_workflow_duties(db,mode,actions,changes):
    if not changes:
        return
    if mode=='group_assignments' and not {'roles.manage','access.manage'}.issubset(actions):
        raise AccessDenied('APPLICATION_AUTHORIZATION_MANAGEMENT_REQUIRED')
    if mode=='legacy' and any(c['addedDuties'] for c in changes):
        raise ValueError('APPLICATION_AUTHORIZATION_GROUP_MODEL_REQUIRED')
    # Already-linked identifiers may be absent from a later policy. Always
    # allow a governed removal. Accept new links only from the active policy.
    for change in changes:
        added=change['addedDuties']
        if added:
            found={r['duty'] for r in db.execute(
                'SELECT duty FROM epm.authorization_planning_duties(%s::text[],100)',(added,)).fetchall()}
            if found!=set(added):
                raise ValueError('APPLICATION_AUTHORIZATION_WORKFLOW_DUTY_UNAVAILABLE')


def _write(db,params,before,after,changed):
    for kind in ('assignments','roles','scopes'):
        table,key=_TABLES[kind]
        deleted=[id_ for id_ in changed[kind] if id_ not in after[kind]]
        if deleted:
            db.execute(f'DELETE FROM epm.{table} a WHERE {_LOCATION} AND a.{key}=ANY(%(deleted)s::text[])',
                       {**params,'deleted':deleted})
    for kind in ('roles','scopes','assignments'):
        for key in changed[kind]:
            item=after[kind].get(key)
            if item is None: continue
            values={**params,**item}
            if kind=='roles':
                db.execute("""INSERT INTO epm.application_authorization_role
                    (workspace_id,application_id,role_id,role_name,revision,actions,template_origin,workflow_duties)
                    VALUES (%(workspace)s,%(app)s,%(roleId)s,%(name)s,%(revision)s,%(actions)s,%(origin)s,%(workflowDuties)s)
                    ON CONFLICT (workspace_id,application_id,role_id) DO UPDATE SET
                    role_name=excluded.role_name,revision=excluded.revision,actions=excluded.actions,
                    template_origin=excluded.template_origin,workflow_duties=excluded.workflow_duties""",
                    {**values,'origin':Jsonb(item['templateOrigin']) if item.get('templateOrigin') else None})
            elif kind=='scopes':
                db.execute("""INSERT INTO epm.application_authorization_scope
                    (workspace_id,application_id,scope_id,scope_name,revision,scope_kind,selector)
                    VALUES (%(workspace)s,%(app)s,%(scopeId)s,%(name)s,%(revision)s,%(scopeKind)s,%(selector)s)
                    ON CONFLICT (workspace_id,application_id,scope_id) DO UPDATE SET scope_name=excluded.scope_name,
                    revision=excluded.revision,scope_kind=excluded.scope_kind,selector=excluded.selector""",
                    {**values,'selector':Jsonb(item['selector'])})
            else:
                db.execute("""INSERT INTO epm.application_authorization_assignment
                    (workspace_id,application_id,assignment_id,issuer,group_id,role_id,revision)
                    VALUES (%(workspace)s,%(app)s,%(assignmentId)s,%(issuer)s,%(groupId)s,%(roleId)s,%(revision)s)
                    ON CONFLICT (workspace_id,application_id,assignment_id) DO UPDATE SET
                    group_id=excluded.group_id,role_id=excluded.role_id,revision=excluded.revision""",values)
                db.execute("""DELETE FROM epm.application_authorization_assignment_scope WHERE workspace_id=%(workspace)s
                    AND application_id=%(app)s AND assignment_id=%(assignmentId)s""",values)
                db.cursor().executemany("""INSERT INTO epm.application_authorization_assignment_scope
                    (workspace_id,application_id,assignment_id,action,scope_id)
                    VALUES (%(workspace)s,%(app)s,%(assignmentId)s,%(action)s,%(scopeId)s)""",
                    [{**values,**privilege} for privilege in item['privileges']])


def configuration_state(db,params):
    row=db.execute("""SELECT a.authorization_model,a.created_at::text,s.security_revision,s.schema_epoch,
        s.metadata_revision,s.policy_revision,epm.authorization_directory_revision() AS directory_revision,
        coalesce((SELECT max(audit_id) FROM epm.security_audit WHERE workspace_id=a.workspace_id
            AND application_id IS NULL AND outcome='Accepted'),0) AS workspace_revision
        FROM epm.application a JOIN epm.application_state s USING(workspace_id,application_id)
        WHERE a.workspace_id=%(workspace)s AND a.application_id=%(app)s""",params).fetchone()
    if row is None: raise AccessDenied('APPLICATION_UNAVAILABLE')
    return row


def run_configuration(dsn,scope,actor,program,*,secret,operation_id=None):
    if not isinstance(secret,bytes) or len(secret)<32:
        raise ValueError('APPLICATION_AUTHORIZATION_REVIEW_KEY_INVALID')
    args=compile_config(program)
    function=program['function']
    write=function==APPLY
    if write and (not isinstance(operation_id,str) or not 8<=len(operation_id)<=128):
        raise ValueError(INVALID)
    params={'workspace':scope.workspace_id,'app':scope.application_id,'issuer':actor.issuer}
    with connect_postgres(dsn,row_factory=dict_row) as db, db.transaction():
        if not write: db.execute('SET TRANSACTION READ ONLY')
        db.execute("SELECT set_config('epm.workspace_id',%(workspace)s,true),set_config('epm.application_id',%(app)s,true)",params)
        PostgresAccessChecker.lock_directory_membership_for_assignment(db)
        PostgresAccessChecker.lock_workspace(db,scope.workspace_id,exclusive=write)
        decision=PostgresAccessChecker.check_in_transaction(db,actor,scope,'admin',function=function)
        if write:
            db.execute('''SELECT security_revision FROM epm.application_state WHERE workspace_id=%(workspace)s
                AND application_id=%(app)s FOR UPDATE''',params)
        state=configuration_state(db,params)
        if state['authorization_model']=='legacy' and not decision.workspace_administrator:
            raise AccessDenied('WORKSPACE_ADMIN_REQUIRED')
        params['groups']=list(decision.groups)
        snapshot=_canonical_digest([params,state,actor.subject_id,templates.published_templates()])
        if function==READ:
            result=_overview(db,params,state,args,snapshot,decision)
        else:
            result=_change(db,scope,actor,params,state,decision,args,program,operation_id,secret)
        if not write and configuration_state(db,params)!=state:
            raise ValueError(REVISION)
        if PostgresAccessChecker.current_groups_in_transaction(db,actor)!=decision.groups:
            raise AccessDenied('APPLICATION_ACCESS_GROUPS_CHANGED')
        return {'languageVersion':2,'function':function,'result':result}


def _change(db,scope,actor,params,state,decision,args,program,operation_id,secret):
    write=program['function']==APPLY
    actor_digest=sha256((actor.issuer+'\0'+actor.subject_id).encode()).hexdigest()
    command_digest=_canonical_digest([scope.workspace_id,scope.application_id,actor_digest,program])
    if state['authorization_model']=='group_assignments':
        duties={'roles.manage' if OPERATIONS[c['op']][0]=='roles' else 'access.manage' for c in args['changes']}
        if not duties.issubset(decision.actions):
            raise AccessDenied('APPLICATION_AUTHORIZATION_MANAGEMENT_REQUIRED')
    if write:
        prior=db.execute('''SELECT command_digest,result FROM epm.security_operation_receipt
            WHERE workspace_id=%s AND operation_id=%s''',(scope.workspace_id,operation_id)).fetchone()
        if prior is not None:
            if prior['command_digest']!=command_digest: raise ValueError('IDEMPOTENCY_KEY_REUSED')
            if (state['authorization_model']=='group_assignments'
                    and prior['result']['impact'].get('reviewedWorkflowDuties')
                    and not {'roles.manage','access.manage'}.issubset(decision.actions)):
                raise AccessDenied('APPLICATION_AUTHORIZATION_MANAGEMENT_REQUIRED')
            return prior['result']
    if args['expectedRevision']!=state['security_revision']: raise ValueError(REVISION)
    changes=args['changes']
    before=_load_affected(db,params,changes)
    after,changed=desired_state(before,changes)
    impact=_impact(before,after,changed)
    adopted=[]
    for change in changes:
        if change['op']!='adoptRoleTemplate': continue
        role=after['roles'][change['roleId']]
        previous=before['roles'].get(change['roleId']) or {}
        old_actions=set(previous.get('actions',[]))
        new_actions=set(role['actions'])
        adopted.append({'roleId':role['roleId'],'name':role['name'],'actions':role['actions'],
            'priorVersion':(previous.get('templateOrigin') or {}).get('version'),'origin':role['templateOrigin'],
            'addedActions':sorted(new_actions-old_actions),'removedActions':sorted(old_actions-new_actions)})
    if adopted: impact['reviewedRoleTemplates']=adopted
    _validate_workflow_duties(db,state['authorization_model'],set(decision.actions),impact.get('reviewedWorkflowDuties',()))
    if state['authorization_model']=='group_assignments':
        _target_authority(db,params,set(decision.actions),changes,before,after,impact['affectedAssignments'])
    object_tokens=_validate_targets(db,params,state,changes)
    impact['requesterBenefit']=requester_benefit(db,params,actor.subject_id,before,after,impact['affectedAssignments'])
    review_inputs=[params,actor.subject_id,state,changes,impact,before,after]
    if object_tokens:
        review_inputs.append(object_tokens)
    review_content=_canonical_digest(review_inputs)
    review_digest=keyed_digest(secret, ('authorization-review-v1:'+review_content).encode(), 'sha256').hex()
    if not write:
        return {'workspaceId':scope.workspace_id,'applicationId':scope.application_id,'expectedRevision':args['expectedRevision'],'authorizationMode':state['authorization_model'],
                'changes':changes,'reviewDigest':review_digest,'impact':impact}
    if not compare_digest(review_digest,args['reviewDigest']): raise ValueError(REVIEW)
    changed_any=any(changed.values())
    if changed_any:
        _write(db,params,before,after,changed)
        if state['authorization_model']=='group_assignments' and not db.execute(
                'SELECT epm.authorization_has_reachable_admin(%s,%s) AS reachable',
                (scope.workspace_id,scope.application_id)).fetchone()['reachable']:
            raise ValueError('LAST_APPLICATION_ADMINISTRATOR')
        db.execute('''UPDATE epm.application_state SET security_revision=security_revision+1
            WHERE workspace_id=%(workspace)s AND application_id=%(app)s''',params)
    result={'workspaceId':scope.workspace_id,'applicationId':scope.application_id,'revision':state['security_revision']+int(changed_any),'authorizationMode':state['authorization_model'],
            'reviewDigest':review_digest,'impact':impact,'changed':changed_any}
    db.execute("""INSERT INTO epm.security_operation_receipt
        (workspace_id,operation_id,command_digest,payload_digest,actor_digest,action,result)
        VALUES (%s,%s,%s,%s,%s,'application-authorization.apply',%s)""",
        (scope.workspace_id,operation_id,command_digest,_canonical_digest(args),actor_digest,Jsonb(result)))
    db.execute("""INSERT INTO epm.security_audit
        (actor_id,action,workspace_id,application_id,target_digest,outcome,detail)
        VALUES (%s,'application-authorization.apply',%s,%s,%s,'Accepted',%s)""",
        (actor_digest,scope.workspace_id,scope.application_id,review_digest,
         Jsonb({'operationId':operation_id,'changed':changed_any,'revision':result['revision'],
                'authorizationMode':state['authorization_model'],'requesterBenefit':impact['requesterBenefit']})))
    return result
