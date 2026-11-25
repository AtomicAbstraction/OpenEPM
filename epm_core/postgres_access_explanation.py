"""Explain projected group entitlements for an exact visible raw numeric coordinate."""
from __future__ import annotations

from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .dimensional_privileges import dimensional_privileges_for_groups
from .dimensional_security_policy import ResolvedMemberSecurity
from .metadata_read_contract import read_contract, read_example
from .persistence_contract import Coordinate
from .postgres_access import PostgresAccessChecker, SECURITY_READ_AUTHORIZATION_STALE
from .postgres_connection import connect_postgres
from .postgres_cube_query import _FILTER_ID
from .postgres_dimensional_scope import metadata_reference_read_sql, resolve_effective_dimensional_scope
from .postgres_numeric_catalog import obj
from .postgres_planning_write_guard import WORKFLOW_ROLE_UNBOUND, enforce_active_planning_policy


FUNCTION = 'security.application.access.explain'
INVALID = 'APPLICATION_ACCESS_EXPLAIN_ARGUMENTS_INVALID'
_ACTIONS = ('facts.read','facts.write')
_MAX_ORIGINS = 100
_TEXT = {'type':'string','minLength':1}
_ACTION = {'enum':list(_ACTIONS)}
_ID = {**_TEXT,'maxLength':200,'pattern':'^[^\\u0000\\uD800-\\uDFFF]+$'}
_COORDINATE = {'type':'object','minProperties':1,'maxProperties':128,'propertyNames':_ID,
               'additionalProperties':_ID}
_UNKNOWN = 'unavailable_or_outside_review_scope'


def catalog_entry():
    origin = obj({'assignmentId':_TEXT,'groupId':_TEXT,'roleId':_TEXT,'scopeId':_TEXT,
                  'action':_ACTION,'assignmentRevision':{'type':'integer'},'scopeRevision':{'type':'integer'}})
    from .application_authorization_config import WORKFLOW_DUTIES
    origin['properties']['workflowDuties'] = WORKFLOW_DUTIES
    args = obj({'subjectId':{**_TEXT,'maxLength':300},'action':_ACTION,'coordinate':_COORDINATE,
                'expectedMetadataRevision':{'type':'integer','minimum':0}},['subjectId','action','coordinate'])
    result = obj({'workspaceId':_TEXT,'applicationId':_TEXT,'subjectId':_TEXT,'action':_ACTION,
                  'coordinate':_COORDINATE,
                  'asOf':{'type':'string','format':'date-time'},
                  'entitlement':{'enum':['granted','denied','unknown']},
                  'operation':{'enum':['allowed','blocked','unknown']},
                  'businessState':{'enum':['open','locked','planning_policy_blocked','workflow_role_unbound','not_applicable','unknown']},
                  'reason':_TEXT,'origins':{'type':'array','maxItems':_MAX_ORIGINS,'items':origin},
                  'originsComplete':{'type':'boolean'}})
    contract = read_contract(FUNCTION,args,result,owner='PostgresAccessExplanation',
        examples=[read_example(FUNCTION,{'subjectId':'person-id','action':'facts.write',
                    'coordinate':{'Location':'North','Shift':'Night'}},name='Explain setting one numeric input',
                    binding='Use a person from the selected application and one visible stable member per active fact dimension.')],
        semantic_rules=['Evaluate current projected membership in this group-assigned application. No target session is assumed.',
            'The observer must be authorized to review access and see every supplied dimension and member.',
            'facts.write explains setting a raw numeric input. Read and write must match within the same assignment.',
            'Only duties linked to matching facts.write assignments are evaluated. A linked duty is evidence of the assignment; policy priority and locks determine the final operation.',
            'The result describes authorization and planning state at the observation time; submission repeats all checks.',
            'No fact is queried. Hidden, unresolved and unavailable references have a common result.'])
    return {'mode':'read','permission':'admin','arguments':{'subjectId':'scoped person ID',
        'action':'facts.read or facts.write','coordinate':'one visible member per fact dimension'},
        'result':'current projected entitlement, matching bindings and governing write state',
        'previewRequired':False,'idempotencyRequired':False,'workClass':'short',**contract}


def compile_explanation(program):
    if (not isinstance(program,dict) or set(program)!={'languageVersion','function','arguments'}
            or type(program['languageVersion']) is not int or program['languageVersion']!=2
            or program['function']!=FUNCTION or not isinstance(program['arguments'],dict)):
        raise ValueError(INVALID)
    args=program['arguments']
    if (set(args)-{'expectedMetadataRevision'}!={'subjectId','action','coordinate'} or args['action'] not in _ACTIONS
            or ('expectedMetadataRevision' in args and (type(args['expectedMetadataRevision']) is not int
                or args['expectedMetadataRevision']<0))):
        raise ValueError(INVALID)
    subject=args['subjectId']
    point=args['coordinate']
    if (not isinstance(subject,str) or not 1<=len(subject)<=300 or subject.strip()!=subject
            or any(ord(c)<32 for c in subject) or not _FILTER_ID.fullmatch(subject)
            or not isinstance(point,dict) or not 1<=len(point)<=128
            or any(not isinstance(v,str) or not 1<=len(v)<=200 or not _FILTER_ID.fullmatch(v)
                   for pair in point.items() for v in pair)):
        raise ValueError(INVALID)
    return subject,args['action'],Coordinate.from_mapping(point)


def _state(db,scope):
    return db.execute("""SELECT s.metadata_revision,s.security_revision,s.schema_epoch,s.policy_revision,
        s.capability_revision,s.processing_mode,a.created_at,a.authorization_model,a.status AS app_status,w.status AS workspace_status
        FROM epm.application_state s JOIN epm.application a USING(workspace_id,application_id)
        JOIN epm.workspace w USING(workspace_id) WHERE s.workspace_id=%s AND s.application_id=%s""",
        (scope.workspace_id,scope.application_id)).fetchone()


def _visible_point(db,scope,authority,point):
    """Use the published metadata dimension/member predicates before exposing a classification."""
    statement = sql.SQL("""SELECT d.dimension_id,m.member_id,m.read_security_tags,m.write_security_tags,
            l.dimensions FROM epm.application_state s JOIN epm.coordinate_layout l
            ON (s.workspace_id,s.application_id,s.schema_epoch)=(l.workspace_id,l.application_id,l.schema_epoch)
            CROSS JOIN LATERAL jsonb_each_text(%s::jsonb) q JOIN epm.dimension d
            ON d.dimension_id=q.key JOIN epm.member m ON
            (d.workspace_id,d.application_id,d.dimension_id)=(m.workspace_id,m.application_id,m.dimension_id)
            WHERE s.workspace_id=%s AND s.application_id=%s
            AND (d.workspace_id,d.application_id)=(s.workspace_id,s.application_id)
            AND d.status='Active' AND m.status='Active' AND m.member_id=q.value
            AND {dimension} AND {member} ORDER BY d.dimension_id COLLATE "C" """).format(
            dimension=metadata_reference_read_sql(authority,'d'),member=metadata_reference_read_sql(authority,'m'))
    rows=db.execute(statement,(Jsonb(dict(point.members)),scope.workspace_id,scope.application_id)).fetchall()
    if not rows or tuple(row['dimension_id'] for row in rows)!=tuple(rows[0]['dimensions']) or len(rows)!=len(point.members):
        return ()
    return tuple(ResolvedMemberSecurity(row['dimension_id'],row['member_id'],tuple(row['read_security_tags']),
                                        tuple(row['write_security_tags'])) for row in rows)


def _target_groups(db,scope,issuer,subject):
    # Intersect the directory projection with current assignments before any group is returned.
    return db.execute("""SELECT a.group_id,bool_or(p.action='application.enter' AND
        p.scope_kind='entire_application') AS admits FROM epm.application_authorization_assignment a
        LEFT JOIN epm.application_authorization_privilege p USING(workspace_id,application_id,assignment_id)
        WHERE a.workspace_id=%s AND a.application_id=%s AND a.issuer=%s AND
            a.group_id=ANY(epm.managed_identity_groups_for_delegation(%s,%s))
        GROUP BY a.group_id ORDER BY a.group_id COLLATE "C" LIMIT 101""",
        (scope.workspace_id,scope.application_id,issuer,issuer,subject)).fetchall()


def planning_set_failure(error):
    code = str(error)
    if code == WORKFLOW_ROLE_UNBOUND:
        return 'workflow_role_unbound', 'workflow_role_binding_unavailable'
    if code == 'PLANNING_WRITE_DENIED:0:PLANNING_INTERSECTION_LOCKED':
        return 'locked', 'intersection_locked'
    if code.startswith('PLANNING_WRITE_DENIED:0:') or code == 'PLANNING_POLICY_AMBIGUOUS_MATCH':
        return 'planning_policy_blocked', 'planning_policy_blocks_set'
    return 'unknown', 'planning_state_unavailable'


def _evaluate(db,scope,actor,access,state,subject,action,point):
    unknown = {'entitlement':'unknown','operation':'unknown','businessState':'unknown',
               'reason':_UNKNOWN,'origins':[],'originsComplete':False}
    if state['authorization_model']!='group_assignments':
        return {**unknown,'reason':'unsupported_authorization_model'}
    if 'metadata.browse' not in access.actions:
        return unknown
    authority=resolve_effective_dimensional_scope(db,actor,scope,access=access)
    members=_visible_point(db,scope,authority,point)
    if not members:
        return unknown
    groups=_target_groups(db,scope,actor.issuer,subject)
    if not groups or len(groups)>100:
        return unknown
    denied={**unknown,'entitlement':'denied','operation':'blocked','originsComplete':True}
    if not any(row['admits'] for row in groups):
        return {**denied,'reason':'application_entry_required'}
    privileges=dimensional_privileges_for_groups(db,scope,actor.issuer,[row['group_id'] for row in groups],maximum_rows=4096)
    matches=privileges.matching_rows(members,action,authority.policy)
    if not matches:
        return {**denied,'reason':'no_complete_assignment'}
    evidence={'entitlement':'granted','origins':[{'assignmentId':r.assignment_id,'groupId':r.group_id,
        'roleId':r.role_id,'scopeId':r.scope_id,'action':r.action,'assignmentRevision':r.assignment_revision,
        'scopeRevision':r.scope_revision,
        **({'workflowDuties':list(r.workflow_duties)} if r.action=='facts.write' else {})}
        for r in matches[:_MAX_ORIGINS]],'originsComplete':len(matches)<=_MAX_ORIGINS}
    if action=='facts.read':
        return {**evidence,'operation':'allowed','businessState':'not_applicable','reason':'scope_allows_read'}
    if state['app_status']!='Active' or state['workspace_status']!='Active' or state['processing_mode']!='Active':
        return {**evidence,'operation':'blocked','businessState':'unknown','reason':'application_or_workspace_not_writable'}
    try:
        # Use the same planning-state decision as a raw numeric Set.
        enforce_active_planning_policy(db,scope,writes=((point,'Set'),),workflow_role='Assigned',matched_write_rows=matches)
    except ValueError as error:
        status, reason = planning_set_failure(error)
        return {**evidence,'operation':'unknown' if status=='unknown' else 'blocked','businessState':status,'reason':reason}
    return {**evidence,'operation':'allowed','businessState':'open','reason':'scope_and_planning_allow_set'}


def read_explanation(dsn,scope,actor,program):
    subject,action,point=compile_explanation(program)
    with connect_postgres(dsn,row_factory=dict_row) as db:
        with PostgresAccessChecker.application_security_read(db,actor,scope,function=FUNCTION,fence_directory=True) as access:
            state=_state(db,scope)
            if (not state or program['arguments'].get('expectedMetadataRevision',state['metadata_revision'])!=state['metadata_revision']):
                raise ValueError(SECURITY_READ_AUTHORIZATION_STALE)
            try:
                result=_evaluate(db,scope,actor,access,state,subject,action,point)
            except ValueError as error:
                if str(error) not in ('DIMENSIONAL_PRIVILEGE_REVIEW_LIMIT','MEMBER_SECURITY_TAG_CARDINALITY_VIOLATION',
                        'GROUP_ASSIGNMENT_DIMENSIONAL_POLICY_REQUIRED','DIMENSIONAL_SECURITY_ACTIVE_POLICY_CORRUPT'):
                    raise
                result={'entitlement':'unknown','operation':'unknown','businessState':'unknown',
                        'reason':_UNKNOWN,'origins':[],'originsComplete':False}
            if _state(db,scope)!=state:
                raise ValueError(SECURITY_READ_AUTHORIZATION_STALE)
            as_of=db.execute('SELECT statement_timestamp() AS as_of').fetchone()['as_of']
    return {'languageVersion':2,'function':FUNCTION,'result':{'workspaceId':scope.workspace_id,
        'applicationId':scope.application_id,'subjectId':subject,'coordinate':dict(point.members),
        'action':action,'asOf':as_of.isoformat(),**result}}
