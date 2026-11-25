"""Application-local entitlement inspection. The requesting actor remains the observer."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json

from psycopg.rows import dict_row

from .metadata_read_contract import read_contract, read_example
from .postgres_access import PostgresAccessChecker, SECURITY_READ_AUTHORIZATION_STALE, _ROLE_RANK
from .postgres_connection import connect_postgres
from .postgres_numeric_catalog import obj


FUNCTION = 'security.application.effective-access.list'
INVALID = 'EFFECTIVE_ACCESS_ARGUMENTS_INVALID'
STALE = 'EFFECTIVE_ACCESS_CURSOR_STALE'
ORIGIN_PREVIEW = 8


def catalog_entry():
    text = {'type': 'string'}
    nullable = {'type': ['string', 'null']}
    tags = {'type': 'object', 'additionalProperties': {'type': 'array', 'items': text}}
    rules = {'oneOf': [obj({k: {'type': 'boolean'} for k in ('design', 'publish', 'run')}),
                       {'type': 'null'}]}
    privilege = obj({'action': text, 'scopeId': text, 'scopeName': text, 'scopeRevision': {'type': 'integer'},
                     'scopeKind': text, 'selector': {'type': 'object'}})
    from .application_authorization_config import WORKFLOW_DUTIES
    privilege['properties']['workflowDuties'] = WORKFLOW_DUTIES
    origin = obj({'kind': {'enum': ['workspace_direct', 'workspace_group',
                                    'application_direct', 'application_group']},
                  'groupId': nullable, 'groupName': nullable, 'assignmentId': nullable,
                  'role': text, 'roleName': nullable, 'roleRevision': {'type': ['integer', 'null']},
                  'readTags': tags, 'writeTags': tags, 'rulePermissions': rules,
                  'privileges': {'type': 'array', 'items': privilege}})
    person = obj({'subjectId': text, 'displayName': nullable, 'username': nullable,
                  'directoryStatus': {'enum': ['Active', 'Inactive', 'Unresolved']},
                  'applicationRole': nullable, 'workspaceAdministrator': {'type': ['boolean', 'null']},
                  'admitted': {'type': ['boolean', 'null']}, 'originsComplete': {'type': 'boolean'},
                  'origins': {'type': 'array', 'maxItems': 100, 'items': origin}})
    arguments = obj({'subjectId': {'type': 'string', 'minLength': 1, 'maxLength': 300},
                     'query': {'type': 'string', 'minLength': 1, 'maxLength': 128},
                     'cursor': {'type': 'string', 'minLength': 1, 'maxLength': 8192},
                     'limit': {'type': 'integer', 'minimum': 1, 'maximum': 100}}, [])
    arguments['not'] = {'required': ['query', 'subjectId']}
    result = obj({'workspaceId': text, 'applicationId': text,
                  'authorizationMode': {'enum': ['legacy', 'group_assignments']},
                  'coverage': {'enum': ['complete_in_application', 'partial']},
                  'coverageReasons': {'type': 'array', 'items': text},
                  'asOf': {'type': 'string', 'format': 'date-time'},
                  'people': {'type': 'array', 'maxItems': 100, 'items': person},
                  'nextCursor': nullable})
    examples = [read_example(FUNCTION, {'limit': 25}, name='Inspect people in this application',
                             binding='Select a workspace and application you may review.'),
                read_example(FUNCTION, {'subjectId': 'example-person', 'limit': 25},
                             name='Inspect the origin of one person’s entitlement',
                             binding='Use a subjectId returned by the roster.')]
    contract = read_contract(FUNCTION, arguments, result, owner='PostgresEffectiveAccess',
                            examples=examples, semantic_rules=[
                                'Coverage is limited to this application, issuer and current directory projection.',
                                'This administrative read evaluates assignments, not another person’s actual signed-in session.',
                                'Omit subjectId for people pages. Supply subjectId to page its origins. Continue with the same filter and limit.',
                                'Legacy role and tag combination uses the existing legacy rules. Group assignments retain each action and scope together.',
                                'Each group facts.write privilege includes the planning duties linked to its role. The exact cell and current planning policy determine whether a Set is allowed.',
                                'A null workspaceAdministrator in group assignment mode means the application report does not inspect workspace authority.'])
    contract['programContract']['recovery'] = (
        f'After {STALE} or {SECURITY_READ_AUTHORIZATION_STALE}, restart in the currently authorized application without the cursor.')
    return {'mode': 'read', 'permission': 'admin', 'arguments': {
                'subjectId': 'optional subject from this application roster',
                'query': 'optional case-insensitive name or username search',
                'limit': 'optional 1-100', 'cursor': 'optional signed continuation'},
            'result': 'current application-scoped entitlements and granting assignments',
            'previewRequired': False, 'idempotencyRequired': False, 'workClass': 'short', **contract}


def compile_report(program):
    if (not isinstance(program, dict) or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int or program['languageVersion'] != 2
            or program['function'] != FUNCTION or not isinstance(program['arguments'], dict)):
        raise ValueError(INVALID)
    args = program['arguments']
    if not set(args) <= {'subjectId', 'query', 'limit', 'cursor'} or {'subjectId', 'query'} <= set(args):
        raise ValueError(INVALID)
    for key, maximum in (('subjectId', 300), ('query', 128), ('cursor', 8192)):
        if key in args:
            value = args[key]
            if (not isinstance(value, str) or not 1 <= len(value) <= maximum or value != value.strip()
                    or any(ord(char) < 32 for char in value)):
                raise ValueError(INVALID)
    limit = args.get('limit', 25)
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError(INVALID)
    return args.get('subjectId'), args.get('query'), limit, args.get('cursor')


# The legacy branches preserve the origin's role and tags even though the
# legacy runtime ranks roles and combines tags across those origins.
_LEGACY_BINDINGS = """
SELECT g.subject_id,NULL::text AS group_id,'application_direct' AS kind,
       NULL::text AS assignment_id,g.role,g.role AS role_name,NULL::bigint AS role_revision,
       g.read_security_tags,g.write_security_tags,
       CASE WHEN r.subject_id IS NOT NULL THEN jsonb_build_object(
         'design',r.can_design,'publish',r.can_publish,'run',r.can_run) END AS rule_permissions,
       '[]'::jsonb AS privileges,true AS admits
FROM epm.application_access_grant g
LEFT JOIN epm.rule_access_grant r USING(issuer,subject_id,workspace_id,application_id)
WHERE g.issuer=%(issuer)s AND g.workspace_id=%(workspace)s AND g.application_id=%(application)s
UNION ALL
SELECT NULL,g.group_id,'application_group',NULL,g.role,g.role,NULL,g.read_security_tags,g.write_security_tags,
       CASE WHEN r.group_id IS NOT NULL THEN jsonb_build_object(
         'design',r.can_design,'publish',r.can_publish,'run',r.can_run) END,'[]'::jsonb,true
FROM epm.application_group_access_grant g
LEFT JOIN epm.rule_group_access_grant r USING(issuer,group_id,workspace_id,application_id)
WHERE g.issuer=%(issuer)s AND g.workspace_id=%(workspace)s AND g.application_id=%(application)s
UNION ALL
SELECT subject_id,NULL,'workspace_direct',NULL,role,role,NULL,'{}','{}',NULL,'[]',true
FROM epm.workspace_access_grant WHERE issuer=%(issuer)s AND workspace_id=%(workspace)s
UNION ALL
SELECT NULL,group_id,'workspace_group',NULL,role,role,NULL,'{}','{}',NULL,'[]',true
FROM epm.workspace_group_access_grant WHERE issuer=%(issuer)s AND workspace_id=%(workspace)s
"""

_GROUP_BINDINGS = """
SELECT NULL::text AS subject_id,group_id,'application_group' AS kind,assignment_id,
       role_id AS role,role_name,role_revision,
       '{}'::jsonb AS read_security_tags,'{}'::jsonb AS write_security_tags,NULL::jsonb AS rule_permissions,
       jsonb_agg(jsonb_build_object('action',action,'scopeId',scope_id,'scopeName',scope_name,'scopeRevision',scope_revision,
           'scopeKind',scope_kind,'selector',selector) ||
           CASE WHEN action='facts.write' THEN jsonb_build_object('workflowDuties',workflow_duties)
                ELSE '{}'::jsonb END ORDER BY action,scope_id) AS privileges,
       bool_or(action='application.enter' AND scope_kind='entire_application') AS admits
FROM epm.application_authorization_privilege
WHERE issuer=%(issuer)s AND workspace_id=%(workspace)s AND application_id=%(application)s
GROUP BY group_id,assignment_id,role_id,role_name,role_revision
"""

# The group expansion runs once per distinct assigned group. Only people
# reachable from the selected application enter the name filter and page.
_ROSTER_MEMBERS = """
    SELECT k.group_id,m.subject_id FROM (SELECT DISTINCT group_id FROM bindings
        WHERE group_id IS NOT NULL) k
    CROSS JOIN LATERAL epm.authorization_group_members(%(issuer)s,k.group_id) m
"""
_PERSON_MEMBERS = """
    SELECT g.group_id,%(subject)s::text AS subject_id
    FROM unnest(epm.current_identity_groups(%(issuer)s,%(subject)s,
        ARRAY(SELECT DISTINCT group_id FROM bindings WHERE group_id IS NOT NULL))) AS g(group_id)
"""
_READ = """
WITH bindings AS MATERIALIZED ({bindings}),
grant_groups AS MATERIALIZED ({members}), origins AS MATERIALIZED (
    SELECT coalesce(b.subject_id,m.subject_id) AS person,
           jsonb_build_array(b.kind,b.group_id,b.assignment_id)::text COLLATE "C" AS key,
           b.*,coalesce(g.display_name,g.group_name) AS group_name
    FROM bindings b
    LEFT JOIN grant_groups m ON m.group_id=b.group_id
    LEFT JOIN epm.identity_group_directory_state g ON g.issuer=%(issuer)s AND g.group_id=b.group_id
    WHERE (b.subject_id IS NOT NULL AND (%(subject)s::text IS NULL OR b.subject_id=%(subject)s))
       OR m.subject_id IS NOT NULL
), candidates AS (
    SELECT o.person FROM origins o WHERE %(subject)s::text IS NULL OR o.person=%(subject)s
    GROUP BY o.person
), page AS (
    SELECT c.person,u.username,u.display_name,u.status
    FROM candidates c LEFT JOIN epm.identity_user_directory_state u
      ON u.issuer=%(issuer)s AND u.subject_id=c.person
    WHERE (%(after_person)s::text IS NULL OR c.person COLLATE "C">%(after_person)s)
      AND (%(query)s::text IS NULL OR strpos(lower(u.display_name),lower(%(query)s))>0
                               OR strpos(lower(u.username),lower(%(query)s))>0)
    ORDER BY c.person COLLATE "C" LIMIT %(page_limit)s
), detail AS (
    SELECT p.*,d.roles,d.workspace_admin,d.admits,d.total,d.items,d.page_keys
    FROM page p
    CROSS JOIN LATERAL (
      SELECT array_agg(DISTINCT role) AS roles,
             bool_or(kind IN ('workspace_direct','workspace_group')) AS workspace_admin,
             bool_or(admits) AS admits, count(*) AS total,
             coalesce(jsonb_agg(jsonb_build_object('kind',kind,'role',role,'roleName',role_name,
                 'roleRevision',role_revision,'groupId',group_id,'groupName',group_name,
                 'assignmentId',assignment_id,'readTags',read_security_tags,'writeTags',write_security_tags,
                 'rulePermissions',rule_permissions,'privileges',privileges) ORDER BY key)
                 FILTER(WHERE eligible AND seq<=%(origin_limit)s),'[]'::jsonb) AS items,
             array_agg(key ORDER BY key) FILTER(WHERE eligible AND seq<=%(origin_limit)s+1) AS page_keys
      FROM (
          SELECT o.*, (%(after_origin)s::text IS NULL OR key>%(after_origin)s) AS eligible,
            count(*) FILTER (WHERE %(after_origin)s::text IS NULL OR key>%(after_origin)s)
                OVER(ORDER BY key ROWS UNBOUNDED PRECEDING) AS seq
          FROM origins o WHERE o.person=p.person
      ) ranked
    ) d
), gaps AS (
    SELECT EXISTS(SELECT 1 FROM bindings b
        LEFT JOIN epm.identity_user_directory_state u ON u.issuer=%(issuer)s AND u.subject_id=b.subject_id
        LEFT JOIN epm.identity_group_directory_state g ON g.issuer=%(issuer)s AND g.group_id=b.group_id
        WHERE (b.subject_id IS NOT NULL AND (%(subject)s::text IS NULL OR b.subject_id=%(subject)s)
            AND (u.subject_id IS NULL OR u.status='Active' AND
            (u.display_name IS NULL OR u.username IS NULL OR u.principal_digest IS NULL)))
           OR (b.group_id IS NOT NULL AND (g.group_id IS NULL OR g.status='Active' AND
            (g.group_name IS NULL OR g.principal_digest IS NULL)))) OR EXISTS (
        SELECT 1 FROM grant_groups m JOIN epm.identity_user_directory_state u
          ON u.issuer=%(issuer)s AND u.subject_id=m.subject_id
          WHERE u.display_name IS NULL OR u.username IS NULL OR u.principal_digest IS NULL
    ) AS unresolved
)
SELECT statement_timestamp() AS as_of, gaps.unresolved,
       coalesce((SELECT jsonb_agg(to_jsonb(detail) ORDER BY person COLLATE "C") FROM detail),'[]') AS rows
FROM gaps
"""

_STATE = """
SELECT a.authorization_model,a.created_at::text,s.schema_epoch,s.security_revision,
       epm.authorization_directory_revision() AS directory_revision,
       CASE WHEN a.authorization_model='legacy' THEN coalesce((
         SELECT max(audit_id) FROM epm.security_audit
         WHERE workspace_id=a.workspace_id AND application_id IS NULL AND outcome='Accepted'),0)
       ELSE 0 END AS workspace_revision
FROM epm.application a JOIN epm.application_state s USING (workspace_id,application_id)
WHERE a.workspace_id=%(workspace)s AND a.application_id=%(application)s
"""


def _cursor_value(secret, binding, anchor):
    # Only the anchor was already disclosed to the authorized reviewer.
    # A keyed digest binds the filter, revision and observer without exposing them.
    encoded = json.dumps(anchor, ensure_ascii=False, separators=(',', ':')).encode()
    signature = hmac.digest(secret, binding + encoded, 'sha256')
    return base64.urlsafe_b64encode(signature + encoded).decode('ascii')


def _cursor_anchor(secret, binding, token):
    try:
        data = base64.b64decode(token, altchars=b'-_', validate=True)
        anchor = json.loads(data[32:])
        if (not isinstance(anchor, str) or not anchor or
                not hmac.compare_digest(token, _cursor_value(secret, binding, anchor))):
            raise ValueError(STALE)
        return anchor
    except (ValueError, UnicodeError, binascii.Error):
        raise ValueError(STALE) from None


def read_report(dsn, scope, actor, program, *, secret):
    subject, query, limit, cursor = compile_report(program)
    params = {'workspace': scope.workspace_id, 'application': scope.application_id,
              'issuer': actor.issuer, 'subject': subject, 'query': query,
              'page_limit': 1 if subject else limit + 1,
              'origin_limit': limit if subject else ORIGIN_PREVIEW}
    with connect_postgres(dsn, row_factory=dict_row) as db:
        with PostgresAccessChecker.application_security_read(db, actor, scope, function=FUNCTION):
            state = db.execute(_STATE, params).fetchone()
            if not state or state['authorization_model'] not in ('legacy', 'group_assignments'):
                raise ValueError(SECURITY_READ_AUTHORIZATION_STALE)
            binding = hashlib.sha256(json.dumps([FUNCTION, params, state, actor.subject_id,
                actor.groups, limit], sort_keys=True, separators=(',', ':')).encode()).digest()
            after = _cursor_anchor(secret, binding, cursor) if cursor is not None else None
            params.update(after_person=after if not subject else None,
                          after_origin=after if subject else None)
            legacy = state['authorization_model'] == 'legacy'
            statement = _READ.format(bindings=_LEGACY_BINDINGS if legacy else _GROUP_BINDINGS,
                                     members=_PERSON_MEMBERS if subject else _ROSTER_MEMBERS)
            page = db.execute(statement, params).fetchone()
            if db.execute(_STATE, params).fetchone() != state:
                raise ValueError(SECURITY_READ_AUTHORIZATION_STALE)
    result = _page_result(scope, state, page, limit=limit, subject=subject,
                          secret=secret, binding=binding)
    return {'languageVersion': 2, 'function': FUNCTION, 'result': result}


def _page_result(scope, state, page, *, limit, subject, secret, binding):
    people = []
    next_cursor = None
    legacy = state['authorization_model'] == 'legacy'
    for row in page['rows'][:limit]:
        keys = row['page_keys'] or []
        status = row['status'] or 'Unresolved'
        admitted = row['admits'] if status == 'Active' else (False if status == 'Inactive' else None)
        people.append({'subjectId': row['person'], 'username': row['username'],
                       'displayName': row['display_name'], 'directoryStatus': status, 'admitted': admitted,
                       'workspaceAdministrator': (bool(row['workspace_admin'] and admitted)
                           if legacy and admitted is not None else None),
                       'applicationRole': (max(row['roles'], key=_ROLE_RANK.__getitem__)
                           if legacy and admitted else None),
                       'origins': row['items'], 'originsComplete': len(row['items']) == row['total']})
        if subject and len(keys) > limit:
            next_cursor = _cursor_value(secret, binding, keys[limit - 1])
    if not subject and len(page['rows']) > limit:
        next_cursor = _cursor_value(secret, binding, people[-1]['subjectId'])
    reasons = []
    if not state['directory_revision']:
        reasons.append('directory_unavailable')
    if page['unresolved']:
        reasons.append('directory_identity_unresolved')
    return {'workspaceId': scope.workspace_id, 'applicationId': scope.application_id,
            'authorizationMode': state['authorization_model'],
            'coverage': 'partial' if reasons else 'complete_in_application', 'coverageReasons': reasons,
            'asOf': page['as_of'].isoformat(), 'people': people, 'nextCursor': next_cursor}
