"""Offer active dimensional security tags within an administrator's delegation."""
from __future__ import annotations

import hmac

from psycopg.rows import dict_row

from .application_authorization_actions import ACTION_SCOPE_KINDS
from .metadata_read_contract import read_contract, read_example
from .postgres_access import AccessDenied, PostgresAccessChecker, SECURITY_READ_AUTHORIZATION_STALE
from .postgres_authorization_config import configuration_state
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_numeric_catalog import obj


FUNCTION = 'security.application.authorization.tags.list'
INVALID = 'APPLICATION_AUTHORIZATION_TAGS_ARGUMENTS_INVALID'
STALE = 'APPLICATION_AUTHORIZATION_TAGS_SNAPSHOT_STALE'
# Only actions that can actually be assigned to a dimensional scope qualify.
_DIMENSION_DELEGATES = tuple('delegate.' + action for action, kinds in ACTION_SCOPE_KINDS.items()
                            if not action.startswith('delegate.') and 'dimension_tags' in kinds)
_TEXT = {'type': 'string', 'minLength': 1}
_KEY = obj({'dimensionId': {**_TEXT, 'maxLength': 200}, 'tagId': {**_TEXT, 'maxLength': 20}})
_ARGUMENTS = obj({'limit': {'type': 'integer', 'minimum': 1, 'maximum': 100},
                  'after': _KEY, 'expectedSnapshot': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'}}, [])
_ARGUMENTS['dependentRequired'] = {'after': ['expectedSnapshot'], 'expectedSnapshot': ['after']}


def catalog_entry():
    item = obj({**_KEY['properties'], 'dimensionName': _TEXT, 'tagName': _TEXT})
    result = obj({'workspaceId': _TEXT, 'applicationId': _TEXT, 'tags': {
        'type': 'array', 'maxItems': 100, 'items': item}, 'snapshotToken': _TEXT,
        'nextAfter': {'oneOf': [_KEY, {'type': 'null'}]}})
    contract = read_contract(FUNCTION, _ARGUMENTS, result, owner='PostgresAuthorizationTags',
        examples=[read_example(FUNCTION, {'limit': 25}, name='Choose tags for a dimensional scope',
                               binding='Use the application in which you administer resource scopes.')],
        semantic_rules=[
            'Group-assigned administrators can discover tag choices from their current applicable delegation.',
            'Individual choices are descriptive. The reviewed assignment must fit one complete action and scope ceiling.',
            'Continue with nextAfter and snapshotToken. On a stale snapshot, restart the list.'])
    return {'mode': 'read', 'permission': 'admin', 'arguments': {
        'limit': 'optional 1-100', 'after': 'previous nextAfter', 'expectedSnapshot': 'previous snapshotToken'},
        'result': 'eligible scope-authoring tag choices within this application', 'previewRequired': False,
        'idempotencyRequired': False, 'workClass': 'short', **contract}


def compile_tags(program):
    if (not isinstance(program, dict) or set(program) != {'function', 'languageVersion', 'arguments'}
            or program['function'] != FUNCTION or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2 or not isinstance(program['arguments'], dict)):
        raise ValueError(INVALID)
    args = program['arguments']
    limit = args.get('limit', 50)
    if (not set(args) <= {'limit', 'after', 'expectedSnapshot'} or
            ('after' in args) != ('expectedSnapshot' in args) or type(limit) is not int or not 1 <= limit <= 100):
        raise ValueError(INVALID)
    after = args.get('after')
    if 'after' in args:
        if not isinstance(after, dict) or set(after) != {'dimensionId', 'tagId'}:
            raise ValueError(INVALID)
        for key, maximum in (('dimensionId', 200), ('tagId', 20)):
            value = after[key]
            if (not isinstance(value, str) or not 1 <= len(value) <= maximum
                    or any(ord(char) < 32 for char in value)):
                raise ValueError(INVALID)
        token = args['expectedSnapshot']
        if not isinstance(token, str) or len(token) != 64 or any(c not in '0123456789abcdef' for c in token):
            raise ValueError(INVALID)
    return limit, after, args.get('expectedSnapshot')


_TAGS = """
WITH ceilings AS MATERIALIZED (
    SELECT scope_kind,selector FROM epm.application_authorization_privilege
     WHERE workspace_id=%(workspace)s AND application_id=%(app)s AND issuer=%(issuer)s
       AND group_id=ANY(%(groups)s::text[]) AND action=ANY(%(delegates)s::text[])
), unrestricted AS (
    SELECT %(staging)s::boolean OR EXISTS (
        SELECT 1 FROM ceilings WHERE scope_kind='entire_application') AS allowed
), eligible_pairs AS (
    SELECT DISTINCT axis.key AS dimension_id,tag.value AS tag_id
      FROM ceilings c CROSS JOIN LATERAL jsonb_each(c.selector) axis
      CROSS JOIN LATERAL jsonb_array_elements_text(axis.value) tag
     WHERE c.scope_kind='dimension_tags'
)
SELECT t.dimension_id AS "dimensionId",d.name AS "dimensionName",
       t.tag_id AS "tagId",t.display_name AS "tagName"
  FROM epm.security_tag t JOIN epm.dimension d USING(workspace_id,application_id,dimension_id)
 WHERE t.workspace_id=%(workspace)s AND t.application_id=%(app)s
   AND t.status='Active' AND d.status='Active'
   AND ((SELECT allowed FROM unrestricted) OR (t.dimension_id,t.tag_id) IN
        (SELECT dimension_id,tag_id FROM eligible_pairs))
   AND (%(axis)s::text IS NULL OR
        (t.dimension_id COLLATE "C",t.tag_id COLLATE "C") > (%(axis)s::text COLLATE "C",%(tag)s::text COLLATE "C"))
 ORDER BY t.dimension_id COLLATE "C",t.tag_id COLLATE "C" LIMIT %(page_size)s
"""


def read_tags(dsn, scope, actor, program):
    limit, after, expected = compile_tags(program)
    params = {'workspace': scope.workspace_id, 'app': scope.application_id, 'issuer': actor.issuer}
    with connect_postgres(dsn, row_factory=dict_row) as db:
        with PostgresAccessChecker.application_security_read(db, actor, scope, function=FUNCTION) as decision:
            state = configuration_state(db, params)
            if state['authorization_model'] != decision.authorization_model:
                raise ValueError(SECURITY_READ_AUTHORIZATION_STALE)
            staging = decision.authorization_model == 'legacy'
            if staging and not decision.workspace_administrator:
                raise AccessDenied('WORKSPACE_ADMIN_REQUIRED')
            snapshot = _canonical_digest([FUNCTION, params, actor.subject_id, list(decision.groups), state])
            if expected is not None and not hmac.compare_digest(expected, snapshot):
                raise ValueError(STALE)
            rows = db.execute(_TAGS, {**params, 'staging': staging, 'groups': list(decision.groups),
                'delegates': list(_DIMENSION_DELEGATES), 'page_size': limit + 1,
                'axis': after['dimensionId'] if after else None, 'tag': after['tagId'] if after else None}).fetchall()
            if configuration_state(db, params) != state:
                raise ValueError(SECURITY_READ_AUTHORIZATION_STALE)
    tags = rows[:limit]
    next_after = {k: tags[-1][k] for k in ('dimensionId', 'tagId')} if len(rows) > limit else None
    return {'languageVersion': 2, 'function': FUNCTION, 'result': {
        'workspaceId': scope.workspace_id, 'applicationId': scope.application_id,
        'tags': tags, 'snapshotToken': snapshot, 'nextAfter': next_after}}
