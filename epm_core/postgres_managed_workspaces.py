"""Discover currently administered workspaces independently of application entry."""
import json

from psycopg.rows import dict_row

from .postgres_access import PostgresAccessChecker
from .postgres_connection import connect_postgres
from .postgres_effective_access import _cursor_anchor, _cursor_value
from .postgres_processing_limits import configure_statement_timeout


_PAGE = """
WITH grants AS (
    SELECT workspace_id FROM epm.workspace_access_grant
     WHERE issuer=%(issuer)s AND subject_id=%(subject)s AND role='Administrator'
    UNION
    SELECT workspace_id FROM epm.workspace_group_access_grant
     WHERE issuer=%(issuer)s AND group_id=ANY(%(groups)s::text[]) AND role='Administrator'
), managed AS MATERIALIZED (
    SELECT w.workspace_id,w.name FROM grants JOIN epm.workspace w USING(workspace_id)
     WHERE w.status='Active'
), page AS (
    SELECT workspace_id,name FROM managed WHERE workspace_id COLLATE "C">%(after)s
     ORDER BY workspace_id COLLATE "C" LIMIT %(fetch)s
)
SELECT (SELECT encode(sha256(convert_to(coalesce(jsonb_agg(jsonb_build_array(workspace_id,name)
               ORDER BY workspace_id COLLATE "C"),'[]')::text,'UTF8')),'hex') FROM managed) AS revision,
       (SELECT coalesce(jsonb_agg(jsonb_build_object('workspaceId',workspace_id,'workspaceName',name)
               ORDER BY workspace_id COLLATE "C"),'[]') FROM page) AS workspaces
"""


def list_managed_workspaces(dsn, identity, *, after, limit, secret):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError('WORKSPACE_DISCOVERY_LIMIT_INVALID')
    if after is not None and (not isinstance(after, str) or not 1 <= len(after) <= 8192):
        raise ValueError('WORKSPACE_DISCOVERY_CURSOR_INVALID')
    with connect_postgres(dsn, row_factory=dict_row) as db:
        with db.transaction():
            db.execute('SET TRANSACTION READ ONLY')
            configure_statement_timeout(db, 5000)
            groups = PostgresAccessChecker.current_groups_in_transaction(db, identity)
            binding = json.dumps(['managed-workspaces-v1',identity.issuer,identity.subject_id,groups,limit],
                                 separators=(',', ':')).encode()
            anchor, prior_revision = '', None
            if after is not None:
                try:
                    anchor, prior_revision = json.loads(_cursor_anchor(secret, binding, after))
                except ValueError:
                    raise ValueError('WORKSPACE_DISCOVERY_STALE') from None
            page = db.execute(_PAGE, {'issuer':identity.issuer,'subject':identity.subject_id,
                'groups':list(groups),'after':anchor,'fetch':limit+1}).fetchone()
            if (prior_revision is not None and prior_revision != page['revision']
                    or PostgresAccessChecker.current_groups_in_transaction(db, identity) != groups):
                raise ValueError('WORKSPACE_DISCOVERY_STALE')
    rows = page['workspaces']
    continuation = None
    if len(rows) > limit:
        continuation = _cursor_value(secret,binding,json.dumps([rows[limit-1]['workspaceId'],page['revision']],
                                                               separators=(',', ':')))
    return {'workspaces':rows[:limit], 'nextAfter':continuation}
