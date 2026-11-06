"""PostgreSQL grant checks for already verified provider identities.

This is a fixed-server component. JWT verification and application-language
admission must happen before calling it; a client must never submit a role.
``check_in_transaction`` must run inside the effect transaction at READ COMMITTED.
Its shared workspace lock fences fixed-core grant writers, which take the
matching exclusive lock. Callers must participate in this lock order before taking application-state locks.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Mapping

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_processing_limits import configure_lock_wait, lock_busy_boundary


_ROLE_RANK = {'Reader': 1, 'Editor': 2, 'Administrator': 3}
_PERMISSION_RANK = {
    'read': 1, 'write': 2, 'admin': 3, 'workspace_admin': 3,
    'rule_design': 1, 'rule_publish': 1, 'rule_run': 1,
}
_RULE_COLUMN = {
    'rule_design': 'can_design',
    'rule_publish': 'can_publish',
    'rule_run': 'can_run',
}

# Logical read interfaces must not hide ownership of their RLS-protected
# storage. These names are fixed server schema, never client configuration.
_PROJECTION_BACKING = {
    'numeric_cell_current': 'numeric_cell_projection',
    'text_cell_current': 'text_cell_projection',
    'line_detail_current': 'line_detail_projection',
    'generic_fact_current': 'generic_fact_projection',
    'coordinate_member': 'coordinate_member_projection',
    'coordinate_projection': 'coordinate_projection_state',
}


class AccessDenied(ValueError):
    pass


def assert_nonowner_role(dsn: str, role_name: str,
                         protected_tables: tuple[str,...]) -> None:
    """Reject credentials that would bypass RLS in a process boundary."""
    if (not isinstance(dsn,str) or not dsn
            or role_name not in ('epm_runtime','epm_worker','epm_lifecycle',
                                 'epm_provision','epm_access','epm_security')
            or not protected_tables):
        raise ValueError('Invalid PostgreSQL service role configuration')
    protected_relations = list(dict.fromkeys(
        relation for name in protected_tables
        for relation in (name, _PROJECTION_BACKING.get(name, name))))
    # Every service credential must remain unable to bypass derived-state RLS,
    # even when this particular constructor only names event/control tables.
    protected_relations = list(dict.fromkeys(
        [*protected_relations, *_PROJECTION_BACKING, *_PROJECTION_BACKING.values(),
         'projection_recovery_manifest','projection_cleanup_manifest','raw_operation_membership']))
    with connect_postgres(dsn,row_factory=dict_row) as db:
        row=db.execute('''SELECT r.rolsuper,r.rolbypassrls,
            pg_has_role(current_user,%s,'member') AS has_required_role,
            EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n
                ON n.oid=c.relnamespace WHERE n.nspname='epm'
                AND c.relname=ANY(%s::text[])
                AND pg_has_role(current_user,c.relowner,'USAGE'))
                AS owns_protected_table
            FROM pg_roles r WHERE r.rolname=current_user''',
            (role_name,protected_relations)).fetchone()
    if (not row or row['rolsuper'] or row['rolbypassrls']
            or row['owns_protected_table'] or not row['has_required_role']):
        raise ValueError('POSTGRES_SERVICE_REQUIRES_NONOWNER_'+
                         role_name.upper())


def assert_security_writer_role(dsn: str) -> None:
    """Require a dedicated security writer with no unrelated table effects."""
    assert_nonowner_role(dsn, 'epm_security',
        ('workspace_access_grant', 'application_access_grant',
         'workspace_group_access_grant', 'application_group_access_grant',
         'rule_group_access_grant',
         'security_operation_receipt',
         'dimensional_security_policy_version'))
    with connect_postgres(dsn, row_factory=dict_row) as db:
        row = db.execute('''SELECT r.rolcreaterole,r.rolcreatedb,
            r.rolreplication,
            pg_has_role(current_user,'epm_runtime','member') AS runtime,
            pg_has_role(current_user,'epm_worker','member') AS worker,
            pg_has_role(current_user,'epm_lifecycle','member') AS lifecycle,
            pg_has_role(current_user,'epm_provision','member') AS provision,
            pg_has_role(current_user,'epm_access','member') AS access_role,
            has_schema_privilege(current_user,'epm','CREATE') AS can_create,
            EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n
                ON n.oid=c.relnamespace WHERE n.nspname='epm'
                AND c.relkind IN ('r','p','v')
                AND c.relname <> ALL(%s::text[])
                AND (has_table_privilege(current_user,c.oid,'INSERT')
                  OR has_table_privilege(current_user,c.oid,'UPDATE')
                  OR has_table_privilege(current_user,c.oid,'DELETE')
                  OR has_table_privilege(current_user,c.oid,'TRUNCATE')))
                AS can_write_other
            FROM pg_roles r WHERE r.rolname=current_user''',
            (['workspace_access_grant','application_access_grant',
              'rule_access_grant','workspace_group_access_grant',
              'application_group_access_grant','rule_group_access_grant',
              'security_operation_receipt',
              'security_audit','dimensional_security_policy_version'],)).fetchone()
    if not row or any(row.values()):
        raise ValueError('POSTGRES_SECURITY_ROLE_TOO_BROAD')


def assert_lifecycle_role(dsn: str) -> None:
    """Keep the workspace lifecycle credential separate from business writers."""
    assert_nonowner_role(dsn, 'epm_lifecycle',
        ('workspace', 'application', 'application_state',
         'workspace_access_grant', 'workspace_lifecycle_receipt',
         'platform_operator_grant', 'job', 'source_batch'))
    with connect_postgres(dsn, row_factory=dict_row) as db:
        row = db.execute('''SELECT r.rolcreaterole,r.rolcreatedb,
            r.rolreplication,
            pg_has_role(current_user,'epm_runtime','member') AS runtime,
            pg_has_role(current_user,'epm_worker','member') AS worker,
            pg_has_role(current_user,'epm_provision','member') AS provision,
            pg_has_role(current_user,'epm_security','member') AS security,
            pg_has_role(current_user,'epm_access','member') AS access_role,
            pg_has_role(current_user,'epm_analyst','member') AS analyst,
            has_schema_privilege(current_user,'epm','CREATE') AS can_create,
            EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n
                ON n.oid=c.relnamespace WHERE n.nspname='epm'
                AND c.relkind IN ('r','p','v')
                AND ((c.relname <> ALL(%s::text[])
                    AND has_table_privilege(current_user,c.oid,'INSERT'))
                  OR has_table_privilege(current_user,c.oid,'UPDATE')
                  OR EXISTS (SELECT 1 FROM pg_attribute a
                      WHERE a.attrelid=c.oid AND a.attnum>0
                      AND NOT a.attisdropped
                      AND has_column_privilege(current_user,c.oid,a.attname,'UPDATE')
                      AND NOT (c.relname='workspace' AND a.attname='status'))
                  OR has_table_privilege(current_user,c.oid,'DELETE')
                  OR has_table_privilege(current_user,c.oid,'TRUNCATE')))
                AS can_write_other
            FROM pg_roles r WHERE r.rolname=current_user''',
            (['application','application_state',
              'application_access_grant','security_audit',
              'workspace_lifecycle_receipt'],)).fetchone()
    if not row or any(row.values()):
        raise ValueError('POSTGRES_LIFECYCLE_ROLE_TOO_BROAD')


@dataclass(frozen=True, slots=True)
class VerifiedIdentity:
    issuer: str
    subject_id: str
    groups: tuple[str,...] = ()
    issued_at: int | None = field(default=None, kw_only=True)

    def __post_init__(self) -> None:
        if (not isinstance(self.issuer, str) or not self.issuer or
                not isinstance(self.subject_id, str) or not self.subject_id
                or not isinstance(self.groups,tuple)
                or any(not isinstance(group,str) or not group
                       for group in self.groups)
                or len(self.groups)!=len(set(self.groups))):
            raise ValueError('A verified issuer and subject are required')
        if self.issued_at is not None and (type(self.issued_at) is not int
                                           or self.issued_at < 0):
            raise ValueError('Verified token issue time is invalid')


@dataclass(frozen=True, slots=True)
class VerifiedExecutionIdentity(VerifiedIdentity):
    """Verified principal plus one server-sealed durable scope fence.

    Browser and MCP authentication creates ``VerifiedIdentity``. Only a fixed
    worker reconstructing an already admitted durable request may create this
    narrower type from server-owned storage.
    """
    authorization_scope_digest: str = ''

    def __post_init__(self) -> None:
        VerifiedIdentity.__post_init__(self)
        if (not isinstance(self.authorization_scope_digest, str)
                or re.fullmatch(r'[0-9a-f]{64}',
                                self.authorization_scope_digest) is None):
            raise ValueError(
                'A sealed execution authorization scope is required')


def durable_authority_fields(identity: VerifiedIdentity) -> tuple[int | None, str]:
    """Return the only valid durable authority representation."""
    if identity.issued_at is not None:
        if identity.issued_at <= 0:
            raise AccessDenied('TOKEN_ISSUE_TIME_UNAVAILABLE')
        return identity.issued_at, 'HumanToken'
    if not identity.issuer.startswith('urn:openepm:'):
        raise AccessDenied('TOKEN_ISSUE_TIME_UNAVAILABLE')
    return None, 'Technical'


def durable_execution_identity(row: Mapping[str, object], *,
                               issuer='issuer', subject='subject_id',
                               groups='verified_groups',
                               scope_digest='authorization_scope_digest',
                               token_issued_at='token_issued_at',
                               authority_kind='authority_kind'
                               ) -> VerifiedExecutionIdentity:
    """Reconstruct durable authority without accepting unverified legacy rows."""
    kind=row.get(authority_kind)
    issued_at=row.get(token_issued_at)
    actor_issuer=row.get(issuer)
    if kind == 'HumanToken':
        if type(issued_at) is not int or issued_at <= 0:
            raise AccessDenied('TOKEN_ISSUE_TIME_UNAVAILABLE')
    elif kind == 'Technical':
        if (issued_at is not None or not isinstance(actor_issuer,str)
                or not actor_issuer.startswith('urn:openepm:')):
            raise AccessDenied('TECHNICAL_AUTHORITY_INVALID')
    else:
        raise AccessDenied('TOKEN_ISSUE_TIME_UNAVAILABLE')
    return VerifiedExecutionIdentity(
        actor_issuer,row[subject],tuple(row.get(groups) or ()),
        row.get(scope_digest),issued_at=issued_at)


@dataclass(frozen=True, slots=True)
class AccessDecision:
    role: str
    workspace_administrator: bool
    groups: tuple[str, ...] = ()


class PostgresAccessChecker:
    def __init__(self, dsn: str):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('An access-service PostgreSQL DSN is required')
        self.dsn = dsn

    def check(self, identity: VerifiedIdentity, scope: ApplicationScope,
              permission: str) -> AccessDecision:
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                return self.check_in_transaction(db, identity, scope, permission)

    @staticmethod
    @lock_busy_boundary
    def lock_workspace(db, workspace_id: str, *, exclusive: bool = False) -> None:
        if not isinstance(workspace_id, str) or not workspace_id:
            raise ValueError('Workspace ID is required')
        configure_lock_wait(db)
        function = ('pg_advisory_xact_lock' if exclusive
                    else 'pg_advisory_xact_lock_shared')
        db.execute(f'''SELECT {function}(
            hashtextextended('epm.security.workspace:' || %s, 0))''',
            (workspace_id,))

    @staticmethod
    def try_lock_workspace(db, workspace_id: str) -> bool:
        """Test a workspace fence without waiting under the dispatch gate."""
        if not isinstance(workspace_id, str) or not workspace_id:
            raise ValueError('Workspace ID is required')
        row = db.execute('''SELECT pg_try_advisory_xact_lock_shared(
            hashtextextended('epm.security.workspace:' || %s, 0)) AS locked''',
            (workspace_id,)).fetchone()
        return row['locked'] if isinstance(row, dict) else row[0]

    @staticmethod
    def current_groups_in_transaction(db, identity: VerifiedIdentity
                                      ) -> tuple[str, ...]:
        """Return token groups after the current Keycloak-derived fence.

        The native-only profile admits only users, groups and memberships that
        are current in the governed Keycloak directory projection. Unknown or
        inactive objects fail closed even when an old token still names them.
        """
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('Verified identity is required')
        groups = identity.groups
        if (len(groups) > 100 or tuple(sorted(set(groups))) != groups
                or any(not isinstance(group, str)
                       or not 1 <= len(group) <= 300
                       or group != group.strip()
                       or any(ord(character) < 32 for character in group)
                       or '*' in group for group in groups)):
            raise AccessDenied('VERIFIED_IDENTITY_GROUPS_INVALID')
        current = db.execute('''SELECT
            epm.identity_subject_active(%s,%s) AS subject_active,
            CASE WHEN %s::bigint IS NULL THEN true ELSE
              epm.identity_subject_session_valid(%s,%s,%s) END AS session_valid,
            epm.current_identity_groups(%s,%s,%s::text[]) AS groups''',
            (identity.issuer, identity.subject_id, identity.issued_at,
             identity.issuer, identity.subject_id, identity.issued_at,
             identity.issuer,
             identity.subject_id, list(groups))).fetchone()
        if not current or not current['subject_active']:
            raise AccessDenied('IDENTITY_INACTIVE')
        if not current['session_valid']:
            raise AccessDenied('IDENTITY_SESSION_REVOKED')
        return tuple(current['groups'])

    @staticmethod
    def check_in_transaction(db, identity: VerifiedIdentity,
                             scope: ApplicationScope,
                             permission: str, *, function: str | None = None,
                             arguments: dict | None = None) -> AccessDecision:
        if not isinstance(identity, VerifiedIdentity) or not isinstance(
                scope, ApplicationScope):
            raise ValueError('Verified identity and application scope are required')
        if permission not in _PERMISSION_RANK:
            raise ValueError('Unknown permission')
        isolation = db.execute('SHOW transaction_isolation').fetchone()
        level = (isolation['transaction_isolation'] if isinstance(isolation, dict)
                 else isolation[0])
        if level != 'read committed':
            raise ValueError('Authorization recheck requires READ COMMITTED')
        groups = PostgresAccessChecker.current_groups_in_transaction(
            db, identity)
        PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
        application = db.execute('''SELECT status FROM epm.application
            WHERE workspace_id=%s AND application_id=%s''',
            (scope.workspace_id, scope.application_id)).fetchone()
        if application is None or application['status'] == 'Deleting':
            raise AccessDenied('APPLICATION_UNAVAILABLE')
        workspace = db.execute('''SELECT status FROM epm.workspace
            WHERE workspace_id=%s''',
            (scope.workspace_id,)).fetchone()
        if workspace is None or workspace['status'] == 'Deleting':
            raise AccessDenied('WORKSPACE_UNAVAILABLE')
        if permission != 'read':
            if workspace['status'] != 'Active':
                raise AccessDenied('WORKSPACE_NOT_WRITABLE')
            if application['status'] != 'Active':
                raise AccessDenied('APPLICATION_NOT_WRITABLE')
        administrator = db.execute('''SELECT
            EXISTS (SELECT 1 FROM epm.workspace_access_grant
                WHERE issuer=%s AND subject_id=%s AND workspace_id=%s
                AND role='Administrator')
            OR EXISTS (SELECT 1 FROM epm.workspace_group_access_grant
                WHERE issuer=%s AND group_id=ANY(%s::text[])
                AND workspace_id=%s AND role='Administrator') AS allowed''',
            (identity.issuer, identity.subject_id, scope.workspace_id,
             identity.issuer, list(groups), scope.workspace_id)
            ).fetchone()['allowed']
        if administrator:
            if function is not None:
                PostgresAccessChecker.require_capability_in_transaction(db,scope,function,arguments)
            decision = AccessDecision('Administrator', True, groups)
        else:
            if permission == 'workspace_admin':
                raise AccessDenied('WORKSPACE_ADMIN_REQUIRED')
            grant = db.execute('''SELECT role FROM (
                SELECT role FROM epm.application_access_grant
                WHERE issuer=%s AND subject_id=%s AND workspace_id=%s
                AND application_id=%s
                UNION ALL
                SELECT role FROM epm.application_group_access_grant
                WHERE issuer=%s AND group_id=ANY(%s::text[])
                AND workspace_id=%s AND application_id=%s
            ) effective_grants
            ORDER BY CASE role WHEN 'Administrator' THEN 3
                WHEN 'Editor' THEN 2 WHEN 'Reader' THEN 1 ELSE 0 END DESC
            LIMIT 1''',
                (identity.issuer, identity.subject_id, scope.workspace_id,
                 scope.application_id, identity.issuer, list(groups),
                 scope.workspace_id, scope.application_id)).fetchone()
            role = grant['role'] if grant else ''
            if _ROLE_RANK.get(role, 0) < _PERMISSION_RANK[permission]:
                raise AccessDenied('APPLICATION_GRANT_REQUIRED')
            if permission in _RULE_COLUMN and role != 'Administrator':
                rule = db.execute('''SELECT bool_or(can_design) AS can_design,
                    bool_or(can_publish) AS can_publish,
                    bool_or(can_run) AS can_run
                FROM (
                    SELECT can_design,can_publish,can_run
                    FROM epm.rule_access_grant
                    WHERE issuer=%s AND subject_id=%s AND workspace_id=%s
                    AND application_id=%s
                    UNION ALL
                    SELECT can_design,can_publish,can_run
                    FROM epm.rule_group_access_grant
                    WHERE issuer=%s AND group_id=ANY(%s::text[])
                    AND workspace_id=%s AND application_id=%s
                ) effective_rule_grants''',
                    (identity.issuer, identity.subject_id, scope.workspace_id,
                     scope.application_id, identity.issuer, list(groups),
                     scope.workspace_id, scope.application_id)).fetchone()
                if not rule or not rule[_RULE_COLUMN[permission]]:
                    raise AccessDenied('RULE_GRANT_REQUIRED')
            if function is not None:
                PostgresAccessChecker.require_capability_in_transaction(
                    db,scope,function,arguments)
            decision = AccessDecision(role, False, groups)
        if isinstance(identity, VerifiedExecutionIdentity):
            if groups != identity.groups:
                raise AccessDenied('JOB_AUTHORIZATION_SCOPE_CHANGED')
            from .postgres_dimensional_scope import (
                resolve_effective_dimensional_scope)
            current_scope = resolve_effective_dimensional_scope(
                db, identity, scope, access=decision,
                function=function).scope_digest
            if current_scope != identity.authorization_scope_digest:
                raise AccessDenied('JOB_AUTHORIZATION_SCOPE_CHANGED')
        return decision


    @staticmethod
    def require_capability_in_transaction(db,scope,function,arguments=None,
                                          *,lock_state: bool=True):
        """Call after authorization, with workspace-before-state lock order.

        The caller's shared workspace advisory lock fences capability changes
        until its transaction ends. Writable transactions additionally take a
        shared state-row lock. PostgreSQL forbids row locks in read-only
        transactions, so those callers rely on the workspace fence rather than
        claiming that READ ONLY changes snapshot isolation. Existing policy
        pins reject disable/re-enable between transactions. A no-effect private
        preparation may pass ``lock_state=False`` only when publication repeats
        the default locked check under its final application mutation fence.
        """
        from .postgres_capability_contract import (required_capabilities,
            validate_enabled_capabilities, DISABLED_SAFE_FUNCTIONS)
        required=required_capabilities(function,arguments)
        if not required or function in DISABLED_SAFE_FUNCTIONS:
            return
        read_only=db.execute("""SELECT current_setting('transaction_read_only')
            AS value""").fetchone()['value']=='on'
        lock_clause='' if read_only or not lock_state else ' FOR SHARE'
        row=db.execute("""SELECT enabled_capabilities FROM epm.application_state
            WHERE workspace_id=%s AND application_id=%s"""+lock_clause,
            (scope.workspace_id,scope.application_id)).fetchone()
        if row is None: raise AccessDenied('APPLICATION_UNAVAILABLE')
        enabled=validate_enabled_capabilities(row['enabled_capabilities'])
        if not required <= enabled:
            raise AccessDenied('APPLICATION_CAPABILITY_DISABLED')
