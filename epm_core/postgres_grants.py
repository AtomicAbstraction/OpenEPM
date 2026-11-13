"""Fixed-core PostgreSQL application grant writer for verified identities.

The server validates provider tokens before constructing VerifiedIdentity.
The V2 typed security program calls this writer through a separate non-owner
credential; the live V1 service has not been cut over.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import AccessDenied, PostgresAccessChecker, VerifiedIdentity
from .security_string import render_security_string


def _validate_group_id(group_id: object) -> str:
    if (not isinstance(group_id, str) or not 1 <= len(group_id) <= 300
            or group_id != group_id.strip() or '*' in group_id
            or any(ord(char) < 32 for char in group_id)):
        raise ValueError('AUTHORIZATION_GROUP_ID_INVALID')
    return group_id


_SECURITY_ACTION_LABELS = {
    'application.grant': 'Granted application access',
    'application.revoke': 'Revoked application access',
    'group.grant': 'Granted group application access',
    'group.revoke': 'Revoked group application access',
    'dimension.assign': 'Changed dimensional access',
    'group.dimension.assign': 'Changed group dimensional access',
    'rule.set': 'Changed rule permissions',
    'rule.revoke': 'Revoked rule permissions',
    'group.rule.set': 'Changed group rule permissions',
    'group.rule.revoke': 'Revoked group rule permissions',
}


def _security_action_label(action: str) -> str:
    if action.startswith('denied.'):
        return 'Rejected ' + action.removeprefix('denied.').replace('.', ' ')
    return _SECURITY_ACTION_LABELS.get(
        action, action.replace('.', ' ').replace('_', ' ').capitalize())


class PostgresGrantStore:
    def __init__(self, dsn: str):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL security-writer DSN is required')
        self.dsn = dsn

    def record_privileged_denial(
            self, scope: ApplicationScope, *, actor: VerifiedIdentity,
            function: str, error_code: str, request_digest: str) -> None:
        """Append secret-free evidence after a privileged transaction denies."""
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)
                or not isinstance(function, str)
                or not re.fullmatch(r'[a-z][a-z0-9_.-]{2,179}', function)
                or not isinstance(error_code, str)
                or not re.fullmatch(r'[A-Z][A-Z0-9_]{2,127}', error_code)
                or not isinstance(request_digest, str)
                or not re.fullmatch(r'[0-9a-f]{64}', request_digest)):
            raise ValueError('PRIVILEGED_DENIAL_AUDIT_INVALID')
        actor_digest = sha256((actor.issuer + '\0' + actor.subject_id)
                              .encode('utf-8')).hexdigest()
        with connect_postgres(self.dsn) as db:
            db.execute('''INSERT INTO epm.security_audit
                (actor_id,action,workspace_id,application_id,target_digest,
                 outcome,detail)
                VALUES (%s,%s,%s,%s,%s,'Rejected',%s)''',
                (actor_digest, f'denied.{function}', scope.workspace_id,
                 scope.application_id, request_digest,
                 Jsonb({'function': function, 'errorCode': error_code})))

    def apply_application_grant(
            self, scope: ApplicationScope, *, actor: VerifiedIdentity,
            target: VerifiedIdentity, action: str, role: str | None,
            operation_id: str, command_digest: str) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)
                or not isinstance(target, VerifiedIdentity)):
            raise ValueError('Scope and verified identities are required')
        if target.issuer != actor.issuer:
            raise ValueError('Grant target must have the administrator issuer')
        if action not in ('grant', 'revoke'):
            raise ValueError('Grant action must be grant or revoke')
        if ((action == 'grant' and role not in
             ('Reader', 'Editor', 'Administrator'))
                or (action == 'revoke' and role is not None)):
            raise ValueError('Grant role is invalid for the action')
        if (not isinstance(operation_id, str)
                or not 1 <= len(operation_id) <= 200
                or not isinstance(command_digest, str)
                or not re.fullmatch('[0-9a-f]{64}', command_digest)):
            raise ValueError('Operation ID and SHA-256 digest are required')
        payload = {
            'workspaceId': scope.workspace_id,
            'applicationId': scope.application_id,
            'actorIssuer': actor.issuer,
            'actorSubject': actor.subject_id,
            'targetIssuer': target.issuer,
            'targetSubject': target.subject_id,
            'action': action,
            'role': role,
        }
        payload_digest = sha256(json.dumps(
            payload, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False).encode('utf-8')).hexdigest()
        actor_digest = sha256((actor.issuer + '\0' + actor.subject_id)
                              .encode('utf-8')).hexdigest()
        target_digest = sha256((target.issuer + '\0' + target.subject_id)
                               .encode('utf-8')).hexdigest()
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                # Exclusive workspace lock serializes every grant change with
                # effect transactions that hold the matching shared lock.
                PostgresAccessChecker.lock_workspace(
                    db, scope.workspace_id, exclusive=True)
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, 'admin')
                previous = db.execute('''SELECT command_digest, payload_digest,
                    result FROM epm.security_operation_receipt
                    WHERE workspace_id=%s AND operation_id=%s''',
                    (scope.workspace_id, operation_id)).fetchone()
                if previous:
                    if previous['command_digest'] != command_digest:
                        raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    if previous['payload_digest'] != payload_digest:
                        raise ValueError('IDEMPOTENCY_PAYLOAD_CHANGED')
                    return previous['result']
                keys = (target.issuer, target.subject_id,
                        scope.workspace_id, scope.application_id)
                if action == 'grant':
                    active = db.execute(
                        'SELECT epm.identity_subject_active(%s,%s) AS active',
                        (target.issuer,
                         target.subject_id)).fetchone()['active']
                    if not active:
                        raise AccessDenied('USER_IDENTITY_UNAVAILABLE')
                    db.execute('''INSERT INTO epm.application_access_grant
                        (issuer, subject_id, workspace_id, application_id, role)
                        VALUES (%s,%s,%s,%s,%s)
                        ON CONFLICT (issuer,subject_id,workspace_id,application_id)
                        DO UPDATE SET role=EXCLUDED.role,
                          granted_at=transaction_timestamp()''',
                        (*keys, role))
                    changed = True
                else:
                    db.execute('''DELETE FROM epm.rule_access_grant
                        WHERE issuer=%s AND subject_id=%s AND workspace_id=%s
                        AND application_id=%s''', keys)
                    changed = bool(db.execute('''DELETE FROM
                        epm.application_access_grant WHERE issuer=%s
                        AND subject_id=%s AND workspace_id=%s
                        AND application_id=%s''', keys).rowcount)
                result = {
                    'workspaceId': scope.workspace_id,
                    'applicationId': scope.application_id,
                    'action': action,
                    'role': role,
                    'changed': changed,
                }
                db.execute('''INSERT INTO epm.security_operation_receipt
                    (workspace_id, operation_id, command_digest,
                     payload_digest, actor_digest, action, result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id, operation_id, command_digest,
                     payload_digest, actor_digest,
                     f'application.{action}', Jsonb(result)))
                db.execute('''INSERT INTO epm.security_audit
                    (actor_id,action,workspace_id,application_id,
                     target_digest,outcome,detail)
                    VALUES (%s,%s,%s,%s,%s,'Accepted',%s)''',
                    (actor_digest, f'application.{action}',
                     scope.workspace_id, scope.application_id,
                     target_digest, Jsonb({'operationId': operation_id,
                                           'role': role,
                                           'changed': changed})))
                return result

    def list_application_grants(
            self, scope: ApplicationScope, *, actor: VerifiedIdentity,
            after_subject_id: str | None = None, limit: int = 100) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)
                or (after_subject_id is not None and
                    (not isinstance(after_subject_id, str)
                     or not 1 <= len(after_subject_id) <= 300
                     or after_subject_id != after_subject_id.strip()
                     or any(ord(char) < 32 for char in after_subject_id)))
                or isinstance(limit, bool) or not isinstance(limit, int)
                or not 1 <= limit <= 100):
            raise ValueError('APPLICATION_GRANT_LIST_ARGUMENTS_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, 'admin')
                rows = db.execute('''SELECT g.subject_id,g.role,
                        g.read_security_tags,g.write_security_tags,g.granted_at,
                        r.can_design,r.can_publish,r.can_run,
                        u.display_name,u.username
                    FROM epm.application_access_grant g
                    LEFT JOIN epm.rule_access_grant r
                      USING(issuer,subject_id,workspace_id,application_id)
                    LEFT JOIN epm.identity_user_directory_state u
                      ON u.issuer=g.issuer AND u.subject_id=g.subject_id
                    WHERE g.workspace_id=%s AND g.application_id=%s
                      AND g.issuer=%s
                      AND (%s::text IS NULL OR g.subject_id>%s)
                    ORDER BY g.subject_id LIMIT %s''',
                    (scope.workspace_id, scope.application_id, actor.issuer,
                     after_subject_id, after_subject_id, limit + 1)).fetchall()
                values = [{
                    'subjectId': row['subject_id'], 'role': row['role'],
                    'displayName': row['display_name'],
                    'username': row['username'],
                    'readTags': row['read_security_tags'],
                    'writeTags': row['write_security_tags'],
                    'rulePermissions': ({
                        'design': row['can_design'],
                        'publish': row['can_publish'],
                        'run': row['can_run']}
                        if row['can_design'] is not None else None),
                    'grantedAt': row['granted_at'].isoformat()}
                    for row in rows[:limit]]
                return {'grants': values,
                    'nextAfterSubjectId': (rows[limit-1]['subject_id']
                        if len(rows) > limit else None)}

    def list_application_subjects(
            self, scope: ApplicationScope, *, actor: VerifiedIdentity,
            after_selection_key: str | None = None, limit: int = 100) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)
                or (after_selection_key is not None and
                    (not isinstance(after_selection_key, str)
                     or not 1 <= len(after_selection_key) <= 300
                     or after_selection_key != after_selection_key.strip()
                     or any(ord(char) < 32
                            for char in after_selection_key)))
                or isinstance(limit, bool) or not isinstance(limit, int)
                or not 1 <= limit <= 100):
            raise ValueError('APPLICATION_SUBJECT_LIST_ARGUMENTS_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, 'admin')
                rows = db.execute('''SELECT subject_id,display_name,username
                    FROM epm.identity_user_directory_state
                    WHERE issuer=%s AND status='Active'
                      AND display_name IS NOT NULL AND display_name<>''
                      AND username IS NOT NULL AND username<>''
                      AND principal_digest IS NOT NULL
                      AND (%s::text IS NULL OR subject_id>%s)
                    ORDER BY subject_id LIMIT %s''',
                    (actor.issuer, after_selection_key,
                     after_selection_key, limit + 1)).fetchall()
                subjects = [{
                    'selectionKey': row['subject_id'],
                    'displayName': row['display_name'],
                    'username': row['username'],
                } for row in rows[:limit]]
                return {
                    'subjects': subjects,
                    'nextAfterSelectionKey': (rows[limit - 1]['subject_id']
                        if len(rows) > limit else None),
                }

    def list_application_security_audit(
            self, scope: ApplicationScope, *, actor: VerifiedIdentity,
            before_audit_id: int | None = None, limit: int = 100) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)
                or (before_audit_id is not None and
                    (isinstance(before_audit_id, bool)
                     or not isinstance(before_audit_id, int)
                     or before_audit_id < 1))
                or isinstance(limit, bool) or not isinstance(limit, int)
                or not 1 <= limit <= 100):
            raise ValueError('SECURITY_AUDIT_LIST_ARGUMENTS_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, 'admin')
                rows = db.execute('''SELECT audit.audit_id,audit.occurred_at,
                        audit.action,audit.outcome,
                        coalesce(actor.display_name,actor.username,
                                 'Unavailable directory identity') AS actor_name,
                        coalesce(target_user.display_name,target_user.username,
                                 target_group.display_name,target_group.group_name,
                                 application.name,'Application security')
                            AS target_name,
                        CASE WHEN jsonb_typeof(
                                  audit.detail->'operationId')='string'
                             THEN audit.detail->>'operationId' END
                            AS operation_id
                    FROM epm.security_audit AS audit
                    LEFT JOIN epm.identity_user_directory_state AS actor
                      ON actor.principal_digest=audit.actor_id
                    LEFT JOIN epm.identity_user_directory_state AS target_user
                      ON target_user.principal_digest=audit.target_digest
                    LEFT JOIN epm.identity_group_directory_state AS target_group
                      ON target_group.principal_digest=audit.target_digest
                    LEFT JOIN epm.application AS application
                      ON application.workspace_id=audit.workspace_id
                     AND application.application_id=audit.application_id
                    WHERE audit.workspace_id=%s AND audit.application_id=%s
                      AND (%s::bigint IS NULL OR audit.audit_id<%s)
                    ORDER BY audit.audit_id DESC LIMIT %s''',
                    (scope.workspace_id, scope.application_id,
                     before_audit_id, before_audit_id, limit + 1)).fetchall()
                events = [{
                    'auditId': row['audit_id'],
                    'occurredAt': row['occurred_at'].isoformat(),
                    'actorName': row['actor_name'],
                    'action': _security_action_label(row['action']),
                    'targetName': row['target_name'],
                    'outcome': row['outcome'],
                    'detailsKey': row['operation_id'],
                } for row in rows[:limit]]
                return {
                    'events': events,
                    'nextBeforeAuditId': (rows[limit - 1]['audit_id']
                        if len(rows) > limit else None),
                }

    def read_application_security_receipt(
            self, scope: ApplicationScope, *, actor: VerifiedIdentity,
            operation_id: str) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)
                or not isinstance(operation_id, str)
                or not 1 <= len(operation_id) <= 200
                or operation_id != operation_id.strip()
                or any(ord(char) < 32 for char in operation_id)):
            raise ValueError('SECURITY_RECEIPT_READ_ARGUMENTS_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, 'admin')
                row = db.execute('''SELECT receipt.operation_id,
                        receipt.action,receipt.committed_at,
                        receipt.command_digest,receipt.payload_digest,
                        receipt.actor_digest
                    FROM epm.security_operation_receipt AS receipt
                    WHERE receipt.workspace_id=%s
                      AND receipt.operation_id=%s
                      AND EXISTS (SELECT 1 FROM epm.security_audit AS audit
                        WHERE audit.workspace_id=%s
                          AND audit.application_id=%s
                          AND jsonb_typeof(audit.detail->'operationId')='string'
                          AND audit.detail->>'operationId'=receipt.operation_id)
                    LIMIT 1''',
                    (scope.workspace_id, operation_id, scope.workspace_id,
                     scope.application_id)).fetchone()
                if row is None:
                    raise ValueError('SECURITY_RECEIPT_UNAVAILABLE')
                return {
                    'workspaceId': scope.workspace_id,
                    'applicationId': scope.application_id,
                    'operationId': row['operation_id'],
                    'action': row['action'],
                    'outcome': 'Committed',
                    'committedAt': row['committed_at'].isoformat(),
                    'commandDigest': row['command_digest'],
                    'payloadDigest': row['payload_digest'],
                    'actorDigest': row['actor_digest'],
                }

    def apply_application_group_grant(
            self, scope: ApplicationScope, *, actor: VerifiedIdentity,
            group_id: str, action: str, role: str | None,
            operation_id: str, command_digest: str) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)):
            raise ValueError('Scope and verified actor are required')
        group_id = _validate_group_id(group_id)
        if action not in ('grant', 'revoke'):
            raise ValueError('Grant action must be grant or revoke')
        if ((action == 'grant' and role not in
             ('Reader', 'Editor', 'Administrator'))
                or (action == 'revoke' and role is not None)):
            raise ValueError('Grant role is invalid for the action')
        if (not isinstance(operation_id, str)
                or not 1 <= len(operation_id) <= 200
                or not isinstance(command_digest, str)
                or not re.fullmatch('[0-9a-f]{64}', command_digest)):
            raise ValueError('Operation ID and SHA-256 digest are required')
        payload = {
            'workspaceId': scope.workspace_id,
            'applicationId': scope.application_id,
            'actorIssuer': actor.issuer,
            'actorSubject': actor.subject_id,
            'targetIssuer': actor.issuer,
            'groupId': group_id,
            'action': action,
            'role': role,
        }
        payload_digest = sha256(json.dumps(
            payload, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False).encode('utf-8')).hexdigest()
        actor_digest = sha256((actor.issuer + '\0' + actor.subject_id)
                              .encode('utf-8')).hexdigest()
        target_digest = sha256((actor.issuer + '\0group\0' + group_id)
                               .encode('utf-8')).hexdigest()
        keys = (actor.issuer, group_id,
                scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SELECT set_config('epm.workspace_id',%s,true)",
                           (scope.workspace_id,))
                db.execute("SELECT set_config('epm.application_id',%s,true)",
                           (scope.application_id,))
                PostgresAccessChecker.lock_workspace(
                    db, scope.workspace_id, exclusive=True)
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, 'admin')
                previous = db.execute('''SELECT command_digest,payload_digest,
                    result FROM epm.security_operation_receipt
                    WHERE workspace_id=%s AND operation_id=%s''',
                    (scope.workspace_id, operation_id)).fetchone()
                if previous:
                    if previous['command_digest'] != command_digest:
                        raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    if previous['payload_digest'] != payload_digest:
                        raise ValueError('IDEMPOTENCY_PAYLOAD_CHANGED')
                    return previous['result']
                if action == 'grant':
                    db.execute(
                        'SELECT epm.assert_active_group_authority(%s,%s)',
                        (actor.issuer, group_id))
                current = db.execute('''SELECT role FROM
                    epm.application_group_access_grant WHERE issuer=%s
                    AND group_id=%s AND workspace_id=%s
                    AND application_id=%s''', keys).fetchone()
                if action == 'grant':
                    changed = current is None or current['role'] != role
                    if changed:
                        db.execute('''INSERT INTO
                            epm.application_group_access_grant
                            (issuer,group_id,workspace_id,application_id,role)
                            VALUES (%s,%s,%s,%s,%s)
                            ON CONFLICT (issuer,group_id,workspace_id,
                                application_id) DO UPDATE SET
                            role=EXCLUDED.role,
                            granted_at=transaction_timestamp()''',
                            (*keys, role))
                else:
                    db.execute('''DELETE FROM epm.rule_group_access_grant
                        WHERE issuer=%s AND group_id=%s AND workspace_id=%s
                        AND application_id=%s''', keys)
                    changed = bool(db.execute('''DELETE FROM
                        epm.application_group_access_grant WHERE issuer=%s
                        AND group_id=%s AND workspace_id=%s
                        AND application_id=%s''', keys).rowcount)
                result = {
                    'workspaceId': scope.workspace_id,
                    'applicationId': scope.application_id,
                    'groupId': group_id,
                    'action': action,
                    'role': role,
                    'changed': changed,
                }
                db.execute('''INSERT INTO epm.security_operation_receipt
                    (workspace_id,operation_id,command_digest,payload_digest,
                     actor_digest,action,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id, operation_id, command_digest,
                     payload_digest, actor_digest,
                     f'application-group.{action}', Jsonb(result)))
                db.execute('''INSERT INTO epm.security_audit
                    (actor_id,action,workspace_id,application_id,
                     target_digest,outcome,detail)
                    VALUES (%s,%s,%s,%s,%s,'Accepted',%s)''',
                    (actor_digest, f'application-group.{action}',
                     scope.workspace_id, scope.application_id,
                     target_digest, Jsonb({'operationId': operation_id,
                                           'role': role,
                                           'changed': changed})))
                return result

    def list_application_group_grants(
            self, scope: ApplicationScope, *, actor: VerifiedIdentity,
            after_group_id: str | None = None, limit: int = 100) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)
                or (after_group_id is not None
                    and _validate_group_id(after_group_id) != after_group_id)
                or isinstance(limit, bool) or not isinstance(limit, int)
                or not 1 <= limit <= 100):
            raise ValueError('APPLICATION_GROUP_GRANT_LIST_ARGUMENTS_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                db.execute("SELECT set_config('epm.workspace_id',%s,true)",
                           (scope.workspace_id,))
                db.execute("SELECT set_config('epm.application_id',%s,true)",
                           (scope.application_id,))
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, 'admin')
                rows = db.execute('''SELECT g.group_id,g.role,
                        g.read_security_tags,g.write_security_tags,
                        g.granted_at,r.can_design,r.can_publish,r.can_run
                    FROM epm.application_group_access_grant g
                    LEFT JOIN epm.rule_group_access_grant r
                      USING(issuer,group_id,workspace_id,application_id)
                    WHERE g.workspace_id=%s AND g.application_id=%s
                      AND g.issuer=%s
                      AND (%s::text IS NULL OR g.group_id>%s)
                    ORDER BY g.group_id LIMIT %s''',
                    (scope.workspace_id, scope.application_id, actor.issuer,
                     after_group_id, after_group_id, limit + 1)).fetchall()
                values = [{
                    'groupId': row['group_id'], 'role': row['role'],
                    'readTags': row['read_security_tags'],
                    'writeTags': row['write_security_tags'],
                    'rulePermissions': ({
                        'design': row['can_design'],
                        'publish': row['can_publish'],
                        'run': row['can_run']}
                        if row['can_design'] is not None else None),
                    'grantedAt': row['granted_at'].isoformat()}
                    for row in rows[:limit]]
                return {'grants': values,
                    'nextAfterGroupId': (rows[limit-1]['group_id']
                        if len(rows) > limit else None)}

    def set_dimension_access(
            self, scope: ApplicationScope, *, actor: VerifiedIdentity,
            target: VerifiedIdentity, read_tags: dict[str, list[str]],
            write_tags: dict[str, list[str]],
            expected_security_revision: int, operation_id: str,
            command_digest: str) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)
                or not isinstance(target, VerifiedIdentity)):
            raise ValueError('Scope and verified identities are required')
        if target.issuer != actor.issuer:
            raise ValueError('Grant target must have the administrator issuer')
        if (not isinstance(read_tags, dict) or not isinstance(write_tags, dict)
                or isinstance(expected_security_revision, bool)
                or not isinstance(expected_security_revision, int)
                or expected_security_revision < 0
                or not isinstance(operation_id, str)
                or not 1 <= len(operation_id) <= 200
                or not isinstance(command_digest, str)
                or not re.fullmatch('[0-9a-f]{64}', command_digest)):
            raise ValueError('Dimension access arguments are invalid')
        payload = {
            'workspaceId': scope.workspace_id,
            'applicationId': scope.application_id,
            'actorIssuer': actor.issuer,
            'actorSubject': actor.subject_id,
            'targetIssuer': target.issuer,
            'targetSubject': target.subject_id,
            'readTags': read_tags,
            'writeTags': write_tags,
            'expectedSecurityRevision': expected_security_revision,
        }
        payload_digest = sha256(json.dumps(
            payload, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False).encode('utf-8')).hexdigest()
        actor_digest = sha256((actor.issuer + '\0' + actor.subject_id)
                              .encode('utf-8')).hexdigest()
        target_digest = sha256((target.issuer + '\0' + target.subject_id)
                               .encode('utf-8')).hexdigest()
        keys = (target.issuer, target.subject_id,
                scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SELECT set_config('epm.workspace_id',%s,true)",
                           (scope.workspace_id,))
                db.execute("SELECT set_config('epm.application_id',%s,true)",
                           (scope.application_id,))
                PostgresAccessChecker.lock_workspace(
                    db, scope.workspace_id, exclusive=True)
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, 'admin')
                previous = db.execute('''SELECT command_digest,
                    payload_digest,result FROM epm.security_operation_receipt
                    WHERE workspace_id=%s AND operation_id=%s''',
                    (scope.workspace_id, operation_id)).fetchone()
                if previous:
                    if previous['command_digest'] != command_digest:
                        raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    if previous['payload_digest'] != payload_digest:
                        raise ValueError('IDEMPOTENCY_PAYLOAD_CHANGED')
                    return previous['result']
                state = db.execute('''SELECT security_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if state['security_revision'] != expected_security_revision:
                    raise ValueError('STALE_SECURITY_REVISION')
                current = db.execute('''SELECT read_security_tags,
                    write_security_tags FROM epm.application_access_grant
                    WHERE issuer=%s AND subject_id=%s AND workspace_id=%s
                    AND application_id=%s FOR UPDATE''', keys).fetchone()
                if current is None:
                    raise ValueError('DIMENSION_ACCESS_TARGET_GRANT_REQUIRED')
                for access_kind, assignments, column in (
                        ('READ', read_tags, 'read_security_tags'),
                        ('WRITE', write_tags, 'write_security_tags')):
                    for dimension_id, tags in assignments.items():
                        dimension = db.execute('''SELECT 1 FROM epm.dimension
                            WHERE workspace_id=%s AND application_id=%s
                            AND dimension_id=%s AND status='Active' ''',
                            (scope.workspace_id, scope.application_id,
                             dimension_id)).fetchone()
                        if dimension is None:
                            raise ValueError(
                                f'{access_kind}_DIMENSION_UNAVAILABLE')
                        available = db.execute(f'''SELECT DISTINCT tag
                            FROM epm.member m,
                            unnest(m.{column}) AS tag
                            WHERE m.workspace_id=%s AND m.application_id=%s
                            AND m.dimension_id=%s AND m.status='Active'
                            AND tag=ANY(%s::text[])''',
                            (scope.workspace_id, scope.application_id,
                             dimension_id, tags)).fetchall()
                        if {row['tag'] for row in available} != set(tags):
                            raise ValueError(
                                f'{access_kind}_TAG_NOT_IN_ACTIVE_METADATA')
                changed = (current['read_security_tags'] != read_tags
                           or current['write_security_tags'] != write_tags)
                revision = state['security_revision']
                if changed:
                    revision += 1
                    db.execute('''UPDATE epm.application_access_grant SET
                        read_security_tags=%s,write_security_tags=%s,
                        granted_at=transaction_timestamp()
                        WHERE issuer=%s AND subject_id=%s AND workspace_id=%s
                        AND application_id=%s''',
                        (Jsonb(read_tags), Jsonb(write_tags), *keys))
                    db.execute('''UPDATE epm.application_state
                        SET security_revision=%s WHERE workspace_id=%s
                        AND application_id=%s''',
                        (revision, scope.workspace_id,
                         scope.application_id))
                result = {
                    'workspaceId': scope.workspace_id,
                    'applicationId': scope.application_id,
                    'changed': changed,
                    'securityRevision': revision,
                }
                db.execute('''INSERT INTO epm.security_operation_receipt
                    (workspace_id,operation_id,command_digest,payload_digest,
                     actor_digest,action,result)
                    VALUES (%s,%s,%s,%s,%s,'dimension-access.set',%s)''',
                    (scope.workspace_id, operation_id, command_digest,
                     payload_digest, actor_digest, Jsonb(result)))
                db.execute('''INSERT INTO epm.security_audit
                    (actor_id,action,workspace_id,application_id,
                     target_digest,outcome,detail)
                    VALUES (%s,'dimension-access.set',%s,%s,%s,
                            'Accepted',%s)''',
                    (actor_digest, scope.workspace_id, scope.application_id,
                     target_digest, Jsonb({
                         'operationId': operation_id,
                         'changed': changed,
                         'securityRevision': revision,
                         'readDimensionCount': len(read_tags),
                         'writeDimensionCount': len(write_tags)})))
                return result

    def read_dimension_access(
            self, scope: ApplicationScope, *, actor: VerifiedIdentity,
            target: VerifiedIdentity) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)
                or not isinstance(target, VerifiedIdentity)):
            raise ValueError('Scope and verified identities are required')
        if target.issuer != actor.issuer:
            raise ValueError('Grant target must have the administrator issuer')
        keys = (target.issuer, target.subject_id,
                scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                db.execute("SELECT set_config('epm.workspace_id',%s,true)",
                           (scope.workspace_id,))
                db.execute("SELECT set_config('epm.application_id',%s,true)",
                           (scope.application_id,))
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, 'admin')
                row = db.execute('''SELECT g.role,g.read_security_tags,
                        g.write_security_tags,s.security_revision
                    FROM epm.application_access_grant g
                    JOIN epm.application_state s
                      USING (workspace_id,application_id)
                    WHERE g.issuer=%s AND g.subject_id=%s
                      AND g.workspace_id=%s AND g.application_id=%s''',
                    keys).fetchone()
                if row is None:
                    raise ValueError('DIMENSION_ACCESS_TARGET_GRANT_REQUIRED')
                return {
                    'workspaceId': scope.workspace_id,
                    'applicationId': scope.application_id,
                    'subjectId': target.subject_id,
                    'role': row['role'],
                    'readTags': row['read_security_tags'],
                    'writeTags': row['write_security_tags'],
                    'securityRevision': row['security_revision'],
                }

    def set_group_dimension_access(
            self, scope: ApplicationScope, *, actor: VerifiedIdentity,
            group_id: str, read_tags: dict[str, list[str]],
            write_tags: dict[str, list[str]],
            expected_security_revision: int, operation_id: str,
            command_digest: str) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)):
            raise ValueError('Scope and verified actor are required')
        group_id = _validate_group_id(group_id)
        if (not isinstance(read_tags, dict) or not isinstance(write_tags, dict)
                or isinstance(expected_security_revision, bool)
                or not isinstance(expected_security_revision, int)
                or expected_security_revision < 0
                or not isinstance(operation_id, str)
                or not 1 <= len(operation_id) <= 200
                or not isinstance(command_digest, str)
                or not re.fullmatch('[0-9a-f]{64}', command_digest)):
            raise ValueError('Group dimension access arguments are invalid')
        payload = {
            'workspaceId': scope.workspace_id,
            'applicationId': scope.application_id,
            'actorIssuer': actor.issuer,
            'actorSubject': actor.subject_id,
            'targetIssuer': actor.issuer,
            'groupId': group_id,
            'readTags': read_tags,
            'writeTags': write_tags,
            'expectedSecurityRevision': expected_security_revision,
        }
        payload_digest = sha256(json.dumps(
            payload, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False).encode('utf-8')).hexdigest()
        actor_digest = sha256((actor.issuer + '\0' + actor.subject_id)
                              .encode('utf-8')).hexdigest()
        target_digest = sha256((actor.issuer + '\0group\0' + group_id)
                               .encode('utf-8')).hexdigest()
        keys = (actor.issuer, group_id,
                scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SELECT set_config('epm.workspace_id',%s,true)",
                           (scope.workspace_id,))
                db.execute("SELECT set_config('epm.application_id',%s,true)",
                           (scope.application_id,))
                PostgresAccessChecker.lock_workspace(
                    db, scope.workspace_id, exclusive=True)
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, 'admin')
                previous = db.execute('''SELECT command_digest,
                    payload_digest,result FROM epm.security_operation_receipt
                    WHERE workspace_id=%s AND operation_id=%s''',
                    (scope.workspace_id, operation_id)).fetchone()
                if previous:
                    if previous['command_digest'] != command_digest:
                        raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    if previous['payload_digest'] != payload_digest:
                        raise ValueError('IDEMPOTENCY_PAYLOAD_CHANGED')
                    return previous['result']
                state = db.execute('''SELECT security_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if state['security_revision'] != expected_security_revision:
                    raise ValueError('STALE_SECURITY_REVISION')
                current = db.execute('''SELECT read_security_tags,
                    write_security_tags
                    FROM epm.application_group_access_grant
                    WHERE issuer=%s AND group_id=%s AND workspace_id=%s
                    AND application_id=%s FOR UPDATE''', keys).fetchone()
                if current is None:
                    raise ValueError(
                        'GROUP_DIMENSION_ACCESS_TARGET_GRANT_REQUIRED')
                for access_kind, assignments, column in (
                        ('READ', read_tags, 'read_security_tags'),
                        ('WRITE', write_tags, 'write_security_tags')):
                    for dimension_id, tags in assignments.items():
                        dimension = db.execute('''SELECT 1 FROM epm.dimension
                            WHERE workspace_id=%s AND application_id=%s
                            AND dimension_id=%s AND status='Active' ''',
                            (scope.workspace_id, scope.application_id,
                             dimension_id)).fetchone()
                        if dimension is None:
                            raise ValueError(
                                f'{access_kind}_DIMENSION_UNAVAILABLE')
                        available = db.execute(f'''SELECT DISTINCT tag
                            FROM epm.member m,
                            unnest(m.{column}) AS tag
                            WHERE m.workspace_id=%s AND m.application_id=%s
                            AND m.dimension_id=%s AND m.status='Active'
                            AND tag=ANY(%s::text[])''',
                            (scope.workspace_id, scope.application_id,
                             dimension_id, tags)).fetchall()
                        if {row['tag'] for row in available} != set(tags):
                            raise ValueError(
                                f'{access_kind}_TAG_NOT_IN_ACTIVE_METADATA')
                changed = (current['read_security_tags'] != read_tags
                           or current['write_security_tags'] != write_tags)
                revision = state['security_revision']
                if changed:
                    revision += 1
                    db.execute('''UPDATE
                        epm.application_group_access_grant SET
                        read_security_tags=%s,write_security_tags=%s,
                        granted_at=transaction_timestamp()
                        WHERE issuer=%s AND group_id=%s AND workspace_id=%s
                        AND application_id=%s''',
                        (Jsonb(read_tags), Jsonb(write_tags), *keys))
                    db.execute('''UPDATE epm.application_state
                        SET security_revision=%s WHERE workspace_id=%s
                        AND application_id=%s''',
                        (revision, scope.workspace_id,
                         scope.application_id))
                result = {
                    'workspaceId': scope.workspace_id,
                    'applicationId': scope.application_id,
                    'groupId': group_id,
                    'changed': changed,
                    'securityRevision': revision,
                }
                db.execute('''INSERT INTO epm.security_operation_receipt
                    (workspace_id,operation_id,command_digest,payload_digest,
                     actor_digest,action,result)
                    VALUES (%s,%s,%s,%s,%s,
                            'group-dimension-access.set',%s)''',
                    (scope.workspace_id, operation_id, command_digest,
                     payload_digest, actor_digest, Jsonb(result)))
                db.execute('''INSERT INTO epm.security_audit
                    (actor_id,action,workspace_id,application_id,
                     target_digest,outcome,detail)
                    VALUES (%s,'group-dimension-access.set',%s,%s,%s,
                            'Accepted',%s)''',
                    (actor_digest, scope.workspace_id, scope.application_id,
                     target_digest, Jsonb({
                         'operationId': operation_id,
                         'changed': changed,
                         'securityRevision': revision,
                         'readDimensionCount': len(read_tags),
                         'writeDimensionCount': len(write_tags)})))
                return result

    def read_group_dimension_access(
            self, scope: ApplicationScope, *, actor: VerifiedIdentity,
            group_id: str) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)):
            raise ValueError('Scope and verified actor are required')
        group_id = _validate_group_id(group_id)
        keys = (actor.issuer, group_id,
                scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                db.execute("SELECT set_config('epm.workspace_id',%s,true)",
                           (scope.workspace_id,))
                db.execute("SELECT set_config('epm.application_id',%s,true)",
                           (scope.application_id,))
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, 'admin')
                row = db.execute('''SELECT g.role,g.read_security_tags,
                        g.write_security_tags,s.security_revision
                    FROM epm.application_group_access_grant g
                    JOIN epm.application_state s
                      USING (workspace_id,application_id)
                    WHERE g.issuer=%s AND g.group_id=%s
                      AND g.workspace_id=%s AND g.application_id=%s''',
                    keys).fetchone()
                if row is None:
                    raise ValueError(
                        'GROUP_DIMENSION_ACCESS_TARGET_GRANT_REQUIRED')
                return {
                    'workspaceId': scope.workspace_id,
                    'applicationId': scope.application_id,
                    'groupId': group_id,
                    'role': row['role'],
                    'readTags': row['read_security_tags'],
                    'writeTags': row['write_security_tags'],
                    'securityRevision': row['security_revision'],
                }

    def read_dimension_tags(self, scope: ApplicationScope, *,
                            actor: VerifiedIdentity) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)):
            raise ValueError('Scope and verified identity are required')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                db.execute("SELECT set_config('epm.workspace_id',%s,true)",
                           (scope.workspace_id,))
                db.execute("SELECT set_config('epm.application_id',%s,true)",
                           (scope.application_id,))
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, 'admin')
                state = db.execute('''SELECT metadata_revision,
                        security_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                dimensions = db.execute('''SELECT dimension_id,name,
                        model_role FROM epm.dimension
                    WHERE workspace_id=%s AND application_id=%s
                      AND status='Active'
                    ORDER BY created_at,dimension_id''',
                    (scope.workspace_id, scope.application_id)).fetchall()
                rows = []
                for order, dimension in enumerate(dimensions, start=1):
                    tags = db.execute('''SELECT read_security_tags,
                            write_security_tags FROM epm.member
                        WHERE workspace_id=%s AND application_id=%s
                          AND dimension_id=%s AND status='Active' ''',
                        (scope.workspace_id, scope.application_id,
                         dimension['dimension_id'])).fetchall()
                    rows.append({
                        'order': order,
                        'dimensionId': dimension['dimension_id'],
                        'name': dimension['name'],
                        'modelRole': dimension['model_role'],
                        'readTags': sorted({tag for row in tags
                                            for tag in
                                            row['read_security_tags']}),
                        'writeTags': sorted({tag for row in tags
                                             for tag in
                                             row['write_security_tags']}),
                    })
                return {
                    'workspaceId': scope.workspace_id,
                    'applicationId': scope.application_id,
                    'metadataRevision': state['metadata_revision'],
                    'securityRevision': state['security_revision'],
                    'dimensions': rows,
                }

    def read_member_security_tags(
            self, scope: ApplicationScope, *, actor: VerifiedIdentity,
            dimension_id: str, member_id: str) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)
                or not isinstance(dimension_id, str)
                or not 1 <= len(dimension_id) <= 200
                or dimension_id != dimension_id.strip()
                or not isinstance(member_id, str)
                or not 1 <= len(member_id) <= 200
                or member_id != member_id.strip()):
            raise ValueError('MEMBER_SECURITY_TAG_READ_ARGUMENTS_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                db.execute("SELECT set_config('epm.workspace_id',%s,true)",
                           (scope.workspace_id,))
                db.execute("SELECT set_config('epm.application_id',%s,true)",
                           (scope.application_id,))
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, 'admin')
                row = db.execute('''SELECT m.name,m.status,
                        m.read_security_tags,m.write_security_tags,
                        s.metadata_revision,s.security_revision
                    FROM epm.member m JOIN epm.application_state s
                      USING(workspace_id,application_id)
                    WHERE m.workspace_id=%s AND m.application_id=%s
                      AND m.dimension_id=%s AND m.member_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     dimension_id, member_id)).fetchone()
                if row is None:
                    raise ValueError('MEMBER_UNAVAILABLE')
                return {
                    'workspaceId': scope.workspace_id,
                    'applicationId': scope.application_id,
                    'dimensionId': dimension_id, 'memberId': member_id,
                    'name': row['name'], 'status': row['status'],
                    'readTags': row['read_security_tags'],
                    'writeTags': row['write_security_tags'],
                    'securityString': render_security_string(
                        row['read_security_tags'], row['write_security_tags']),
                    'metadataRevision': row['metadata_revision'],
                    'securityRevision': row['security_revision'],
                }

    def read_dimension_security_tags(
            self, scope: ApplicationScope, *, actor: VerifiedIdentity,
            dimension_id: str) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)
                or not isinstance(dimension_id, str)
                or not 1 <= len(dimension_id) <= 200
                or dimension_id != dimension_id.strip()):
            raise ValueError('DIMENSION_SECURITY_TAG_READ_ARGUMENTS_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                db.execute("SELECT set_config('epm.workspace_id',%s,true)",
                           (scope.workspace_id,))
                db.execute("SELECT set_config('epm.application_id',%s,true)",
                           (scope.application_id,))
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, 'admin')
                row = db.execute('''SELECT d.name,d.status,
                        d.read_security_tags,d.write_security_tags,
                        s.metadata_revision,s.security_revision
                    FROM epm.dimension d JOIN epm.application_state s
                      USING(workspace_id,application_id)
                    WHERE d.workspace_id=%s AND d.application_id=%s
                      AND d.dimension_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     dimension_id)).fetchone()
                if row is None:
                    raise ValueError('DIMENSION_UNAVAILABLE')
                return {
                    'workspaceId': scope.workspace_id,
                    'applicationId': scope.application_id,
                    'dimensionId': dimension_id,
                    'name': row['name'], 'status': row['status'],
                    'readTags': row['read_security_tags'],
                    'writeTags': row['write_security_tags'],
                    'securityString': render_security_string(
                        row['read_security_tags'], row['write_security_tags']),
                    'metadataRevision': row['metadata_revision'],
                    'securityRevision': row['security_revision'],
                }

    def read_relationship_security_tags(
            self, scope: ApplicationScope, *, actor: VerifiedIdentity,
            relationship_id: str) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)
                or not isinstance(relationship_id, str)
                or not 1 <= len(relationship_id) <= 200
                or relationship_id != relationship_id.strip()):
            raise ValueError('RELATIONSHIP_SECURITY_TAG_READ_ARGUMENTS_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                db.execute("SELECT set_config('epm.workspace_id',%s,true)",
                           (scope.workspace_id,))
                db.execute("SELECT set_config('epm.application_id',%s,true)",
                           (scope.application_id,))
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, 'admin')
                row = db.execute('''SELECT r.dimension_id,r.name,r.status,
                        r.read_security_tags,r.write_security_tags,
                        s.metadata_revision,s.security_revision
                    FROM epm.relationship r JOIN epm.application_state s
                      USING(workspace_id,application_id)
                    WHERE r.workspace_id=%s AND r.application_id=%s
                      AND r.relationship_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     relationship_id)).fetchone()
                if row is None:
                    raise ValueError('RELATIONSHIP_UNAVAILABLE')
                return {
                    'workspaceId': scope.workspace_id,
                    'applicationId': scope.application_id,
                    'dimensionId': row['dimension_id'],
                    'relationshipId': relationship_id,
                    'name': row['name'], 'status': row['status'],
                    'readTags': row['read_security_tags'],
                    'writeTags': row['write_security_tags'],
                    'securityString': render_security_string(
                        row['read_security_tags'], row['write_security_tags']),
                    'metadataRevision': row['metadata_revision'],
                    'securityRevision': row['security_revision'],
                }

    def apply_workspace_grant(
            self, workspace_id: str, *, actor: VerifiedIdentity,
            target: VerifiedIdentity, action: str,
            operation_id: str, command_digest: str) -> dict:
        if (not isinstance(workspace_id, str)
                or not 1 <= len(workspace_id) <= 200
                or not isinstance(actor, VerifiedIdentity)
                or not isinstance(target, VerifiedIdentity)):
            raise ValueError('Workspace and verified identities are required')
        if target.issuer != actor.issuer:
            raise ValueError('Grant target must have the administrator issuer')
        if action not in ('grant', 'revoke'):
            raise ValueError('Grant action must be grant or revoke')
        if (not isinstance(operation_id, str)
                or not 1 <= len(operation_id) <= 200
                or not isinstance(command_digest, str)
                or not re.fullmatch('[0-9a-f]{64}', command_digest)):
            raise ValueError('Operation ID and SHA-256 digest are required')
        payload = {'workspaceId': workspace_id,
                   'actorIssuer': actor.issuer,
                   'actorSubject': actor.subject_id,
                   'targetIssuer': target.issuer,
                   'targetSubject': target.subject_id,
                   'action': action}
        payload_digest = sha256(json.dumps(payload, sort_keys=True,
            separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        actor_digest = sha256((actor.issuer + '\0' + actor.subject_id)
                              .encode()).hexdigest()
        target_digest = sha256((target.issuer + '\0' + target.subject_id)
                               .encode()).hexdigest()
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SELECT set_config('epm.workspace_id',%s,true)",
                           (workspace_id,))
                PostgresAccessChecker.lock_workspace(
                    db, workspace_id, exclusive=True)
                workspace = db.execute('''SELECT status FROM epm.workspace
                    WHERE workspace_id=%s''', (workspace_id,)).fetchone()
                if not workspace or workspace['status'] != 'Active':
                    raise AccessDenied('WORKSPACE_UNAVAILABLE')
                administrator = db.execute('''SELECT
                    EXISTS (SELECT 1 FROM epm.workspace_access_grant
                        WHERE workspace_id=%s AND issuer=%s
                        AND subject_id=%s AND role='Administrator')
                    OR EXISTS (SELECT 1 FROM epm.workspace_group_access_grant
                        WHERE workspace_id=%s AND issuer=%s
                        AND group_id=ANY(%s::text[])
                        AND role='Administrator') AS allowed''',
                    (workspace_id, actor.issuer, actor.subject_id,
                     workspace_id, actor.issuer, list(actor.groups))
                    ).fetchone()['allowed']
                if not administrator:
                    raise AccessDenied('WORKSPACE_ADMIN_REQUIRED')
                previous = db.execute('''SELECT command_digest,payload_digest,
                    result FROM epm.security_operation_receipt
                    WHERE workspace_id=%s AND operation_id=%s''',
                    (workspace_id, operation_id)).fetchone()
                if previous:
                    if previous['command_digest'] != command_digest:
                        raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    if previous['payload_digest'] != payload_digest:
                        raise ValueError('IDEMPOTENCY_PAYLOAD_CHANGED')
                    return previous['result']
                keys = (target.issuer, target.subject_id, workspace_id)
                if action == 'grant':
                    active = db.execute(
                        'SELECT epm.identity_subject_active(%s,%s) AS active',
                        (target.issuer,
                         target.subject_id)).fetchone()['active']
                    if not active:
                        raise AccessDenied('USER_IDENTITY_UNAVAILABLE')
                    db.execute('''INSERT INTO epm.workspace_access_grant
                        (issuer,subject_id,workspace_id,role)
                        VALUES (%s,%s,%s,'Administrator')
                        ON CONFLICT (issuer,subject_id,workspace_id)
                        DO UPDATE SET role=EXCLUDED.role,
                            granted_at=transaction_timestamp()''', keys)
                    changed = True
                else:
                    present = db.execute('''SELECT 1 FROM
                        epm.workspace_access_grant WHERE issuer=%s
                        AND subject_id=%s AND workspace_id=%s''',
                        keys).fetchone() is not None
                    if present:
                        count = db.execute('''SELECT
                            (SELECT count(*) FROM epm.workspace_access_grant
                                WHERE workspace_id=%s)
                          + (SELECT count(*) FROM
                                epm.workspace_group_access_grant
                                WHERE workspace_id=%s) AS total''',
                            (workspace_id, workspace_id)).fetchone()['total']
                        if count <= 1:
                            raise ValueError('LAST_WORKSPACE_ADMINISTRATOR')
                        db.execute('''DELETE FROM epm.workspace_access_grant
                            WHERE issuer=%s AND subject_id=%s
                            AND workspace_id=%s''', keys)
                    changed = present
                result = {'workspaceId': workspace_id, 'action': action,
                          'role': 'Administrator' if action == 'grant' else None,
                          'changed': changed}
                db.execute('''INSERT INTO epm.security_operation_receipt
                    (workspace_id,operation_id,command_digest,
                    payload_digest,actor_digest,action,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (workspace_id, operation_id, command_digest,
                     payload_digest, actor_digest,
                     f'workspace.{action}', Jsonb(result)))
                db.execute('''INSERT INTO epm.security_audit
                    (actor_id,action,workspace_id,target_digest,
                    outcome,detail) VALUES (%s,%s,%s,%s,'Accepted',%s)''',
                    (actor_digest, f'workspace.{action}', workspace_id,
                     target_digest, Jsonb({'changed': changed})))
                return result

    def apply_workspace_group_grant(
            self, workspace_id: str, *, actor: VerifiedIdentity,
            group_id: str, action: str,
            operation_id: str, command_digest: str) -> dict:
        if (not isinstance(workspace_id, str)
                or not 1 <= len(workspace_id) <= 200
                or not isinstance(actor, VerifiedIdentity)):
            raise ValueError('Workspace and verified actor are required')
        group_id = _validate_group_id(group_id)
        if action not in ('grant', 'revoke'):
            raise ValueError('Grant action must be grant or revoke')
        if (not isinstance(operation_id, str)
                or not 1 <= len(operation_id) <= 200
                or not isinstance(command_digest, str)
                or not re.fullmatch('[0-9a-f]{64}', command_digest)):
            raise ValueError('Operation ID and SHA-256 digest are required')
        payload = {'workspaceId': workspace_id,
                   'actorIssuer': actor.issuer,
                   'actorSubject': actor.subject_id,
                   'targetIssuer': actor.issuer,
                   'groupId': group_id, 'action': action}
        payload_digest = sha256(json.dumps(payload, sort_keys=True,
            separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        actor_digest = sha256((actor.issuer + '\0' + actor.subject_id)
                              .encode()).hexdigest()
        target_digest = sha256((actor.issuer + '\0group\0' + group_id)
                               .encode()).hexdigest()
        keys = (actor.issuer, group_id, workspace_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SELECT set_config('epm.workspace_id',%s,true)",
                           (workspace_id,))
                PostgresAccessChecker.lock_workspace(
                    db, workspace_id, exclusive=True)
                workspace = db.execute('''SELECT status FROM epm.workspace
                    WHERE workspace_id=%s''', (workspace_id,)).fetchone()
                if not workspace or workspace['status'] != 'Active':
                    raise AccessDenied('WORKSPACE_UNAVAILABLE')
                allowed = db.execute('''SELECT
                    EXISTS (SELECT 1 FROM epm.workspace_access_grant
                        WHERE workspace_id=%s AND issuer=%s
                        AND subject_id=%s AND role='Administrator')
                    OR EXISTS (SELECT 1 FROM epm.workspace_group_access_grant
                        WHERE workspace_id=%s AND issuer=%s
                        AND group_id=ANY(%s::text[])
                        AND role='Administrator') AS allowed''',
                    (workspace_id, actor.issuer, actor.subject_id,
                     workspace_id, actor.issuer, list(actor.groups))
                    ).fetchone()['allowed']
                if not allowed:
                    raise AccessDenied('WORKSPACE_ADMIN_REQUIRED')
                previous = db.execute('''SELECT command_digest,payload_digest,
                    result FROM epm.security_operation_receipt
                    WHERE workspace_id=%s AND operation_id=%s''',
                    (workspace_id, operation_id)).fetchone()
                if previous:
                    if previous['command_digest'] != command_digest:
                        raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    if previous['payload_digest'] != payload_digest:
                        raise ValueError('IDEMPOTENCY_PAYLOAD_CHANGED')
                    return previous['result']
                if action == 'grant':
                    db.execute(
                        'SELECT epm.assert_active_group_authority(%s,%s)',
                        (actor.issuer, group_id))
                current = db.execute('''SELECT 1 FROM
                    epm.workspace_group_access_grant WHERE issuer=%s
                    AND group_id=%s AND workspace_id=%s''', keys).fetchone()
                if action == 'grant':
                    changed = current is None
                    if changed:
                        db.execute('''INSERT INTO
                            epm.workspace_group_access_grant
                            (issuer,group_id,workspace_id,role)
                            VALUES (%s,%s,%s,'Administrator')''', keys)
                else:
                    if current:
                        count = db.execute('''SELECT
                            (SELECT count(*) FROM epm.workspace_access_grant
                                WHERE workspace_id=%s)
                          + (SELECT count(*) FROM
                                epm.workspace_group_access_grant
                                WHERE workspace_id=%s) AS total''',
                            (workspace_id, workspace_id)).fetchone()['total']
                        if count <= 1:
                            raise ValueError('LAST_WORKSPACE_ADMINISTRATOR')
                        db.execute('''DELETE FROM
                            epm.workspace_group_access_grant WHERE issuer=%s
                            AND group_id=%s AND workspace_id=%s''', keys)
                    changed = current is not None
                result = {'workspaceId': workspace_id, 'groupId': group_id,
                          'action': action,
                          'role': ('Administrator'
                                   if action == 'grant' else None),
                          'changed': changed}
                db.execute('''INSERT INTO epm.security_operation_receipt
                    (workspace_id,operation_id,command_digest,payload_digest,
                     actor_digest,action,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (workspace_id, operation_id, command_digest,
                     payload_digest, actor_digest,
                     f'workspace-group.{action}', Jsonb(result)))
                db.execute('''INSERT INTO epm.security_audit
                    (actor_id,action,workspace_id,target_digest,
                     outcome,detail) VALUES (%s,%s,%s,%s,'Accepted',%s)''',
                    (actor_digest, f'workspace-group.{action}', workspace_id,
                     target_digest, Jsonb({'changed': changed})))
                return result

    def list_workspace_group_grants(
            self, workspace_id: str, *, actor: VerifiedIdentity,
            after_group_id: str | None = None, limit: int = 100) -> dict:
        if (not isinstance(workspace_id, str)
                or not 1 <= len(workspace_id) <= 200
                or not isinstance(actor, VerifiedIdentity)
                or (after_group_id is not None
                    and _validate_group_id(after_group_id) != after_group_id)
                or isinstance(limit, bool) or not isinstance(limit, int)
                or not 1 <= limit <= 100):
            raise ValueError('WORKSPACE_GROUP_LIST_ARGUMENTS_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                db.execute("SELECT set_config('epm.workspace_id',%s,true)",
                           (workspace_id,))
                allowed = db.execute('''SELECT
                    EXISTS (SELECT 1 FROM epm.workspace_access_grant
                        WHERE workspace_id=%s AND issuer=%s
                        AND subject_id=%s AND role='Administrator')
                    OR EXISTS (SELECT 1 FROM epm.workspace_group_access_grant
                        WHERE workspace_id=%s AND issuer=%s
                        AND group_id=ANY(%s::text[])
                        AND role='Administrator') AS allowed''',
                    (workspace_id, actor.issuer, actor.subject_id,
                     workspace_id, actor.issuer, list(actor.groups))
                    ).fetchone()['allowed']
                if not allowed:
                    raise AccessDenied('WORKSPACE_ADMIN_REQUIRED')
                rows = db.execute('''SELECT group_id,role,granted_at
                    FROM epm.workspace_group_access_grant
                    WHERE workspace_id=%s AND issuer=%s
                      AND (%s::text IS NULL OR group_id>%s)
                    ORDER BY group_id LIMIT %s''',
                    (workspace_id, actor.issuer, after_group_id,
                     after_group_id, limit + 1)).fetchall()
                return {'grants': [{
                    'groupId': row['group_id'], 'role': row['role'],
                    'grantedAt': row['granted_at'].isoformat()}
                    for row in rows[:limit]],
                    'nextAfterGroupId': (rows[limit-1]['group_id']
                        if len(rows) > limit else None)}

    def apply_rule_grant(
            self, scope: ApplicationScope, *, actor: VerifiedIdentity,
            target: VerifiedIdentity, action: str,
            permissions: dict[str, bool] | None,
            operation_id: str, command_digest: str) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)
                or not isinstance(target, VerifiedIdentity)):
            raise ValueError('Scope and verified identities are required')
        if target.issuer != actor.issuer:
            raise ValueError('Grant target must have the administrator issuer')
        if action not in ('set', 'revoke'):
            raise ValueError('Rule grant action must be set or revoke')
        if action == 'set':
            if (not isinstance(permissions, dict)
                    or set(permissions) != {'design','publish','run'}
                    or any(type(value) is not bool
                           for value in permissions.values())
                    or not any(permissions.values())):
                raise ValueError('RULE_PERMISSIONS_INVALID')
        elif permissions is not None:
            raise ValueError('RULE_PERMISSIONS_INVALID')
        if (not isinstance(operation_id, str)
                or not 1 <= len(operation_id) <= 200
                or not isinstance(command_digest, str)
                or not re.fullmatch('[0-9a-f]{64}', command_digest)):
            raise ValueError('Operation ID and SHA-256 digest are required')
        payload = {'scope': [scope.workspace_id,scope.application_id],
                   'actor': [actor.issuer,actor.subject_id],
                   'target': [target.issuer,target.subject_id],
                   'action': action,'permissions': permissions}
        payload_digest=sha256(json.dumps(payload,sort_keys=True,
            separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
        actor_digest=sha256((actor.issuer+'\0'+actor.subject_id)
                            .encode()).hexdigest()
        target_digest=sha256((target.issuer+'\0'+target.subject_id)
                             .encode()).hexdigest()
        keys=(target.issuer,target.subject_id,
              scope.workspace_id,scope.application_id)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresAccessChecker.lock_workspace(
                    db,scope.workspace_id,exclusive=True)
                PostgresAccessChecker.check_in_transaction(
                    db,actor,scope,'admin')
                previous=db.execute('''SELECT command_digest,payload_digest,
                    result FROM epm.security_operation_receipt
                    WHERE workspace_id=%s AND operation_id=%s''',
                    (scope.workspace_id,operation_id)).fetchone()
                if previous:
                    if previous['command_digest']!=command_digest:
                        raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    if previous['payload_digest']!=payload_digest:
                        raise ValueError('IDEMPOTENCY_PAYLOAD_CHANGED')
                    return previous['result']
                current=db.execute('''SELECT can_design,can_publish,can_run
                    FROM epm.rule_access_grant WHERE issuer=%s
                    AND subject_id=%s AND workspace_id=%s
                    AND application_id=%s''',keys).fetchone()
                if action=='set':
                    if not db.execute('''SELECT 1 FROM
                        epm.application_access_grant WHERE issuer=%s
                        AND subject_id=%s AND workspace_id=%s
                        AND application_id=%s''',keys).fetchone():
                        raise ValueError('RULE_TARGET_APPLICATION_ACCESS_REQUIRED')
                    desired=(permissions['design'],permissions['publish'],
                             permissions['run'])
                    changed=(current is None or
                        tuple(current[name] for name in (
                            'can_design','can_publish','can_run'))!=desired)
                    if changed:
                        db.execute('''INSERT INTO epm.rule_access_grant
                            (issuer,subject_id,workspace_id,application_id,
                            can_design,can_publish,can_run)
                            VALUES (%s,%s,%s,%s,%s,%s,%s)
                            ON CONFLICT (issuer,subject_id,workspace_id,
                                application_id) DO UPDATE SET
                            can_design=EXCLUDED.can_design,
                            can_publish=EXCLUDED.can_publish,
                            can_run=EXCLUDED.can_run,
                            granted_at=transaction_timestamp()''',
                            (*keys,*desired))
                else:
                    changed=bool(db.execute('''DELETE FROM
                        epm.rule_access_grant WHERE issuer=%s
                        AND subject_id=%s AND workspace_id=%s
                        AND application_id=%s''',keys).rowcount)
                result={'workspaceId':scope.workspace_id,
                        'applicationId':scope.application_id,
                        'action':action,'permissions':permissions,
                        'changed':changed}
                db.execute('''INSERT INTO epm.security_operation_receipt
                    (workspace_id,operation_id,command_digest,
                    payload_digest,actor_digest,action,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id,operation_id,command_digest,
                     payload_digest,actor_digest,f'rule.{action}',
                     Jsonb(result)))
                db.execute('''INSERT INTO epm.security_audit
                    (actor_id,action,workspace_id,application_id,
                    target_digest,outcome,detail)
                    VALUES (%s,%s,%s,%s,%s,'Accepted',%s)''',
                    (actor_digest,f'rule.{action}',scope.workspace_id,
                     scope.application_id,target_digest,
                     Jsonb({'operationId':operation_id,
                            'changed':changed,
                            'permissions':permissions})))
                return result

    def apply_rule_group_grant(
            self, scope: ApplicationScope, *, actor: VerifiedIdentity,
            group_id: str, action: str,
            permissions: dict[str, bool] | None,
            operation_id: str, command_digest: str) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)):
            raise ValueError('Scope and verified actor are required')
        group_id = _validate_group_id(group_id)
        if action not in ('set', 'revoke'):
            raise ValueError('Rule grant action must be set or revoke')
        if action == 'set':
            if (not isinstance(permissions, dict)
                    or set(permissions) != {'design', 'publish', 'run'}
                    or any(type(value) is not bool
                           for value in permissions.values())
                    or not any(permissions.values())):
                raise ValueError('RULE_PERMISSIONS_INVALID')
        elif permissions is not None:
            raise ValueError('RULE_PERMISSIONS_INVALID')
        if (not isinstance(operation_id, str)
                or not 1 <= len(operation_id) <= 200
                or not isinstance(command_digest, str)
                or not re.fullmatch('[0-9a-f]{64}', command_digest)):
            raise ValueError('Operation ID and SHA-256 digest are required')
        payload = {'scope': [scope.workspace_id, scope.application_id],
                   'actor': [actor.issuer, actor.subject_id],
                   'groupId': group_id, 'action': action,
                   'permissions': permissions}
        payload_digest = sha256(json.dumps(payload, sort_keys=True,
            separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        actor_digest = sha256((actor.issuer + '\0' + actor.subject_id)
                              .encode()).hexdigest()
        target_digest = sha256((actor.issuer + '\0group\0' + group_id)
                               .encode()).hexdigest()
        keys = (actor.issuer, group_id,
                scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SELECT set_config('epm.workspace_id',%s,true)",
                           (scope.workspace_id,))
                db.execute("SELECT set_config('epm.application_id',%s,true)",
                           (scope.application_id,))
                PostgresAccessChecker.lock_workspace(
                    db, scope.workspace_id, exclusive=True)
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, 'admin')
                previous = db.execute('''SELECT command_digest,payload_digest,
                    result FROM epm.security_operation_receipt
                    WHERE workspace_id=%s AND operation_id=%s''',
                    (scope.workspace_id, operation_id)).fetchone()
                if previous:
                    if previous['command_digest'] != command_digest:
                        raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    if previous['payload_digest'] != payload_digest:
                        raise ValueError('IDEMPOTENCY_PAYLOAD_CHANGED')
                    return previous['result']
                if action == 'set':
                    db.execute(
                        'SELECT epm.assert_active_group_authority(%s,%s)',
                        (actor.issuer, group_id))
                current = db.execute('''SELECT can_design,can_publish,can_run
                    FROM epm.rule_group_access_grant WHERE issuer=%s
                    AND group_id=%s AND workspace_id=%s
                    AND application_id=%s''', keys).fetchone()
                if action == 'set':
                    if not db.execute('''SELECT 1 FROM
                        epm.application_group_access_grant WHERE issuer=%s
                        AND group_id=%s AND workspace_id=%s
                        AND application_id=%s''', keys).fetchone():
                        raise ValueError(
                            'RULE_TARGET_APPLICATION_ACCESS_REQUIRED')
                    desired = (permissions['design'], permissions['publish'],
                               permissions['run'])
                    changed = (current is None or tuple(
                        current[name] for name in (
                            'can_design', 'can_publish', 'can_run')) != desired)
                    if changed:
                        db.execute('''INSERT INTO epm.rule_group_access_grant
                            (issuer,group_id,workspace_id,application_id,
                             can_design,can_publish,can_run)
                            VALUES (%s,%s,%s,%s,%s,%s,%s)
                            ON CONFLICT (issuer,group_id,workspace_id,
                                application_id) DO UPDATE SET
                            can_design=EXCLUDED.can_design,
                            can_publish=EXCLUDED.can_publish,
                            can_run=EXCLUDED.can_run,
                            granted_at=transaction_timestamp()''',
                            (*keys, *desired))
                else:
                    changed = bool(db.execute('''DELETE FROM
                        epm.rule_group_access_grant WHERE issuer=%s
                        AND group_id=%s AND workspace_id=%s
                        AND application_id=%s''', keys).rowcount)
                result = {'workspaceId': scope.workspace_id,
                          'applicationId': scope.application_id,
                          'groupId': group_id, 'action': action,
                          'permissions': permissions, 'changed': changed}
                db.execute('''INSERT INTO epm.security_operation_receipt
                    (workspace_id,operation_id,command_digest,payload_digest,
                     actor_digest,action,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id, operation_id, command_digest,
                     payload_digest, actor_digest, f'rule-group.{action}',
                     Jsonb(result)))
                db.execute('''INSERT INTO epm.security_audit
                    (actor_id,action,workspace_id,application_id,
                     target_digest,outcome,detail)
                    VALUES (%s,%s,%s,%s,%s,'Accepted',%s)''',
                    (actor_digest, f'rule-group.{action}', scope.workspace_id,
                     scope.application_id, target_digest,
                     Jsonb({'operationId': operation_id,
                            'changed': changed,
                            'permissions': permissions})))
                return result
