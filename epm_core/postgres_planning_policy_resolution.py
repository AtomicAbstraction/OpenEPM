"""Shared current-state resolver for public reusable planning policies."""
from __future__ import annotations

from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .planning_operation_policy import (
    bind_planning_operation_policy, compile_planning_operation_policy,
)
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore


def resolve_published_planning_policy(
        dsn: str, identity: VerifiedIdentity, scope: ApplicationScope,
        arguments: dict, *, expected_kind: str, function: str) -> tuple[dict, dict]:
    """Resolve one active current policy against application pins."""
    if (not isinstance(arguments, dict)
            or set(arguments) != {'policyId', 'effectiveOn', 'bindings'}):
        raise ValueError('PLANNING_PUBLISHED_POLICY_ARGUMENTS_INVALID')
    with connect_postgres(dsn, row_factory=dict_row) as db:
        with db.transaction():
            db.execute('SET TRANSACTION READ ONLY')
            PostgresNumericFactStore._set_scope(db, scope)
            PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
            PostgresAccessChecker.check_in_transaction(
                db, identity, scope, 'write', function=function,
                arguments=arguments)
            row = db.execute('''SELECT p.policy_id,p.state_token,p.definition,
                p.canonical_digest,
                a.metadata_revision,a.policy_revision,
                app.status AS application_status,a.processing_mode
                FROM epm.planning_operation_policy p
                JOIN epm.application_state a
                 ON a.workspace_id=p.workspace_id
                AND a.application_id=p.application_id
                JOIN epm.application app
                 ON app.workspace_id=p.workspace_id
                AND app.application_id=p.application_id
                WHERE p.workspace_id=%s AND p.application_id=%s
                AND p.policy_id=%s AND p.status='Active' ''',
                (scope.workspace_id, scope.application_id,
                 arguments['policyId'])).fetchone()
            if row is None:
                raise ValueError('PLANNING_POLICY_NOT_PUBLISHED')
            if (row['application_status'] != 'Active'
                    or row['processing_mode'] != 'Active'):
                raise ValueError('APPLICATION_NOT_WRITABLE')
            compiled = compile_planning_operation_policy(row['definition'])
            if (compiled.kind != expected_kind
                    or compiled.document['policyId'] != row['policy_id']
                    or compiled.digest != row['canonical_digest']):
                raise ValueError('PLANNING_POLICY_STORAGE_INVALID')
            if compiled.document['metadataRevision'] != row['metadata_revision']:
                raise ValueError('PLANNING_POLICY_METADATA_STALE')
            authored_metadata = compiled.document['metadataRevision']
            authored_policy = compiled.document['policyRevision']
            bound = bind_planning_operation_policy(
                compiled, arguments['bindings'],
                metadata_revision=authored_metadata,
                policy_revision=authored_policy,
                effective_on=arguments['effectiveOn'])
            bound = {**bound, 'metadataRevision': row['metadata_revision'],
                     'policyRevision': row['policy_revision']}
            pointer = {'authoredMetadataRevision': authored_metadata,
                'authoredPolicyRevision': authored_policy,
                'stateToken': row['state_token']}
    return bound, pointer
