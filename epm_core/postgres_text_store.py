"""Authorized text facts with relational ordinary-batch publication.

Existing MCP/job programs retain original receipts, history and presence semantics.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Sequence

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row

from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security_enforcement import (
    authorize_coordinate, authorize_coordinates,
)
from .persistence_contract import (
    ApplicationScope, Coordinate, MutationReceipt, TextCell, TextMutation,
    TextMutationKind,
)
from .postgres_numeric_store import PostgresNumericFactStore


class PostgresTextFactStore:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL connection string is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn = dsn
        self.identity = identity

    def read_current(self, scope: ApplicationScope, coordinate: Coordinate,
                     *, snapshot_revision: int | None = None) -> TextCell:
        if snapshot_revision is not None and (
                isinstance(snapshot_revision, bool) or
                not isinstance(snapshot_revision, int) or snapshot_revision < 0):
            raise ValueError('Snapshot revision must be a nonnegative integer')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            PostgresNumericFactStore._set_scope(db, scope)
            PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, 'read')
            authorize_coordinate(
                db, self.identity, scope, coordinate, kind=AccessKind.READ)
            state = db.execute('''SELECT commit_revision FROM epm.application_state
                WHERE workspace_id=%s AND application_id=%s''',
                (scope.workspace_id, scope.application_id)).fetchone()
            if state is None:
                raise ValueError('APPLICATION_UNAVAILABLE')
            if snapshot_revision is not None and snapshot_revision > state['commit_revision']:
                raise ValueError('SNAPSHOT_NOT_COMMITTED')
            point = db.execute('''SELECT coordinate_id, members FROM epm.coordinate
                WHERE workspace_id=%s AND application_id=%s AND series_key=%s''',
                (scope.workspace_id, scope.application_id,
                 coordinate.series_key)).fetchone()
            if point is None:
                return TextCell(False, None, '')
            if point['members'] != dict(coordinate.members):
                raise ValueError('COORDINATE_HASH_COLLISION')
            if snapshot_revision is None:
                row = db.execute('''SELECT present, text_value, change_id
                    FROM epm.text_cell_current WHERE workspace_id=%s
                    AND application_id=%s AND coordinate_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     point['coordinate_id'])).fetchone()
                return (TextCell(row['present'], row['text_value'], row['change_id'])
                        if row else TextCell(False, None, ''))
            row = db.execute('''SELECT present, resulting_value AS text_value,
                change_id FROM epm.text_fact_event WHERE workspace_id=%s
                AND application_id=%s AND coordinate_id=%s
                AND committed_revision<=%s
                ORDER BY committed_revision DESC, line_ordinal DESC LIMIT 1''',
                (scope.workspace_id, scope.application_id,
                 point['coordinate_id'], snapshot_revision)).fetchone()
            return (TextCell(row['present'], row['text_value'], row['change_id'])
                    if row else TextCell(False, None, ''))

    def apply(self, scope: ApplicationScope, mutations: Sequence[TextMutation],
              *, operation_id: str, command_digest: str, actor_id: str,
              expected_metadata_revision: int,
              expected_data_revision: int | None = None) -> MutationReceipt:
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                return self.apply_in_transaction(
                    db, scope, mutations, operation_id=operation_id,
                    command_digest=command_digest, actor_id=actor_id,
                    expected_metadata_revision=expected_metadata_revision,
                    expected_data_revision=expected_data_revision)

    def apply_in_transaction(self, db, scope: ApplicationScope,
                             mutations: Sequence[TextMutation], *,
                             operation_id: str, command_digest: str,
                             actor_id: str, expected_metadata_revision: int,
                             expected_data_revision: int | None = None) -> MutationReceipt:
        """Apply through a caller-owned transaction for atomic job publication."""
        if (not isinstance(operation_id, str) or not 1 <= len(operation_id) <= 200
                or not isinstance(actor_id, str) or not 1 <= len(actor_id) <= 200
                or not isinstance(command_digest, str)
                or not re.fullmatch('[0-9a-f]{64}', command_digest)):
            raise ValueError('Operation ID, actor ID and SHA-256 digest are required')
        if actor_id != self.identity.subject_id:
            raise ValueError('Actor ID must match verified identity')
        if (isinstance(expected_metadata_revision, bool)
                or not isinstance(expected_metadata_revision, int)
                or expected_metadata_revision < 0):
            raise ValueError('Expected metadata revision is required')
        if expected_data_revision is not None and (
                isinstance(expected_data_revision, bool)
                or not isinstance(expected_data_revision, int)
                or expected_data_revision < 0):
            raise ValueError('Expected data revision must be nonnegative')
        if not 1 <= len(mutations) <= 500 or any(
                not isinstance(item, TextMutation) for item in mutations):
            raise ValueError('A batch needs 1–500 text mutations')
        if len({item.coordinate for item in mutations}) != len(mutations):
            raise ValueError('One batch cannot target a coordinate twice; use ordered stages')
        payload_digest = self._payload_digest(
            scope, mutations, actor_id, expected_metadata_revision,
            expected_data_revision)
        PostgresNumericFactStore._set_scope(db, scope)
        PostgresAccessChecker.check_in_transaction(
            db, self.identity, scope, 'write')
        state = db.execute('''SELECT a.status, s.processing_mode,
            s.metadata_revision, s.data_revision, s.commit_revision
            FROM epm.application_state s JOIN epm.application a
            USING (workspace_id, application_id)
            WHERE s.workspace_id=%s AND s.application_id=%s''',
            (scope.workspace_id, scope.application_id)).fetchone()
        previous=PostgresNumericFactStore._previous_receipt(
            db,scope,operation_id)
        if previous:
            return PostgresNumericFactStore._replay_receipt(
                previous,operation_id,command_digest,payload_digest)
        authorize_coordinates(
            db, self.identity, scope,
            (item.coordinate for item in mutations), kind=AccessKind.WRITE)
        PostgresNumericFactStore._validate_state(
            state,expected_metadata_revision,expected_data_revision)
        self._lock_mutation_points(db,scope,mutations)
        from .postgres_text_batch import prepare
        prepared=prepare(db,scope,mutations)

        state = db.execute('''SELECT a.status, s.processing_mode,
            s.metadata_revision, s.data_revision, s.commit_revision
            FROM epm.application_state s JOIN epm.application a
            USING (workspace_id, application_id)
            WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s''',
            (scope.workspace_id, scope.application_id)).fetchone()
        previous=PostgresNumericFactStore._previous_receipt(
            db,scope,operation_id)
        if previous:
            return PostgresNumericFactStore._replay_receipt(
                previous,operation_id,command_digest,payload_digest)
        PostgresNumericFactStore._validate_state(
            state,expected_metadata_revision,expected_data_revision)
        access=PostgresAccessChecker.check_in_transaction(
            db,self.identity,scope,'write')
        authorize_coordinates(
            db, self.identity, scope,
            (item.coordinate for item in mutations), kind=AccessKind.WRITE)
        from .postgres_planning_write_guard import (
            PlanningReceiptEvidenceConnection,enforce_active_planning_policy,
        )
        actions={TextMutationKind.SET:'Set',TextMutationKind.CLEAR:'Clear'}
        policy_evidence=enforce_active_planning_policy(
            db,scope,writes=tuple((item.coordinate,actions[item.kind])
                                  for item in mutations),
            workflow_role=access.role)
        from .postgres_text_batch import (
            publish_prepared,recheck_prepared_inputs,
        )
        evidence_db=PlanningReceiptEvidenceConnection(db,policy_evidence)
        recheck_prepared_inputs(evidence_db,scope,prepared)
        return publish_prepared(evidence_db,
            scope,prepared,revision=state['commit_revision']+1,
            operation_id=operation_id,command_digest=command_digest,
            actor_id=actor_id,payload_digest=payload_digest)

    @staticmethod
    def _mutation_point_keys(scope,mutations) -> tuple[str,...]:
        return tuple(sorted({'epm.pov.text:' + json.dumps(
                        [scope.workspace_id,scope.application_id,
                         item.coordinate.series_key],
                        separators=(',',':'),ensure_ascii=False)
                     for item in mutations}))

    @staticmethod
    def _lock_mutation_points(db,scope,mutations) -> None:
        keys=PostgresTextFactStore._mutation_point_keys(scope,mutations)
        db.execute('''SELECT pg_advisory_xact_lock(hashtextextended(key,0))
            FROM unnest(%s::text[]) key ORDER BY key''',(list(keys),))

    @staticmethod
    def _payload_digest(scope: ApplicationScope,
                        mutations: Sequence[TextMutation], actor_id: str,
                        expected_metadata_revision: int,
                        expected_data_revision: int | None) -> str:
        payload = {
            'workspaceId': scope.workspace_id,
            'applicationId': scope.application_id,
            'actorId': actor_id,
            'expectedMetadataRevision': expected_metadata_revision,
            'expectedDataRevision': expected_data_revision,
            'mutations': [
                {'members': list(item.coordinate.members),
                 'kind': item.kind.value,
                 'value': item.value,
                 'expectedChangeId': item.expected_change_id}
                for item in mutations
            ],
        }
        return sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'),
                                 ensure_ascii=False).encode('utf-8')).hexdigest()
