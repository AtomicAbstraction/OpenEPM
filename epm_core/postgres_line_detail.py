"""Atomic supporting-detail and numeric-total writes for PostgreSQL.

Financial metadata policy validation is a separate P06/P07 dependency. This
generic adapter is not yet connected to the live application-language runtime.
"""
from __future__ import annotations

from decimal import Decimal, localcontext
from hashlib import sha256
import json
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security_enforcement import authorize_coordinate
from .persistence_contract import (
    ApplicationScope, Coordinate, LineDetailCell, LineItem, MutationReceipt,
    NumericCell,
)
from .postgres_numeric_store import PostgresNumericFactStore


class PostgresLineDetailStore:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL connection string is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn = dsn
        self.identity = identity

    def read_current(self, scope: ApplicationScope, coordinate: Coordinate,
                     *, snapshot_revision: int | None = None) -> LineDetailCell:
        if snapshot_revision is not None and (
                isinstance(snapshot_revision, bool)
                or not isinstance(snapshot_revision, int)
                or snapshot_revision < 0):
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
                return LineDetailCell(False, (), None, '')
            if point['members'] != dict(coordinate.members):
                raise ValueError('COORDINATE_HASH_COLLISION')
            if snapshot_revision is None:
                row = db.execute('''SELECT items, total, change_id
                    FROM epm.line_detail_current WHERE workspace_id=%s
                    AND application_id=%s AND coordinate_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     point['coordinate_id'])).fetchone()
            else:
                row = db.execute('''SELECT items, total, change_id,
                    present
                    FROM epm.line_detail_event WHERE workspace_id=%s
                    AND application_id=%s AND coordinate_id=%s
                    AND committed_revision<=%s
                    ORDER BY committed_revision DESC LIMIT 1''',
                    (scope.workspace_id, scope.application_id,
                     point['coordinate_id'], snapshot_revision)).fetchone()
            if row is None or row.get('present') is False:
                return LineDetailCell(False, (), None, '')
            return LineDetailCell(True, tuple(
                LineItem(item['description'], Decimal(item['amount']))
                for item in row['items']), row['total'], row['change_id'])

    def apply(self, scope: ApplicationScope, coordinate: Coordinate,
              items: tuple[LineItem, ...], *, operation_id: str,
              command_digest: str, actor_id: str,
              expected_metadata_revision: int,
              expected_cell_change_id: str,
              expected_detail_change_id: str,
              expected_data_revision: int | None = None,
              _connection=None, _shared_revision: int | None = None,
              _write_control: bool = True, _ordinal: int = 1,
              _policy_evidence=None, _point_fenced: bool = False) -> MutationReceipt:
        if (not isinstance(operation_id, str) or not 1 <= len(operation_id) <= 200
                or not isinstance(actor_id, str) or not 1 <= len(actor_id) <= 200
                or not isinstance(command_digest, str)
                or not re.fullmatch('[0-9a-f]{64}', command_digest)):
            raise ValueError('Operation ID, actor ID and SHA-256 digest are required')
        if actor_id != self.identity.subject_id:
            raise ValueError('Actor ID must match verified identity')
        if (not isinstance(coordinate, Coordinate) or not isinstance(items, tuple)
                or len(items) > 500 or any(
                    not isinstance(item, LineItem) for item in items)):
            raise ValueError('Line detail needs a coordinate and at most 500 items')
        if (not isinstance(expected_cell_change_id, str)
                or not isinstance(expected_detail_change_id, str)):
            raise ValueError('Expected cell and detail change IDs are required')
        if (isinstance(expected_metadata_revision, bool)
                or not isinstance(expected_metadata_revision, int)
                or expected_metadata_revision < 0):
            raise ValueError('Expected metadata revision is required')
        if expected_data_revision is not None and (
                isinstance(expected_data_revision, bool)
                or not isinstance(expected_data_revision, int)
                or expected_data_revision < 0):
            raise ValueError('Expected data revision must be nonnegative')
        with localcontext() as context:
            context.prec = 64
            total = sum((item.amount for item in items), Decimal(0))
            NumericCell(True, total, '')  # Validate NUMERIC(28,8) before writing.
        encoded_items = [{'description': item.description,
                          'amount': format(item.amount, 'f')} for item in items]
        payload = {
            'workspaceId': scope.workspace_id,
            'applicationId': scope.application_id,
            'members': list(coordinate.members),
            'items': encoded_items,
            'actorId': actor_id,
            'expectedMetadataRevision': expected_metadata_revision,
            'expectedDataRevision': expected_data_revision,
            'expectedCellChangeId': expected_cell_change_id,
            'expectedDetailChangeId': expected_detail_change_id,
        }
        payload_digest = sha256(json.dumps(
            payload, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False).encode('utf-8')).hexdigest()
        if _connection is None:
            with connect_postgres(self.dsn, row_factory=dict_row) as db:
                with db.transaction():
                    return self.apply(scope, coordinate, items,
                        operation_id=operation_id, command_digest=command_digest,
                        actor_id=actor_id,
                        expected_metadata_revision=expected_metadata_revision,
                        expected_cell_change_id=expected_cell_change_id,
                        expected_detail_change_id=expected_detail_change_id,
                        expected_data_revision=expected_data_revision,
                        _connection=db,_shared_revision=_shared_revision,
                        _write_control=_write_control,_ordinal=_ordinal,
                        _policy_evidence=_policy_evidence,
                        _point_fenced=True)
        db = _connection
        PostgresNumericFactStore._set_scope(db, scope)

        def prior_receipt():
            return (db.execute('''SELECT command_digest, committed_revision,
                result FROM epm.operation_receipt WHERE workspace_id=%s
                AND application_id=%s AND operation_id=%s''',
                (scope.workspace_id, scope.application_id,
                 operation_id)).fetchone() if _write_control else None)

        def replay(previous):
            if previous['command_digest'] != command_digest:
                raise ValueError('IDEMPOTENCY_KEY_REUSED')
            if previous['result'].get('payloadDigest') != payload_digest:
                raise ValueError('IDEMPOTENCY_PAYLOAD_CHANGED')
            return MutationReceipt(operation_id,previous['committed_revision'],
                                   previous['result']['changedCount'])

        def state(lock: bool):
            suffix = ' FOR UPDATE OF s' if lock else ''
            return db.execute('''SELECT a.status, s.processing_mode,
                s.metadata_revision, s.data_revision, s.commit_revision
                FROM epm.application_state s JOIN epm.application a
                USING (workspace_id, application_id)
                WHERE s.workspace_id=%s AND s.application_id=%s''' + suffix,
                (scope.workspace_id, scope.application_id)).fetchone()

        access=PostgresAccessChecker.check_in_transaction(
            db,self.identity,scope,'write')
        if _point_fenced:
            initial_state=state(False)
            previous=prior_receipt()
            if previous:
                return replay(previous)
            authorize_coordinate(
                db, self.identity, scope, coordinate, kind=AccessKind.WRITE)
            PostgresNumericFactStore._validate_state(
                initial_state,expected_metadata_revision,
                expected_data_revision)
            self._lock_point(db,scope,coordinate)
            prepared=self._current_inputs(db,scope,coordinate,False)
            self._validate_inputs(prepared,expected_cell_change_id,
                                  expected_detail_change_id)
            current_state=state(True)
            previous=prior_receipt()
            if previous:
                return replay(previous)
            PostgresNumericFactStore._validate_state(
                current_state,expected_metadata_revision,
                expected_data_revision)
            access=PostgresAccessChecker.check_in_transaction(
                db,self.identity,scope,'write')
            authorize_coordinate(
                db, self.identity, scope, coordinate, kind=AccessKind.WRITE)
            current=self._current_inputs(db,scope,coordinate,False)
            self._validate_inputs(current,expected_cell_change_id,
                                  expected_detail_change_id)
            if not self._same_inputs(prepared,current):
                raise ValueError('STALE_DETAIL_CHANGE_ID')
            coordinate_id,_,prior_cell,prior_detail=current
        else:
            # Worker/composite callers already own the application fence.  Do
            # not invert their application-before-effect lock order.
            current_state=state(True)
            previous=prior_receipt()
            if previous:
                return replay(previous)
            authorize_coordinate(
                db, self.identity, scope, coordinate, kind=AccessKind.WRITE)
            PostgresNumericFactStore._validate_state(
                current_state,expected_metadata_revision,
                expected_data_revision)
            current=self._current_inputs(db,scope,coordinate,True)
            self._validate_inputs(current,expected_cell_change_id,
                                  expected_detail_change_id)
            coordinate_id,_,prior_cell,prior_detail=current

        from .postgres_planning_write_guard import enforce_active_planning_policy
        policy_evidence=(_policy_evidence if _policy_evidence is not None
            else enforce_active_planning_policy(db,scope,
                writes=((coordinate,'ReplaceDetail'),),
                workflow_role=access.role))
        if coordinate_id is None:
            coordinate_id=PostgresNumericFactStore._coordinate_id(
                db,scope,coordinate)
        revision = (_shared_revision if _shared_revision is not None
                    else current_state['commit_revision'] + 1)
        change_id = f'{revision}:{_ordinal}'
        before = (prior_cell['amount'] if prior_cell and prior_cell['present']
                  else Decimal(0))
        with localcontext() as context:
            context.prec = 64
            delta = total - before
        if _write_control:
            db.execute('''UPDATE epm.application_state SET
                    data_revision=data_revision+1, commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (revision, scope.workspace_id, scope.application_id))
            db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id, application_id, operation_id, command_digest,
                     actor_id, committed_revision, result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id, scope.application_id, operation_id,
                     command_digest, actor_id, revision,
                     Jsonb({'changedCount': 1, 'payloadDigest': payload_digest,
                            'planningPolicy':policy_evidence})))
        db.execute('''INSERT INTO epm.numeric_fact_event
                    (workspace_id, application_id, coordinate_id, operation_id,
                     line_ordinal, kind, delta, present, resulting_amount,
                     change_id, committed_revision)
                    VALUES (%s,%s,%s,%s,%s,'set',%s,true,%s,%s,%s)''',
                    (scope.workspace_id, scope.application_id, coordinate_id,
                     operation_id,_ordinal,delta,total,change_id,revision))
        db.execute('''INSERT INTO epm.numeric_cell_projection
                    (workspace_id, application_id, coordinate_id, present,
                     amount, change_id, last_revision,projection_generation)
                    VALUES (%s,%s,%s,true,%s,%s,%s,(SELECT epm.active_projection_generation()))
                    ON CONFLICT (workspace_id, application_id,projection_generation, coordinate_id)
                    DO UPDATE SET present=true, amount=EXCLUDED.amount,
                      change_id=EXCLUDED.change_id,
                      last_revision=EXCLUDED.last_revision''',
                    (scope.workspace_id, scope.application_id,
                     coordinate_id, total, change_id, revision))
        db.execute('''INSERT INTO epm.line_detail_event
                    (workspace_id, application_id, coordinate_id, operation_id,
                     prior_items, prior_total, items, total, change_id,
                     committed_revision)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id, scope.application_id, coordinate_id,
                     operation_id,
                     Jsonb(prior_detail['items']) if prior_detail else None,
                     prior_detail['total'] if prior_detail else None,
                     Jsonb(encoded_items), total, change_id, revision))
        db.execute('''INSERT INTO epm.line_detail_projection
                    (workspace_id, application_id, coordinate_id, items,
                     total, change_id, last_revision,projection_generation)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,(SELECT epm.active_projection_generation()))
                    ON CONFLICT (workspace_id, application_id,projection_generation, coordinate_id)
                    DO UPDATE SET items=EXCLUDED.items, total=EXCLUDED.total,
                      change_id=EXCLUDED.change_id,
                      last_revision=EXCLUDED.last_revision''',
                    (scope.workspace_id, scope.application_id,
                     coordinate_id, Jsonb(encoded_items), total,
                     change_id, revision))
        return MutationReceipt(operation_id, revision, 1)

    @staticmethod
    def _lock_point(db,scope,coordinate) -> None:
        key='epm.pov.detail:' + json.dumps(
            [scope.workspace_id,scope.application_id,coordinate.series_key],
            separators=(',',':'),ensure_ascii=False)
        db.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',
                   (key,))

    @staticmethod
    def _current_inputs(db,scope,coordinate,lock: bool):
        from .postgres_fact_batch import validate_coordinates
        rows=[{'series_key':coordinate.series_key,
               'members':dict(coordinate.members)}]
        validate_coordinates(db,scope,rows)
        point=db.execute('''SELECT coordinate_id FROM epm.coordinate
            WHERE workspace_id=%s AND application_id=%s
            AND series_key=%s''',(scope.workspace_id,
            scope.application_id,coordinate.series_key)).fetchone()
        if point is None:
            return None,False,None,None
        coordinate_id=point['coordinate_id']
        text=db.execute('''SELECT present FROM epm.text_cell_current
            WHERE workspace_id=%s AND application_id=%s
            AND coordinate_id=%s''',(scope.workspace_id,
            scope.application_id,coordinate_id)).fetchone()
        suffix=' FOR UPDATE' if lock else ''
        cell=db.execute('''SELECT present, amount, change_id
            FROM epm.numeric_cell_current WHERE workspace_id=%s
            AND application_id=%s AND coordinate_id=%s''' + suffix,
            (scope.workspace_id,scope.application_id,
             coordinate_id)).fetchone()
        detail=db.execute('''SELECT items, total, change_id
            FROM epm.line_detail_current WHERE workspace_id=%s
            AND application_id=%s AND coordinate_id=%s''' + suffix,
            (scope.workspace_id,scope.application_id,
             coordinate_id)).fetchone()
        return coordinate_id,bool(text and text['present']),cell,detail

    @staticmethod
    def _validate_inputs(current,expected_cell_change_id,
                         expected_detail_change_id) -> None:
        _,text_present,cell,detail=current
        if text_present:
            raise ValueError('COORDINATE_HAS_TEXT_VALUE')
        if expected_cell_change_id != (cell['change_id'] if cell else ''):
            raise ValueError('STALE_CELL_CHANGE_ID')
        if expected_detail_change_id != (detail['change_id'] if detail else ''):
            raise ValueError('STALE_DETAIL_CHANGE_ID')

    @staticmethod
    def _same_inputs(left,right) -> bool:
        def cell_value(value):
            return (None if value is None else
                (value['present'],value['amount'],value['change_id']))
        def detail_value(value):
            return (None if value is None else
                (value['items'],value['total'],value['change_id']))
        return (left[1] == right[1]
                and cell_value(left[2]) == cell_value(right[2])
                and detail_value(left[3]) == detail_value(right[3]))
