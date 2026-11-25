"""Lease-fenced durable execution of an already prepared source batch.

The execution record is technical state.  Business effects remain owned by
``PostgresSourceBatch.publish`` and therefore retain its single transaction,
revision, receipt, exact-value and replacement semantics.
"""
from __future__ import annotations

import json
import logging
import os
import re
import traceback
import uuid
from hashlib import sha256

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import (AccessDenied,PostgresAccessChecker,
                              VerifiedIdentity,durable_authority_fields,
                              durable_execution_identity)
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout
from .postgres_source_batch import PostgresSourceBatch, source_publication_receipt_schema


REQUEST = 'facts.transfer.import.request'
READ = 'facts.transfer.import.read'
CANCEL = 'facts.transfer.import.cancel'
PUBLIC_FUNCTIONS = frozenset((REQUEST, READ, CANCEL))
_LOGGER = logging.getLogger(__name__)
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_ID = re.compile(r'[0-9a-f]{32}\Z')


def _digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False).encode()).hexdigest()


def _classify_worker_error(error: Exception) -> tuple[str, bool]:
    """Return one bounded public code and whether the error is terminal.

    Losing the final fence includes expiry of this worker's own lease.  It is
    control loss, not evidence that the import failed: the current generation
    may retry, or a successor may adopt the atomic source-batch receipt.
    """
    transient=isinstance(error,(psycopg.OperationalError,
        psycopg.InterfaceError,psycopg.errors.LockNotAvailable,
        psycopg.errors.SerializationFailure,psycopg.errors.DeadlockDetected))
    if transient:
        return 'IMPORT_EXECUTION_RETRYABLE_DATABASE',False
    if isinstance(error,ValueError) and str(error)==(
            'IMPORT_EXECUTION_FINAL_FENCE_FAILED'):
        return 'IMPORT_EXECUTION_RETRYABLE_CONTROL_LOSS',False
    if isinstance(error,AccessDenied):
        return 'IMPORT_EXECUTION_AUTHORIZATION_REVOKED',True
    if (isinstance(error, ValueError)
            and re.fullmatch(
                r'PLANNING_WRITE_DENIED:[0-9]+:[A-Z][A-Z0-9_]{2,127}',
                str(error))):
        # The coordinate ordinal and policy reason remain private evaluation
        # detail. This is a deterministic current-policy rejection, never an
        # uncertain publication outcome and therefore never retryable.
        return 'PLANNING_WRITE_DENIED', True
    if (isinstance(error,ValueError)
            and re.fullmatch(r'[A-Z][A-Z0-9_]{2,127}',str(error))):
        return str(error),True
    return 'IMPORT_PUBLICATION_OUTCOME_UNKNOWN',False


def _exception_location(error: Exception) -> str:
    """Return a value-free source location for private diagnostics."""
    frames = traceback.extract_tb(error.__traceback__)
    if not frames:
        return 'unavailable'
    frame = frames[-1]
    return f'{os.path.basename(frame.filename)}:{frame.lineno}:{frame.name}'


def import_program_contract(function: str) -> dict | None:
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj

    identifier = {'type': 'string', 'pattern': '^' + _ID.pattern.removesuffix(r'\Z') + r'(?![\s\S])'}
    count = {'type': 'integer', 'minimum': 0, 'maximum': 2**63 - 1}
    receipt = {'oneOf': [source_publication_receipt_schema(), {'type': 'null'}],
               'description': 'Original publication receipt owned by the source batch publisher.'}
    operation = {'type': 'string', 'pattern': '^' + _KEY.pattern.removesuffix(r'\Z') + r'(?![\s\S])'}
    status = {
        'requestId': identifier,
        'batchId': identifier,
        'status': {'enum': ['Accepted', 'Claimed', 'Publishing', 'Completed', 'Failed', 'Cancelled']},
        'claimGeneration': count,
        'cancelRequested': {'type': 'boolean'},
        'result': receipt,
        'errorCode': {'type': ['string', 'null'], 'maxLength': 200,
                      'description': 'A retained failure code. With Accepted, a worker retry is pending.'},
    }
    rules = ['The core checks current application WRITE and the original calling identity.',
             'Accepted, Claimed and Publishing are unfinished. Completed carries the original publication receipt.',
             'Accepted with an errorCode means the worker will retry the same request. Read its current status.',
             'Failed and Cancelled are terminal. A true cancelRequested flag records intent; use status for the outcome.',
             'The source batch publisher owns the details of the retained receipt.']
    recovery = ('Keep the same identity. A missing status may permit an explicit retry of the '
                'exact original request under its original admission rules.')
    if function == REQUEST:
        arguments = obj({'idempotencyKey': operation, 'batchId': identifier,
                         'previewToken': {'type': 'string', 'minLength': 1, 'maxLength': 16384}})
        status['duplicate'] = {'type': 'boolean'}
        examples = [read_example(function, {
            'idempotencyKey': 'original-import-operation', 'batchId': 'a' * 32,
            'previewToken': 'example-confirmed-import-preview'},
            name='Submit the reviewed source batch',
            binding='Use the ready batch ID and exact token from facts.source.preview. Use a fresh key for each new intent.')]
        rules.append('An authorized exact replay returns the existing request with duplicate=true. A changed batch or token under the same key conflicts.')
        recovery = ('If acknowledgement is lost, read by original operationId before retrying. '
                    'Use the original MCP key or the server-issued Browser admission ID and the same identity.')
    elif function == READ:
        arguments = obj({'requestId': identifier, 'operationId': operation}, [])
        arguments['oneOf'] = [{'required': [key]} for key in arguments['properties']]
        examples = [read_example(function, {'requestId': 'a' * 32},
            name='Read the status of an accepted import',
            binding='Use the requestId returned by facts.transfer.import.request in this application.'),
        read_example(function, {'operationId': 'original-import-operation'},
            name='Inspect an import after losing the original acknowledgement',
            binding='Use the server-issued Browser admission ID or the original MCP idempotencyKey in the same application.'),
        ]
        rules.insert(1, 'Supply exactly one selector. The original operation remains readable after admission expiry. An unavailable result leaves the outcome unconfirmed.')
    elif function == CANCEL:
        arguments = obj({'requestId': identifier})
        examples = [read_example(function, {'requestId': 'a' * 32},
            name='Request cancellation of an import',
            binding='Use the owned requestId returned by facts.transfer.import.request.')]
        rules.append('Cancellation stops accepted work or records intent for claimed work. An already published import retains its original receipt.')
        recovery = 'Read the original request under the same identity to confirm the outcome of an uncertain cancellation.'
    else:
        return None
    contract = read_contract(function, arguments, obj(status), owner='PostgresImportExecution',
        examples=examples, semantic_rules=rules)
    contract['programContract']['recovery'] = recovery
    return contract


def catalog() -> dict:
    return {
        REQUEST: {
            'mode': 'durable_write', 'permission': 'write',
            'arguments': {'idempotencyKey': '8–128 safe characters',
                          'batchId': 'owned ready source batch',
                          'previewToken': 'signed exact publication preview'},
            'result': 'durable accepted import execution identity',
            'previewRequired': True, 'idempotencyRequired': True,
            'workClass': 'short', **import_program_contract(REQUEST)},
        READ: {
            'mode': 'read', 'permission': 'write',
            'arguments': {'requestId': 'owned execution identity, exclusive with operationId',
                          'operationId': 'original operation identity, exclusive with requestId'},
            'result': 'actual execution, lease and receipt status',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short', **import_program_contract(READ)},
        CANCEL: {
            'mode': 'technical_cancel', 'permission': 'write',
            'arguments': {'requestId': 'owned import execution identity'},
            'result': 'actual status after cancellation request',
            'previewRequired': False, 'idempotencyRequired': True,
            'workClass': 'short', **import_program_contract(CANCEL)},
    }


def _wire(row: dict, *, duplicate: bool | None = None) -> dict:
    result = {'requestId': row['request_id'], 'batchId': row['batch_id'],
              'status': row['status'],
              'claimGeneration': row['claim_generation'],
              'cancelRequested': row['cancel_requested'],
              'result': row['result'], 'errorCode': row['error_code']}
    if duplicate is not None:
        result['duplicate'] = duplicate
    return result


class PostgresImportExecution:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('IMPORT_EXECUTION_IDENTITY_INVALID')
        self.dsn, self.identity = dsn, identity

    def _connection(self, scope: ApplicationScope, *, read_only=False):
        db = connect_postgres(self.dsn, row_factory=dict_row)
        if read_only:
            db.execute('SET TRANSACTION READ ONLY')
        PostgresNumericFactStore._set_scope(db, scope)
        return db

    def request(self, scope: ApplicationScope, *, idempotency_key: str,
                batch_id: str, preview_token: str) -> dict:
        return self._request(scope, idempotency_key=idempotency_key,
            batch_id=batch_id, preview_token=preview_token, replay_only=False)

    def replay(self, scope: ApplicationScope, *, idempotency_key: str,
               batch_id: str, preview_token: str) -> dict | None:
        """Read the original exact request under current write authority only."""
        return self._request(scope, idempotency_key=idempotency_key,
            batch_id=batch_id, preview_token=preview_token, replay_only=True)

    def _request(self, scope: ApplicationScope, *, idempotency_key: str,
                 batch_id: str, preview_token: str, replay_only: bool) -> dict | None:
        if (not isinstance(idempotency_key, str)
                or not _KEY.fullmatch(idempotency_key)
                or not isinstance(batch_id, str) or not _ID.fullmatch(batch_id)
                or not isinstance(preview_token, str)
                or not 1 <= len(preview_token) <= 16384):
            raise ValueError('IMPORT_EXECUTION_REQUEST_INVALID')
        digest = _digest({'scope': [scope.workspace_id, scope.application_id],
                          'actor': [self.identity.issuer,
                                    self.identity.subject_id],
                          'batchId': batch_id, 'previewToken': preview_token})
        with self._connection(scope, read_only=replay_only) as db, db.transaction():
            configure_statement_timeout(db, 5000)
            access=PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, 'write')
            authorization_scope_digest=resolve_effective_dimensional_scope(
                db,self.identity,scope,access=access,
                function=REQUEST).scope_digest
            db.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',
                       ('|'.join((scope.workspace_id, scope.application_id,
                                  self.identity.issuer,
                                  self.identity.subject_id,
                                  idempotency_key)),))
            prior = db.execute('''SELECT * FROM epm.source_import_execution
                WHERE workspace_id=%s AND application_id=%s AND issuer=%s
                AND subject_id=%s AND idempotency_key=%s''',
                (scope.workspace_id, scope.application_id,
                 self.identity.issuer, self.identity.subject_id,
                 idempotency_key)).fetchone()
            if prior is not None:
                if prior['request_digest'] != digest:
                    raise ValueError('IMPORT_EXECUTION_REQUEST_CONFLICT')
                return _wire(prior, duplicate=True)
            if replay_only:
                return None
            batch = db.execute('''SELECT status,row_count FROM epm.source_batch
                WHERE workspace_id=%s AND application_id=%s AND batch_id=%s
                AND issuer=%s AND subject_id=%s''',
                (scope.workspace_id, scope.application_id, batch_id,
                 self.identity.issuer,
                 self.identity.subject_id)).fetchone()
            # A new execution may only bind an unconsumed preview. Recovery of
            # an acknowledged execution uses its existing execution record;
            # it must not mint a second certificate around a published batch.
            if batch is None or batch['status'] != 'ready':
                raise ValueError('IMPORT_EXECUTION_BATCH_NOT_READY')
            if batch['row_count'] > 100000:
                raise ValueError('SOURCE_PUBLICATION_ROW_LIMIT')
            token_issued_at,authority_kind=durable_authority_fields(self.identity)
            row = db.execute('''INSERT INTO epm.source_import_execution
                (workspace_id,application_id,request_id,batch_id,issuer,
                 subject_id,idempotency_key,request_digest,preview_token,
                 verified_groups,authorization_scope_digest,token_issued_at,
                 authority_kind,status)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'Accepted') RETURNING *''',
                (scope.workspace_id, scope.application_id, uuid.uuid4().hex,
                 batch_id, self.identity.issuer, self.identity.subject_id,
                 idempotency_key, digest, preview_token,list(access.groups),
                 authorization_scope_digest,token_issued_at,
                 authority_kind)).fetchone()
            return _wire(row, duplicate=False)

    def read(self, scope: ApplicationScope, request_id: str | None = None, *,
             operation_id: str | None = None) -> dict:
        if (request_id is None) == (operation_id is None):
            raise ValueError('IMPORT_EXECUTION_ARGUMENTS_INVALID')
        if operation_id is not None:
            if not isinstance(operation_id, str) or not _KEY.fullmatch(operation_id):
                raise ValueError('IMPORT_EXECUTION_OPERATION_ID_INVALID')
            column, value = 'idempotency_key', operation_id
        else:
            if not isinstance(request_id, str) or not _ID.fullmatch(request_id):
                raise ValueError('IMPORT_EXECUTION_REQUEST_ID_INVALID')
            column, value = 'request_id', request_id
        with self._connection(scope, read_only=True) as db, db.transaction():
            configure_statement_timeout(db, 5000)
            PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, 'write')
            row = db.execute(f'''SELECT * FROM epm.source_import_execution
                WHERE workspace_id=%s AND application_id=%s AND {column}=%s
                AND issuer=%s AND subject_id=%s''',
                (scope.workspace_id, scope.application_id, value,
                 self.identity.issuer, self.identity.subject_id)).fetchone()
            if row is None:
                raise ValueError('IMPORT_EXECUTION_UNAVAILABLE')
            return _wire(row)

    def cancel(self, scope: ApplicationScope, request_id: str) -> dict:
        return self.request_cancel_as_task_controller(
            scope, request_id, allow_application_admin=False)

    def request_cancel_as_task_controller(self, scope: ApplicationScope,
                                          request_id: str, *,
                                          allow_application_admin=False
                                          ) -> dict:
        """Cancel through the native import lifecycle and current authority."""
        if type(allow_application_admin) is not bool:
            raise ValueError('IMPORT_EXECUTION_UNAVAILABLE')
        with self._connection(scope) as db, db.transaction():
            configure_statement_timeout(db, 5000)
            configure_lock_wait(db)
            PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, 'write')
            if not isinstance(request_id, str) or not _ID.fullmatch(request_id):
                raise ValueError('IMPORT_EXECUTION_REQUEST_ID_INVALID')
            row = db.execute('''SELECT * FROM epm.source_import_execution
                WHERE workspace_id=%s AND application_id=%s AND request_id=%s
                FOR UPDATE''', (scope.workspace_id, scope.application_id,
                                request_id)).fetchone()
            owner = (row is not None and
                (row['issuer'], row['subject_id']) ==
                (self.identity.issuer, self.identity.subject_id))
            administrator = False
            if row is not None and not owner and allow_application_admin:
                try:
                    PostgresAccessChecker.check_in_transaction(
                        db, self.identity, scope, 'admin')
                    administrator = True
                except AccessDenied:
                    pass
            if row is None or not (owner or administrator):
                raise ValueError('IMPORT_EXECUTION_UNAVAILABLE')
            if row['status'] == 'Accepted':
                row = db.execute('''UPDATE epm.source_import_execution SET
                    status='Cancelled',cancel_requested=true,
                    updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                    AND request_id=%s RETURNING *''',
                    (scope.workspace_id, scope.application_id,
                     request_id)).fetchone()
            elif row['status'] == 'Claimed':
                row = db.execute('''UPDATE epm.source_import_execution SET
                    cancel_requested=true,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                    AND request_id=%s RETURNING *''',
                    (scope.workspace_id, scope.application_id,
                     request_id)).fetchone()
            return _wire(row)


class PostgresImportExecutionWorker:
    """Private adapter. A scheduler supplies one request, never caller SQL."""
    def __init__(self, dsn: str, *, worker_id: str, preview_secret: bytes,
                 runtime_dsn: str | None = None):
        if (not isinstance(worker_id, str) or not 1 <= len(worker_id) <= 200
                or not isinstance(preview_secret, bytes)
                or len(preview_secret) < 32):
            raise ValueError('IMPORT_EXECUTION_WORKER_INVALID')
        self.dsn, self.runtime_dsn, self.worker_id = dsn, runtime_dsn or dsn, worker_id
        self.preview_secret = preview_secret

    def claim_next(self, *, lease_seconds=120, capacity_limits=(16,4,1)):
        if (type(lease_seconds) is not int or not 10<=lease_seconds<=600
                or type(capacity_limits) is not tuple or len(capacity_limits)!=3
                or any(type(value) is not int or not 1<=value<=10000
                       for value in capacity_limits)
                or not capacity_limits[0]>=capacity_limits[1]>=capacity_limits[2]):
            raise ValueError('IMPORT_EXECUTION_CLAIM_INVALID')
        with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
            configure_statement_timeout(db,5000);configure_lock_wait(db)
            row=db.execute('''SELECT * FROM epm.source_import_execution_worker_claim(
                %s,%s::integer,%s::integer,%s::integer,%s::integer)''',
                (self.worker_id,lease_seconds,
                *capacity_limits)).fetchone()
            return None if row is None else dict(row)

    def _claim(self, scope, request_id, lease_seconds):
        if (not isinstance(request_id, str) or not _ID.fullmatch(request_id)
                or type(lease_seconds) is not int
                or not 10 <= lease_seconds <= 600):
            raise ValueError('IMPORT_EXECUTION_CLAIM_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db, db.transaction():
            configure_statement_timeout(db,5000);configure_lock_wait(db)
            PostgresNumericFactStore._set_scope(db, scope)
            row = db.execute('''SELECT * FROM epm.source_import_execution
                WHERE workspace_id=%s AND application_id=%s AND request_id=%s
                FOR UPDATE''', (scope.workspace_id, scope.application_id,
                                request_id)).fetchone()
            if row is None:
                raise ValueError('IMPORT_EXECUTION_UNAVAILABLE')
            if row['status'] in ('Completed', 'Failed', 'Cancelled'):
                return row
            current=db.execute('SELECT clock_timestamp() AS now').fetchone()['now']
            if (row['status'] in ('Claimed', 'Publishing') and
                    row['lease_until'] >= current):
                raise ValueError('IMPORT_EXECUTION_ALREADY_CLAIMED')
            if row['status'] in ('Claimed', 'Publishing'):
                db.execute('''SELECT epm.source_import_execution_worker_settle_failure(
                    %s,%s,%s,%s,%s,%s,false)''',(scope.workspace_id,
                    scope.application_id,request_id,row['claim_generation'],
                    row['claimant'],'IMPORT_EXECUTION_RETRYABLE_CONTROL_LOSS'))
                return db.execute('''SELECT * FROM epm.source_import_execution
                    WHERE workspace_id=%s AND application_id=%s
                    AND request_id=%s''',(scope.workspace_id,
                    scope.application_id,request_id)).fetchone()
            if (row.get('next_attempt_at') is not None
                    and row['next_attempt_at'] > current):
                return row
            return db.execute('''UPDATE epm.source_import_execution SET
                status='Claimed',claim_generation=claim_generation+1,
                claimant=%s,lease_until=clock_timestamp()+make_interval(secs=>%s),
                error_code=NULL,updated_at=transaction_timestamp()
                WHERE workspace_id=%s AND application_id=%s
                AND request_id=%s RETURNING *''',
                (self.worker_id, lease_seconds, scope.workspace_id,
                 scope.application_id, request_id)).fetchone()

    def process(self, scope: ApplicationScope, request_id: str, *,
                lease_seconds: int = 120) -> dict:
        claim = self._claim(scope, request_id, lease_seconds)
        if claim['status'] != 'Claimed':
            return _wire(claim)
        return self._process_claim(scope,request_id,claim)

    def run_claim(self,claim:dict)->dict:
        required={'workspace_id','application_id','request_id','claim_generation'}
        if (not isinstance(claim,dict) or not required<=set(claim)
                or type(claim['claim_generation']) is not int):
            raise ValueError('IMPORT_EXECUTION_CLAIM_INVALID')
        scope=ApplicationScope(claim['workspace_id'],claim['application_id'])
        with connect_postgres(self.runtime_dsn,row_factory=dict_row) as db,db.transaction():
            configure_statement_timeout(db,5000);configure_lock_wait(db)
            PostgresNumericFactStore._set_scope(db,scope)
            row=db.execute('''SELECT * FROM epm.source_import_execution
                WHERE workspace_id=%s AND application_id=%s AND request_id=%s
                AND status='Claimed' AND claim_generation=%s AND claimant=%s''',(
                scope.workspace_id,scope.application_id,claim['request_id'],
                claim['claim_generation'],self.worker_id)).fetchone()
        if row is None:raise ValueError('IMPORT_EXECUTION_STALE_CLAIM')
        return self._process_claim(scope,claim['request_id'],row)

    def _process_claim(self,scope,request_id,claim):
        if claim['status'] in ('Completed', 'Failed', 'Cancelled'):
            return _wire(claim)
        generation = claim['claim_generation']
        identity = durable_execution_identity(claim)

        def authorization_fence(db, checked_scope):
            access=PostgresAccessChecker.check_in_transaction(
                db,identity,checked_scope,'write')
            current=resolve_effective_dimensional_scope(
                db,identity,checked_scope,access=access,
                function=REQUEST).scope_digest
            if (claim['authorization_scope_digest'] is None
                    or claim['authorization_scope_digest']!=current):
                raise AccessDenied('IMPORT_EXECUTION_AUTHORIZATION_REVOKED')
            return current

        def final_fence(db, checked_scope):
            authorization_fence(db,checked_scope)
            row = db.execute('''SELECT * FROM epm.source_import_execution
                WHERE workspace_id=%s AND application_id=%s AND request_id=%s
                FOR UPDATE''', (checked_scope.workspace_id,
                                checked_scope.application_id,
                                request_id)).fetchone()
            # Source publication deliberately calls its authorizer once
            # before preparation and again under the final application
            # fence.  The first successful call advances this exact claim to
            # Publishing; the second must be an idempotent recheck of the
            # same generation, claimant, cancellation flag and live lease.
            if (row is None or row['status'] not in ('Claimed', 'Publishing')
                    or row['claim_generation'] != generation
                    or row['claimant'] != self.worker_id
                    or row['cancel_requested']
                    or row['lease_until'] < db.execute(
                        'SELECT clock_timestamp() AS now').fetchone()['now']):
                raise ValueError('IMPORT_EXECUTION_FINAL_FENCE_FAILED')
            db.execute('''UPDATE epm.source_import_execution SET
                status='Publishing',updated_at=transaction_timestamp()
                WHERE workspace_id=%s AND application_id=%s
                AND request_id=%s AND status='Claimed' ''', (
                                      checked_scope.workspace_id,
                                      checked_scope.application_id,
                                      request_id))
            return True

        source = PostgresSourceBatch(
            self.runtime_dsn, identity=identity, preview_secret=self.preview_secret,
            publication_authorizer=final_fence)
        try:
            result = source.publish(scope, claim['batch_id'],
                                    preview_token=claim['preview_token'])
        except Exception as error:
            # Never expose payloads, credentials or arbitrary driver text in
            # the durable/public error.  The server log still needs enough
            # bounded structure to distinguish a deterministic application
            # error from an uncertain transport/database outcome.
            _LOGGER.warning(
                'Import publication attempt failed request=%s generation=%s '
                'exception=%s sqlstate=%s location=%s', request_id,
                generation, type(error).__name__,
                getattr(error, 'sqlstate', None), _exception_location(error))
            with connect_postgres(self.runtime_dsn, row_factory=dict_row) as db, db.transaction():
                configure_statement_timeout(db,5000);configure_lock_wait(db)
                PostgresNumericFactStore._set_scope(db, scope)
                published=db.execute('''SELECT status,result FROM epm.source_batch
                    WHERE workspace_id=%s AND application_id=%s AND batch_id=%s
                    AND issuer=%s AND subject_id=%s''',(scope.workspace_id,
                    scope.application_id,claim['batch_id'],claim['issuer'],
                    claim['subject_id'])).fetchone()
                if (published is not None and published['status']=='published'
                        and isinstance(published['result'],dict)):
                    row=db.execute('''UPDATE epm.source_import_execution SET
                        status='Completed',result=%s,error_code=NULL,claimant=NULL,
                        lease_until=NULL,updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s AND request_id=%s
                        AND claim_generation=%s AND claimant=%s
                        AND status IN ('Claimed','Publishing') RETURNING *''',(
                        Jsonb(published['result']),scope.workspace_id,
                        scope.application_id,request_id,generation,
                        self.worker_id)).fetchone()
                    if row is not None:return _wire(row)
            # Source receipts remain runtime-owned. Only the technical failure
            # transition uses the worker credential authorized by migration 0272;
            # the original generation/claimant fence rejects a successor's claim.
            code,terminal=_classify_worker_error(error)
            with connect_postgres(self.dsn, row_factory=dict_row) as db, db.transaction():
                configure_statement_timeout(db,5000);configure_lock_wait(db)
                PostgresNumericFactStore._set_scope(db, scope)
                outcome=db.execute('''SELECT
                    epm.source_import_execution_worker_settle_failure(
                      %s,%s,%s,%s,%s,%s,%s) AS outcome''',(
                    scope.workspace_id,scope.application_id,request_id,
                    generation,self.worker_id,code,terminal)).fetchone()
                row = None if outcome is None or outcome['outcome'] is None else db.execute(
                    '''SELECT * FROM epm.source_import_execution
                    WHERE workspace_id=%s AND application_id=%s
                    AND request_id=%s''',(scope.workspace_id,
                    scope.application_id,request_id)).fetchone()
            if row is None:raise ValueError('IMPORT_EXECUTION_STALE_CLAIM')
            return _wire(row)
        with connect_postgres(self.runtime_dsn, row_factory=dict_row) as db, db.transaction():
            configure_statement_timeout(db,5000);configure_lock_wait(db)
            PostgresNumericFactStore._set_scope(db, scope)
            row = db.execute('''UPDATE epm.source_import_execution SET
                status='Completed',result=%s,error_code=NULL,claimant=NULL,
                lease_until=NULL,updated_at=transaction_timestamp()
                WHERE workspace_id=%s AND application_id=%s
                AND request_id=%s AND claim_generation=%s
                AND claimant=%s AND status IN ('Claimed','Publishing')
                RETURNING *''',
                (Jsonb(result), scope.workspace_id, scope.application_id,
                 request_id, generation, self.worker_id)).fetchone()
            if row is None:
                raise ValueError('IMPORT_EXECUTION_COMPLETION_FENCED')
            return _wire(row)


class PostgresImportExecutionPublic:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        self.repository = PostgresImportExecution(dsn, identity=identity)

    def execute(self, scope: ApplicationScope, program: object) -> dict:
        if (not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or program.get('languageVersion') != 2
                or program.get('function') not in PUBLIC_FUNCTIONS
                or not isinstance(program.get('arguments'), dict)):
            raise ValueError('IMPORT_EXECUTION_PROGRAM_INVALID')
        function, args = program['function'], program['arguments']
        if function == REQUEST:
            if set(args) != {'idempotencyKey', 'batchId', 'previewToken'}:
                raise ValueError('IMPORT_EXECUTION_ARGUMENTS_INVALID')
            return self.repository.request(
                scope, idempotency_key=args['idempotencyKey'],
                batch_id=args['batchId'], preview_token=args['previewToken'])
        if function == READ and set(args) == {'operationId'}:
            return self.repository.read(scope, operation_id=args['operationId'])
        if set(args) != {'requestId'}:
            raise ValueError('IMPORT_EXECUTION_ARGUMENTS_INVALID')
        if function == READ:
            return self.repository.read(scope, args['requestId'])
        return self.repository.cancel(scope, args['requestId'])
