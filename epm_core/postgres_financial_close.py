"""Durable structural financial-period close and explicit reopen lifecycle.

This lifecycle consumes an exact, balanced structural reconciliation.  It is
not an accounting-policy approval or whole-statement certification.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
import time
import uuid
from hashlib import sha256

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_planning_locks import PostgresPlanningLocks
from .postgres_statement_reconciliation import (
    FUNCTION as RECONCILIATION, PostgresStatementReconciliation,
    compile_program as compile_reconciliation)
from .postgres_statement_pack import (FUNCTION as STATEMENT_PACK,
    PostgresStatementPack)
from .consolidation_statement_pack import compile_pack
from .postgres_bound_statement_pack import (
    FUNCTION as BOUND_STATEMENT_PACK, PostgresBoundStatementPack,
    compile_request as compile_bound_statement_pack)


REQUEST = 'consolidation.period.close.request'
READ = 'consolidation.period.close.read'
REOPEN = 'consolidation.period.close.reopen'
FUNCTIONS = frozenset((REQUEST, READ, REOPEN))
_ID = re.compile(r'[0-9a-f]{32}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')


def _persisted_proof_kind(program):
    if isinstance(program,dict):
        if program.get('function')==BOUND_STATEMENT_PACK:
            return 'DefinitionBoundStatementPack'
        if program.get('function')==STATEMENT_PACK:
            return 'StatementPack'
    return 'Reconciliation'


def _reason(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 500 or '\x00' in value:
        raise ValueError('FINANCIAL_CLOSE_REASON_INVALID')
    return value


def compile_program(program):
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program.get('languageVersion')) is not int
            or program['languageVersion'] != 2
            or program.get('function') not in FUNCTIONS
            or not isinstance(program.get('arguments'), dict)):
        raise ValueError('FINANCIAL_CLOSE_PROGRAM_INVALID')
    function = program['function']; args = program['arguments']
    if function == REQUEST:
        legacy={'scopeMembers','reconciliationProgram','expectedReconciliationDigest','reason'}
        packed={'scopeMembers','statementPackProgram','expectedStatementPackDigest','reason'}
        if set(args) not in (legacy,packed):
            raise ValueError('FINANCIAL_CLOSE_ARGUMENTS_INVALID')
        members = args['scopeMembers']
        if (not isinstance(members, dict) or not 1 <= len(members) <= 8
                or any(not isinstance(axis, str) or not 1 <= len(axis) <= 200
                       or not isinstance(member, str) or not 1 <= len(member) <= 200
                       for axis, member in members.items())
                or not isinstance(args['expectedReconciliationDigest' if set(args)==legacy else 'expectedStatementPackDigest'], str)
                or not _DIGEST.fullmatch(args['expectedReconciliationDigest' if set(args)==legacy else 'expectedStatementPackDigest'])):
            raise ValueError('FINANCIAL_CLOSE_ARGUMENTS_INVALID')
        is_pack=set(args)==packed
        proof_program=args['statementPackProgram' if is_pack else 'reconciliationProgram']
        bound=(is_pack and isinstance(proof_program,dict) and
               proof_program.get('function')==BOUND_STATEMENT_PACK)
        reconciliation=(compile_bound_statement_pack(proof_program) if bound
          else compile_pack(proof_program,STATEMENT_PACK) if is_pack
          else compile_reconciliation(proof_program))
        source_members=([binding['source'].get('members')
                         for binding in reconciliation['bindings']]
                        if bound else [source['members']
                         for source in reconciliation['sources']]
                        if is_pack else [term['members']
                         for term in reconciliation['terms']])
        if any(any(point.get(axis) != member for axis,member in members.items())
               for point in source_members):
            raise ValueError('FINANCIAL_CLOSE_RECONCILIATION_SCOPE_MISMATCH')
        normalized={'function': function, 'scopeMembers': dict(sorted(members.items())),
                'reconciliationProgram': proof_program,
                'reconciliationPlanDigest': _canonical_digest(reconciliation),
                'expectedReconciliationDigest': args['expectedStatementPackDigest' if is_pack else 'expectedReconciliationDigest'],
                'reason': _reason(args['reason'])}
        if is_pack:
            normalized['proofKind']=('DefinitionBoundStatementPack'
                                      if bound else 'StatementPack')
        return normalized
    if function == READ:
        if (set(args) != {'closeId'} or not isinstance(args['closeId'], str)
                or not _ID.fullmatch(args['closeId'])):
            raise ValueError('FINANCIAL_CLOSE_ARGUMENTS_INVALID')
        return {'function': function, 'closeId': args['closeId']}
    if (set(args) != {'closeId', 'expectedVersion', 'reason'}
            or not isinstance(args['closeId'], str) or not _ID.fullmatch(args['closeId'])
            or type(args['expectedVersion']) is not int or args['expectedVersion'] != 1):
        raise ValueError('FINANCIAL_CLOSE_ARGUMENTS_INVALID')
    return {'function': function, 'closeId': args['closeId'],
            'expectedVersion': args['expectedVersion'], 'reason': _reason(args['reason'])}


def catalog():
    return {
        REQUEST: {'mode': 'reviewed_policy_write', 'permission': 'admin',
            'previewRequired': True, 'idempotencyRequired': True, 'workClass': 'short',
            'arguments': {'scopeMembers': 'explicit bounded period members including Scenario/Year/Period roles',
                'reconciliationProgram': 'exact legacy single-equation reconciliation program; mutually exclusive with statementPackProgram',
                'expectedReconciliationDigest': 'legacy exact current structural lineage digest',
                'statementPackProgram': 'ordinary caller-supplied or active-definition-bound 2-8 equation structural pack; mutually exclusive with reconciliationProgram',
                'expectedStatementPackDigest': 'pack exact current structural lineage digest',
                'reason': 'required audit reason'},
            'result': 'atomic period lock and immutable Unreviewed close receipt'},
        READ: {'mode': 'read', 'permission': 'read', 'previewRequired': False,
            'idempotencyRequired': False, 'workClass': 'short',
            'arguments': {'closeId': 'server-issued close identity'},
            'result': 'close status, scope, proof identity and immutable events'},
        REOPEN: {'mode': 'reviewed_policy_write', 'permission': 'admin',
            'previewRequired': True, 'idempotencyRequired': True, 'workClass': 'short',
            'arguments': {'closeId': 'server-issued close identity',
                'expectedVersion': 'exact Closed version 1', 'reason': 'required audit reason'},
            'result': 'versioned reopen event that releases the linked writer lock'}}


class PostgresFinancialClose:
    def __init__(self, dsn, *, identity, preview_secret):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        if not isinstance(preview_secret, bytes) or len(preview_secret) < 32:
            raise ValueError('A server-owned preview secret is required')
        self.dsn, self.identity, self.preview_secret = dsn, identity, preview_secret

    def _proof(self, scope, normalized):
        kind=normalized.get('proofKind')
        result=(PostgresBoundStatementPack(
            self.dsn,identity=self.identity).read(
                scope,normalized['reconciliationProgram'])
            if kind=='DefinitionBoundStatementPack' else
            PostgresStatementPack(self.dsn,identity=self.identity).read(
                scope,normalized['reconciliationProgram'])
            if kind=='StatementPack' else
            PostgresStatementReconciliation(self.dsn,identity=self.identity).read(
                scope,normalized['reconciliationProgram']))
        reconciled=(result['allReconciled'] if kind in (
                    'StatementPack','DefinitionBoundStatementPack')
                    else result['reconciled'] and
                    result['signedTotal']=='0.00000000')
        if not reconciled:
            raise ValueError('FINANCIAL_CLOSE_RECONCILIATION_UNBALANCED')
        if result['lineageDigest'] != normalized['expectedReconciliationDigest']:
            raise ValueError('FINANCIAL_CLOSE_RECONCILIATION_STALE')
        return result

    @staticmethod
    def _state(db, scope, lock=False):
        return db.execute('''SELECT a.status,s.processing_mode,s.metadata_revision,
            s.data_revision,s.policy_revision,s.commit_revision
            FROM epm.application_state s JOIN epm.application a
            USING(workspace_id,application_id) WHERE s.workspace_id=%s
            AND s.application_id=%s ''' + ('FOR UPDATE OF s' if lock else ''),
            (scope.workspace_id, scope.application_id)).fetchone()

    @staticmethod
    def _scope(db, scope, members):
        PostgresPlanningLocks._scope_members(db, scope, members)
        rows = db.execute('''SELECT d.model_role,input.dimension_id
            FROM jsonb_to_recordset(%s::jsonb) input(dimension_id text,member_id text)
            JOIN epm.dimension d ON d.workspace_id=%s AND d.application_id=%s
            AND d.dimension_id=input.dimension_id''',
            (Jsonb([{'dimension_id': a, 'member_id': m} for a,m in members.items()]),
             scope.workspace_id, scope.application_id)).fetchall()
        roles = {row['model_role'] for row in rows}
        if not {'Scenario','Year','Period'} <= roles:
            raise ValueError('FINANCIAL_CLOSE_PERIOD_SCOPE_REQUIRED')

    @staticmethod
    def _reject_overlap(db, scope, members):
        overlap = db.execute('''SELECT lock_id FROM epm.cube_write_scope_lock
            WHERE workspace_id=%s AND application_id=%s AND status='Locked'
            AND (scope_all OR scope_members @> %s::jsonb
                 OR %s::jsonb @> scope_members) LIMIT 1''',
            (scope.workspace_id,scope.application_id,
             Jsonb(members),Jsonb(members))).fetchone()
        if overlap:
            raise ValueError('PLANNING_SLICE_LOCKED')

    def _token(self, scope, normalized, revisions):
        payload = {'scope': [scope.workspace_id, scope.application_id],
            'identity': [self.identity.issuer, self.identity.subject_id],
            'digest': _canonical_digest(normalized), 'revisions': revisions,
            'expiresAt': int(time.time()) + 300}
        raw = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
        return base64.urlsafe_b64encode(
            raw + hmac.new(self.preview_secret, raw, sha256).digest()).decode()

    def _verify(self, token, scope, normalized, revisions):
        try:
            packed = base64.b64decode(token, altchars=b'-_', validate=True)
            raw, signature = packed[:-32], packed[-32:]
            if not hmac.compare_digest(signature, hmac.new(self.preview_secret, raw, sha256).digest()):
                raise ValueError('signature')
            payload = json.loads(raw)
        except (ValueError, TypeError, binascii.Error) as error:
            raise ValueError('FINANCIAL_CLOSE_PREVIEW_INVALID') from error
        if (payload.get('scope') != [scope.workspace_id, scope.application_id]
                or payload.get('identity') != [self.identity.issuer, self.identity.subject_id]
                or payload.get('digest') != _canonical_digest(normalized)
                or payload.get('revisions') != revisions
                or type(payload.get('expiresAt')) is not int
                or payload['expiresAt'] < time.time()):
            raise ValueError('FINANCIAL_CLOSE_PREVIEW_STALE')

    def preview(self, scope, program):
        normalized = compile_program(program)
        proof = self._proof(scope, normalized) if normalized['function'] == REQUEST else None
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin', function=normalized['function'])
                state = self._state(db, scope)
                if not state or state['status'] != 'Active' or state['processing_mode'] != 'Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if normalized['function'] == REQUEST:
                    self._scope(db, scope, normalized['scopeMembers'])
                    self._reject_overlap(db, scope, normalized['scopeMembers'])
                    target = {'scopeMembers': normalized['scopeMembers'],
                        'reconciliationDigest': proof['lineageDigest']}
                else:
                    row = db.execute('''SELECT close_id,status,version FROM epm.financial_period_close
                        WHERE workspace_id=%s AND application_id=%s AND close_id=%s''',
                        (scope.workspace_id,scope.application_id,normalized['closeId'])).fetchone()
                    if not row or row['status'] != 'Closed' or row['version'] != normalized['expectedVersion']:
                        raise ValueError('FINANCIAL_CLOSE_STALE')
                    target = dict(row)
                revisions = [state[k] for k in ('metadata_revision','data_revision','policy_revision','commit_revision')]
        return {'languageVersion': 2, 'function': normalized['function'], 'target': target,
            'accountingPolicyStatus': 'Unreviewed',
            'previewToken': self._token(scope, normalized, revisions)}

    def _identity(self, scope, normalized, idempotency_key):
        if not isinstance(idempotency_key, str) or not re.fullmatch(r'[A-Za-z0-9._-]{8,128}', idempotency_key):
            raise ValueError('FINANCIAL_CLOSE_IDEMPOTENCY_INVALID')
        digest = _canonical_digest({'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],
            'program':normalized,'idempotencyKey':idempotency_key})
        operation = 'financial-close-' + sha256(json.dumps({
            'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],
            'key':idempotency_key},sort_keys=True,separators=(',',':')).encode()).hexdigest()
        return digest, operation

    def apply(self, scope, program, *, preview_token, idempotency_key):
        normalized = compile_program(program)
        if normalized['function'] not in (REQUEST, REOPEN):
            raise ValueError('FINANCIAL_CLOSE_WRITE_FUNCTION_INVALID')
        digest, operation = self._identity(scope, normalized, idempotency_key)
        # Lost acknowledgements replay the immutable receipt before mutable
        # proof/pointer validation, but only after current authorization and
        # capability checks. Changed content under the same key still fails.
        with connect_postgres(self.dsn, row_factory=dict_row) as replay_db:
            with replay_db.transaction():
                PostgresNumericFactStore._set_scope(replay_db, scope)
                PostgresAccessChecker.check_in_transaction(
                    replay_db,self.identity,scope,'admin',
                    function=normalized['function'])
                prior = replay_db.execute('''SELECT command_digest,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id,scope.application_id,operation)).fetchone()
                if prior:
                    if prior['command_digest'] != digest:
                        raise ValueError('FINANCIAL_CLOSE_IDEMPOTENCY_CONFLICT')
                    return prior['result']
        proof = self._proof(scope, normalized) if normalized['function'] == REQUEST else None
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                state = self._state(db, scope, lock=True)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'admin',function=normalized['function'])
                prior = db.execute('''SELECT command_digest,result FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id,scope.application_id,operation)).fetchone()
                if prior:
                    if prior['command_digest'] != digest:
                        raise ValueError('FINANCIAL_CLOSE_IDEMPOTENCY_CONFLICT')
                    return prior['result']
                if not state or state['status'] != 'Active' or state['processing_mode'] != 'Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                revisions = [state[k] for k in ('metadata_revision','data_revision','policy_revision','commit_revision')]
                self._verify(preview_token, scope, normalized, revisions)
                revision = state['commit_revision'] + 1
                if normalized['function'] == REQUEST:
                    proof_kind=normalized.get('proofKind')
                    pins = (compile_bound_statement_pack(
                            normalized['reconciliationProgram'])['pins']
                            if proof_kind=='DefinitionBoundStatementPack' else
                            compile_pack(normalized['reconciliationProgram'],
                            STATEMENT_PACK)['pins'] if proof_kind=='StatementPack' else
                            compile_reconciliation(normalized[
                            'reconciliationProgram'])['pins'])
                    expected = [pins[k] for k in ('expectedMetadataRevision','expectedDataRevision',
                        'expectedPolicyRevision','expectedCommitRevision')]
                    if expected != revisions:
                        raise ValueError('FINANCIAL_CLOSE_RECONCILIATION_STALE')
                    self._scope(db, scope, normalized['scopeMembers'])
                    self._reject_overlap(db, scope, normalized['scopeMembers'])
                    active = db.execute('''SELECT 1 FROM epm.financial_period_close
                        WHERE workspace_id=%s AND application_id=%s AND status='Closed'
                        AND scope_members=%s LIMIT 1''',
                        (scope.workspace_id,scope.application_id,Jsonb(normalized['scopeMembers']))).fetchone()
                    if active: raise ValueError('FINANCIAL_PERIOD_ALREADY_CLOSED')
                    close_id, lock_id = uuid.uuid4().hex, uuid.uuid4().hex
                    db.execute('''INSERT INTO epm.cube_write_scope_lock
                        (workspace_id,application_id,lock_id,issuer,subject_id,idempotency_key,
                         request_digest,scope_members,scope_all,status,version,reason,locked_revision)
                        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,false,'Locked',1,%s,%s)''',
                        (scope.workspace_id,scope.application_id,lock_id,self.identity.issuer,
                         self.identity.subject_id,idempotency_key,digest,Jsonb(normalized['scopeMembers']),
                         normalized['reason'],revision))
                    db.execute('''INSERT INTO epm.cube_write_scope_lock_event
                        (workspace_id,application_id,lock_id,event_ordinal,kind,issuer,subject_id,reason,committed_revision)
                        VALUES(%s,%s,%s,1,'Locked',%s,%s,%s,%s)''',
                        (scope.workspace_id,scope.application_id,lock_id,self.identity.issuer,
                         self.identity.subject_id,normalized['reason'],revision))
                    db.execute('''INSERT INTO epm.financial_period_close
                        (workspace_id,application_id,close_id,lock_id,scope_members,
                         reconciliation_digest,reconciliation_lineage_digest,reconciliation_program,
                         status,version,close_issuer,close_subject_id,close_reason,closed_revision)
                        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'Closed',1,%s,%s,%s,%s)''',
                        (scope.workspace_id,scope.application_id,close_id,lock_id,
                         Jsonb(normalized['scopeMembers']),normalized['reconciliationPlanDigest'],
                         proof['lineageDigest'],Jsonb(normalized['reconciliationProgram']),
                         self.identity.issuer,self.identity.subject_id,normalized['reason'],revision))
                    kind, version = 'Closed', 1
                    result = {'closeId':close_id,'lockId':lock_id,'status':kind,'version':version,
                        'scopeMembers':normalized['scopeMembers'],'committedRevision':revision,
                        'reconciliationDigest':proof['lineageDigest'],
                        'accountingPolicyStatus':'Unreviewed','wholeStatementCertified':False,
                        'statementPackStructurallyReconciled':proof_kind in (
                            'StatementPack','DefinitionBoundStatementPack'),
                        'declaredCoverageComplete':proof_kind==
                            'DefinitionBoundStatementPack'}
                else:
                    close_id = normalized['closeId']
                    close = db.execute('''SELECT * FROM epm.financial_period_close
                        WHERE workspace_id=%s AND application_id=%s AND close_id=%s FOR UPDATE''',
                        (scope.workspace_id,scope.application_id,close_id)).fetchone()
                    if not close or close['status']!='Closed' or close['version']!=normalized['expectedVersion']:
                        raise ValueError('FINANCIAL_CLOSE_STALE')
                    lock = PostgresPlanningLocks._locked_row(db,scope,close['lock_id'])
                    if lock['status']!='Locked' or lock['version']!=1:
                        raise ValueError('FINANCIAL_CLOSE_LOCK_STALE')
                    db.execute('''UPDATE epm.cube_write_scope_lock SET status='Open',version=2,
                        reopened_revision=%s,updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s AND lock_id=%s''',
                        (revision,scope.workspace_id,scope.application_id,close['lock_id']))
                    db.execute('''INSERT INTO epm.cube_write_scope_lock_event
                        (workspace_id,application_id,lock_id,event_ordinal,kind,issuer,subject_id,reason,committed_revision)
                        VALUES(%s,%s,%s,2,'Reopened',%s,%s,%s,%s)''',
                        (scope.workspace_id,scope.application_id,close['lock_id'],self.identity.issuer,
                         self.identity.subject_id,normalized['reason'],revision))
                    db.execute('''UPDATE epm.financial_period_close SET status='Reopened',version=2,
                        reopen_issuer=%s,reopen_subject_id=%s,reopen_reason=%s,reopened_revision=%s,
                        updated_at=transaction_timestamp() WHERE workspace_id=%s AND application_id=%s AND close_id=%s''',
                        (self.identity.issuer,self.identity.subject_id,normalized['reason'],revision,
                         scope.workspace_id,scope.application_id,close_id))
                    kind, version, lock_id = 'Reopened', 2, close['lock_id']
                    result = {'closeId':close_id,'lockId':lock_id,'status':kind,'version':version,
                        'committedRevision':revision,'accountingPolicyStatus':'Unreviewed'}
                db.execute('''INSERT INTO epm.financial_period_close_event
                    (workspace_id,application_id,close_id,event_ordinal,kind,issuer,subject_id,reason,committed_revision)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id,scope.application_id,close_id,version,kind,
                     self.identity.issuer,self.identity.subject_id,normalized['reason'],revision))
                db.execute('''UPDATE epm.application_state SET commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (revision,scope.workspace_id,scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result)
                    VALUES(%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id,scope.application_id,operation,digest,
                     self.identity.subject_id,revision,Jsonb(result)))
                return result

    def read(self, scope, program):
        normalized = compile_program(program)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'read',function=READ)
                row=db.execute('''SELECT * FROM epm.financial_period_close
                    WHERE workspace_id=%s AND application_id=%s AND close_id=%s''',
                    (scope.workspace_id,scope.application_id,normalized['closeId'])).fetchone()
                if not row: raise ValueError('FINANCIAL_CLOSE_UNAVAILABLE')
                events=db.execute('''SELECT event_ordinal,kind,issuer,subject_id,reason,committed_revision
                    FROM epm.financial_period_close_event WHERE workspace_id=%s
                    AND application_id=%s AND close_id=%s ORDER BY event_ordinal''',
                    (scope.workspace_id,scope.application_id,normalized['closeId'])).fetchall()
        proof_kind=_persisted_proof_kind(row['reconciliation_program'])
        return {'closeId':row['close_id'],'lockId':row['lock_id'],'status':row['status'],
            'version':row['version'],'scopeMembers':row['scope_members'],
            'reconciliationDigest':row['reconciliation_lineage_digest'],
            'proofKind':proof_kind,
            'statementPackStructurallyReconciled':proof_kind in (
                'StatementPack','DefinitionBoundStatementPack'),
            'declaredCoverageComplete':proof_kind==
                'DefinitionBoundStatementPack',
            'closedRevision':row['closed_revision'],'reopenedRevision':row['reopened_revision'],
            'events':[dict(event) for event in events],
            'accountingPolicyStatus':'Unreviewed','wholeStatementCertified':False}
