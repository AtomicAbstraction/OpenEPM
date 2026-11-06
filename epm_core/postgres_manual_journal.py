"""Fixed V2 manual journal layer with exact balancing and linked reversal.

This is a distinct adjustment layer. It does not overwrite input facts or
claim that an IFRS/US GAAP consolidation policy has been executed.
"""
from __future__ import annotations

from decimal import Decimal, localcontext
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate, NumericCell
from .dimensional_security_policy import AccessKind
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_fact_batch import validate_coordinates
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_planning_write_guard import enforce_active_planning_policy


POST_FUNCTION = 'consolidation.journal.post'
REVERSE_FUNCTION = 'consolidation.journal.reverse'
READ_FUNCTION = 'consolidation.journal.read'
BALANCE_READ_FUNCTION = 'consolidation.journal.balance.read'
ADJUSTED_READ_FUNCTION = 'facts.numeric.adjusted.read'
_ID = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_DISJOINT_POST_ADMISSION = object()


def valid_idempotency_key(value: object) -> bool:
    """Shared operation identity wire contract used by journal composites."""
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _reason(value: object) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 500
            or value != value.strip()):
        raise ValueError('JOURNAL_REASON_INVALID')
    return value


def compile_journal_program(program: object) -> tuple[str, dict]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] not in (POST_FUNCTION, REVERSE_FUNCTION,
                                           READ_FUNCTION,
                                           BALANCE_READ_FUNCTION,
                                           ADJUSTED_READ_FUNCTION)
            or not isinstance(program['arguments'], dict)):
        raise ValueError('V2_JOURNAL_FUNCTION_INVALID')
    name, args = program['function'], program['arguments']
    if name == READ_FUNCTION:
        if (set(args) != {'journalId'} or not isinstance(args['journalId'], str)
                or not _ID.fullmatch(args['journalId'])):
            raise ValueError('V2_JOURNAL_ARGUMENTS_INVALID')
        return name, {'journalId': args['journalId']}
    if name in (BALANCE_READ_FUNCTION, ADJUSTED_READ_FUNCTION):
        if (set(args) - {'members', 'snapshotRevision'}
                or 'members' not in args
                or not isinstance(args['members'], dict)
                or len(args['members']) > 32):
            raise ValueError('V2_JOURNAL_ARGUMENTS_INVALID')
        coordinate = Coordinate.from_mapping(args['members'])
        revision = args.get('snapshotRevision')
        if (revision is not None and
                (type(revision) is not int or revision < 0)):
            raise ValueError('SNAPSHOT_REVISION_INVALID')
        return name, {'coordinate': coordinate,
                      'snapshotRevision': revision}
    common = {'reason', 'expectedMetadataRevision',
              'expectedPolicyRevision', 'expectedDataRevision'}
    expected = common | ({'lines'} if name == POST_FUNCTION else {'journalId'})
    if set(args) != expected:
        raise ValueError('V2_JOURNAL_ARGUMENTS_INVALID')
    reason = _reason(args['reason'])
    revisions = {key: args[key] for key in common if key != 'reason'}
    if any(type(value) is not int or value < 0
           for value in revisions.values()):
        raise ValueError('V2_JOURNAL_ARGUMENTS_INVALID')
    if name == REVERSE_FUNCTION:
        if (not isinstance(args['journalId'], str)
                or not _ID.fullmatch(args['journalId'])):
            raise ValueError('V2_JOURNAL_ARGUMENTS_INVALID')
        return name, {'reason': reason, 'journalId': args['journalId'],
                      **revisions}
    raw_lines = args['lines']
    if not isinstance(raw_lines, list) or not 2 <= len(raw_lines) <= 100:
        raise ValueError('JOURNAL_LINE_BOUNDS')
    lines = []
    for raw in raw_lines:
        if (not isinstance(raw, dict)
                or set(raw) != {'members', 'amount', 'sourceRef'}
                or not isinstance(raw['sourceRef'], str)
                or not 1 <= len(raw['sourceRef']) <= 200
                or not isinstance(raw['amount'], dict)
                or set(raw['amount']) != {'type', 'decimal'}
                or raw['amount']['type'] != 'AmountLiteral'):
            raise ValueError('JOURNAL_LINE_INVALID')
        coordinate = Coordinate.from_mapping(raw['members'])
        amount = NumericCell.from_wire(
            present=True, amount=raw['amount']['decimal']).amount
        if amount == 0:
            raise ValueError('JOURNAL_ZERO_LINE')
        lines.append((coordinate, amount, raw['sourceRef']))
    if len({line[0] for line in lines}) != len(lines):
        raise ValueError('JOURNAL_DUPLICATE_COORDINATE')
    with localcontext() as context:
        context.prec = 64
        if sum((line[1] for line in lines), Decimal(0)) != 0:
            raise ValueError('JOURNAL_NOT_BALANCED')
    return name, {'reason': reason, 'lines': lines, **revisions}


def _manual_reversal_candidate(db,scope,args,*,workflow_role,identity):
    keys=(scope.workspace_id,scope.application_id)
    original=db.execute('''SELECT journal_id,reversal_of,issuer,subject_id,
        reason,metadata_revision,policy_revision,committed_revision
        FROM epm.manual_journal WHERE workspace_id=%s AND application_id=%s
        AND journal_id=%s''',
        (*keys,args['journalId'])).fetchone()
    if original is None:raise ValueError('JOURNAL_UNAVAILABLE')
    if original['reversal_of'] is not None:
        raise ValueError('JOURNAL_REVERSAL_CANNOT_REVERSE')
    if db.execute('''SELECT 1 FROM epm.manual_journal
        WHERE workspace_id=%s AND application_id=%s AND reversal_of=%s''',
        (*keys,args['journalId'])).fetchone():
        raise ValueError('JOURNAL_ALREADY_REVERSED')
    source=db.execute('''SELECT l.coordinate_id,l.signed_amount,
        l.line_ordinal,l.source_ref,c.members
        FROM epm.manual_journal_line l JOIN epm.coordinate c ON
          c.workspace_id=l.workspace_id
          AND c.application_id=l.application_id
          AND c.coordinate_id=l.coordinate_id
        WHERE l.workspace_id=%s AND l.application_id=%s
        AND l.journal_id=%s ORDER BY l.line_ordinal''',
        (*keys,args['journalId'])).fetchall()
    if not source:raise ValueError('JOURNAL_LINES_UNAVAILABLE')
    points=tuple(Coordinate.from_mapping(row['members']) for row in source)
    authorize_coordinates(
        db, identity, scope, points, kind=AccessKind.WRITE)
    policy_evidence=enforce_active_planning_policy(
        db,scope,writes=tuple((point,'Add') for point in points),
        workflow_role=workflow_role,ordered_actions=True)
    identity={'original':dict(original),'lines':tuple((
        row['line_ordinal'],row['coordinate_id'],row['signed_amount'],
        row['source_ref'],row['members']) for row in source)}
    lines=[(row['coordinate_id'],-row['signed_amount'],
        'reversal:'+args['journalId']+':'+str(row['line_ordinal']))
        for row in source]
    return {'identity':identity,'lines':lines,
        'planningPolicy':policy_evidence}


def _manual_post_candidate(db,scope,args,*,workflow_role,identity):
    PostgresManualJournal._validate_financial_context(db,scope,args['lines'])
    rows=[{'series_key':point.series_key,'members':dict(point.members)}
          for point,_,_ in args['lines']]
    validate_coordinates(db,scope,rows)
    authorize_coordinates(db, identity, scope,
        tuple(point for point,_,_ in args['lines']), kind=AccessKind.WRITE)
    policy_evidence=enforce_active_planning_policy(
        db,scope,writes=tuple((point,'Add')
                              for point,_,_ in args['lines']),
        workflow_role=workflow_role,ordered_actions=True)
    return {'planningPolicy':policy_evidence}


class PostgresManualJournal:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('Verified identity is required')
        self.dsn, self.identity = dsn, identity

    @staticmethod
    def _state(db, scope: ApplicationScope) -> dict:
        # Lifecycle/security own the workspace fence before application rows.
        PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
        state = db.execute('''SELECT s.metadata_revision,s.policy_revision,
            s.data_revision,s.commit_revision,s.processing_mode,
            s.currency_settings,
            a.status AS application_status
            FROM epm.application_state s JOIN epm.application a
              USING (workspace_id,application_id)
            WHERE s.workspace_id=%s AND s.application_id=%s
            FOR UPDATE OF s''',
            (scope.workspace_id,scope.application_id)).fetchone()
        if not state:
            raise ValueError('APPLICATION_UNAVAILABLE')
        if (state['application_status'] != 'Active'
                or state['processing_mode'] != 'Active'):
            raise ValueError('APPLICATION_NOT_WRITABLE')
        return state

    @staticmethod
    def _validate_revisions(state: dict, args: dict) -> None:
        for key, column in (('expectedMetadataRevision', 'metadata_revision'),
                            ('expectedPolicyRevision', 'policy_revision'),
                            ('expectedDataRevision', 'data_revision')):
            if args[key] != state[column]:
                raise ValueError('STALE_JOURNAL_REVISION')

    @staticmethod
    def _validate_financial_context(db, scope: ApplicationScope,
                                    lines: list[tuple]) -> None:
        rows = db.execute('''SELECT dimension_id,model_role
            FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
            AND status='Active' AND model_role IS NOT NULL''',
            (scope.workspace_id,scope.application_id)).fetchall()
        roles = {}
        for row in rows:
            if row['model_role'] in roles and row['model_role'] != 'Custom':
                raise ValueError('JOURNAL_MODEL_ROLE_AMBIGUOUS')
            roles[row['model_role']] = row['dimension_id']
        if not {'Scenario','Year','Period','Entity','Account'} <= set(roles):
            raise ValueError('JOURNAL_FINANCIAL_MODEL_ROLES_REQUIRED')
        account_axis, entity_axis = roles['Account'], roles['Entity']
        baseline = {key: value for key, value in lines[0][0].members
                    if key not in (account_axis, entity_axis)}
        for coordinate, _, _ in lines:
            members = dict(coordinate.members)
            if account_axis not in members or entity_axis not in members:
                raise ValueError('JOURNAL_FINANCIAL_COORDINATE_REQUIRED')
            if ({key: value for key, value in coordinate.members
                 if key not in (account_axis, entity_axis)} != baseline):
                raise ValueError('JOURNAL_BALANCING_SCOPE_MISMATCH')
            if db.execute('''SELECT 1 FROM epm.relationship
                WHERE workspace_id=%s AND application_id=%s
                AND dimension_id=%s AND parent_member_id=%s
                AND status='Active' LIMIT 1''',
                (scope.workspace_id,scope.application_id,account_axis,
                 members[account_axis])).fetchone():
                raise ValueError('JOURNAL_ACCOUNT_MUST_BE_LEAF')

    def post_in_transaction(self, db, scope: ApplicationScope,
                            program: object, *, idempotency_key: str,
                            state: dict | None = None,
                            result_extension: dict | None = None,
                            _admission_token: object | None = None) -> dict:
        """Post through a caller-owned transaction for composite publishers.

        The caller must already have set the scoped session variables.  This
        method owns the ordinary workspace/application locks, authorization,
        receipt, policy guard and journal writes, but never commits.
        """
        name, args = compile_journal_program(program)
        if name != POST_FUNCTION:
            raise ValueError('JOURNAL_POST_FUNCTION_REQUIRED')
        if not valid_idempotency_key(idempotency_key):
            raise ValueError('JOURNAL_IDEMPOTENCY_KEY_INVALID')
        digest = _canonical_digest({'scope': [scope.workspace_id,
                                             scope.application_id],
          'identity': [self.identity.issuer, self.identity.subject_id],
          'program': program})
        state = state or self._state(db, scope)
        access = PostgresAccessChecker.check_in_transaction(
            db, self.identity, scope, 'admin', function=name)
        prior = db.execute('''SELECT command_digest,actor_id,result
            FROM epm.operation_receipt WHERE workspace_id=%s
            AND application_id=%s AND operation_id=%s''',
            (scope.workspace_id, scope.application_id,
             idempotency_key)).fetchone()
        if prior:
            if (prior['command_digest'] != digest
                    or prior['actor_id'] != self.identity.subject_id
                    or prior['result'].get('journalId') != idempotency_key):
                raise ValueError('JOURNAL_IDEMPOTENCY_CONFLICT')
            return prior['result']
        if (_admission_token is not None
                and _admission_token is not _DISJOINT_POST_ADMISSION):
            raise ValueError('JOURNAL_ADMISSION_TOKEN_INVALID')
        if _admission_token is _DISJOINT_POST_ADMISSION:
            for expected,column in (
                    ('expectedMetadataRevision','metadata_revision'),
                    ('expectedPolicyRevision','policy_revision')):
                if args[expected]!=state[column]:
                    raise ValueError('STALE_JOURNAL_REVISION')
            if state['data_revision']<args['expectedDataRevision']:
                raise ValueError('STALE_JOURNAL_REVISION')
        else:
            self._validate_revisions(state,args)
        candidate=_manual_post_candidate(
            db,scope,args,workflow_role=access.role,identity=self.identity)
        lines = [(PostgresNumericFactStore._coordinate_id(
            db, scope, coordinate), amount, ref)
            for coordinate, amount, ref in args['lines']]
        policy_evidence=candidate['planningPolicy']
        revision = state['commit_revision'] + 1
        result = {'journalId': idempotency_key, 'status': 'Posted',
          'lineCount': len(lines), 'reversalOf': None,
          'dataRevision': state['data_revision'] + 1,
          'committedRevision': revision,
          'planningPolicy': policy_evidence,
          **(result_extension or {})}
        db.execute('''UPDATE epm.application_state SET
            data_revision=data_revision+1,commit_revision=%s
            WHERE workspace_id=%s AND application_id=%s''',
            (revision, scope.workspace_id, scope.application_id))
        db.execute('''INSERT INTO epm.operation_receipt
            (workspace_id,application_id,operation_id,
             command_digest,actor_id,committed_revision,result)
            VALUES (%s,%s,%s,%s,%s,%s,%s)''',
            (scope.workspace_id, scope.application_id, idempotency_key,
             digest, self.identity.subject_id, revision, Jsonb(result)))
        db.execute('''INSERT INTO epm.manual_journal
            (workspace_id,application_id,journal_id,issuer,
             subject_id,reason,reversal_of,metadata_revision,
             policy_revision,committed_revision)
            VALUES (%s,%s,%s,%s,%s,%s,NULL,%s,%s,%s)''',
            (scope.workspace_id, scope.application_id, idempotency_key,
             self.identity.issuer, self.identity.subject_id, args['reason'],
             state['metadata_revision'], state['policy_revision'], revision))
        db.cursor().executemany('''INSERT INTO epm.manual_journal_line
            (workspace_id,application_id,journal_id,line_ordinal,
             coordinate_id,signed_amount,source_ref)
            VALUES (%s,%s,%s,%s,%s,%s,%s)''',
            [(scope.workspace_id, scope.application_id, idempotency_key,
              ordinal, coordinate_id, amount, ref)
             for ordinal, (coordinate_id, amount, ref)
             in enumerate(lines, 1)])
        return result

    def execute(self, scope: ApplicationScope, program: object, *,
                idempotency_key: str) -> dict:
        name, args = compile_journal_program(program)
        if name == READ_FUNCTION:
            raise ValueError('JOURNAL_READ_REQUIRES_READ_PATH')
        if not valid_idempotency_key(idempotency_key):
            raise ValueError('JOURNAL_IDEMPOTENCY_KEY_INVALID')
        digest = _canonical_digest({'scope': [scope.workspace_id,
                                             scope.application_id],
                                    'identity': [self.identity.issuer,
                                                 self.identity.subject_id],
                                    'program': program})
        if name == POST_FUNCTION:
            try:
                with connect_postgres(self.dsn,row_factory=dict_row) as before:
                    with before.transaction():
                        configure_statement_timeout(before,10000)
                        PostgresNumericFactStore._set_scope(before,scope)
                        PostgresAccessChecker.lock_workspace(
                            before,scope.workspace_id)
                        initial_access=PostgresAccessChecker.check_in_transaction(
                            before,self.identity,scope,'admin',function=name)
                        prior=before.execute('''SELECT command_digest,
                            actor_id,result FROM epm.operation_receipt
                            WHERE workspace_id=%s AND application_id=%s
                            AND operation_id=%s''',(scope.workspace_id,
                            scope.application_id,idempotency_key)).fetchone()
                        if prior:
                            if (prior['command_digest']!=digest
                                    or prior['actor_id']!=
                                        self.identity.subject_id
                                    or prior['result'].get('journalId')!=
                                        idempotency_key):
                                raise ValueError(
                                    'JOURNAL_IDEMPOTENCY_CONFLICT')
                            return prior['result']
                        initial_state=before.execute('''SELECT
                            s.metadata_revision,s.policy_revision,
                            s.data_revision,s.commit_revision,
                            s.processing_mode,
                            a.status AS application_status
                            FROM epm.application_state s
                            JOIN epm.application a
                            USING(workspace_id,application_id)
                            WHERE s.workspace_id=%s
                            AND s.application_id=%s''',(scope.workspace_id,
                            scope.application_id)).fetchone()
                        if (not initial_state
                                or initial_state['application_status']!='Active'
                                or initial_state['processing_mode']!='Active'):
                            raise ValueError('APPLICATION_NOT_WRITABLE')
                        self._validate_revisions(initial_state,args)
                        _manual_post_candidate(before,scope,args,
                            workflow_role=initial_access.role,
                            identity=self.identity)
                with connect_postgres(self.dsn, row_factory=dict_row) as db:
                    with db.transaction():
                        PostgresNumericFactStore._set_scope(db, scope)
                        return self.post_in_transaction(
                            db, scope, program,
                            idempotency_key=idempotency_key,
                            _admission_token=_DISJOINT_POST_ADMISSION)
            except UniqueViolation as error:
                raise ValueError(
                    'JOURNAL_ALREADY_REVERSED_OR_EXISTS') from error
        with connect_postgres(self.dsn,row_factory=dict_row) as before:
            with before.transaction():
                configure_statement_timeout(before,10000)
                PostgresNumericFactStore._set_scope(before,scope)
                PostgresAccessChecker.lock_workspace(
                    before,scope.workspace_id)
                initial_access=PostgresAccessChecker.check_in_transaction(
                    before,self.identity,scope,'admin',function=name)
                prior=before.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id,scope.application_id,
                     idempotency_key)).fetchone()
                if prior:
                    if (prior['command_digest']!=digest
                            or prior['actor_id']!=self.identity.subject_id
                            or prior['result'].get('journalId')!=
                                idempotency_key):
                        raise ValueError('JOURNAL_IDEMPOTENCY_CONFLICT')
                    return prior['result']
                initial_state=before.execute('''SELECT s.metadata_revision,
                    s.policy_revision,s.data_revision,s.commit_revision,
                    s.processing_mode,a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if (not initial_state
                        or initial_state['application_status']!='Active'
                        or initial_state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                self._validate_revisions(initial_state,args)
                candidate=_manual_reversal_candidate(
                    before,scope,args,workflow_role=initial_access.role,
                    identity=self.identity)
        try:
            with connect_postgres(self.dsn, row_factory=dict_row) as db:
                with db.transaction():
                    PostgresNumericFactStore._set_scope(db, scope)
                    state = self._state(db, scope)
                    access = PostgresAccessChecker.check_in_transaction(
                        db, self.identity, scope, 'admin', function=name)
                    prior = db.execute('''SELECT command_digest,actor_id,result
                        FROM epm.operation_receipt WHERE workspace_id=%s
                        AND application_id=%s AND operation_id=%s''',
                        (scope.workspace_id,scope.application_id,
                         idempotency_key)).fetchone()
                    if prior:
                        if (prior['command_digest'] != digest
                                or prior['actor_id'] != self.identity.subject_id
                                or prior['result'].get('journalId') != idempotency_key):
                            raise ValueError('JOURNAL_IDEMPOTENCY_CONFLICT')
                        return prior['result']
                    for expected,column in (
                            ('expectedMetadataRevision','metadata_revision'),
                            ('expectedPolicyRevision','policy_revision')):
                        if args[expected]!=state[column]:
                            raise ValueError('STALE_JOURNAL_REVISION')
                    # _state holds the application publication row. Manual
                    # journals remain immutable, so the runtime role must not
                    # gain UPDATE merely to add a redundant row lock here.
                    final_candidate=_manual_reversal_candidate(
                        db,scope,args,workflow_role=access.role,
                        identity=self.identity)
                    if final_candidate['identity']!=candidate['identity']:
                        raise ValueError('JOURNAL_REVERSAL_CANDIDATE_STALE')
                    lines=final_candidate['lines']
                    reversal_of=args['journalId']
                    policy_evidence=final_candidate['planningPolicy']
                    revision = state['commit_revision'] + 1
                    result = {'journalId': idempotency_key,
                              'status': 'Posted', 'lineCount': len(lines),
                              'reversalOf': reversal_of,
                              'dataRevision': state['data_revision'] + 1,
                              'committedRevision': revision,
                              'planningPolicy': policy_evidence}
                    db.execute('''UPDATE epm.application_state SET
                        data_revision=data_revision+1,commit_revision=%s
                        WHERE workspace_id=%s AND application_id=%s''',
                        (revision,scope.workspace_id,scope.application_id))
                    db.execute('''INSERT INTO epm.operation_receipt
                        (workspace_id,application_id,operation_id,
                         command_digest,actor_id,committed_revision,result)
                        VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                        (scope.workspace_id,scope.application_id,idempotency_key,
                         digest,self.identity.subject_id,revision,Jsonb(result)))
                    db.execute('''INSERT INTO epm.manual_journal
                        (workspace_id,application_id,journal_id,issuer,
                         subject_id,reason,reversal_of,metadata_revision,
                         policy_revision,committed_revision)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                        (scope.workspace_id,scope.application_id,idempotency_key,
                         self.identity.issuer,self.identity.subject_id,
                         args['reason'],reversal_of,state['metadata_revision'],
                         state['policy_revision'],revision))
                    db.cursor().executemany('''INSERT INTO epm.manual_journal_line
                        (workspace_id,application_id,journal_id,line_ordinal,
                         coordinate_id,signed_amount,source_ref)
                        VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                        [(scope.workspace_id,scope.application_id,
                          idempotency_key,ordinal,coordinate_id,amount,ref)
                         for ordinal,(coordinate_id,amount,ref)
                         in enumerate(lines,1)])
                    return result
        except UniqueViolation as error:
            raise ValueError('JOURNAL_ALREADY_REVERSED_OR_EXISTS') from error

    def read(self, scope: ApplicationScope, program: object) -> dict:
        name, args = compile_journal_program(program)
        if name != READ_FUNCTION:
            raise ValueError('JOURNAL_READ_FUNCTION_REQUIRED')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'read')
                journal = db.execute('''SELECT journal_id,reason,reversal_of,
                    committed_revision,metadata_revision,policy_revision,
                    posted_at FROM epm.manual_journal WHERE workspace_id=%s
                    AND application_id=%s AND journal_id=%s''',
                    (scope.workspace_id,scope.application_id,
                     args['journalId'])).fetchone()
                if not journal:
                    raise ValueError('JOURNAL_UNAVAILABLE')
                rows = db.execute('''SELECT l.line_ordinal,c.members,
                    l.signed_amount,l.source_ref
                    FROM epm.manual_journal_line l JOIN epm.coordinate c
                    USING (workspace_id,application_id,coordinate_id)
                    WHERE l.workspace_id=%s AND l.application_id=%s
                    AND l.journal_id=%s ORDER BY l.line_ordinal''',
                    (scope.workspace_id,scope.application_id,
                     args['journalId'])).fetchall()
                authorize_coordinates(db, self.identity, scope, tuple(
                    Coordinate.from_mapping(row['members']) for row in rows),
                    kind=AccessKind.READ)
                reversed_by = db.execute('''SELECT journal_id FROM
                    epm.manual_journal WHERE workspace_id=%s
                    AND application_id=%s AND reversal_of=%s''',
                    (scope.workspace_id,scope.application_id,
                     args['journalId'])).fetchone()
                return {'journalId': journal['journal_id'],
                        'reason': journal['reason'],
                        'reversalOf': journal['reversal_of'],
                        'reversedBy': reversed_by['journal_id'] if reversed_by
                            else None,
                        'status': 'Posted',
                        'committedRevision': journal['committed_revision'],
                        'metadataRevision': journal['metadata_revision'],
                        'policyRevision': journal['policy_revision'],
                        'postedAt': journal['posted_at'].isoformat(),
                        'lines': [{'lineOrdinal': row['line_ordinal'],
                                   'members': row['members'],
                                   'signedAmount': format(row['signed_amount'],'f'),
                                   'sourceRef': row['source_ref']}
                                  for row in rows]}

    def read_balance(self, scope: ApplicationScope, program: object) -> dict:
        """Read one exact journal-layer coordinate at a committed snapshot."""
        name, args = compile_journal_program(program)
        if name not in (BALANCE_READ_FUNCTION, ADJUSTED_READ_FUNCTION):
            raise ValueError('JOURNAL_BALANCE_READ_FUNCTION_REQUIRED')
        coordinate = args['coordinate']
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                state = db.execute('''SELECT metadata_revision,commit_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if not state:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                revision = (state['commit_revision'] if
                            args['snapshotRevision'] is None else
                            args['snapshotRevision'])
                if revision > state['commit_revision']:
                    raise ValueError('SNAPSHOT_NOT_COMMITTED')
                self._validate_financial_context(
                    db, scope, [(coordinate,None,None)])
                active = {row['dimension_id'] for row in db.execute('''
                    SELECT dimension_id FROM epm.dimension
                    WHERE workspace_id=%s AND application_id=%s
                    AND status='Active'
                    AND model_role IS DISTINCT FROM 'Currency' ''',
                    (scope.workspace_id,scope.application_id)).fetchall()}
                if set(dict(coordinate.members)) != active:
                    raise ValueError('COORDINATE_DIMENSIONS_MISMATCH')
                for axis, member in coordinate.members:
                    if not db.execute('''SELECT 1 FROM epm.member
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND member_id=%s
                        AND status='Active' ''',
                        (scope.workspace_id,scope.application_id,
                         axis,member)).fetchone():
                        raise ValueError('COORDINATE_MEMBER_UNAVAILABLE')
                authorize_coordinates(db, self.identity, scope, (coordinate,),
                                      kind=AccessKind.READ)
                point = db.execute('''SELECT coordinate_id,members
                    FROM epm.coordinate WHERE workspace_id=%s
                    AND application_id=%s AND series_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     coordinate.series_key)).fetchone()
                if point and point['members'] != dict(coordinate.members):
                    raise ValueError('COORDINATE_HASH_COLLISION')
                summary = None
                source_row = None
                text_row = None
                if point:
                    summary = db.execute('''SELECT
                        count(*) AS line_count,
                        COALESCE(sum(l.signed_amount),0) AS adjustment_amount,
                        max(j.committed_revision) AS last_journal_revision
                        FROM epm.manual_journal_line l
                        JOIN epm.manual_journal j USING
                          (workspace_id,application_id,journal_id)
                        WHERE l.workspace_id=%s AND l.application_id=%s
                        AND l.coordinate_id=%s
                        AND j.committed_revision<=%s''',
                        (scope.workspace_id,scope.application_id,
                         point['coordinate_id'],revision)).fetchone()
                    if name == ADJUSTED_READ_FUNCTION:
                        source_row = db.execute('''SELECT present,
                            resulting_amount,change_id,committed_revision
                            FROM epm.numeric_fact_event
                            WHERE workspace_id=%s AND application_id=%s
                            AND coordinate_id=%s AND committed_revision<=%s
                            ORDER BY committed_revision DESC,line_ordinal DESC
                            LIMIT 1''',
                            (scope.workspace_id,scope.application_id,
                             point['coordinate_id'],revision)).fetchone()
                        text_row = db.execute('''SELECT present
                            FROM epm.text_fact_event
                            WHERE workspace_id=%s AND application_id=%s
                            AND coordinate_id=%s AND committed_revision<=%s
                            ORDER BY committed_revision DESC,line_ordinal DESC
                            LIMIT 1''',
                            (scope.workspace_id,scope.application_id,
                             point['coordinate_id'],revision)).fetchone()
                        if text_row and text_row['present']:
                            raise ValueError('ADJUSTED_BALANCE_TEXT_COORDINATE')
                after_state = db.execute('''SELECT metadata_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if (not after_state or after_state['metadata_revision'] !=
                        state['metadata_revision']):
                    raise ValueError('STALE_METADATA_REVISION')
                adjustment = (summary['adjustment_amount'] if summary else
                              Decimal('0.00000000'))
                result = {'members':dict(coordinate.members),
                        'snapshotRevision':revision,
                        'metadataRevision':state['metadata_revision'],
                        'adjustmentAmount':format(adjustment,'.8f'),
                        'lineCount':summary['line_count'] if summary else 0,
                        'lastJournalRevision':(
                            summary['last_journal_revision'] if summary
                            else None)}
                if name == ADJUSTED_READ_FUNCTION:
                    source_present = bool(source_row and source_row['present'])
                    with localcontext() as decimal_context:
                        decimal_context.prec = 64
                        adjusted = ((source_row['resulting_amount'] if
                                     source_present else Decimal(0)) +
                                    adjustment)
                    adjusted_present = source_present or adjustment != 0
                    if adjusted_present:
                        NumericCell(True,adjusted,'')
                    result.update({
                        'sourcePresent':source_present,
                        'sourceAmount':(format(
                            source_row['resulting_amount'],'.8f') if
                            source_present else None),
                        'sourceChangeId':(
                            source_row['change_id'] if source_present else ''),
                        'sourceLastRevision':(
                            source_row['committed_revision'] if
                            source_present else None),
                        'adjustedPresent':adjusted_present,
                        'adjustedAmount':(
                            format(adjusted,'.8f') if adjusted_present
                            else None),
                    })
                return result
