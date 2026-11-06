"""Publish a pinned typed calculation as one balanced manual journal.

This is a generic fixed-core lowering target for user-authored expressions.
It does not infer accounts, signs, accounting policy, or a consolidation
treatment.  The admitted program supplies explicit source/target mappings;
the worker resolves the already-published calculation values and delegates the
actual immutable posting to :mod:`postgres_manual_journal` in the same
transaction.
"""
from __future__ import annotations

from decimal import Decimal, localcontext
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate, NumericCell
from .dimensional_security_policy import AccessKind
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_calculation_status import published_input_status
from .postgres_job_final_fence import finish_published_job
from .postgres_jobs import _canonical_digest, _require_python_job_authority
from .postgres_manual_journal import POST_FUNCTION, PostgresManualJournal
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout


FUNCTION = 'consolidation.journal.from_calculation.publish'
COMPILER = 'calculation-to-manual-journal-v1'
PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION,
    'compiler': COMPILER,
    'source': 'current pinned calculation publication with explicit Amount unit',
    'mapping': 'caller-declared target coordinate and sign only',
    'publication': 'one exact balanced immutable manual journal',
    'policyInference': 'none',
})

_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_GENERATION = re.compile(r'[0-9a-f]{32}\Z')
_ROLE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z')
_WIRE_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z')


def _identifier(value: object, *, maximum: int = 200) -> str:
    if (type(value) is not str or not 1 <= len(value) <= maximum
            or value != value.strip() or '\x00' in value):
        raise ValueError('CALCULATION_JOURNAL_IDENTIFIER_INVALID')
    return value


def _coordinate(value: object) -> dict[str, str]:
    if type(value) is not dict or not 1 <= len(value) <= 32:
        raise ValueError('CALCULATION_JOURNAL_COORDINATE_INVALID')
    if any(type(axis) is not str or type(member) is not str
           or _WIRE_ID.fullmatch(axis) is None
           or _WIRE_ID.fullmatch(member) is None
           for axis, member in value.items()):
        raise ValueError('CALCULATION_JOURNAL_COORDINATE_INVALID')
    coordinate = Coordinate.from_mapping(value)
    return dict(coordinate.members)


def _unit(value: object) -> dict[str, str]:
    if (type(value) is not dict
            or set(value) != {'dimensionId', 'memberId'}):
        raise ValueError('CALCULATION_JOURNAL_UNIT_INVALID')
    return {'dimensionId': _identifier(value['dimensionId']),
            'memberId': _identifier(value['memberId'])}


def compile_program(raw: object) -> dict:
    """Strictly normalize the public wire program without database access."""
    if (type(raw) is not dict
            or set(raw) != {'languageVersion', 'function', 'arguments'}
            or type(raw.get('languageVersion')) is not int
            or raw['languageVersion'] != 2
            or raw.get('function') != FUNCTION
            or type(raw.get('arguments')) is not dict):
        raise ValueError('EXPRESSION_JOURNAL_PROGRAM_INVALID')
    args = raw['arguments']
    expected = {'reason', 'expectedMetadataRevision', 'expectedDataRevision',
                'expectedPolicyRevision', 'lines'}
    if (set(args) != expected or type(args['reason']) is not str
            or not 1 <= len(args['reason']) <= 500
            or args['reason'] != args['reason'].strip()
            or '\x00' in args['reason']
            or any(type(args[name]) is not int or args[name] < 0 for name in (
                'expectedMetadataRevision', 'expectedDataRevision',
                'expectedPolicyRevision'))
            or type(args['lines']) is not list
            or not 2 <= len(args['lines']) <= 100):
        if type(args.get('lines')) is list and not 2 <= len(args['lines']) <= 100:
            raise ValueError('EXPRESSION_JOURNAL_LINE_BOUNDS')
        if any(name in args and (type(args[name]) is not int or args[name] < 0)
               for name in ('expectedMetadataRevision','expectedDataRevision',
                            'expectedPolicyRevision')):
            raise ValueError('EXPRESSION_JOURNAL_REVISION_INVALID')
        raise ValueError('EXPRESSION_JOURNAL_PROGRAM_INVALID')
    normalized = []
    for item in args['lines']:
        required = {'source','targetMembers','multiplier','sourceRole'}
        if type(item) is not dict or set(item) != required:
            raise ValueError('EXPRESSION_JOURNAL_LINE_INVALID')
        source=item['source']
        if (type(source) is not dict or set(source)!={'resultKey','generationId',
                'publishedRevision','members','expectedUnit'}
                or type(source['resultKey']) is not str
                or _KEY.fullmatch(source['resultKey']) is None
                or type(source['generationId']) is not str
                or _GENERATION.fullmatch(source['generationId']) is None
                or source['generationId']=='0'*32
                or type(source['publishedRevision']) is not int
                or source['publishedRevision']<=0):
            raise ValueError('EXPRESSION_JOURNAL_SOURCE_PIN_INVALID')
        if item['multiplier'] not in ('-1','1'):
            raise ValueError('EXPRESSION_JOURNAL_MULTIPLIER_INVALID')
        if (type(item['sourceRole']) is not str
                or _ROLE.fullmatch(item['sourceRole']) is None):
            raise ValueError('EXPRESSION_JOURNAL_SOURCE_ROLE_INVALID')
        try: source_members=_coordinate(source['members'])
        except ValueError as error:
            raise ValueError('EXPRESSION_JOURNAL_SOURCE_PIN_INVALID') from error
        try: expected_unit=_unit(source['expectedUnit'])
        except ValueError as error:
            raise ValueError('EXPRESSION_JOURNAL_UNIT_PIN_INVALID') from error
        try: target_members=_coordinate(item['targetMembers'])
        except ValueError as error:
            raise ValueError('EXPRESSION_JOURNAL_TARGET_INVALID') from error
        normalized.append({
            'source':{'resultKey':source['resultKey'],
                'generationId':source['generationId'],
                'publishedRevision':source['publishedRevision'],
                'members':source_members,'expectedUnit':expected_unit},
            'targetMembers': target_members,
            'multiplier': item['multiplier'],
            'sourceRole': item['sourceRole'],
        })
    targets = [Coordinate.from_mapping(item['targetMembers']).series_key
               for item in normalized]
    if len(targets) != len(set(targets)):
        raise ValueError('EXPRESSION_JOURNAL_DUPLICATE_TARGET')
    sources=[(item['source']['resultKey'],item['source']['generationId'],
              item['source']['publishedRevision'],
              Coordinate.from_mapping(item['source']['members']).series_key)
             for item in normalized]
    if len(sources)!=len(set(sources)):
        raise ValueError('EXPRESSION_JOURNAL_SOURCE_REUSED')
    units = {(item['source']['expectedUnit']['dimensionId'],
              item['source']['expectedUnit']['memberId']) for item in normalized}
    if len(units) != 1:
        raise ValueError('CALCULATION_JOURNAL_UNIT_MISMATCH')
    return {'languageVersion': 2, 'function': FUNCTION, 'arguments': {
        'reason': args['reason'],
        'expectedMetadataRevision': args['expectedMetadataRevision'],
        'expectedDataRevision': args['expectedDataRevision'],
        'expectedPolicyRevision': args['expectedPolicyRevision'],
        'lines': normalized,
    }}


def _state_matches(state: dict, args: dict, *, allow_newer_data=False) -> None:
    if (args['expectedMetadataRevision'] != state['metadata_revision']
            or args['expectedPolicyRevision'] != state['policy_revision']
            or (state['data_revision'] < args['expectedDataRevision']
                if allow_newer_data else
                state['data_revision'] != args['expectedDataRevision'])):
        raise ValueError('STALE_CALCULATION_JOURNAL_REVISION')


def _active_financial_axes(db, scope: ApplicationScope) -> tuple[set[str], str]:
    rows = db.execute('''SELECT dimension_id,model_role FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active' ''',
        (scope.workspace_id, scope.application_id)).fetchall()
    axes = {row['dimension_id'] for row in rows
            if row['model_role'] != 'Currency'}
    currencies = [row['dimension_id'] for row in rows
                  if row['model_role'] == 'Currency']
    if len(currencies) != 1:
        raise ValueError('CALCULATION_JOURNAL_CURRENCY_ROLE_REQUIRED')
    return axes, currencies[0]


def _active_members(db, scope: ApplicationScope, members: dict[str, str]) -> bool:
    return not db.execute('''SELECT 1 FROM jsonb_each_text(%s::jsonb) item
        LEFT JOIN epm.member m ON m.workspace_id=%s AND m.application_id=%s
          AND m.dimension_id=item.key AND m.member_id=item.value
          AND m.status='Active'
        WHERE m.member_id IS NULL LIMIT 1''',
        (Jsonb(members), scope.workspace_id, scope.application_id)).fetchone()


def _resolve_line(db, scope: ApplicationScope, line: dict,
                  state: dict, currency_axis: str, *, admitted_data_revision: int,
                  allow_newer_data=False) -> tuple[Decimal, dict]:
    keys = (scope.workspace_id, scope.application_id)
    pin=line['source'];source = Coordinate.from_mapping(pin['members'])
    generation = db.execute('''SELECT
        p.generation_id AS current_generation_id,
        p.published_revision AS current_published_revision,
        g.generation_id,g.result_key,g.published_revision,
        g.source_commit_revision,g.source_metadata_revision,
        g.source_policy_revision,g.function_name,
        j.status AS job_status,j.expected_metadata_revision,
        j.expected_data_revision,j.expected_policy_revision,j.result AS job_result
        FROM epm.calculation_publication p
        JOIN epm.calculation_generation g USING(
          workspace_id,application_id,generation_id)
        JOIN epm.job j ON j.workspace_id=g.workspace_id
          AND j.application_id=g.application_id AND j.job_id=g.job_id
        WHERE p.workspace_id=%s AND p.application_id=%s
          AND p.result_key=%s''', (*keys, pin['resultKey'])).fetchone()
    if (generation is None
            or generation['current_generation_id'] != pin['generationId']
            or generation['current_published_revision'] !=
                pin['publishedRevision']
            or generation['generation_id'] != pin['generationId']
            or generation['result_key'] != pin['resultKey']
            or generation['published_revision'] != pin['publishedRevision']
            or generation['job_status'] != 'published'):
        raise ValueError('CALCULATION_JOURNAL_SOURCE_NOT_CURRENT')
    unit = pin['expectedUnit']
    if unit['dimensionId'] != currency_axis:
        raise ValueError('CALCULATION_JOURNAL_UNIT_INVALID')
    rows = db.execute('''SELECT r.coordinate_id,c.members,r.amount,
          r.output_unit_currency_dimension_id AS unit_dimension_id,
          r.output_unit_currency_member_id AS unit_member_id
        FROM epm.calculation_unit_result r JOIN epm.coordinate c USING(
          workspace_id,application_id,coordinate_id)
        WHERE r.workspace_id=%s AND r.application_id=%s
          AND r.generation_id=%s AND c.series_key=%s
          AND r.output_unit_currency_dimension_id=%s
          AND r.output_unit_currency_member_id=%s
        ORDER BY r.coordinate_id LIMIT 2''', (*keys, pin['generationId'],
            source.series_key, unit['dimensionId'], unit['memberId'])).fetchall()
    if not rows:
        # Authoritative postings require an immutable typed Amount result.
        # A caller assertion or legacy untyped calculation must never be
        # upgraded into a financial unit at this boundary.
        raise ValueError('CALCULATION_JOURNAL_EXPLICIT_UNIT_REQUIRED')
    current = {
        'metadata': generation['expected_metadata_revision'] ==
            state['metadata_revision'] == generation['source_metadata_revision'],
        'data': (generation['expected_data_revision'] == admitted_data_revision
            and (state['data_revision'] >= admitted_data_revision
                 if allow_newer_data else
                 state['data_revision'] == admitted_data_revision)),
        'policy': generation['expected_policy_revision'] ==
            state['policy_revision'] == generation['source_policy_revision'],
    }
    dependency=published_input_status(db,scope,{'publishedInputs':[{
        'resultKey':pin['resultKey'],'generationId':pin['generationId'],
        'publishedRevision':pin['publishedRevision']}]},
        allow_newer_data=allow_newer_data)
    if (len(rows) != 1 or rows[0]['members'] != pin['members']
            or dependency is None or not dependency['matchesAtRead']
            or not all(current.values())):
        raise ValueError('CALCULATION_JOURNAL_SOURCE_STALE')
    amount = rows[0]['amount'] * Decimal(line['multiplier'])
    NumericCell(True, amount, '')
    if amount == 0:
        raise ValueError('CALCULATION_JOURNAL_ZERO_LINE')
    status = {'matchesAtRead': True, 'revisionMatches': current,
              'sourceStorage': 'calculation_unit_result',
              'sourceCommitRevision': generation['source_commit_revision'],
              'dependencyStatus':dependency}
    lineage = {
        'resultKey': pin['resultKey'],
        'generationId': pin['generationId'],
        'publishedRevision': pin['publishedRevision'],
        'sourceCoordinateId': rows[0]['coordinate_id'],
        'unitDimensionId': rows[0]['unit_dimension_id'],
        'unitMemberId': rows[0]['unit_member_id'],
        'dependencyStatus': status,
    }
    return amount, lineage


def validate_in_transaction(db, scope: ApplicationScope, program: object,
                            state: dict, *, allow_newer_data=False
                            ) -> tuple[list[tuple[Coordinate, Decimal, str]], list[dict]]:
    """Resolve exact current sources; perform no writes."""
    normalized = compile_program(program)
    args = normalized['arguments']
    _state_matches(state, args, allow_newer_data=allow_newer_data)
    axes, currency_axis = _active_financial_axes(db, scope)
    unit = args['lines'][0]['source']['expectedUnit']
    if not db.execute('''SELECT 1 FROM epm.member WHERE workspace_id=%s
        AND application_id=%s AND dimension_id=%s AND member_id=%s
        AND status='Active' ''', (scope.workspace_id, scope.application_id,
            unit['dimensionId'], unit['memberId'])).fetchone():
        raise ValueError('CALCULATION_JOURNAL_UNIT_UNAVAILABLE')
    resolved = []
    lineage = []
    for line in args['lines']:
        target = line['targetMembers']
        if set(target) != axes or not _active_members(db, scope, target):
            raise ValueError('CALCULATION_JOURNAL_TARGET_GRAIN_INVALID')
        amount, source = _resolve_line(db, scope, line, state, currency_axis,
            admitted_data_revision=args['expectedDataRevision'],
            allow_newer_data=allow_newer_data)
        resolved.append((Coordinate.from_mapping(target), amount,
                         line['sourceRole']))
        lineage.append(source)
    with localcontext() as context:
        context.prec = 80
        if sum((amount for _, amount, _ in resolved), Decimal(0)) != 0:
            raise ValueError('CALCULATION_JOURNAL_NOT_BALANCED')
    # Apply the same financial-grain and leaf-account rules used at posting.
    PostgresManualJournal._validate_financial_context(db, scope, resolved)
    return resolved, lineage


def _candidate_identity(resolved, lineage):
    return _canonical_digest({'lines':[{'members':dict(point.members),
        'amount':format(amount,'.8f'),'sourceRole':role}
        for point,amount,role in resolved], 'lineage':lineage})


def enforce_expression_journal_dimensional_security(
        db, identity, scope, program, resolved):
    """Authorize pinned calculation inputs separately from journal targets."""
    lines = program['arguments']['lines']
    sources = tuple(Coordinate.from_mapping(item['source']['members'])
                    for item in lines)
    targets = tuple(point for point, _, _ in resolved)
    if not sources or not targets or len(sources) != len(targets):
        raise ValueError('CALCULATION_JOURNAL_SECURITY_COORDINATES_INVALID')
    authorize_coordinates(db, identity, scope, sources, kind=AccessKind.READ)
    authorize_coordinates(db, identity, scope, targets, kind=AccessKind.WRITE)


def _read_candidate_state(db, scope):
    row=db.execute('''SELECT s.metadata_revision,s.data_revision,
        s.policy_revision,s.commit_revision,s.processing_mode,
        a.status application_status FROM epm.application_state s
        JOIN epm.application a USING(workspace_id,application_id)
        WHERE s.workspace_id=%s AND s.application_id=%s''',
        (scope.workspace_id,scope.application_id)).fetchone()
    if row is None:
        raise ValueError('APPLICATION_UNAVAILABLE')
    if row['application_status']!='Active' or row['processing_mode']!='Active':
        raise ValueError('APPLICATION_NOT_WRITABLE')
    return dict(row)


def _published_replay(job, receipt):
    if receipt is None:
        return None
    if (job is None or job['status']!='published'
            or job['receipt_revision']!=receipt['committed_revision']
            or job['result']!=receipt['result']
            or job['subject_id']!=receipt['actor_id']):
        raise ValueError('CALCULATION_JOURNAL_RECEIPT_CONFLICT')
    return receipt['result']


class PostgresExpressionJournalPublisher:
    """Fixed worker for an already-admitted calculation-to-journal job."""

    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if type(dsn) is not str or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def publish(self, claim: dict) -> dict:
        if (type(claim) is not dict
                or type(claim.get('job_id')) is not str
                or _GENERATION.fullmatch(claim['job_id']) is None
                or type(claim.get('claimant')) is not str
                or type(claim.get('claim_generation')) is not int):
            raise ValueError('INVALID_WORKER_CLAIM')
        scope = ApplicationScope(claim['workspace_id'], claim['application_id'])
        keys = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as before:
            with before.transaction():
                configure_statement_timeout(before, 15000)
                PostgresNumericFactStore._set_scope(before, scope)
                PostgresAccessChecker.check_in_transaction(
                    before, self.identity, scope, 'admin', function=FUNCTION)
                state = _read_candidate_state(before, scope)
                job = before.execute('''SELECT *,lease_until>clock_timestamp() AS unexpired
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s''', (*keys, claim['job_id'])).fetchone()
                receipt=before.execute('''SELECT committed_revision,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (*keys,claim['job_id'])).fetchone()
                replay=_published_replay(job,receipt)
                if replay is not None:
                    return replay
                if (job is None or job['issuer'] != self.identity.issuer
                        or job['subject_id'] != self.identity.subject_id):
                    raise ValueError('JOB_UNAVAILABLE')
                if (job['status'] != 'running' or not job['unexpired']
                        or job['claim_generation'] != claim['claim_generation']
                        or job['claimant'] != claim['claimant']):
                    raise ValueError('STALE_WORKER_FENCE')
                _require_python_job_authority(before, scope, job)
                if (job['function_name'] != FUNCTION
                        or job['compiler_version'] != COMPILER
                        or job['plan_digest'] != PLAN_DIGEST
                        or job['program_digest'] !=
                            _canonical_digest(job['normalized_program'])):
                    raise ValueError('CALCULATION_JOURNAL_JOB_MISMATCH')
                for name in ('metadata', 'data', 'policy'):
                    if job['expected_' + name + '_revision'] != state[
                            name + '_revision']:
                        raise ValueError('STALE_CALCULATION_JOURNAL_REVISION')
                program = compile_program(job['normalized_program'])
                resolved, lineage = validate_in_transaction(
                    before, scope, program, state)
                enforce_expression_journal_dimensional_security(
                    before,self.identity,scope,program,resolved)
                initial_identity=_candidate_identity(resolved,lineage)
                initial_job=dict(job)

        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,15000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state=PostgresManualJournal._state(db,scope)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'admin',function=FUNCTION)
                job=db.execute('''SELECT *,lease_until>clock_timestamp() AS unexpired
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s FOR UPDATE''',(*keys,claim['job_id'])).fetchone()
                receipt=db.execute('''SELECT committed_revision,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (*keys,claim['job_id'])).fetchone()
                replay=_published_replay(job,receipt)
                if replay is not None:return replay
                immutable=('issuer','subject_id','function_name','normalized_program',
                    'program_digest','compiler_version','plan_digest',
                    'expected_metadata_revision','expected_data_revision',
                    'expected_policy_revision')
                if (not job or any(job[name]!=initial_job[name]
                                   for name in immutable)):
                    raise ValueError('STALE_WORKER_FENCE')
                if (job['status']!='running' or not job['unexpired']
                        or job['claim_generation']!=claim['claim_generation']
                        or job['claimant']!=claim['claimant']):
                    raise ValueError('STALE_WORKER_FENCE')
                _require_python_job_authority(db,scope,job)
                if (job['function_name']!=FUNCTION
                        or job['compiler_version']!=COMPILER
                        or job['plan_digest']!=PLAN_DIGEST
                        or job['program_digest']!=
                            _canonical_digest(job['normalized_program'])):
                    raise ValueError('CALCULATION_JOURNAL_JOB_MISMATCH')
                if (job['expected_metadata_revision']!=state['metadata_revision']
                        or job['expected_policy_revision']!=state['policy_revision']
                        or state['data_revision']<job['expected_data_revision']):
                    raise ValueError('STALE_CALCULATION_JOURNAL_REVISION')
                resolved,lineage=validate_in_transaction(db,scope,program,state,
                    allow_newer_data=True)
                if _candidate_identity(resolved,lineage)!=initial_identity:
                    raise ValueError('CALCULATION_JOURNAL_SOURCE_STALE')
                enforce_expression_journal_dimensional_security(
                    db,self.identity,scope,program,resolved)
                journal_program = {'languageVersion': 2,
                    'function': POST_FUNCTION, 'arguments': {
                        'reason': program['arguments']['reason'],
                        'expectedMetadataRevision': state['metadata_revision'],
                        'expectedDataRevision': state['data_revision'],
                        'expectedPolicyRevision': state['policy_revision'],
                        'lines': [{
                            'members': dict(point.members),
                            'amount': {'type': 'AmountLiteral',
                                       'decimal': format(amount, '.8f')},
                            'sourceRef': 'calc:' + claim['job_id'] + ':' +
                                str(ordinal) + ':' + role,
                        } for ordinal, (point, amount, role)
                            in enumerate(resolved, 1)],
                    }}
                result = PostgresManualJournal(
                    self.dsn, identity=self.identity).post_in_transaction(
                        db, scope, journal_program,
                        idempotency_key=claim['job_id'], state=state,
                        result_extension={
                            'function': FUNCTION,
                            'compilerVersion': COMPILER,
                            'sourceLayer': 'calculation_publication',
                            'sourceCalculationCount': len(lineage),
                            'effects': 'ManualJournal',
                        })
                db.cursor().executemany('''INSERT INTO
                    epm.manual_journal_calculation_source(
                      workspace_id,application_id,journal_id,line_ordinal,
                      result_key,generation_id,published_revision,
                      source_coordinate_id,unit_dimension_id,unit_member_id,
                      dependency_status)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''', [
                    (*keys, claim['job_id'], ordinal, item['resultKey'],
                     item['generationId'], item['publishedRevision'],
                     item['sourceCoordinateId'], item['unitDimensionId'],
                     item['unitMemberId'], Jsonb(item['dependencyStatus']))
                    for ordinal, item in enumerate(lineage, 1)])
                finish_published_job(db, scope, claim,
                    revision=result['committedRevision'], result=result)
                return result
