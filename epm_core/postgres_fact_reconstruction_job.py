"""Administrator-only, source-pinned recovery through the durable job path."""
from contextlib import contextmanager
import threading
import time

import psycopg
from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity, assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_execution_scope import current_deadline, tool_execution_scope, ToolDeadlineExpired
from .postgres_jobs import (PostgresJobQueue, _canonical_digest, _JOB_ID, _KEY,
                            _job_request_descriptor,
                            _verify_job_replay_authorization)
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout, lock_busy_boundary

FUNCTION = 'facts.projections.rebuild'
LEGACY_COMPILER = 'fact-projections-rebuild-v1'
COMPILER = 'fact-projections-rebuild-v2'
EXECUTION_SECONDS = 20
LEGACY_PLAN_DIGEST = _canonical_digest({'function': FUNCTION, 'compiler': LEGACY_COMPILER,
    'source': 'sealed-immutable-history', 'effect': 'atomic-derived-state-reconstruction',
    'preserve': ['source-events', 'change-ids', 'data-revision', 'metadata-revision', 'schema-epoch'],
    'executionSeconds': EXECUTION_SECONDS})
PLAN_DIGEST = _canonical_digest({'function': FUNCTION, 'compiler': COMPILER,
    'source': 'sealed-immutable-history', 'effect': 'bounded-native-generation-reconstruction',
    'publication': 'certified-generation-pointer-swap', 'checkpoint': 'durable-ready-yield',
    'retryAccounting': 'successful-quantum-does-not-consume-failure-attempt',
    'preserve': ['source-events', 'change-ids', 'data-revision', 'metadata-revision', 'schema-epoch'],
    'executionSeconds': EXECUTION_SECONDS})


def compiler_for(normalized):
    return ((LEGACY_COMPILER, LEGACY_PLAN_DIGEST) if normalized['version'] == 1
            else (COMPILER, PLAN_DIGEST))

_NATIVE_CODES = frozenset(('STALE_WORKER_FENCE', 'STALE_RECONSTRUCTION_SOURCE',
    'APPLICATION_NOT_WRITABLE', 'APPLICATION_GRANT_REQUIRED',
    'RECONSTRUCTION_RECEIPT_INVALID', 'RECONSTRUCTION_NUMERIC_LINEAGE_INVALID',
    'RECONSTRUCTION_TEXT_LINEAGE_INVALID', 'RECONSTRUCTION_DETAIL_LINEAGE_INVALID',
    'RECONSTRUCTION_GENERIC_LINEAGE_INVALID', 'RECONSTRUCTION_VALUE_TYPE_CONFLICT',
    'RECONSTRUCTION_DETAIL_HISTORY_TOTAL_CONFLICT', 'RECONSTRUCTION_DETAIL_TOTAL_CONFLICT',
    'RECONSTRUCTION_SCOPE_INVALID', 'RECONSTRUCTION_JOB_INVALID',
    'RECONSTRUCTION_TARGET_NOT_EMPTY', 'RECONSTRUCTION_LAYOUT_INVALID',
    'RECONSTRUCTION_MANIFEST_INVALID', 'RECONSTRUCTION_CARRY_INVALID',
    'RECONSTRUCTION_CERTIFICATE_INVALID', 'RECONSTRUCTION_INACTIVE_WRITE_FORBIDDEN',
    'PROJECTION_GENERATION_ACTIVATION_FORBIDDEN', 'COORDINATE_LAYOUT_GRAIN_MISMATCH'))


@contextmanager
def _native_error_boundary():
    """Translate only fixed recovery decisions, after the SQL statement fails.

    Constraint violations outside this explicit contract retain their native
    type, as do cancellation, lock timeout and other database failures.
    """
    try:
        yield
    except (psycopg.errors.CheckViolation, psycopg.errors.RaiseException) as error:
        code = error.diag.message_primary
        if code in _NATIVE_CODES:
            raise ValueError(code) from error
        raise


def intent(raw):
    if (not isinstance(raw, dict) or set(raw) != {'languageVersion', 'function', 'arguments'}
            or type(raw['languageVersion']) is not int or raw['languageVersion'] != 2
            or raw['function'] != FUNCTION or not isinstance(raw['arguments'], dict)
            or set(raw['arguments']) != {'reason'}):
        raise ValueError('RECONSTRUCTION_PROGRAM_INVALID')
    reason = raw['arguments']['reason']
    if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 500 or '\0' in reason:
        raise ValueError('RECONSTRUCTION_REASON_INVALID')
    return reason.strip()


def compile_program(raw, source_commit_revision, schema_epoch, *, version=2):
    reason = intent(raw)
    if type(version) is not int or version not in (1, 2):
        raise ValueError('RECONSTRUCTION_NORMALIZED_INVALID')
    if any(type(v) is not int or v < 0 for v in (source_commit_revision, schema_epoch)):
        raise ValueError('RECONSTRUCTION_SOURCE_PIN_INVALID')
    return {'version': version, 'function': FUNCTION, 'reason': reason,
            'sourceCommitRevision': source_commit_revision, 'schemaEpoch': schema_epoch}


def decode_program(value):
    try:
        if (not isinstance(value, dict) or set(value) != {'version', 'function', 'reason',
                'sourceCommitRevision', 'schemaEpoch'} or type(value['version']) is not int
                or value['version'] not in (1, 2)):
            raise ValueError('shape')
        checked = compile_program({'languageVersion': 2, 'function': value['function'],
            'arguments': {'reason': value['reason']}}, value['sourceCommitRevision'], value['schemaEpoch'], version=value['version'])
        if checked != value:
            raise ValueError('noncanonical')
        return checked
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError('RECONSTRUCTION_NORMALIZED_INVALID') from error


def preview(language, scope, raw):
    intent(raw)
    with connect_postgres(language.dsn, row_factory=dict_row) as db:
        with db.transaction():
            PostgresNumericFactStore._set_scope(db, scope)
            PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
            access=PostgresAccessChecker.check_in_transaction(
                db,language.identity,scope,'admin',function=FUNCTION)
            configure_statement_timeout(db, 5000)
            state = db.execute('''SELECT a.status,s.processing_mode,s.metadata_revision,
                s.data_revision,s.policy_revision,s.commit_revision,s.schema_epoch,s.commit_open
                FROM epm.application_state s JOIN epm.application a USING(workspace_id,application_id)
                WHERE workspace_id=%s AND application_id=%s FOR SHARE OF s''',
                (scope.workspace_id, scope.application_id)).fetchone()
            if state is None or state['status'] != 'Active' or state['processing_mode'] != 'Active':
                raise ValueError('APPLICATION_NOT_WRITABLE')
            if state['commit_open']:
                raise ValueError('STALE_RECONSTRUCTION_SOURCE')
            normalized = compile_program(raw, state['commit_revision'], state['schema_epoch'])
            revisions = {k: state[k] for k in ('metadata_revision', 'data_revision', 'policy_revision')}
    extra = {k: normalized[k] for k in ('sourceCommitRevision', 'schemaEpoch')}
    token, digest = language._sign_preview(scope, FUNCTION, normalized, revisions, extra=extra)
    return {'languageVersion': 2, 'function': FUNCTION, 'previewToken': token,
            'programDigest': digest, 'revisionVector': revisions, 'workClass': 'long', **extra}


def submit(language, scope, raw, token, key, dependencies):
    reason = intent(raw)
    if (not isinstance(key, str) or not _KEY.fullmatch(key)
            or not isinstance(dependencies, tuple) or len(dependencies) > 16
            or any(not isinstance(d, str) or not _JOB_ID.fullmatch(d) for d in dependencies)
            or len(set(dependencies)) != len(dependencies)):
        raise ValueError('RECONSTRUCTION_REQUEST_INVALID')
    # Accepted intent can be replayed after token expiry, but never after grant
    # revocation, under altered dependencies, or with newly rebased source pins.
    with connect_postgres(language.dsn, row_factory=dict_row) as db:
        with db.transaction():
            PostgresNumericFactStore._set_scope(db, scope)
            PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
            access=PostgresAccessChecker.check_in_transaction(db, language.identity, scope, 'admin', function=FUNCTION)
            prior = db.execute('''SELECT * FROM epm.job WHERE workspace_id=%s AND application_id=%s
                AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',
                (scope.workspace_id, scope.application_id, language.identity.issuer,
                 language.identity.subject_id, key)).fetchone()
            if prior:
                normalized = decode_program(prior['normalized_program'])
                accepted_compiler, accepted_plan = compiler_for(normalized)
                signed = language._unpack_preview(scope, FUNCTION, token, allow_expired=True)
                signed_revisions = {k: prior['expected_' + k] for k in
                    ('metadata_revision', 'data_revision', 'policy_revision')}
                if (set(signed) != {'scope', 'identity', 'function', 'programDigest', 'revisions',
                        'expiresAt', 'sourceCommitRevision', 'schemaEpoch'}
                        or signed['programDigest'] != _canonical_digest(normalized)
                        or signed['sourceCommitRevision'] != normalized['sourceCommitRevision']
                        or signed['schemaEpoch'] != normalized['schemaEpoch']
                        or signed['revisions'] != signed_revisions):
                    raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
                auth_scope=_verify_job_replay_authorization(db,scope,
                    language.identity,prior,access=access,function_name=FUNCTION)
                descriptor=_job_request_descriptor(scope,language.identity,
                    function_name=FUNCTION,
                    program_digest=_canonical_digest(normalized),
                    compiler_version=accepted_compiler,plan_digest=accepted_plan,
                    revisions=(prior['expected_metadata_revision'],
                        prior['expected_data_revision'],prior['expected_policy_revision']),
                    resource_class='long',dependencies=dependencies,
                    authorization_scope_digest=auth_scope,
                    verified_groups=access.groups)
                if (normalized['reason'] != reason or prior['function_name'] != FUNCTION
                        or prior['compiler_version'] != accepted_compiler or prior['plan_digest'] != accepted_plan
                        or prior['program_digest'] != descriptor['programDigest']
                        or prior['resource_class'] != 'long'
                        or prior['request_digest'] != _canonical_digest(descriptor)):
                    raise ValueError('RECONSTRUCTION_IDEMPOTENCY_CONFLICT')
                return {'jobId': prior['job_id'], 'status': prior['status'], 'duplicate': True}
    payload = language._unpack_preview(scope, FUNCTION, token)
    if set(payload) != {'scope', 'identity', 'function', 'programDigest', 'revisions',
                        'expiresAt', 'sourceCommitRevision', 'schemaEpoch'}:
        raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
    normalized = compile_program(raw, payload['sourceCommitRevision'], payload['schemaEpoch'])
    if payload['programDigest'] != _canonical_digest(normalized):
        raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
    revisions = payload['revisions']
    return PostgresJobQueue(language.dsn, identity=language.identity).submit(scope,
        idempotency_key=key, function_name=FUNCTION, normalized_program=normalized,
        compiler_version=COMPILER, plan_digest=PLAN_DIGEST, resource_class='long',
        expected_metadata_revision=revisions['metadata_revision'],
        expected_data_revision=revisions['data_revision'], expected_policy_revision=revisions['policy_revision'],
        depends_on_job_ids=dependencies)


@contextmanager
def _execution_budget(deadline):
    try:
        with tool_execution_scope(deadline):
            yield
    except (ToolDeadlineExpired, psycopg.errors.QueryCanceled):
        raise ValueError('RECONSTRUCTION_EXECUTION_BUDGET') from None


@contextmanager
def _heartbeat(worker, claim):
    stop = threading.Event()
    failures = []
    def renew():
        while not stop.wait(5):
            try:
                worker.heartbeat(claim)
            except Exception as error:
                failures.append(error)
                return
    thread = threading.Thread(target=renew, name='epm-reconstruction-lease', daemon=True) if worker else None
    if thread:
        worker.heartbeat(claim)
        thread.start()
    try:
        yield failures
    finally:
        stop.set()
        if thread:
            thread.join(timeout=5)


class PostgresFactReconstructionPublisher:
    def __init__(self, dsn, *, identity, worker=None):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        assert_nonowner_role(dsn, 'epm_runtime', ('application_state', 'numeric_fact_event',
            'text_fact_event', 'line_detail_event', 'generic_fact_event'))
        self.dsn, self.identity, self.worker = dsn, identity, worker

    @lock_busy_boundary
    def publish(self, claim):
        if (not isinstance(claim, dict) or any(not isinstance(claim.get(k), str) or not claim[k]
                for k in ('workspace_id', 'application_id', 'job_id', 'claimant'))
                or not _JOB_ID.fullmatch(claim['job_id']) or type(claim.get('claim_generation')) is not int
                or claim['claim_generation'] < 1):
            raise ValueError('STALE_WORKER_FENCE')
        scope = ApplicationScope(claim['workspace_id'], claim['application_id'])
        deadline = time.monotonic() + EXECUTION_SECONDS
        if current_deadline() is not None:
            deadline = min(deadline, current_deadline())
        with _execution_budget(deadline), _heartbeat(self.worker, claim) as failures:
            with connect_postgres(self.dsn, row_factory=dict_row) as db:
                with db.transaction():
                    PostgresNumericFactStore._set_scope(db, scope)
                    PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                    PostgresAccessChecker.check_in_transaction(db, self.identity, scope, 'admin', function=FUNCTION)
                    configure_statement_timeout(db, 20000)
                    state = db.execute('''SELECT * FROM epm.application_state
                        WHERE workspace_id=%s AND application_id=%s''' +
                        ('' if claim.get('compiler_version') == COMPILER else ' FOR UPDATE'),
                        (scope.workspace_id, scope.application_id)).fetchone()
                    job = db.execute('''SELECT *,lease_until>clock_timestamp() AS lease_live FROM epm.job
                        WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',
                        (scope.workspace_id, scope.application_id, claim['job_id'])).fetchone()
                    if (not job or job['status'] != 'running' or not job['lease_live']
                            or job['claimant'] != claim['claimant']
                            or job['claim_generation'] != claim['claim_generation']
                            or job['issuer'] != self.identity.issuer or job['subject_id'] != self.identity.subject_id):
                        raise ValueError('STALE_WORKER_FENCE')
                    normalized = decode_program(job['normalized_program'])
                    compiler, plan_digest = compiler_for(normalized)
                    if (job['function_name'] != FUNCTION or job['compiler_version'] != compiler
                            or job['plan_digest'] != plan_digest
                            or job['program_digest'] != _canonical_digest(normalized)
                            or job['resource_class'] != 'long'):
                        raise ValueError('RECONSTRUCTION_JOB_INVALID')
                    if (state is None or state['processing_mode'] != 'Active' or state['commit_open']
                            or state['commit_revision'] != normalized['sourceCommitRevision']
                            or state['schema_epoch'] != normalized['schemaEpoch']):
                        raise ValueError('STALE_RECONSTRUCTION_SOURCE')
                    if any(state[k] != job['expected_' + k] for k in
                           ('metadata_revision', 'data_revision', 'policy_revision')):
                        raise ValueError('STALE_JOB_INPUT_REVISION')
                    # Native code alone validates and publishes derived values.
                    # V1 keeps its accepted atomic/20-second execution contract;
                    # V2 performs one bounded durable quantum per worker claim.
                    if failures:
                        raise ValueError('STALE_WORKER_FENCE')
                    configure_statement_timeout(db, 20000)
                    with _native_error_boundary():
                        statement = ('''SELECT epm.fact_projections_rebuild_step(%s,%s,%s,%s,%s) AS result'''
                            if normalized['version'] == 2 else
                            '''SELECT epm.fact_projections_rebuild(%s,%s,%s,%s,%s) AS result''')
                        result = db.execute(statement,
                            (scope.workspace_id, scope.application_id, claim['job_id'], claim['claimant'],
                             claim['claim_generation'])).fetchone()['result']
                    if (not isinstance(result, dict) or
                            (result.get('checkpoint') is True and
                             (normalized['version'] != 2 or result.get('status') != 'ready'))):
                        raise ValueError('RECONSTRUCTION_NATIVE_RESULT_INVALID')
                    return result


def catalog():
    schema = {'$schema': 'https://json-schema.org/draft/2020-12/schema', 'type': 'object',
        'additionalProperties': False, 'required': ['languageVersion', 'function', 'arguments'],
        'properties': {'languageVersion': {'const': 2}, 'function': {'const': FUNCTION},
            'arguments': {'type': 'object', 'additionalProperties': False, 'required': ['reason'],
                'properties': {'reason': {'type': 'string', 'minLength': 1, 'maxLength': 500}}}}}
    return {FUNCTION: {'mode': 'durable_write', 'permission': 'admin',
        'arguments': {'reason': '1–500 nonblank characters explaining derived-state recovery'},
        'result': 'jobId then durable checkpoints and atomic generation activation receipt; source history and original change IDs preserved',
        'previewRequired': True, 'idempotencyRequired': True, 'workClass': 'long',
        'programContract': {'programSchema': schema,
            'examples': [{'program': {'languageVersion': 2, 'function': FUNCTION,
                'arguments': {'reason': 'Recover current projections from sealed history'}}}],
            'semanticRules': ['Administrator permission is required at preview, admission, replay and publication.',
                'Reason is trimmed, nonblank and excludes NUL; arbitrary SQL or replacement values are forbidden.',
                'Preview pins commit revision, schema epoch and metadata/data/policy revisions without scanning facts.',
                'A stale source fails; accepted requests never silently rebase onto later business state.',
                'The fixed compiler builds hidden numeric, text, detail, opaque JSON and coordinate projections in bounded durable quanta.',
                'Only native certified generation activation publishes the complete replacement; checkpoints remain invisible to current readers.',
                'Source events, change IDs and data revision are retained; only commit revision advances.',
                'Each V2 quantum has a 20-second budget and preserves shorter deployment limits; accepted V1 jobs keep their 20-second total budget.'],
            'execution': {'scope': 'one authorized application; durable long worker queue',
                'compiler': COMPILER, 'planDigest': PLAN_DIGEST}}}}
