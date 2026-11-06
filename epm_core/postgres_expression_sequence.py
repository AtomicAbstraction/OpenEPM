"""Durable, bounded orchestration of published expression rules.

Each rule remains a separately fenced calculation job. The coordinator never
executes client code or cell loops; it admits the next fixed job only after the
prior generation is published and still current.
"""
from __future__ import annotations

import re
import uuid

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_calculation_status import published_input_status
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_expression import (compile_expression_program,
                                  expression_references)
from .postgres_expression_rules import (
    _active_members, bind_rule_calculation, member_parameter_names)
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout
from .postgres_sequence_dispatch import durable_sequence_identity,select_candidate


FUNCTION = 'rules.expression.sequence.run'
READ = 'rules.expression.sequence.read'
CANCEL = 'rules.expression.sequence.cancel'
_ID = re.compile(r'[A-Za-z0-9._-]{1,100}\Z')
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_SEQUENCE_ID = re.compile(r'[0-9a-f]{32}\Z')
_MANIFEST_EXTENSIONS = frozenset(('equityChain',
                                  'cashFlowReconciliation'))


def _manifest_extension(value: object) -> dict:
    if (not isinstance(value, dict) or len(value) != 1
            or not set(value) <= _MANIFEST_EXTENSIONS
            or not isinstance(next(iter(value.values())), dict)):
        raise ValueError('RULE_SEQUENCE_MANIFEST_EXTENSION_INVALID')
    return value


def _program(raw: object, function: str) -> dict:
    if (not isinstance(raw, dict)
            or set(raw) != {'languageVersion', 'function', 'arguments'}
            or type(raw['languageVersion']) is not int
            or raw['languageVersion'] != 2
            or raw['function'] != function
            or not isinstance(raw['arguments'], dict)):
        raise ValueError('V2_RULE_SEQUENCE_FUNCTION_INVALID')
    args = raw['arguments']
    if function in (READ, CANCEL):
        if (set(args) != {'sequenceId'}
                or not isinstance(args['sequenceId'], str)
                or not _SEQUENCE_ID.fullmatch(args['sequenceId'])):
            raise ValueError('V2_RULE_SEQUENCE_ARGUMENTS_INVALID')
        return args
    rules = args.get('ruleIds')
    if (set(args) not in ({'ruleIds'}, {'ruleIds', 'bindings'})
            or not isinstance(rules, list)
            or not 2 <= len(rules) <= 8
            or any(not isinstance(rule, str) or not _ID.fullmatch(rule)
                   for rule in rules)
            or len(set(rules)) != len(rules)):
        raise ValueError('V2_RULE_SEQUENCE_ARGUMENTS_INVALID')
    bindings = args.get('bindings', {})
    if (not isinstance(bindings, dict)
            or not set(bindings) <= set(rules)
            or any(not isinstance(values, dict)
                   for values in bindings.values())):
        raise ValueError('V2_RULE_SEQUENCE_ARGUMENTS_INVALID')
    return args


def _manifest(db, scope: ApplicationScope, rule_ids: list[str],
              metadata_revision: int, bindings: dict | None = None, *,
              include_bound_program: bool = False) -> dict:
    rows = db.execute('''SELECT p.rule_id,p.version,p.published_revision,
        v.program,v.program_digest,v.metadata_revision
        FROM epm.expression_rule_publication p
        JOIN epm.expression_rule_version v
          ON v.workspace_id=p.workspace_id
         AND v.application_id=p.application_id
         AND v.rule_id=p.rule_id AND v.version=p.version
        WHERE p.workspace_id=%s AND p.application_id=%s
          AND p.rule_id=ANY(%s::text[])''',
        (scope.workspace_id, scope.application_id, rule_ids)).fetchall()
    by_id = {row['rule_id']: row for row in rows}
    if set(by_id) != set(rule_ids):
        raise ValueError('RULE_SEQUENCE_RULE_UNPUBLISHED')
    steps = []
    bindings = bindings or {}
    for rule_id in rule_ids:
        row = by_id[rule_id]
        if row['metadata_revision'] != metadata_revision:
            raise ValueError('RULE_SEQUENCE_RULE_METADATA_STALE')
        if _canonical_digest(row['program']) != row['program_digest']:
            raise ValueError('RULE_SEQUENCE_RULE_DEFINITION_CORRUPT')
        bound, values = bind_rule_calculation(
            row['program'], bindings.get(rule_id))
        if values is None and rule_id in bindings:
            raise ValueError('RULE_SEQUENCE_BINDINGS_UNEXPECTED')
        plan = compile_expression_program(
            bound, expected_publication_revision=0)
        _active_members(db, scope, plan)
        step = {'ruleId': rule_id, 'version': row['version'],
                      'programDigest': row['program_digest'],
                      'publishedRevision': row['published_revision'],
                      'resultKey': plan.result_key,
                      'references': list(expression_references(plan.expression))}
        if include_bound_program:
            step['boundProgram'] = bound
        if values is not None:
            step['bindings'] = values
        names = member_parameter_names(row['program'])
        if names:
            step['memberParameters'] = names
        steps.append(step)
    keys = [step['resultKey'] for step in steps]
    if len(keys) != len(set(keys)):
        raise ValueError('RULE_SEQUENCE_RESULT_KEY_REPEATED')
    external = set()
    for index, step in enumerate(steps):
        earlier = set(keys[:index])
        later = set(keys[index:])
        for reference in step['references']:
            if reference in later:
                raise ValueError('RULE_SEQUENCE_FORWARD_OR_SELF_REFERENCE')
            if reference not in earlier:
                external.add(reference)
    publication_keys = sorted(external | set(keys))
    publications = db.execute('''SELECT result_key,generation_id,
        published_revision FROM epm.calculation_publication
        WHERE workspace_id=%s AND application_id=%s
          AND result_key=ANY(%s::text[])''',
        (scope.workspace_id, scope.application_id,
         publication_keys)).fetchall()
    by_key = {row['result_key']: row for row in publications}
    if any(key not in by_key for key in external):
        raise ValueError('RULE_SEQUENCE_EXTERNAL_INPUT_UNAVAILABLE')
    external_pins = [{'resultKey': key,
                      'generationId': by_key[key]['generation_id'],
                      'publishedRevision': by_key[key]['published_revision']}
                     for key in sorted(external)]
    if external_pins:
        status = published_input_status(
            db, scope, {'publishedInputs': external_pins})
        if status is None or not status['matchesAtRead']:
            raise ValueError('STALE_PUBLISHED_INPUT')
    for step in steps:
        current = by_key.get(step['resultKey'])
        step['expectedTargetRevision'] = (
            current['published_revision'] if current else 0)
    return {'steps': steps, 'externalInputs': external_pins}


def _current(db, scope: ApplicationScope, manifest: dict,
             revisions: dict, job_ids: list[str]) -> None:
    state = db.execute('''SELECT metadata_revision,data_revision,
        policy_revision,processing_mode FROM epm.application_state
        WHERE workspace_id=%s AND application_id=%s''',
        (scope.workspace_id, scope.application_id)).fetchone()
    if state is None or state['processing_mode'] != 'Active':
        raise ValueError('APPLICATION_NOT_WRITABLE')
    if any(state[f'{name}_revision'] != revisions[name]
           for name in ('metadata', 'data', 'policy')):
        raise ValueError('RULE_SEQUENCE_INPUT_REVISION_STALE')
    for step in manifest['steps']:
        row = db.execute('''SELECT p.version,p.published_revision,
            v.program_digest FROM epm.expression_rule_publication p
            JOIN epm.expression_rule_version v
              ON v.workspace_id=p.workspace_id
             AND v.application_id=p.application_id
             AND v.rule_id=p.rule_id AND v.version=p.version
            WHERE p.workspace_id=%s AND p.application_id=%s
              AND p.rule_id=%s''',
            (scope.workspace_id, scope.application_id,
             step['ruleId'])).fetchone()
        if (row is None or row['version'] != step['version']
                or row['published_revision'] != step['publishedRevision']
                or row['program_digest'] != step['programDigest']):
            raise ValueError('RULE_SEQUENCE_RULE_PUBLICATION_STALE')
    for pin in manifest['externalInputs']:
        row = db.execute('''SELECT generation_id,published_revision FROM
            epm.calculation_publication WHERE workspace_id=%s
            AND application_id=%s AND result_key=%s''',
            (scope.workspace_id, scope.application_id,
             pin['resultKey'])).fetchone()
        if (row is None or row['generation_id'] != pin['generationId']
                or row['published_revision'] != pin['publishedRevision']):
            raise ValueError('RULE_SEQUENCE_EXTERNAL_INPUT_STALE')
    if manifest['externalInputs']:
        status = published_input_status(
            db, scope, {'publishedInputs': manifest['externalInputs']})
        if status is None or not status['matchesAtRead']:
            raise ValueError('RULE_SEQUENCE_EXTERNAL_INPUT_STALE')
    for index, job_id in enumerate(job_ids):
        if index >= len(manifest['steps']):
            raise ValueError('RULE_SEQUENCE_JOB_HISTORY_INVALID')
        step = manifest['steps'][index]
        job = db.execute('''SELECT status FROM epm.job
            WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',
            (scope.workspace_id, scope.application_id, job_id)).fetchone()
        if job is None:
            raise ValueError('RULE_SEQUENCE_JOB_HISTORY_INVALID')
        if job['status'] == 'published':
            pointer = db.execute('''SELECT generation_id FROM
                epm.calculation_publication WHERE workspace_id=%s
                  AND application_id=%s AND result_key=%s''',
                (scope.workspace_id, scope.application_id,
                 step['resultKey'])).fetchone()
            if pointer is None or pointer['generation_id'] != job_id:
                raise ValueError('RULE_SEQUENCE_OUTPUT_REPUBLISHED')


class PostgresExpressionSequence:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 preview_secret: bytes):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        if not isinstance(preview_secret, bytes) or len(preview_secret) < 32:
            raise ValueError('A server-owned preview secret is required')
        self.dsn, self.identity = dsn, identity
        self.preview_secret = preview_secret

    def _authorization_scope_digest(self, db, scope: ApplicationScope, *,
                                    access=None) -> str:
        return resolve_effective_dimensional_scope(
            db, self.identity, scope, access=access,
            function=FUNCTION).scope_digest

    def _require_current_scope(self, db, scope: ApplicationScope,
                               sequence_id: str, *, access=None) -> None:
        row = db.execute('''SELECT authorization_scope_digest FROM
            epm.expression_rule_sequence WHERE workspace_id=%s
              AND application_id=%s AND sequence_id=%s''',
            (scope.workspace_id, scope.application_id,
             sequence_id)).fetchone()
        current = self._authorization_scope_digest(
            db, scope, access=access)
        if (row is None or row['authorization_scope_digest'] is None
                or row['authorization_scope_digest'] != current):
            raise ValueError('RULE_SEQUENCE_AUTHORIZATION_SCOPE_CHANGED')

    def preview(self, scope: ApplicationScope, raw: dict, *,
                manifest_extension: dict | None = None) -> dict:
        args = _program(raw, FUNCTION)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                state = db.execute('''SELECT metadata_revision,data_revision,
                    policy_revision,processing_mode FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s FOR SHARE''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None or state['processing_mode'] != 'Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'rule_run')
                manifest = _manifest(db, scope, args['ruleIds'],
                                     state['metadata_revision'],
                                     args.get('bindings'),
                                     include_bound_program=(
                                         manifest_extension is not None))
                if manifest_extension is not None:
                    manifest = {**manifest,
                                **_manifest_extension(manifest_extension)}
                revisions = {f'{name}_revision': state[f'{name}_revision']
                             for name in ('metadata', 'data', 'policy')}
        from .postgres_language_v2 import PostgresLanguageV2
        language = PostgresLanguageV2(
            self.dsn, identity=self.identity,
            preview_secret=self.preview_secret)
        token, digest = language._sign_preview(
            scope, FUNCTION, manifest, revisions)
        return {'languageVersion': 2, 'function': FUNCTION,
                'programDigest': digest, 'previewToken': token,
                'revisionVector': revisions,
                'steps': manifest['steps'],
                'externalInputs': manifest['externalInputs']}

    def submit(self, scope: ApplicationScope, raw: dict, *,
               preview_token: str, idempotency_key: str,
               manifest_extension: dict | None = None) -> dict:
        args = _program(raw, FUNCTION)
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(
                idempotency_key):
            raise ValueError('RULE_SEQUENCE_IDEMPOTENCY_KEY_INVALID')
        from .postgres_language_v2 import PostgresLanguageV2
        language = PostgresLanguageV2(
            self.dsn, identity=self.identity,
            preview_secret=self.preview_secret)
        payload = language._unpack_preview(scope, FUNCTION, preview_token)
        if self.identity.issued_at is not None:
            authority_kind = 'HumanToken'
        elif self.identity.issuer.startswith('urn:openepm:'):
            authority_kind = 'Technical'
        else:
            raise ValueError('DURABLE_HUMAN_TOKEN_ISSUED_AT_REQUIRED')
        request_digest = _canonical_digest({
            'scope': [scope.workspace_id, scope.application_id],
            'identity': [self.identity.issuer, self.identity.subject_id],
            'tokenIssuedAt': self.identity.issued_at,
            'program': raw})
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                state = db.execute('''SELECT metadata_revision,data_revision,
                    policy_revision,processing_mode FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None or state['processing_mode'] != 'Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'rule_run')
                authorization_scope_digest = self._authorization_scope_digest(
                    db, scope, access=access)
                prior = db.execute('''SELECT sequence_id,request_digest,status,
                    verified_groups,authorization_scope_digest
                    FROM epm.expression_rule_sequence WHERE workspace_id=%s
                    AND application_id=%s AND issuer=%s AND subject_id=%s
                    AND idempotency_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     self.identity.issuer, self.identity.subject_id,
                     idempotency_key)).fetchone()
                if prior:
                    if prior['request_digest'] != request_digest:
                        raise ValueError('RULE_SEQUENCE_IDEMPOTENCY_CONFLICT')
                    if (tuple(prior['verified_groups']) != self.identity.groups
                            or prior['authorization_scope_digest'] is None
                            or prior['authorization_scope_digest'] !=
                               authorization_scope_digest):
                        raise ValueError(
                            'RULE_SEQUENCE_AUTHORIZATION_SCOPE_CHANGED')
                    return {'sequenceId': prior['sequence_id'],
                            'status': prior['status'], 'duplicate': True}
                revisions = {f'{name}_revision': state[f'{name}_revision']
                             for name in ('metadata', 'data', 'policy')}
                manifest = _manifest(db, scope, args['ruleIds'],
                                     state['metadata_revision'],
                                     args.get('bindings'),
                                     include_bound_program=(
                                         manifest_extension is not None))
                if manifest_extension is not None:
                    manifest = {**manifest,
                                **_manifest_extension(manifest_extension)}
                if (set(payload) != {'scope', 'identity', 'function',
                                     'programDigest', 'revisions', 'expiresAt'}
                        or payload['programDigest'] != _canonical_digest(manifest)
                        or payload['revisions'] != revisions):
                    raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
                sequence_id = uuid.uuid4().hex
                db.execute('''INSERT INTO epm.expression_rule_sequence
                    (workspace_id,application_id,sequence_id,issuer,subject_id,
                     idempotency_key,request_digest,manifest,
                     expected_metadata_revision,expected_data_revision,
                     expected_policy_revision,verified_groups,
                     authorization_scope_digest,token_issued_at,authority_kind)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id, scope.application_id, sequence_id,
                     self.identity.issuer, self.identity.subject_id,
                     idempotency_key, request_digest, Jsonb(manifest),
                     revisions['metadata_revision'],
                     revisions['data_revision'],
                     revisions['policy_revision'],list(self.identity.groups),
                     authorization_scope_digest,self.identity.issued_at,
                     authority_kind))
                return {'sequenceId': sequence_id,
                        'status': 'accepted', 'duplicate': False}

    def read(self, scope: ApplicationScope, raw: dict) -> dict:
        args = _program(raw, READ)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                row = db.execute('''SELECT sequence_id,issuer,subject_id,
                    manifest,status,current_step,job_ids,error_code,
                    created_at,updated_at FROM epm.expression_rule_sequence
                    WHERE workspace_id=%s AND application_id=%s
                      AND sequence_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     args['sequenceId'])).fetchone()
                if (row is None or (row['issuer'], row['subject_id']) !=
                        (self.identity.issuer, self.identity.subject_id)):
                    raise ValueError('RULE_SEQUENCE_UNAVAILABLE')
                self._require_current_scope(
                    db, scope, row['sequence_id'], access=access)
                return {'sequenceId': row['sequence_id'],
                        'status': row['status'],
                        'currentStep': row['current_step'],
                        'stepCount': len(row['manifest']['steps']),
                        'jobIds': row['job_ids'],
                        'errorCode': row['error_code'],
                        'createdAt': row['created_at'].isoformat(),
                        'updatedAt': row['updated_at'].isoformat()}

    def cancel(self, scope: ApplicationScope, raw: dict, *,
               _allow_application_admin: bool = False) -> dict:
        args = _program(raw, CANCEL)
        if not isinstance(_allow_application_admin, bool):
            raise ValueError('RULE_SEQUENCE_CANCEL_POLICY_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000)
                configure_lock_wait(db)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(db,self.identity,scope,
                    'admin' if _allow_application_admin else 'write')
                row = db.execute('''SELECT issuer,subject_id,status,
                    current_step,job_ids,manifest
                    FROM epm.expression_rule_sequence
                    WHERE workspace_id=%s AND application_id=%s
                      AND sequence_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id,
                     args['sequenceId'])).fetchone()
                if (row is None or (not _allow_application_admin and
                        (row['issuer'], row['subject_id']) !=
                        (self.identity.issuer, self.identity.subject_id))):
                    raise ValueError('RULE_SEQUENCE_UNAVAILABLE')
                if row['status'] not in ('accepted', 'running'):
                    result={'sequenceId':args['sequenceId'],'status':row['status']}
                    if _allow_application_admin:
                        result['committedEffectsRemain']=(
                            row['current_step']>0 or row['status']=='published')
                    return result
                job_ids = list(row['job_ids'])
                current = row['current_step']
                steps = row['manifest']['steps']
                if (current >= len(steps) or len(job_ids) < current
                        or len(job_ids) > current + 1):
                    raise ValueError('RULE_SEQUENCE_JOB_HISTORY_INVALID')
                status = 'cancelled'
                error_code = None
                job = None
                if len(job_ids) > current:
                    job = db.execute('''SELECT job_id,status,error_code,
                        normalized_program FROM epm.job
                        WHERE workspace_id=%s AND application_id=%s
                          AND job_id=%s FOR UPDATE''',
                        (scope.workspace_id, scope.application_id,
                         job_ids[current])).fetchone()
                    if job is None:
                        raise ValueError('RULE_SEQUENCE_JOB_HISTORY_INVALID')
                else:
                    job = db.execute('''SELECT job_id,status,error_code,
                        normalized_program FROM epm.job
                        WHERE workspace_id=%s AND application_id=%s
                          AND issuer=%s AND subject_id=%s
                          AND idempotency_key=%s FOR UPDATE''',
                        (scope.workspace_id, scope.application_id,
                         row['issuer'], row['subject_id'],
                         f'rule-seq-{args["sequenceId"]}-{current}')).fetchone()
                    if job:
                        job_ids.append(job['job_id'])
                if job:
                    pin = job['normalized_program'].get('savedRule')
                    if (pin is None or any(pin.get(key) != steps[current][key]
                        for key in ('ruleId', 'version', 'programDigest',
                                    'publishedRevision'))):
                        raise ValueError('RULE_SEQUENCE_ADOPTED_JOB_MISMATCH')
                    if job['status'] in ('accepted', 'ready',
                                         'running', 'staged'):
                        job_status = ('cancelled' if job['status'] in
                                      ('accepted', 'ready') else
                                      'cancel_requested')
                        db.execute('''UPDATE epm.job SET status=%s,
                            claim_generation=claim_generation+1,
                            claimant=NULL,lease_until=NULL,
                            updated_at=transaction_timestamp()
                            WHERE workspace_id=%s AND application_id=%s
                              AND job_id=%s''',
                            (job_status, scope.workspace_id,
                             scope.application_id, job_ids[current]))
                        status = 'cancel_requested'
                    elif job['status'] == 'cancel_requested':
                        status = 'cancel_requested'
                    elif job['status'] == 'published':
                        current += 1
                        status = ('published' if current == len(steps)
                                  else 'cancelled')
                    elif job['status'] in ('failed', 'needs_inspection'):
                        status = 'failed'
                        error_code = (job['error_code'] or
                                      'RULE_SEQUENCE_STEP_FAILED')
                db.execute('''UPDATE epm.expression_rule_sequence
                    SET status=%s,current_step=%s,job_ids=%s,error_code=%s,
                        updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                      AND sequence_id=%s''',
                    (status, current, Jsonb(job_ids), error_code,
                     scope.workspace_id, scope.application_id,
                     args['sequenceId']))
                result={'sequenceId':args['sequenceId'],'status':status,
                        'currentStep':current}
                if _allow_application_admin:
                    result['committedEffectsRemain']=(
                        current>0 or status=='published')
                return result

    @classmethod
    def request_cancel_as_task_controller(cls,dsn,*,identity,scope,sequence_id):
        """Use native sequence cancellation with current administrator policy."""
        if (not isinstance(dsn,str) or not dsn
         or not isinstance(identity,VerifiedIdentity)
         or not isinstance(scope,ApplicationScope)
         or not isinstance(sequence_id,str) or not _SEQUENCE_ID.fullmatch(sequence_id)):
            raise ValueError('RULE_SEQUENCE_UNAVAILABLE')
        controller=object.__new__(cls)
        controller.dsn,controller.identity=dsn,identity
        controller.preview_secret=None
        return controller.cancel(scope,{'languageVersion':2,'function':CANCEL,
            'arguments':{'sequenceId':sequence_id}},
            _allow_application_admin=True)


class PostgresExpressionSequenceCoordinator:
    """Advance one eligible sequence step under a durable row claim."""

    def __init__(self, *, worker_dsn: str, runtime_dsn: str,
                 preview_secret: bytes):
        if (not isinstance(worker_dsn, str) or not worker_dsn
                or not isinstance(runtime_dsn, str) or not runtime_dsn
                or not isinstance(preview_secret, bytes)
                or len(preview_secret) < 32):
            raise ValueError('Rule sequence coordinator credentials required')
        self.worker_dsn = worker_dsn
        self.runtime_dsn = runtime_dsn
        self._selection_cursor = None
        self.preview_secret = preview_secret

    def advance_once(self, *, scope: ApplicationScope | None = None) -> dict | None:
        if scope is not None and not isinstance(scope, ApplicationScope):
            raise ValueError('A valid application scope is required')
        with connect_postgres(self.worker_dsn, row_factory=dict_row) as worker:
            with worker.transaction():
                configure_lock_wait(worker)
                row, self._selection_cursor = select_candidate(
                    worker, self.runtime_dsn, 'expression_rule_sequence', scope, self._selection_cursor)
                if row is None:
                    return None
                scope = ApplicationScope(row['workspace_id'],
                                         row['application_id'])
                identity = durable_sequence_identity(row)
                manifest = row['manifest']
                job_ids = list(row['job_ids'])
                step_index = row['current_step']
                revisions = {
                    'metadata': row['expected_metadata_revision'],
                    'data': row['expected_data_revision'],
                    'policy': row['expected_policy_revision']}
                if row['status'] == 'cancel_requested':
                    job = None
                    if len(job_ids) > step_index:
                        job = worker.execute('''SELECT status FROM epm.job
                            WHERE workspace_id=%s AND application_id=%s
                              AND job_id=%s''',
                            (scope.workspace_id, scope.application_id,
                             job_ids[step_index])).fetchone()
                    if job is None or job['status'] in (
                            'published', 'failed', 'cancelled',
                            'needs_inspection'):
                        worker.execute('''UPDATE epm.expression_rule_sequence
                            SET status='cancelled',
                                updated_at=transaction_timestamp()
                            WHERE workspace_id=%s AND application_id=%s
                              AND sequence_id=%s''',
                            (scope.workspace_id, scope.application_id,
                             row['sequence_id']))
                        return {'sequenceId': row['sequence_id'],
                                'status': 'cancelled'}
                    return {'sequenceId': row['sequence_id'],
                            'status': 'cancel_requested'}
                existing = None
                if len(job_ids) <= step_index:
                    idem = f'rule-seq-{row["sequence_id"]}-{step_index}'
                    existing = worker.execute('''SELECT job_id,status,
                        function_name,program_digest,normalized_program
                        FROM epm.job
                        WHERE workspace_id=%s AND application_id=%s
                          AND issuer=%s AND subject_id=%s
                          AND idempotency_key=%s''',
                        (scope.workspace_id, scope.application_id,
                         identity.issuer, identity.subject_id,
                         idem)).fetchone()
                try:
                    if len(job_ids) > step_index:
                        current_job = worker.execute('''SELECT status,error_code
                            FROM epm.job WHERE workspace_id=%s
                            AND application_id=%s AND job_id=%s''',
                            (scope.workspace_id, scope.application_id,
                             job_ids[step_index])).fetchone()
                        if current_job is None:
                            raise ValueError('RULE_SEQUENCE_JOB_HISTORY_INVALID')
                        if current_job['status'] in (
                                'failed', 'cancelled', 'needs_inspection'):
                            raise ValueError(current_job['error_code'] or
                                             'RULE_SEQUENCE_STEP_FAILED')
                        if (current_job['status'] == 'published'
                                and step_index + 1 == len(manifest['steps'])):
                            worker.execute('''UPDATE epm.expression_rule_sequence
                                SET current_step=%s,status='published',
                                    updated_at=transaction_timestamp()
                                WHERE workspace_id=%s AND application_id=%s
                                  AND sequence_id=%s''',
                                (step_index + 1, scope.workspace_id,
                                 scope.application_id, row['sequence_id']))
                            return {'sequenceId': row['sequence_id'],
                                    'status': 'published',
                                    'currentStep': step_index + 1}
                    if existing is not None:
                        step = manifest['steps'][step_index]
                        normalized = existing['normalized_program']
                        pin = normalized.get('savedRule')
                        if (existing['function_name'] !=
                                'facts.expression.calculate'
                            or existing['program_digest'] !=
                                _canonical_digest(normalized)
                            or normalized.get('resultKey') != step['resultKey']
                            or normalized.get('expectedPublicationRevision') !=
                                step['expectedTargetRevision']
                            or pin is None
                            or pin.get('bindings') != step.get('bindings')
                            or pin.get('memberParameters', []) !=
                                step.get('memberParameters', [])
                            or any(pin.get(key) != step[key]
                            for key in ('ruleId','version','programDigest',
                                        'publishedRevision'))):
                            raise ValueError('RULE_SEQUENCE_ADOPTED_JOB_MISMATCH')
                        if existing['status'] in (
                                'published', 'failed', 'cancelled',
                                'needs_inspection'):
                            job_ids.append(existing['job_id'])
                            worker.execute('''UPDATE epm.expression_rule_sequence
                                SET job_ids=%s,status='running',
                                    updated_at=transaction_timestamp()
                                WHERE workspace_id=%s AND application_id=%s
                                  AND sequence_id=%s''',
                                (Jsonb(job_ids), scope.workspace_id,
                                 scope.application_id, row['sequence_id']))
                            return {'sequenceId': row['sequence_id'],
                                    'status': 'running',
                                    'currentStep': step_index,
                                    'jobId': existing['job_id']}
                    with connect_postgres(self.runtime_dsn,
                                         row_factory=dict_row) as runtime:
                        with runtime.transaction():
                            PostgresNumericFactStore._set_scope(runtime, scope)
                            PostgresAccessChecker.check_in_transaction(
                                runtime, identity, scope, 'write')
                            access = PostgresAccessChecker.check_in_transaction(
                                runtime, identity, scope, 'rule_run')
                            current_scope = resolve_effective_dimensional_scope(
                                runtime, identity, scope, access=access,
                                function=FUNCTION).scope_digest
                            if (row['authorization_scope_digest'] is None
                                    or row['authorization_scope_digest'] !=
                                       current_scope):
                                raise ValueError(
                                    'RULE_SEQUENCE_AUTHORIZATION_SCOPE_CHANGED')
                            _current(runtime, scope, manifest,
                                     revisions, job_ids)
                            if len(job_ids) <= step_index and existing is None:
                                step = manifest['steps'][step_index]
                                target = runtime.execute('''SELECT
                                    published_revision FROM
                                    epm.calculation_publication
                                    WHERE workspace_id=%s
                                      AND application_id=%s
                                      AND result_key=%s''',
                                    (scope.workspace_id, scope.application_id,
                                     step['resultKey'])).fetchone()
                                observed = (target['published_revision']
                                            if target else 0)
                                if observed != step['expectedTargetRevision']:
                                    raise ValueError(
                                        'RULE_SEQUENCE_TARGET_REPUBLISHED')
                    if len(job_ids) > step_index:
                        if current_job['status'] != 'published':
                            return {'sequenceId': row['sequence_id'],
                                    'status': row['status'],
                                    'currentStep': step_index}
                        step_index += 1
                        status = ('published' if step_index ==
                                  len(manifest['steps']) else 'running')
                        worker.execute('''UPDATE epm.expression_rule_sequence
                            SET current_step=%s,status=%s,
                            updated_at=transaction_timestamp()
                            WHERE workspace_id=%s AND application_id=%s
                              AND sequence_id=%s''',
                            (step_index, status, scope.workspace_id,
                             scope.application_id, row['sequence_id']))
                        return {'sequenceId': row['sequence_id'],
                                'status': status, 'currentStep': step_index}
                    step = manifest['steps'][step_index]
                    if existing:
                        job_id = existing['job_id']
                    else:
                        from .postgres_language_v2 import PostgresLanguageV2
                        language = PostgresLanguageV2(
                            self.runtime_dsn, identity=identity,
                            preview_secret=self.preview_secret)
                        program = {'languageVersion': 2,
                                   'function': 'rules.expression.run',
                                   'arguments': {
                                       'ruleId': step['ruleId'],
                                       **({'bindings': step['bindings']}
                                          if 'bindings' in step else {})}}
                        preview = language.preview(scope, program)
                        # Preview runs after the earlier validation transaction.
                        # Preserve sequence pins across that window; submit
                        # rechecks the signed preview in its admission transaction.
                        if preview['revisionVector'] != {
                                f'{name}_revision': revisions[name]
                                for name in ('metadata', 'data', 'policy')}:
                            raise ValueError('RULE_SEQUENCE_INPUT_REVISION_STALE')
                        if preview['expectedPublicationRevision'] != (
                                step['expectedTargetRevision']):
                            raise ValueError('RULE_SEQUENCE_TARGET_REPUBLISHED')
                        external = {pin['resultKey']: pin
                                    for pin in manifest['externalInputs']}
                        internal = {manifest['steps'][index]['resultKey']: job_id
                                    for index, job_id in enumerate(job_ids)}
                        for dependency in preview['publishedInputs']:
                            key = dependency['resultKey']
                            if key in external:
                                if dependency != external[key]:
                                    raise ValueError('RULE_SEQUENCE_EXTERNAL_INPUT_STALE')
                            elif dependency['generationId'] != internal.get(key):
                                raise ValueError('RULE_SEQUENCE_OUTPUT_REPUBLISHED')
                        pin = preview['savedRule']
                        if any(pin[key] != step[key]
                               for key in ('ruleId','version','programDigest',
                                           'publishedRevision')):
                            raise ValueError('RULE_SEQUENCE_RULE_PUBLICATION_STALE')
                        submitted = language.submit(
                            scope, program,
                            preview_token=preview['previewToken'],
                            idempotency_key=idem)
                        job_id = submitted['jobId']
                    job_ids.append(job_id)
                    worker.execute('''UPDATE epm.expression_rule_sequence
                        SET job_ids=%s,status='running',
                            updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                          AND sequence_id=%s''',
                        (Jsonb(job_ids), scope.workspace_id,
                         scope.application_id, row['sequence_id']))
                    return {'sequenceId': row['sequence_id'],
                            'status': 'running',
                            'currentStep': step_index, 'jobId': job_id}
                except ValueError as error:
                    reason = str(error)
                    if reason == 'JOB_AUTHORIZATION_SCOPE_CHANGED':
                        reason = 'RULE_SEQUENCE_AUTHORIZATION_SCOPE_CHANGED'
                    code = (reason if re.fullmatch(
                        r'[A-Z][A-Z0-9_]{2,127}', reason)
                        else 'RULE_SEQUENCE_VALIDATION_FAILED')
                    worker.execute('''UPDATE epm.expression_rule_sequence
                        SET status='failed',error_code=%s,
                            updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                          AND sequence_id=%s''',
                        (code, scope.workspace_id, scope.application_id,
                         row['sequence_id']))
                    return {'sequenceId': row['sequence_id'],
                            'status': 'failed', 'errorCode': code,
                            'currentStep': step_index}
