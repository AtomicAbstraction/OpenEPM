"""Durable ordering of bounded, explicit multilevel Full aggregations.

The sequence owns ordering and recovery, not accounting decisions. Each stage
is previewed, admitted and published by the existing fixed Full core. Results
remain Unreviewed until a supported policy pack and close protocol exist.
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
from .postgres_consolidation_aggregate import (
    FUNCTION as AGGREGATE, compile_full_aggregate, validate_full_aggregate)
from .postgres_jobs import _canonical_digest
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout
from .postgres_sequence_dispatch import durable_sequence_identity,select_candidate


FUNCTION = 'consolidation.full.sequence.run'
READ = 'consolidation.full.sequence.read'
CANCEL = 'consolidation.full.sequence.cancel'
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_SEQUENCE_ID = re.compile(r'[0-9a-f]{32}\Z')


def _program(raw: object, function: str) -> dict:
    if (not isinstance(raw, dict)
            or set(raw) != {'languageVersion', 'function', 'arguments'}
            or type(raw['languageVersion']) is not int
            or raw['languageVersion'] != 2 or raw['function'] != function
            or not isinstance(raw['arguments'], dict)):
        raise ValueError('FULL_SEQUENCE_PROGRAM_INVALID')
    args = raw['arguments']
    if function in (READ, CANCEL):
        if (set(args) != {'sequenceId'}
                or not isinstance(args['sequenceId'], str)
                or not _SEQUENCE_ID.fullmatch(args['sequenceId'])):
            raise ValueError('FULL_SEQUENCE_ARGUMENTS_INVALID')
        return args
    if (set(args) != {'steps'} or not isinstance(args['steps'], list)
            or not 2 <= len(args['steps']) <= 8):
        raise ValueError('FULL_SEQUENCE_ARGUMENTS_INVALID')
    used = []
    keys = set()
    for index, step in enumerate(args['steps']):
        if (not isinstance(step, dict)
                or set(step) != {'program', 'publishedChildrenFromSteps'}
                or not isinstance(step['publishedChildrenFromSteps'], list)
                or len(step['publishedChildrenFromSteps']) > 8):
            raise ValueError('FULL_SEQUENCE_STEP_INVALID')
        plan = compile_full_aggregate(step['program'],
                                      expected_publication_revision=0)
        if plan.published_children or 'publishedChildren' in (
                step['program']['arguments']):
            raise ValueError('FULL_SEQUENCE_EXTERNAL_CHILD_PIN_UNSUPPORTED')
        if plan.result_key in keys:
            raise ValueError('FULL_SEQUENCE_RESULT_KEY_REPEATED')
        keys.add(plan.result_key)
        relationships = set()
        for dependency in step['publishedChildrenFromSteps']:
            if (not isinstance(dependency, dict)
                    or set(dependency) != {'relationshipId', 'stepIndex'}
                    or not isinstance(dependency['relationshipId'], str)
                    or dependency['relationshipId'] not in plan.relationship_ids
                    or dependency['relationshipId'] in relationships
                    or type(dependency['stepIndex']) is not int
                    or not 0 <= dependency['stepIndex'] < index):
                raise ValueError('FULL_SEQUENCE_DEPENDENCY_INVALID')
            relationships.add(dependency['relationshipId'])
            used.append(dependency['stepIndex'])
    if set(used) != set(range(len(args['steps']) - 1)) or len(used) != len(set(used)):
        raise ValueError('FULL_SEQUENCE_NOT_ONE_TREE')
    return args


def _manifest(db, scope: ApplicationScope, steps: list[dict]) -> dict:
    entity_axes = db.execute('''SELECT dimension_id FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active'
          AND model_role='Entity' ''',
        (scope.workspace_id, scope.application_id)).fetchall()
    if len(entity_axes) != 1:
        raise ValueError('FULL_SEQUENCE_ENTITY_ROLE_REQUIRED')
    entity_axis = entity_axes[0]['dimension_id']
    normalized = []
    for index, step in enumerate(steps):
        program = step['program']
        plan = compile_full_aggregate(program,
                                      expected_publication_revision=0)
        parent = dict(plan.parent_members)
        if entity_axis not in parent:
            raise ValueError('FULL_SEQUENCE_ENTITY_COORDINATE_REQUIRED')
        for dependency in step['publishedChildrenFromSteps']:
            earlier = normalized[dependency['stepIndex']]
            earlier_parent = earlier['program']['arguments']['parentMembers']
            if (plan.source_layer != earlier['program']['arguments']['sourceLayer']
                    or {key: value for key, value in parent.items()
                        if key != entity_axis} !=
                       {key: value for key, value in earlier_parent.items()
                        if key != entity_axis}):
                raise ValueError('FULL_SEQUENCE_STAGE_OR_GRAIN_MISMATCH')
            edge = db.execute('''SELECT 1 FROM epm.relationship
                WHERE workspace_id=%s AND application_id=%s
                  AND dimension_id=%s AND relationship_id=%s
                  AND parent_member_id=%s AND child_member_id=%s
                  AND status='Active' ''',
                (scope.workspace_id, scope.application_id, entity_axis,
                 dependency['relationshipId'], parent[entity_axis],
                 earlier_parent[entity_axis])).fetchone()
            if not edge:
                raise ValueError('FULL_SEQUENCE_DEPENDENCY_EDGE_MISMATCH')
        pointer = db.execute('''SELECT published_revision FROM
            epm.calculation_publication WHERE workspace_id=%s
              AND application_id=%s AND result_key=%s''',
            (scope.workspace_id, scope.application_id,
             plan.result_key)).fetchone()
        if not step['publishedChildrenFromSteps']:
            validate_full_aggregate(db, scope, plan)
        normalized.append({
            'program': program,
            'resultKey': plan.result_key,
            'expectedTargetRevision': (pointer['published_revision']
                                       if pointer else 0),
            'publishedChildrenFromSteps': sorted(
                step['publishedChildrenFromSteps'],
                key=lambda item: (item['relationshipId'], item['stepIndex']))})
    return {'steps': normalized, 'entityAxis': entity_axis,
            'accountingPolicyStatus': 'Unreviewed'}


def _step_program(db, scope: ApplicationScope, manifest: dict,
                  job_ids: list[str], index: int) -> dict:
    step = manifest['steps'][index]
    program = step['program']
    pins = []
    for dependency in step['publishedChildrenFromSteps']:
        prior = dependency['stepIndex']
        if prior >= len(job_ids):
            raise ValueError('FULL_SEQUENCE_DEPENDENCY_NOT_PUBLISHED')
        earlier = manifest['steps'][prior]
        pointer = db.execute('''SELECT generation_id,published_revision
            FROM epm.calculation_publication WHERE workspace_id=%s
              AND application_id=%s AND result_key=%s''',
            (scope.workspace_id, scope.application_id,
             earlier['resultKey'])).fetchone()
        if pointer is None or pointer['generation_id'] != job_ids[prior]:
            raise ValueError('FULL_SEQUENCE_CHILD_REPUBLISHED')
        pins.append({'relationshipId': dependency['relationshipId'],
                     'resultKey': earlier['resultKey'],
                     'generationId': job_ids[prior],
                     'publishedRevision': pointer['published_revision']})
    return {**program, 'arguments': {**program['arguments'],
                                     **({'publishedChildren': pins}
                                        if pins else {})}}


def _verify_adopted_job(manifest: dict, job_ids: list[str],
                        index: int, job: dict) -> None:
    """A deterministic idempotency key must not adopt an unrelated job."""
    step = manifest['steps'][index]
    actual = job['normalized_program']
    expected = compile_full_aggregate(step['program'],
        expected_publication_revision=
        step['expectedTargetRevision']).normalized_program
    if (job['function_name'] != AGGREGATE
            or not isinstance(actual, dict)
            or job['program_digest'] != _canonical_digest(actual)
            or {key: value for key, value in actual.items()
                if key != 'publishedChildren'} != expected):
        raise ValueError('FULL_SEQUENCE_ADOPTED_JOB_MISMATCH')
    pins = actual.get('publishedChildren', [])
    dependencies = step['publishedChildrenFromSteps']
    if (not isinstance(pins, list) or len(pins) != len(dependencies)):
        raise ValueError('FULL_SEQUENCE_ADOPTED_JOB_MISMATCH')
    for pin, dependency in zip(pins, dependencies):
        prior = dependency['stepIndex']
        if (prior >= len(job_ids) or not isinstance(pin, dict)
                or set(pin) != {'relationshipId', 'resultKey',
                                'generationId', 'publishedRevision'}
                or pin['relationshipId'] != dependency['relationshipId']
                or pin['resultKey'] != manifest['steps'][prior]['resultKey']
                or pin['generationId'] != job_ids[prior]
                or type(pin['publishedRevision']) is not int
                or pin['publishedRevision'] <= 0):
            raise ValueError('FULL_SEQUENCE_ADOPTED_JOB_MISMATCH')


def _current(db, scope: ApplicationScope, manifest: dict,
             revisions: dict, job_ids: list[str]) -> None:
    state = db.execute('''SELECT metadata_revision,data_revision,
        policy_revision,processing_mode FROM epm.application_state
        WHERE workspace_id=%s AND application_id=%s FOR SHARE''',
        (scope.workspace_id, scope.application_id)).fetchone()
    if state is None or state['processing_mode'] != 'Active':
        raise ValueError('APPLICATION_NOT_WRITABLE')
    if any(state[f'{kind}_revision'] != revisions[kind]
           for kind in ('metadata', 'data', 'policy')):
        raise ValueError('FULL_SEQUENCE_INPUT_REVISION_STALE')
    for index, job_id in enumerate(job_ids):
        step = manifest['steps'][index]
        job = db.execute('''SELECT status FROM epm.job WHERE
            workspace_id=%s AND application_id=%s AND job_id=%s''',
            (scope.workspace_id, scope.application_id, job_id)).fetchone()
        if job is None:
            raise ValueError('FULL_SEQUENCE_JOB_HISTORY_INVALID')
        if job['status'] == 'published':
            pointer = db.execute('''SELECT generation_id FROM
                epm.calculation_publication WHERE workspace_id=%s
                  AND application_id=%s AND result_key=%s''',
                (scope.workspace_id, scope.application_id,
                 step['resultKey'])).fetchone()
            if pointer is None or pointer['generation_id'] != job_id:
                raise ValueError('FULL_SEQUENCE_CHILD_REPUBLISHED')


class PostgresFullAggregateSequence:
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

    def preview(self, scope: ApplicationScope, raw: dict) -> dict:
        args = _program(raw, FUNCTION)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT metadata_revision,data_revision,
                    policy_revision,processing_mode FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s FOR SHARE''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None or state['processing_mode'] != 'Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write', function=FUNCTION)
                manifest = _manifest(db, scope, args['steps'])
                revisions = {f'{kind}_revision': state[f'{kind}_revision']
                             for kind in ('metadata', 'data', 'policy')}
        from .postgres_language_v2 import PostgresLanguageV2
        language = PostgresLanguageV2(
            self.dsn, identity=self.identity,
            preview_secret=self.preview_secret)
        token, digest = language._sign_preview(
            scope, FUNCTION, manifest, revisions)
        return {'languageVersion': 2, 'function': FUNCTION,
                'previewToken': token, 'programDigest': digest,
                'revisionVector': revisions, 'steps': manifest['steps'],
                'accountingPolicyStatus': 'Unreviewed'}

    def submit(self, scope: ApplicationScope, raw: dict, *,
               preview_token: str, idempotency_key: str) -> dict:
        args = _program(raw, FUNCTION)
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(
                idempotency_key):
            raise ValueError('FULL_SEQUENCE_IDEMPOTENCY_KEY_INVALID')
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
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT metadata_revision,data_revision,
                    policy_revision,processing_mode FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None or state['processing_mode'] != 'Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write', function=FUNCTION)
                authorization_scope_digest = resolve_effective_dimensional_scope(
                    db, self.identity, scope,
                    function=FUNCTION).scope_digest
                request_digest = _canonical_digest({
                    'scope': [scope.workspace_id, scope.application_id],
                    'identity': [self.identity.issuer,self.identity.subject_id],
                    'tokenIssuedAt': self.identity.issued_at,
                    'verifiedGroups': list(self.identity.groups),
                    'authorizationScopeDigest':authorization_scope_digest,
                    'program': raw})
                prior = db.execute('''SELECT sequence_id,request_digest,status,
                    verified_groups,authorization_scope_digest
                    FROM epm.full_aggregate_sequence WHERE workspace_id=%s
                    AND application_id=%s AND issuer=%s AND subject_id=%s
                    AND idempotency_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     self.identity.issuer, self.identity.subject_id,
                     idempotency_key)).fetchone()
                if prior:
                    if prior['request_digest'] != request_digest:
                        raise ValueError('FULL_SEQUENCE_IDEMPOTENCY_CONFLICT')
                    if (tuple(prior['verified_groups'] or ()) !=
                            self.identity.groups
                            or prior['authorization_scope_digest'] !=
                               authorization_scope_digest):
                        raise ValueError(
                            'FULL_SEQUENCE_AUTHORIZATION_SCOPE_CHANGED')
                    return {'sequenceId': prior['sequence_id'],
                            'status': prior['status'], 'duplicate': True}
                revisions = {f'{kind}_revision': state[f'{kind}_revision']
                             for kind in ('metadata', 'data', 'policy')}
                manifest = _manifest(db, scope, args['steps'])
                if (set(payload) != {'scope', 'identity', 'function',
                                     'programDigest', 'revisions', 'expiresAt'}
                        or payload['programDigest'] !=
                           _canonical_digest(manifest)
                        or payload['revisions'] != revisions):
                    raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
                sequence_id = uuid.uuid4().hex
                db.execute('''INSERT INTO epm.full_aggregate_sequence
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
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=READ)
                row = db.execute('''SELECT sequence_id,issuer,subject_id,
                    manifest,status,current_step,job_ids,error_code,
                    created_at,updated_at FROM epm.full_aggregate_sequence
                    WHERE workspace_id=%s AND application_id=%s
                      AND sequence_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     args['sequenceId'])).fetchone()
                if (row is None or (row['issuer'], row['subject_id']) !=
                        (self.identity.issuer, self.identity.subject_id)):
                    raise ValueError('FULL_SEQUENCE_UNAVAILABLE')
                return {'sequenceId': row['sequence_id'],
                        'status': row['status'],
                        'currentStep': row['current_step'],
                        'stepCount': len(row['manifest']['steps']),
                        'jobIds': row['job_ids'],
                        'errorCode': row['error_code'],
                        'accountingPolicyStatus': 'Unreviewed',
                        'createdAt': row['created_at'].isoformat(),
                        'updatedAt': row['updated_at'].isoformat()}

    def cancel(self, scope: ApplicationScope, raw: dict, *,
               _allow_application_admin: bool = False) -> dict:
        args = _program(raw, CANCEL)
        if not isinstance(_allow_application_admin,bool):
            raise ValueError('FULL_SEQUENCE_CANCEL_POLICY_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000)
                configure_lock_wait(db)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,
                    'admin' if _allow_application_admin else 'write',
                    **({} if _allow_application_admin else {'function':CANCEL}))
                row = db.execute('''SELECT issuer,subject_id,status,current_step,
                    job_ids,manifest FROM epm.full_aggregate_sequence
                    WHERE workspace_id=%s AND application_id=%s
                      AND sequence_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id,
                     args['sequenceId'])).fetchone()
                if (row is None or (not _allow_application_admin and
                        (row['issuer'], row['subject_id']) !=
                        (self.identity.issuer, self.identity.subject_id))):
                    raise ValueError('FULL_SEQUENCE_UNAVAILABLE')
                if row['status'] not in ('accepted', 'running'):
                    result={'sequenceId':args['sequenceId'],'status':row['status']}
                    if _allow_application_admin:
                        result['committedEffectsRemain']=(
                            row['current_step']>0 or row['status']=='published')
                    return result
                job_ids = list(row['job_ids'])
                current = row['current_step']
                job = None
                if len(job_ids) > current:
                    job = db.execute('''SELECT job_id,status,function_name,
                        normalized_program,program_digest FROM epm.job
                        WHERE workspace_id=%s AND application_id=%s
                          AND job_id=%s FOR UPDATE''',
                        (scope.workspace_id, scope.application_id,
                         job_ids[current])).fetchone()
                else:
                    job = db.execute('''SELECT job_id,status,function_name,
                        normalized_program,program_digest FROM epm.job
                        WHERE workspace_id=%s AND application_id=%s
                          AND issuer=%s AND subject_id=%s
                          AND idempotency_key=%s FOR UPDATE''',
                        (scope.workspace_id, scope.application_id,
                         row['issuer'], row['subject_id'],
                         f'full-seq-{args["sequenceId"]}-{current}')).fetchone()
                if job:
                    _verify_adopted_job(row['manifest'], job_ids,
                                        current, job)
                    if len(job_ids) <= current:
                        job_ids.append(job['job_id'])
                status = 'cancelled'
                if job and job['status'] in ('accepted', 'ready',
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
                         scope.application_id, job['job_id']))
                    status = 'cancel_requested'
                elif job and job['status'] == 'cancel_requested':
                    status = 'cancel_requested'
                elif job and job['status'] == 'published':
                    current += 1
                    if current == len(row['manifest']['steps']):
                        status = 'published'
                elif job and job['status'] in ('failed', 'needs_inspection'):
                    status = 'failed'
                db.execute('''UPDATE epm.full_aggregate_sequence
                    SET status=%s,current_step=%s,job_ids=%s,
                        updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                      AND sequence_id=%s''',
                    (status, current, Jsonb(job_ids), scope.workspace_id,
                     scope.application_id, args['sequenceId']))
                result={'sequenceId':args['sequenceId'],
                        'status':status,'currentStep':current}
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
            raise ValueError('FULL_SEQUENCE_UNAVAILABLE')
        controller=object.__new__(cls)
        controller.dsn,controller.identity=dsn,identity
        controller.preview_secret=None
        return controller.cancel(scope,{'languageVersion':2,'function':CANCEL,
            'arguments':{'sequenceId':sequence_id}},
            _allow_application_admin=True)


class PostgresFullAggregateSequenceCoordinator:
    """Advance one durable sequence while preserving independent app work."""

    def __init__(self, *, worker_dsn: str, runtime_dsn: str,
                 preview_secret: bytes):
        if (not isinstance(worker_dsn, str) or not worker_dsn
                or not isinstance(runtime_dsn, str) or not runtime_dsn
                or not isinstance(preview_secret, bytes)
                or len(preview_secret) < 32):
            raise ValueError('Full sequence coordinator credentials required')
        self.worker_dsn, self.runtime_dsn = worker_dsn, runtime_dsn
        self._selection_cursor = None
        self.preview_secret = preview_secret

    def advance_once(self, *, scope: ApplicationScope | None = None) -> dict | None:
        if scope is not None and not isinstance(scope, ApplicationScope):
            raise ValueError('A valid application scope is required')
        with connect_postgres(self.worker_dsn, row_factory=dict_row) as worker:
            with worker.transaction():
                configure_lock_wait(worker)
                row, self._selection_cursor = select_candidate(
                    worker, self.runtime_dsn, 'full_aggregate_sequence', scope, self._selection_cursor)
                if row is None:
                    return None
                bound_scope = ApplicationScope(row['workspace_id'],
                                               row['application_id'])
                identity = durable_sequence_identity(row)
                manifest = row['manifest']
                job_ids = list(row['job_ids'])
                index = row['current_step']
                steps = manifest['steps']
                try:
                    if index >= len(steps):
                        raise ValueError('FULL_SEQUENCE_JOB_HISTORY_INVALID')
                    idem = f'full-seq-{row["sequence_id"]}-{index}'
                    job = worker.execute('''SELECT job_id,status,error_code,
                        function_name,normalized_program,program_digest
                        FROM epm.job WHERE workspace_id=%s
                        AND application_id=%s AND issuer=%s AND subject_id=%s
                        AND idempotency_key=%s''',
                        (bound_scope.workspace_id, bound_scope.application_id,
                         identity.issuer, identity.subject_id, idem)).fetchone()
                    if len(job_ids) > index and (
                            job is None or job['job_id'] != job_ids[index]):
                        raise ValueError('FULL_SEQUENCE_JOB_HISTORY_INVALID')
                    if job:
                        _verify_adopted_job(manifest, job_ids, index, job)
                    if row['status'] == 'cancel_requested':
                        status = ('cancelled' if job is None or job['status'] in
                                  ('published','failed','cancelled',
                                   'needs_inspection') else 'cancel_requested')
                        worker.execute('''UPDATE epm.full_aggregate_sequence
                            SET status=%s,updated_at=transaction_timestamp()
                            WHERE workspace_id=%s AND application_id=%s
                              AND sequence_id=%s''',
                            (status, bound_scope.workspace_id,
                             bound_scope.application_id, row['sequence_id']))
                        return {'sequenceId': row['sequence_id'], 'status': status}
                    if job and job['status'] in ('failed','cancelled',
                                                 'needs_inspection'):
                        raise ValueError(job['error_code'] or
                                         'FULL_SEQUENCE_STEP_FAILED')
                    if job and job['status'] == 'published' and index + 1 == len(steps):
                        if len(job_ids) <= index:
                            job_ids.append(job['job_id'])
                        worker.execute('''UPDATE epm.full_aggregate_sequence
                            SET job_ids=%s,current_step=%s,status='published',
                                updated_at=transaction_timestamp()
                            WHERE workspace_id=%s AND application_id=%s
                              AND sequence_id=%s''',
                            (Jsonb(job_ids), index + 1,
                             bound_scope.workspace_id,
                             bound_scope.application_id, row['sequence_id']))
                        return {'sequenceId': row['sequence_id'],
                                'status': 'published', 'currentStep': index + 1}
                    with connect_postgres(self.runtime_dsn,
                                         row_factory=dict_row) as runtime:
                        with runtime.transaction():
                            PostgresNumericFactStore._set_scope(
                                runtime, bound_scope)
                            PostgresAccessChecker.lock_workspace(runtime,bound_scope.workspace_id)
                            PostgresAccessChecker.check_in_transaction(
                                runtime, identity, bound_scope, 'write', function=FUNCTION)
                            revisions = {kind: row[
                                f'expected_{kind}_revision']
                                for kind in ('metadata','data','policy')}
                            _current(runtime, bound_scope, manifest,
                                     revisions, job_ids)
                            step = steps[index]
                            pointer = runtime.execute('''SELECT
                                published_revision FROM
                                epm.calculation_publication
                                WHERE workspace_id=%s AND application_id=%s
                                  AND result_key=%s''',
                                (bound_scope.workspace_id,
                                 bound_scope.application_id,
                                 step['resultKey'])).fetchone()
                            observed = (pointer['published_revision']
                                        if pointer else 0)
                            if (not job and observed !=
                                    step['expectedTargetRevision']):
                                raise ValueError('FULL_SEQUENCE_TARGET_REPUBLISHED')
                            program = _step_program(
                                runtime, bound_scope, manifest, job_ids, index)
                            if job:
                                expected = compile_full_aggregate(
                                    program, expected_publication_revision=
                                    step['expectedTargetRevision'])
                                if job['program_digest'] != _canonical_digest(
                                        expected.normalized_program):
                                    raise ValueError(
                                        'FULL_SEQUENCE_ADOPTED_JOB_MISMATCH')
                    if job:
                        if len(job_ids) <= index:
                            job_ids.append(job['job_id'])
                        if job['status'] == 'published':
                            index += 1
                            status = ('published' if index == len(steps)
                                      else 'running')
                        else:
                            status = 'running'
                        worker.execute('''UPDATE epm.full_aggregate_sequence
                            SET job_ids=%s,current_step=%s,status=%s,
                                updated_at=transaction_timestamp()
                            WHERE workspace_id=%s AND application_id=%s
                              AND sequence_id=%s''',
                            (Jsonb(job_ids), index, status,
                             bound_scope.workspace_id,
                             bound_scope.application_id,
                             row['sequence_id']))
                        return {'sequenceId': row['sequence_id'],
                                'status': status, 'currentStep': index}
                    from .postgres_language_v2 import PostgresLanguageV2
                    language = PostgresLanguageV2(
                        self.runtime_dsn, identity=identity,
                        preview_secret=self.preview_secret)
                    preview = language.preview(bound_scope, program)
                    # The earlier transaction is no longer holding state locks.
                    # A new preview must preserve the accepted sequence pins;
                    # ordinary submit then checks these same signed pins again
                    # atomically with admission. Never rebase accepted work.
                    if preview['revisionVector'] != {
                            f'{kind}_revision': revisions[kind]
                            for kind in ('metadata', 'data', 'policy')}:
                        raise ValueError('FULL_SEQUENCE_INPUT_REVISION_STALE')
                    if preview['expectedPublicationRevision'] != (
                            step['expectedTargetRevision']):
                        raise ValueError('FULL_SEQUENCE_TARGET_REPUBLISHED')
                    submitted = language.submit(
                        bound_scope, program,
                        preview_token=preview['previewToken'],
                        idempotency_key=idem)
                    job_ids.append(submitted['jobId'])
                    worker.execute('''UPDATE epm.full_aggregate_sequence
                        SET job_ids=%s,status='running',
                            updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                          AND sequence_id=%s''',
                        (Jsonb(job_ids), bound_scope.workspace_id,
                         bound_scope.application_id,row['sequence_id']))
                    return {'sequenceId': row['sequence_id'],
                            'status': 'running', 'currentStep': index,
                            'jobId': submitted['jobId']}
                except ValueError as error:
                    reason = str(error)
                    code = (reason if re.fullmatch(
                        r'[A-Z][A-Z0-9_]{2,127}', reason)
                        else 'FULL_SEQUENCE_VALIDATION_FAILED')
                    worker.execute('''UPDATE epm.full_aggregate_sequence
                        SET status='failed',error_code=%s,
                            updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                          AND sequence_id=%s''',
                        (code, bound_scope.workspace_id,
                         bound_scope.application_id,row['sequence_id']))
                    return {'sequenceId': row['sequence_id'],
                            'status': 'failed', 'errorCode': code,
                            'currentStep': index}
