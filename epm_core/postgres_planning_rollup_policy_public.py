"""Sealed public execution of one published reusable Rollup policy."""
from __future__ import annotations

from hashlib import sha256
import json

from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .planning_operation_policy_lowering import lower_bound_policy_to_legacy_v2
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_jobs import (PostgresJobQueue,_canonical_digest,
    _job_request_descriptor,_verify_job_replay_authorization)
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_planning_policy_resolution import resolve_published_planning_policy
from .postgres_planning_rollup import (
    FUNCTION, POLICY_COMPILER, POLICY_PLAN_DIGEST, active_hierarchy_version,
    POLICY_PLACEMENT_COMPILER, POLICY_PLACEMENT_PLAN_DIGEST,
    compile_rollup_program, encode_policy_rollup_program,
    decode_policy_rollup_program, validate_rollup_inputs,
)
from .postgres_processing_limits import configure_statement_timeout
from .postgres_planning_rollup_slice import (COMPILER as SLICE_COMPILER,
    PLAN_DIGEST as SLICE_PLAN_DIGEST,compile_slice_rollup,
    decode_slice_rollup,validate_slice_rollup)


PREVIEW = 'planning.operation.policy.rollup.preview'
RUN = 'planning.operation.policy.rollup.run'
FUNCTIONS = frozenset((PREVIEW, RUN))
_EXECUTION = {'otherMembers', 'resultKey'}


def _digest(value: dict) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False, allow_nan=False)
                  .encode('utf-8')).hexdigest()


def _compiler(plan):
    return ((POLICY_PLACEMENT_COMPILER,POLICY_PLACEMENT_PLAN_DIGEST)
            if plan.placement_ids else (POLICY_COMPILER,POLICY_PLAN_DIGEST))


def catalog() -> dict:
    arguments = {'policyId': 'currently published reusable Rollup policy ID',
        'effectiveOn': 'ISO date within immutable policy effective range',
        'bindings': 'all and only typed policy parameters',
        'resultKey': 'named immutable rollup publication'}
    return {
        PREVIEW: {'mode': 'calculation_preview', 'permission': 'write',
            'requiredCapabilities': [], 'arguments': arguments,
            'optionalArguments': {'otherMembers':
                'required only by legacy v1 single-slice policies'},
            'result': 'sealed policy, hierarchy, source and publication pins',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'},
        RUN: {'mode': 'durable_calculation', 'permission': 'write',
            'requiredCapabilities': [],
            'arguments': {**arguments,
                          'previewToken': 'unexpired server-signed exact preview'},
            'optionalArguments': {'otherMembers':
                'required only by legacy v1 single-slice policies'},
            'result': 'durable rollup job ID; standard job read/cancel applies',
            'previewRequired': True, 'idempotencyRequired': True,
            'workClass': 'short'}}


class PostgresPublishedPlanningRollup:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 preview_secret: bytes):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity
        from .postgres_language_v2 import PostgresLanguageV2
        self.language = PostgresLanguageV2(
            dsn, identity=identity, preview_secret=preview_secret)

    @staticmethod
    def _arguments(program: object, function: str, *, token: bool) -> dict:
        required = {'policyId', 'effectiveOn', 'bindings'} | _EXECUTION
        if token:
            required |= {'previewToken'}
        if (not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != function
                or not isinstance(program['arguments'], dict)
                or set(program['arguments']) not in (required,
                    required-{'otherMembers'})):
            raise ValueError('PLANNING_ROLLUP_POLICY_PROGRAM_INVALID')
        return dict(program['arguments'])

    def _resolve(self, scope: ApplicationScope, arguments: dict):
        bound, pointer = resolve_published_planning_policy(
            self.dsn, self.identity, scope,
            {key: arguments[key] for key in
             ('policyId', 'effectiveOn', 'bindings')},
            expected_kind='Rollup', function=RUN)
        v2=bound.get('policyFormat')=='openepm-planning-operation-policy-v2'
        if v2 == ('otherMembers' in arguments):
            raise ValueError('PLANNING_ROLLUP_POLICY_PROGRAM_INVALID')
        policy = {key: bound[key] for key in (
            'policyId', 'version', 'policyDigest', 'metadataRevision',
            'policyRevision')}
        policy.update(pointer)
        return bound, policy

    def _compile_current(self, scope: ApplicationScope, arguments: dict):
        bound, policy = self._resolve(scope, arguments)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                access=PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write', function=RUN,
                    arguments=arguments)
                state = db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (state is None or state['status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['metadata_revision'] != policy['metadataRevision']
                        or state['policy_revision'] != policy['policyRevision']):
                    raise ValueError('PLANNING_ROLLUP_POLICY_STALE')
                dimension = bound['definition']['dimension']
                hierarchy = active_hierarchy_version(db, scope, dimension)
                pointer = db.execute('''SELECT published_revision
                    FROM epm.calculation_publication
                    WHERE workspace_id=%s AND application_id=%s
                    AND result_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     arguments['resultKey'])).fetchone()
                publication = pointer['published_revision'] if pointer else 0
                if bound.get('policyFormat')==(
                        'openepm-planning-operation-policy-v2'):
                    plan=compile_slice_rollup(bound,{
                        'resultKey':arguments['resultKey']},
                        hierarchy_version=hierarchy,
                        expected_publication_revision=publication,
                        pointer=policy)
                    summary=validate_slice_rollup(db,scope,plan)
                    revisions = {key: state[key] for key in (
                        'metadata_revision', 'data_revision', 'policy_revision')}
                    return plan,policy,summary,revisions
                lowered = lower_bound_policy_to_legacy_v2(bound, {
                    'otherMembers': arguments['otherMembers'],
                    'resultKey': arguments['resultKey'],
                    'hierarchyVersion': hierarchy,
                    'expectedPublicationRevision': publication})
                plan = compile_rollup_program(
                    lowered.program, hierarchy_version=hierarchy,
                    expected_publication_revision=publication)
                summary = validate_rollup_inputs(db, scope, plan)
                revisions = {key: state[key] for key in (
                    'metadata_revision', 'data_revision', 'policy_revision')}
        return plan, policy, summary, revisions

    def preview(self, scope: ApplicationScope, program: object) -> dict:
        arguments = self._arguments(program, PREVIEW, token=False)
        plan, policy, summary, revisions = self._compile_current(
            scope, arguments)
        normalized = (plan.normalized_program if hasattr(plan,'slice_members')
                      else encode_policy_rollup_program(plan, policy))
        compiler,plan_digest=((SLICE_COMPILER,SLICE_PLAN_DIGEST)
          if hasattr(plan,'slice_members') else _compiler(plan))
        token, program_digest = self.language._sign_preview(
            scope, RUN, normalized, revisions,
            extra={'requestDigest': _digest(arguments),
                   'expectedPublicationRevision':
                       plan.expected_publication_revision,
                   'hierarchyVersion': plan.hierarchy_version})
        return {'languageVersion': 2, 'function': RUN,
            'programDigest': program_digest, 'revisionVector': revisions,
            'expectedPublicationRevision': plan.expected_publication_revision,
            'hierarchyVersion': plan.hierarchy_version,
            'sourceCount': summary['sourceCount'],
            **({'outputCount':summary['outputCount'],'outputs':summary['amounts']}
               if 'outputCount' in summary else {'amount':format(summary['amount'],'f'),
               'target':summary['target']}), 'reusablePolicy': policy,
            'compilerVersion': compiler,
            'planDigest': plan_digest,
            'engine': 'postgres_exact_sql', 'previewToken': token}

    def _replay(self, scope: ApplicationScope, *, idempotency_key: str,
                arguments: dict, payload: dict) -> dict | None:
        if payload.get('requestDigest') != _digest(arguments):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                access=PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write', function=RUN,
                    arguments=arguments)
                prior = db.execute('''SELECT job_id,status,function_name,
                    normalized_program,compiler_version,program_digest,
                    request_digest,plan_digest,expected_metadata_revision,
                    expected_data_revision,expected_policy_revision,
                    resource_class,verified_groups,authorization_scope_digest
                    FROM epm.job WHERE workspace_id=%s
                    AND application_id=%s AND issuer=%s AND subject_id=%s
                    AND idempotency_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     self.identity.issuer, self.identity.subject_id,
                     idempotency_key)).fetchone()
                if prior is None:
                    return None
                dependencies = db.execute('''SELECT depends_on_job_id
                    FROM epm.job_dependency WHERE workspace_id=%s
                    AND application_id=%s AND job_id=%s
                    ORDER BY depends_on_job_id''',
                    (scope.workspace_id, scope.application_id,
                     prior['job_id'])).fetchall()
                auth_scope=_verify_job_replay_authorization(db,scope,
                    self.identity,prior,access=access,
                    function_name=prior['function_name'])
        try:
            if prior['compiler_version']==SLICE_COMPILER:
                prior_plan=decode_slice_rollup(prior['normalized_program'])
                policy=prior_plan.reusable_policy
            else:
                prior_plan, policy = decode_policy_rollup_program(
                    prior['normalized_program'])
        except ValueError as error:
            raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT') from error
        revisions = payload.get('revisions')
        compiler,plan_digest=((SLICE_COMPILER,SLICE_PLAN_DIGEST)
          if hasattr(prior_plan,'slice_members') else _compiler(prior_plan))
        if (prior['function_name'] != FUNCTION
                or prior['compiler_version'] != compiler
                or prior['plan_digest'] != plan_digest
                or prior['program_digest'] != _canonical_digest(
                    prior['normalized_program'])
                or prior['program_digest'] != payload.get('programDigest')
                or policy.get('policyId') != arguments['policyId']
                or not isinstance(revisions, dict)
                or [prior['expected_metadata_revision'],
                    prior['expected_data_revision'],
                    prior['expected_policy_revision']] != [
                        revisions.get('metadata_revision'),
                        revisions.get('data_revision'),
                        revisions.get('policy_revision')]):
            raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT')
        dependency_ids = tuple(row['depends_on_job_id'] for row in dependencies)
        descriptor=_job_request_descriptor(scope,self.identity,
            function_name=FUNCTION,program_digest=prior['program_digest'],
            compiler_version=compiler,plan_digest=plan_digest,
            revisions=(prior['expected_metadata_revision'],
                prior['expected_data_revision'],prior['expected_policy_revision']),
            resource_class=prior['resource_class'],dependencies=dependency_ids,
            authorization_scope_digest=auth_scope)
        if dependency_ids or _canonical_digest(descriptor) != prior['request_digest']:
            raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT')
        return {'jobId': prior['job_id'], 'status': prior['status'],
                'duplicate': True}

    def run(self, scope: ApplicationScope, program: object, *,
            idempotency_key: str) -> dict:
        arguments = self._arguments(program, RUN, token=True)
        token = arguments.pop('previewToken')
        payload = self.language._unpack_preview(scope, RUN, token)
        replay = self._replay(scope, idempotency_key=idempotency_key,
                              arguments=arguments, payload=payload)
        if replay is not None:
            return replay
        required_payload = {'scope', 'identity', 'function', 'programDigest',
            'revisions', 'expiresAt', 'requestDigest',
            'expectedPublicationRevision', 'hierarchyVersion'}
        if set(payload) != required_payload:
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        plan, policy, _, current_revisions = self._compile_current(
            scope, arguments)
        normalized=(plan.normalized_program if hasattr(plan,'slice_members')
                    else encode_policy_rollup_program(plan,policy))
        compiler,plan_digest=((SLICE_COMPILER,SLICE_PLAN_DIGEST)
          if hasattr(plan,'slice_members') else _compiler(plan))
        if (payload['programDigest'] != _canonical_digest(normalized)
                or payload['requestDigest'] != _digest(arguments)
                or payload['revisions'] != current_revisions
                or payload['hierarchyVersion'] != plan.hierarchy_version
                or payload['expectedPublicationRevision'] !=
                    plan.expected_publication_revision):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        return PostgresJobQueue(self.dsn, identity=self.identity).submit(
            scope, idempotency_key=idempotency_key, function_name=FUNCTION,
            normalized_program=normalized, compiler_version=compiler,
            plan_digest=plan_digest,
            expected_metadata_revision=current_revisions['metadata_revision'],
            expected_data_revision=current_revisions['data_revision'],
            expected_policy_revision=current_revisions['policy_revision'],
            depends_on_job_ids=())
