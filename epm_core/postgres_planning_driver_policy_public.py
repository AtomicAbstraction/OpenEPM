"""Public preview/admission boundary for one published reusable Driver policy."""
from __future__ import annotations

from hashlib import sha256
import json
import re

from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_expression import decode_expression_program, compiler_for
from .postgres_jobs import (_canonical_digest,_job_request_descriptor,
                            _verify_job_replay_authorization)
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_calculation_status import published_input_status
from .postgres_planning_driver_policy import compile_driver_policy_program
from .planning_operation_policy import FORMAT_V2
from .postgres_planning_policy_resolution import (
    resolve_published_planning_policy,
)


PREVIEW = 'planning.operation.policy.driver.preview'
RUN = 'planning.operation.policy.driver.run'
FUNCTIONS = frozenset((PREVIEW, RUN))
_EXECUTION = {'inputMemberMappings', 'outputMemberMapping', 'activeGrain',
              'measureDimensionId', 'resultKey'}
_PUBLISHED_BINDINGS='publishedInputBindings'


def _request_digest(arguments: dict) -> str:
    return sha256(json.dumps(arguments, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False, allow_nan=False)
                  .encode('utf-8')).hexdigest()


def catalog() -> dict:
    arguments = {'policyId': 'currently published reusable Driver policy ID',
        'effectiveOn': 'ISO date within immutable policy effective range',
        'bindings': 'all and only typed policy parameters',
        'inputMemberMappings': 'explicit dimension/member mapping per input',
        'outputMemberMapping': 'explicit target member mapping',
        'activeGrain': 'complete declared output dimension grain',
        'measureDimensionId': 'typed amount/ratio measure dimension',
        'resultKey': 'stable named current calculation result'}
    return {
        PREVIEW: {'mode': 'calculation_preview', 'permission': 'write',
            'requiredCapabilities': [], 'arguments': arguments,
            'optionalArguments': {_PUBLISHED_BINDINGS:
                'required only for V2: exact input name to resultKey/resultStateToken pin'},
            'result': 'sealed active policy pointer, current revisions and exact plan',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'},
        RUN: {'mode': 'durable_calculation', 'permission': 'write',
            'requiredCapabilities': [],
            'arguments': {**arguments,
                          'previewToken': 'unexpired server-signed exact preview'},
            'optionalArguments': {_PUBLISHED_BINDINGS:
                'required only for V2: exact input name to resultKey/resultStateToken pin'},
            'result': 'durable job ID; standard job read/cancel and receipt apply',
            'previewRequired': True, 'idempotencyRequired': True,
            'workClass': 'short'}}


class PostgresPublishedPlanningDriver:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 preview_secret: bytes):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity
        from .postgres_language_v2 import PostgresLanguageV2
        self.language = PostgresLanguageV2(
            dsn, identity=identity, preview_secret=preview_secret)

    def _resolve(self, scope: ApplicationScope, args: dict):
        required = {'policyId', 'effectiveOn', 'bindings'} | _EXECUTION
        if (not isinstance(args, dict)
                or set(args) not in (required,required|{_PUBLISHED_BINDINGS})):
            raise ValueError('PLANNING_DRIVER_POLICY_ARGUMENTS_INVALID')
        bound, pointer = resolve_published_planning_policy(
            self.dsn, self.identity, scope,
            {key: args[key] for key in ('policyId', 'effectiveOn', 'bindings')},
            expected_kind='Driver', function=RUN)
        v2=bound.get('policyFormat')==FORMAT_V2
        if v2 != (_PUBLISHED_BINDINGS in args):
            raise ValueError('PLANNING_DRIVER_POLICY_ARGUMENTS_INVALID')
        execution = {key: args[key] for key in _EXECUTION}
        dependency=None
        if v2:
            execution[_PUBLISHED_BINDINGS]=args[_PUBLISHED_BINDINGS]
            dependency=self._resolve_dependency(scope,args[_PUBLISHED_BINDINGS],
                function=RUN)
        return compile_driver_policy_program(
            bound, execution, published_pointer=pointer,
            resolved_dependency=dependency)

    def _resolve_dependency(self,scope,bindings,*,function):
        if (not isinstance(bindings,dict) or len(bindings)!=1
                or any(not isinstance(name,str) or not name
                       or not isinstance(pin,dict)
                       or set(pin)!={'resultKey','resultStateToken'}
                       or not isinstance(pin['resultKey'],str)
                       or not re.fullmatch(r'[A-Za-z0-9._-]{8,128}',
                                           pin['resultKey'])
                       or not isinstance(pin['resultStateToken'],str)
                       or not re.fullmatch(r'[0-9a-f]{64}',
                                           pin['resultStateToken'])
                       for name,pin in bindings.items())):
            raise ValueError('PLANNING_DRIVER_POLICY_PUBLISHED_INPUT_INVALID')
        input_name,pin=next(iter(bindings.items()))
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write',function=function,
                    arguments={'publishedInputBindings':bindings})
                row=db.execute('''SELECT p.result_key,p.state_token,j.status
                    FROM epm.calculation_result_state p
                    JOIN epm.job j ON j.workspace_id=p.workspace_id
                     AND j.application_id=p.application_id
                     AND j.job_id=p.source_operation_id
                    WHERE p.workspace_id=%s AND p.application_id=%s
                      AND p.result_key=%s''',(
                    scope.workspace_id,scope.application_id,
                    pin['resultKey'])).fetchone()
                freshness = published_input_status(db, scope, {
                    'publishedInputs': [pin]})
        if (row is None or row['status']!='published'
                or row['state_token']!=pin['resultStateToken']
                or freshness is None or not freshness['matchesAtRead']):
            raise ValueError('DRIVER_POLICY_PUBLISHED_INPUT_STALE')
        return {'inputName':input_name,'resultKey':row['result_key'],
            'resultStateToken':row['state_token']}

    def preview(self, scope: ApplicationScope, program: object) -> dict:
        if (not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != PREVIEW):
            raise ValueError('PLANNING_DRIVER_POLICY_PREVIEW_INVALID')
        compiled = self._resolve(scope, program['arguments'])
        request_digest = _request_digest(program['arguments'])
        result = self.language._preview_expression(
            scope, compiled.program, driver_policy=compiled.driver_policy,
            preview_function=RUN, request_digest=request_digest)
        dependency=compiled.driver_policy.get('publishedDependency')
        if dependency is not None:
            if (result['publishedInputs'] != [{
                    'resultKey':dependency['resultKey'],
                    'resultStateToken':dependency['resultStateToken']}]
                    or not 1<=result['estimatedRows']<=500):
                raise ValueError('DRIVER_POLICY_PUBLISHED_INPUT_STALE')
        revisions = result['revisionVector']
        if (revisions['metadata_revision'] !=
                compiled.driver_policy['metadataRevision']
                or revisions['policy_revision'] !=
                compiled.driver_policy['policyRevision']):
            raise ValueError('PLANNING_DRIVER_POLICY_STALE_PREVIEW')
        return {**result, 'driverPolicy': compiled.driver_policy,
                'compilerVersion': compiled.compiler_version,
                'planDigest': compiled.plan_digest}

    def _replay(self, scope: ApplicationScope, *, idempotency_key: str,
                arguments: dict, preview_payload: dict) -> dict | None:
        """Return one exact accepted run without consulting a newer pointer."""
        if preview_payload.get('requestDigest') != _request_digest(arguments):
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
                    FROM epm.job
                    WHERE workspace_id=%s AND application_id=%s
                    AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',
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
        normalized = prior['normalized_program']
        try:
            plan = decode_expression_program(normalized)
            compiler, plan_digest = compiler_for(plan)
        except ValueError as error:
            raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT') from error
        policy = plan.driver_policy
        revisions = preview_payload.get('revisions')
        base_policy={'policyId', 'policyDigest',
                    'metadataRevision', 'policyRevision',
                    'authoredMetadataRevision', 'authoredPolicyRevision',
                    'stateToken'}
        v2_policy=base_policy|{'policyFormat','publishedDependency','maxCells',
                               'upstreamLineageBudget'}
        if (prior['function_name'] != 'facts.expression.calculate'
                or not isinstance(policy, dict)
                or set(policy) not in (base_policy,v2_policy)
                or policy['policyId'] != arguments['policyId']
                or prior['compiler_version'] != compiler
                or prior['plan_digest'] != plan_digest
                or prior['program_digest'] != _canonical_digest(normalized)
                or prior['program_digest'] != preview_payload.get('programDigest')
                or not isinstance(revisions, dict)
                or [prior['expected_metadata_revision'],
                    prior['expected_data_revision'],
                    prior['expected_policy_revision']] != [
                        revisions.get('metadata_revision'),
                        revisions.get('data_revision'),
                        revisions.get('policy_revision')]):
            raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT')
        dependency_ids = tuple(row['depends_on_job_id'] for row in dependencies)
        expected_dependencies=()
        descriptor=_job_request_descriptor(scope,self.identity,
            function_name=prior['function_name'],
            program_digest=prior['program_digest'],compiler_version=compiler,
            plan_digest=plan_digest,revisions=(
                prior['expected_metadata_revision'],
                prior['expected_data_revision'],prior['expected_policy_revision']),
            resource_class=prior['resource_class'],dependencies=dependency_ids,
            authorization_scope_digest=auth_scope,
            verified_groups=access.groups)
        if (dependency_ids!=expected_dependencies or _canonical_digest(descriptor)
                != prior['request_digest']):
            raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT')
        return {'jobId': prior['job_id'], 'status': prior['status'],
                'duplicate': True}

    def run(self, scope: ApplicationScope, program: object, *,
            idempotency_key: str) -> dict:
        if (not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != RUN
                or not isinstance(program['arguments'], dict)
                or set(program['arguments']) not in (
                    ({'previewToken', 'policyId', 'effectiveOn', 'bindings'}
                     | _EXECUTION),
                    ({'previewToken', 'policyId', 'effectiveOn', 'bindings',
                      _PUBLISHED_BINDINGS}|_EXECUTION))):
            raise ValueError('PLANNING_DRIVER_POLICY_RUN_INVALID')
        args = dict(program['arguments'])
        token = args.pop('previewToken')
        request_digest = _request_digest(args)
        payload = self.language._unpack_preview(scope, RUN, token)
        replay = self._replay(
            scope, idempotency_key=idempotency_key, arguments=args,
            preview_payload=payload)
        if replay is not None:
            return replay
        compiled = self._resolve(scope, args)
        return self.language._submit_expression(
            scope, compiled.program, preview_token=token,
            idempotency_key=idempotency_key,
            depends_on_job_ids=(),
            driver_policy=compiled.driver_policy, preview_function=RUN,
            request_digest=request_digest)
