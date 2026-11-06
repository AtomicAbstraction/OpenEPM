"""Durable PostgreSQL job admission and fenced worker-state foundation.

Only fixed server/compiler code may submit normalized programs. Bounded
numeric and text batches publish their effects and job results in one
transaction; selected calculations publish immutable result generations.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re
import uuid

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import (ApplicationScope, Coordinate, MutationKind,
                                   NumericCell, NumericMutation, TextMutation,
                                   TextMutationKind, LineItem)
from .postgres_access import (AccessDenied, PostgresAccessChecker,
                              VerifiedExecutionIdentity, VerifiedIdentity)
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import (configure_lock_wait,
                                         configure_statement_timeout,
                                         lock_busy_boundary, BUSY_CODE)
from .postgres_text_store import PostgresTextFactStore
from .postgres_calculation_status import (
    published_child_status, published_input_status)


_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_JOB_ID = re.compile(r'[0-9a-f]{32}\Z')
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_NUMERIC_FUNCTION = 'facts.numeric.batch'
_NUMERIC_COMPILER = 'numeric-fixed-v1'
_TEXT_FUNCTION = 'facts.text.batch'
_TEXT_COMPILER = 'text-fixed-v1'
_DETAIL_FUNCTION = 'facts.line-detail.replace'
_DETAIL_COMPILER = 'line-detail-fixed-v1'
_TARGET_SCOPED_WRITE_FUNCTIONS = frozenset((
    _NUMERIC_FUNCTION, _TEXT_FUNCTION, _DETAIL_FUNCTION))
_CONTROL_FENCED_NUMERIC_FUNCTIONS = frozenset((
    'facts.numeric.sequence', 'rules.numeric_sequence.run',
    'facts.numeric.iterate', 'facts.projections.rebuild', 'facts.projections.cleanup'))
_AUTHORIZATION_FUNCTION_PAIRS = frozenset((
    ('consolidation.method.contribute', 'consolidation.full.contribute'),
    ('consolidation.equity.contribution.publish',
     'consolidation.equity.contribution.publish.certified'),
    ('consolidation.proportional.contribution.publish',
     'consolidation.proportional.contribution.publish.certified'),
    ('consolidation.method.total.publish',
     'consolidation.method.total.publish'),
    ('consolidation.inventory.unrealized_profit.request',
     'consolidation.inventory.unrealized_profit.request'),
))


def _validate_authorization_function(function_name, authorization_function):
    if (authorization_function is not None and
            (function_name, authorization_function)
            not in _AUTHORIZATION_FUNCTION_PAIRS):
        raise ValueError('JOB_AUTHORIZATION_FUNCTION_INVALID')


def _validate_submission_revisions(state: dict, function_name: str,
        expected_metadata_revision: int, expected_data_revision: int,
        expected_policy_revision: int) -> None:
    """Fence shared dependencies while deferring target conflicts to workers."""
    if (state['metadata_revision'] != expected_metadata_revision
            or state['policy_revision'] != expected_policy_revision):
        raise ValueError('STALE_JOB_INPUT_REVISION')
    if function_name in _TARGET_SCOPED_WRITE_FUNCTIONS:
        if expected_data_revision > state['data_revision']:
            raise ValueError('STALE_JOB_INPUT_REVISION')
    elif state['data_revision'] != expected_data_revision:
        raise ValueError('STALE_JOB_INPUT_REVISION')


_STAGED_COMPILERS = {
    'facts.projections.rebuild':'fact-projections-rebuild-v2',
    'facts.projections.cleanup':'projection-generations-cleanup-v1',
}


def _is_staged_compiler(function,compiler):
    return function in _STAGED_COMPILERS and _STAGED_COMPILERS[function]==compiler


def _canonical_digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False, allow_nan=False)
                  .encode('utf-8')).hexdigest()


def _job_request_descriptor(scope: ApplicationScope,
        identity: VerifiedIdentity, *, function_name: str,
        program_digest: str, compiler_version: str, plan_digest: str,
        revisions: tuple[int, int, int] | list[int], resource_class: str,
        dependencies: tuple[str, ...], authorization_scope_digest: str,
        authorization_function: str | None = None,
        execution_authority: dict | None = None) -> dict:
    """Build the one canonical durable-job request identity."""
    descriptor = {
        'scope': [scope.workspace_id, scope.application_id],
        'identity': [identity.issuer, identity.subject_id],
        'verifiedGroups': list(identity.groups),
        'authorizationScopeDigest': authorization_scope_digest,
        'function': function_name, 'programDigest': program_digest,
        'compilerVersion': compiler_version, 'planDigest': plan_digest,
        'revisions': list(revisions), 'resourceClass': resource_class,
        'dependencies': dependencies,
        'tokenIssuedAt': identity.issued_at,
    }
    if authorization_function is not None:
        descriptor['authorizationFunction'] = authorization_function
    if execution_authority is not None:
        descriptor['executionAuthority'] = execution_authority
    return descriptor


def _verify_job_replay_authorization(db, scope: ApplicationScope,
        identity: VerifiedIdentity, prior: dict, *, access,
        function_name: str, authorization_function: str | None = None) -> str:
    """Recheck a stored job's exact current group and dimensional authority."""
    current_scope = resolve_effective_dimensional_scope(
        db, identity, scope, access=access,
        function=authorization_function or function_name).scope_digest
    if (tuple(prior.get('verified_groups') or ()) != identity.groups
            or prior.get('authorization_scope_digest') is None
            or prior['authorization_scope_digest'] != current_scope):
        raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT')
    return current_scope


_NUMERIC_PLAN_DIGEST = _canonical_digest({
    'function': _NUMERIC_FUNCTION, 'loweringVersion': 1,
    'effect': 'numeric-batch-transaction',
})
_TEXT_PLAN_DIGEST = _canonical_digest({
    'function': _TEXT_FUNCTION, 'loweringVersion': 1,
    'effect': 'text-batch-transaction',
})
_DETAIL_PLAN_DIGEST = _canonical_digest({
    'function': _DETAIL_FUNCTION, 'loweringVersion': 1,
    'effect': 'supporting-detail-and-numeric-total-transaction',
})


def _numeric_program(mutations: tuple[NumericMutation, ...]) -> dict:
    if not 1 <= len(mutations) <= 500 or any(
            not isinstance(item, NumericMutation) for item in mutations):
        raise ValueError('A batch needs 1–500 numeric mutations')
    if len({item.coordinate for item in mutations}) != len(mutations):
        raise ValueError('One batch cannot target a coordinate twice')
    if any(not isinstance(item.expected_change_id, str)
           for item in mutations):
        raise ValueError('Expected change IDs must be strings')
    return {'version': 1, 'function': _NUMERIC_FUNCTION, 'mutations': [
        {'members': dict(item.coordinate.members), 'kind': item.kind.value,
         'amount': format(item.amount, 'f') if item.amount is not None else None,
         'expectedChangeId': item.expected_change_id}
        for item in mutations]}


def _decode_numeric_program(program: object) -> tuple[NumericMutation, ...]:
    if (not isinstance(program, dict)
            or set(program) != {'version', 'function', 'mutations'}
            or type(program['version']) is not int or program['version'] != 1
            or program['function'] != _NUMERIC_FUNCTION
            or not isinstance(program['mutations'], list)
            or not 1 <= len(program['mutations']) <= 500):
        raise ValueError('UNSUPPORTED_NUMERIC_JOB_PROGRAM')
    decoded = []
    for raw in program['mutations']:
        if (not isinstance(raw, dict)
                or set(raw) != {'members', 'kind', 'amount', 'expectedChangeId'}
                or not isinstance(raw['expectedChangeId'], str)):
            raise ValueError('INVALID_NUMERIC_JOB_MUTATION')
        try:
            kind = MutationKind(raw['kind'])
            amount = NumericCell.from_wire(
                present=kind != MutationKind.CLEAR,
                amount=raw['amount']).amount
            decoded.append(NumericMutation(
                Coordinate.from_mapping(raw['members']), kind, amount,
                raw['expectedChangeId']))
        except (TypeError, ValueError) as error:
            raise ValueError('INVALID_NUMERIC_JOB_MUTATION') from error
    mutations = tuple(decoded)
    if _numeric_program(mutations) != program:
        raise ValueError('NONCANONICAL_NUMERIC_JOB_PROGRAM')
    return mutations


def _text_program(mutations: tuple[TextMutation, ...]) -> dict:
    if not 1 <= len(mutations) <= 500 or any(
            not isinstance(item, TextMutation) for item in mutations):
        raise ValueError('A batch needs 1–500 text mutations')
    if len({item.coordinate for item in mutations}) != len(mutations):
        raise ValueError('One batch cannot target a coordinate twice')
    if any(not isinstance(item.expected_change_id, str)
           for item in mutations):
        raise ValueError('Expected change IDs must be strings')
    return {'version': 1, 'function': _TEXT_FUNCTION, 'mutations': [
        {'members': dict(item.coordinate.members), 'kind': item.kind.value,
         'value': item.value, 'expectedChangeId': item.expected_change_id}
        for item in mutations]}


def _decode_text_program(program: object) -> tuple[TextMutation, ...]:
    if (not isinstance(program, dict)
            or set(program) != {'version', 'function', 'mutations'}
            or type(program['version']) is not int or program['version'] != 1
            or program['function'] != _TEXT_FUNCTION
            or not isinstance(program['mutations'], list)
            or not 1 <= len(program['mutations']) <= 500):
        raise ValueError('UNSUPPORTED_TEXT_JOB_PROGRAM')
    decoded = []
    for raw in program['mutations']:
        if (not isinstance(raw, dict)
                or set(raw) != {'members', 'kind', 'value', 'expectedChangeId'}
                or not isinstance(raw['expectedChangeId'], str)):
            raise ValueError('INVALID_TEXT_JOB_MUTATION')
        try:
            decoded.append(TextMutation(
                Coordinate.from_mapping(raw['members']),
                TextMutationKind(raw['kind']), raw['value'],
                raw['expectedChangeId']))
        except (TypeError, ValueError) as error:
            raise ValueError('INVALID_TEXT_JOB_MUTATION') from error
    mutations = tuple(decoded)
    if _text_program(mutations) != program:
        raise ValueError('NONCANONICAL_TEXT_JOB_PROGRAM')
    return mutations


def _detail_program(coordinate: Coordinate, items: tuple[LineItem, ...],
                    expected_cell_change_id: str,
                    expected_detail_change_id: str) -> dict:
    if (not isinstance(coordinate, Coordinate) or not isinstance(items, tuple)
            or not 0 <= len(items) <= 500
            or any(not isinstance(item, LineItem) for item in items)
            or type(expected_cell_change_id) is not str
            or type(expected_detail_change_id) is not str):
        raise ValueError('INVALID_LINE_DETAIL_JOB_PROGRAM')
    return {'version': 1, 'function': _DETAIL_FUNCTION,
        'members': dict(coordinate.members),
        'items': [{'description': item.description,
                   'amount': format(item.amount, 'f')} for item in items],
        'expectedCellChangeId': expected_cell_change_id,
        'expectedDetailChangeId': expected_detail_change_id}


def _decode_detail_program(program: object):
    if (type(program) is not dict or set(program) != {'version','function',
            'members','items','expectedCellChangeId','expectedDetailChangeId'}
            or program.get('version') != 1
            or program.get('function') != _DETAIL_FUNCTION
            or type(program.get('items')) is not list
            or not 0 <= len(program['items']) <= 500):
        raise ValueError('UNSUPPORTED_LINE_DETAIL_JOB_PROGRAM')
    try:
        coordinate=Coordinate.from_mapping(program['members'])
        items=tuple(LineItem(row['description'], NumericCell.from_wire(
            present=True,amount=row['amount']).amount) for row in program['items']
            if type(row) is dict and set(row)=={'description','amount'})
    except (TypeError,ValueError,KeyError) as error:
        raise ValueError('INVALID_LINE_DETAIL_JOB_PROGRAM') from error
    if len(items)!=len(program['items']):
        raise ValueError('INVALID_LINE_DETAIL_JOB_PROGRAM')
    result=(coordinate,items,program['expectedCellChangeId'],
            program['expectedDetailChangeId'])
    if _detail_program(*result)!=program:
        raise ValueError('NONCANONICAL_LINE_DETAIL_JOB_PROGRAM')
    return result


def _dependency_available(row: dict | None, published_pin: dict | None,
                          identity: VerifiedIdentity) -> bool:
    """Keep ordinary ownership rules; allow only exact settled result edges."""
    if row is None:
        return False
    if published_pin is None:
        return (row['issuer'] == identity.issuer
                and row['subject_id'] == identity.subject_id)
    return (row['status'] == 'published'
        and all(row[field] == published_pin[key] for field,key in (
            ('result_key','resultKey'),('generation_id','generationId'),
            ('published_revision','publishedRevision')))
        and row['observed_generation_id'] == published_pin['generationId']
        and row['observed_published_revision'] ==
            published_pin['publishedRevision'])


class PostgresJobQueue:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn = dsn
        self.identity = identity

    @lock_busy_boundary
    def replay(self, scope: ApplicationScope, *, idempotency_key: str,
               function_name: str, normalized_program: dict,
               compiler_version: str, plan_digest: str,
               depends_on_job_ids: tuple[str, ...] = ()) -> dict | None:
        """Return an already accepted exact job without using fresh revisions."""
        if (not isinstance(scope,ApplicationScope)
                or not isinstance(idempotency_key,str)
                or not _KEY.fullmatch(idempotency_key)
                or not isinstance(function_name,str)
                or not isinstance(normalized_program,dict)
                or not isinstance(compiler_version,str)
                or not isinstance(plan_digest,str)
                or not isinstance(depends_on_job_ids,tuple)
                or len(depends_on_job_ids)>16
                or any(not isinstance(value,str) or not _JOB_ID.fullmatch(value)
                       for value in depends_on_job_ids)
                or len(set(depends_on_job_ids))!=len(depends_on_job_ids)):
            raise ValueError('JOB_REPLAY_ARGUMENTS_INVALID')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write',function=function_name,
                    arguments=normalized_program)
                authorization_scope_digest=resolve_effective_dimensional_scope(
                    db,self.identity,scope,access=access,
                    function=function_name).scope_digest
                prior=db.execute('''SELECT job_id,status,request_digest,
                    expected_metadata_revision,expected_data_revision,
                    expected_policy_revision,verified_groups,
                    authorization_scope_digest
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',(
                    scope.workspace_id,scope.application_id,
                    self.identity.issuer,self.identity.subject_id,
                    idempotency_key)).fetchone()
                if prior is None:
                    return None
                descriptor=_job_request_descriptor(scope,self.identity,
                    function_name=function_name,
                    program_digest=_canonical_digest(normalized_program),
                    compiler_version=compiler_version,plan_digest=plan_digest,
                    revisions=(prior['expected_metadata_revision'],
                        prior['expected_data_revision'],
                        prior['expected_policy_revision']),
                    resource_class='short',dependencies=depends_on_job_ids,
                    authorization_scope_digest=authorization_scope_digest)
                if (tuple(prior['verified_groups'])!=self.identity.groups
                        or prior['authorization_scope_digest'] is None
                        or prior['authorization_scope_digest']!=
                        authorization_scope_digest
                        or _canonical_digest(descriptor)!=prior['request_digest']):
                    raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT')
                return {'jobId':prior['job_id'],'status':prior['status'],
                        'duplicate':True}

    @lock_busy_boundary
    def replay_batch(self, scope: ApplicationScope, *, idempotency_key: str,
                     function_name: str, mutations: tuple,
                     depends_on_job_ids: tuple[str, ...] = (),
                     execution_authority: dict | None = None) -> dict | None:
        """Reconcile existing exact batches; never admit work or extend a preview."""
        if (not isinstance(scope,ApplicationScope)
                or not isinstance(idempotency_key,str) or not _KEY.fullmatch(idempotency_key)
                or function_name not in (_NUMERIC_FUNCTION,_TEXT_FUNCTION,
                                         _DETAIL_FUNCTION)
                or not isinstance(depends_on_job_ids,tuple) or len(depends_on_job_ids)>16
                or any(not isinstance(value,str) or not _JOB_ID.fullmatch(value) for value in depends_on_job_ids)
                or len(set(depends_on_job_ids))!=len(depends_on_job_ids)):
            raise ValueError('BATCH_REPLAY_ARGUMENTS_INVALID')
        numeric=function_name==_NUMERIC_FUNCTION
        detail=function_name==_DETAIL_FUNCTION
        normalized=(_detail_program(*mutations) if detail else
                    (_numeric_program if numeric else _text_program)(mutations))
        compiler=(_DETAIL_COMPILER if detail else
                  _NUMERIC_COMPILER if numeric else _TEXT_COMPILER)
        plan=(_DETAIL_PLAN_DIGEST if detail else
              _NUMERIC_PLAN_DIGEST if numeric else _TEXT_PLAN_DIGEST)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                access=PostgresAccessChecker.check_in_transaction(db,self.identity,scope,
                    'write',function=function_name,arguments=normalized)
                authorization_scope_digest=resolve_effective_dimensional_scope(
                    db,self.identity,scope,access=access,
                    function=function_name).scope_digest
                prior=db.execute('''SELECT job_id,status,request_digest,
                    expected_metadata_revision,expected_data_revision,
                    expected_policy_revision,verified_groups,
                    authorization_scope_digest
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',
                    (scope.workspace_id,scope.application_id,self.identity.issuer,
                     self.identity.subject_id,idempotency_key)).fetchone()
                if prior is None:return None
                descriptor=_job_request_descriptor(scope,self.identity,
                    function_name=function_name,
                    program_digest=_canonical_digest(normalized),
                    compiler_version=compiler,plan_digest=plan,
                    revisions=(prior['expected_metadata_revision'],
                        prior['expected_data_revision'],
                        prior['expected_policy_revision']),
                    resource_class='short',dependencies=depends_on_job_ids,
                    authorization_scope_digest=authorization_scope_digest,
                    execution_authority=execution_authority)
                if (tuple(prior['verified_groups'])!=self.identity.groups
                        or prior['authorization_scope_digest'] is None
                        or prior['authorization_scope_digest']!=
                        authorization_scope_digest
                        or _canonical_digest(descriptor)!=prior['request_digest']):
                    raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT')
                return {'jobId':prior['job_id'],'status':prior['status'],'duplicate':True}

    def submit_numeric(self, scope: ApplicationScope, *, idempotency_key: str,
                       mutations: tuple[NumericMutation, ...],
                       expected_metadata_revision: int,
                       expected_data_revision: int,
                       expected_policy_revision: int,
                       depends_on_job_ids: tuple[str, ...] = (),
                       execution_authority: dict | None = None) -> dict:
        """Fixed lowering for the bounded numeric job subset."""
        return self.submit(
            scope, idempotency_key=idempotency_key,
            function_name=_NUMERIC_FUNCTION,
            normalized_program=_numeric_program(mutations),
            compiler_version=_NUMERIC_COMPILER,
            plan_digest=_NUMERIC_PLAN_DIGEST,
            expected_metadata_revision=expected_metadata_revision,
            expected_data_revision=expected_data_revision,
            expected_policy_revision=expected_policy_revision,
            depends_on_job_ids=depends_on_job_ids,
            execution_authority=execution_authority)

    def submit_text(self, scope: ApplicationScope, *, idempotency_key: str,
                    mutations: tuple[TextMutation, ...],
                    expected_metadata_revision: int,
                    expected_data_revision: int,
                    expected_policy_revision: int,
                    depends_on_job_ids: tuple[str, ...] = (),
                    execution_authority: dict | None = None) -> dict:
        return self.submit(
            scope, idempotency_key=idempotency_key,
            function_name=_TEXT_FUNCTION,
            normalized_program=_text_program(mutations),
            compiler_version=_TEXT_COMPILER,
            plan_digest=_TEXT_PLAN_DIGEST,
            expected_metadata_revision=expected_metadata_revision,
            expected_data_revision=expected_data_revision,
            expected_policy_revision=expected_policy_revision,
            depends_on_job_ids=depends_on_job_ids,
            execution_authority=execution_authority)

    def submit_detail(self, scope: ApplicationScope, *, idempotency_key: str,
                      coordinate: Coordinate, items: tuple[LineItem, ...],
                      expected_cell_change_id: str,
                      expected_detail_change_id: str,
                      expected_metadata_revision: int,
                      expected_data_revision: int,
                      expected_policy_revision: int,
                      depends_on_job_ids: tuple[str, ...] = (),
                      execution_authority: dict | None = None) -> dict:
        return self.submit(scope,idempotency_key=idempotency_key,
            function_name=_DETAIL_FUNCTION,
            normalized_program=_detail_program(coordinate,items,
                expected_cell_change_id,expected_detail_change_id),
            compiler_version=_DETAIL_COMPILER,plan_digest=_DETAIL_PLAN_DIGEST,
            expected_metadata_revision=expected_metadata_revision,
            expected_data_revision=expected_data_revision,
            expected_policy_revision=expected_policy_revision,
            depends_on_job_ids=depends_on_job_ids,
            execution_authority=execution_authority)

    @lock_busy_boundary
    def submit(self, scope: ApplicationScope, *, idempotency_key: str,
               function_name: str, normalized_program: dict,
               compiler_version: str, plan_digest: str,
               expected_metadata_revision: int, expected_data_revision: int,
               expected_policy_revision: int, resource_class: str = 'short',
               depends_on_job_ids: tuple[str, ...] = (),
               settled_published_dependencies: tuple[dict, ...] = (),
               execution_authority: dict | None = None,
               authorization_function: str | None = None) -> dict:
        if not isinstance(scope, ApplicationScope):
            raise ValueError('Application scope is required')
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(idempotency_key):
            raise ValueError('Idempotency key needs 8–128 safe characters')
        if (not isinstance(function_name, str)
                or not 1 <= len(function_name) <= 200
                or not isinstance(compiler_version, str)
                or not 1 <= len(compiler_version) <= 80
                or not isinstance(plan_digest, str)
                or not _DIGEST.fullmatch(plan_digest)
                or resource_class not in ('short', 'medium', 'long')):
            raise ValueError('Function, compiler, plan digest and work class are required')
        _validate_authorization_function(function_name, authorization_function)
        for value in (expected_metadata_revision, expected_data_revision,
                      expected_policy_revision):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError('Expected revisions must be nonnegative integers')
        if (not isinstance(normalized_program, dict)
                or not isinstance(depends_on_job_ids, tuple)
                or len(depends_on_job_ids) > 16
                or any(not isinstance(job_id, str)
                       or not _JOB_ID.fullmatch(job_id)
                       for job_id in depends_on_job_ids)
                or len(set(depends_on_job_ids)) != len(depends_on_job_ids)
                or not isinstance(settled_published_dependencies, tuple)
                or len(settled_published_dependencies) > 8):
            raise ValueError('Normalized program or dependencies are invalid')
        settled_by_job = {}
        for pin in settled_published_dependencies:
            if (not isinstance(pin, dict) or set(pin) != {
                    'jobId','resultKey','generationId','publishedRevision'}
                    or not isinstance(pin['jobId'], str)
                    or not _JOB_ID.fullmatch(pin['jobId'])
                    or not isinstance(pin['resultKey'], str)
                    or not _KEY.fullmatch(pin['resultKey'])
                    or not isinstance(pin['generationId'], str)
                    or not _JOB_ID.fullmatch(pin['generationId'])
                    or type(pin['publishedRevision']) is not int
                    or pin['publishedRevision'] < 1
                    or pin['jobId'] in settled_by_job):
                raise ValueError('PUBLISHED_JOB_DEPENDENCY_INVALID')
            settled_by_job[pin['jobId']] = pin
        if settled_published_dependencies:
            driver = (normalized_program.get('driverPolicy')
                      if isinstance(normalized_program, dict) else None)
            published_inputs = normalized_program.get('publishedInputs')
            allocation = (normalized_program.get('reusablePolicy')
                          if isinstance(normalized_program,dict) else None)
            allocation_pin=normalized_program.get('publishedRatioBasis')
            driver_ok=(function_name=='facts.expression.calculate'
                and compiler_version=='typed-numeric-expression-v25'
                and isinstance(driver,dict) and driver.get('policyFormat')==
                    'openepm-planning-operation-policy-v2'
                and published_inputs==[{key:pin[key] for key in (
                    'resultKey','generationId','publishedRevision')}
                    for pin in settled_published_dependencies])
            allocation_ok=(function_name=='facts.planning.allocate.weighted'
                and compiler_version=='planning-allocation-published-ratio-policy-v2'
                and isinstance(allocation,dict) and allocation.get('policyFormat')==
                    'openepm-planning-operation-policy-v2'
                and len(settled_published_dependencies)==1
                and allocation_pin=={key:settled_published_dependencies[0][key]
                    for key in ('resultKey','generationId','publishedRevision')})
            if (not (driver_ok or allocation_ok)
                    or set(settled_by_job) != set(depends_on_job_ids)):
                raise ValueError('PUBLISHED_JOB_DEPENDENCY_INVALID')
        authority_keys={'python_workflow_id','delegation_id','delegation_version',
                        'schedule_id','schedule_version'}
        if execution_authority is not None and (
                type(execution_authority) is not dict
                or set(execution_authority)!=authority_keys
                or type(execution_authority['python_workflow_id']) is not str
                or not _JOB_ID.fullmatch(execution_authority['python_workflow_id'])
                or type(execution_authority['delegation_id']) is not str
                or re.fullmatch(r'[A-Za-z0-9._-]{1,200}',
                    execution_authority['delegation_id']) is None
                or type(execution_authority['delegation_version']) is not int
                or execution_authority['delegation_version']<1
                or ((execution_authority['schedule_id'] is None) !=
                    (execution_authority['schedule_version'] is None))
                or (execution_authority['schedule_id'] is not None and (
                    type(execution_authority['schedule_id']) is not str
                    or re.fullmatch(r'[A-Za-z0-9._-]{1,200}',
                        execution_authority['schedule_id']) is None
                    or type(execution_authority['schedule_version']) is not int
                    or execution_authority['schedule_version']<1))):
            raise ValueError('PYTHON_JOB_EXECUTION_AUTHORITY_INVALID')
        try:
            program_json = json.dumps(normalized_program, sort_keys=True,
                                      separators=(',', ':'), ensure_ascii=False,
                                      allow_nan=False)
        except (TypeError, ValueError) as error:
            raise ValueError('Normalized program must be JSON') from error
        if len(program_json.encode('utf-8')) > 8_000_000:
            raise ValueError('Normalized program exceeds 8 MB')
        program_digest = sha256(program_json.encode('utf-8')).hexdigest()
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT a.status AS application_status,
                    s.processing_mode, s.metadata_revision, s.data_revision,
                    s.policy_revision,s.commit_revision,s.schema_epoch FROM epm.application_state s
                    JOIN epm.application a USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                access=PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope,
                    'admin' if function_name in ('consolidation.acquisition.journal.publish',
                        'consolidation.journal.from_calculation.publish',
                        'facts.projections.rebuild','facts.projections.cleanup') else 'write',
                    function=authorization_function or function_name,
                    arguments=normalized_program)
                authorization_scope_digest=resolve_effective_dimensional_scope(
                    db,self.identity,scope,access=access,
                    function=authorization_function or function_name).scope_digest
                request_descriptor=_job_request_descriptor(scope,self.identity,
                    function_name=function_name,program_digest=program_digest,
                    compiler_version=compiler_version,plan_digest=plan_digest,
                    revisions=(expected_metadata_revision,
                        expected_data_revision,expected_policy_revision),
                    resource_class=resource_class,
                    dependencies=depends_on_job_ids,
                    authorization_scope_digest=authorization_scope_digest,
                    authorization_function=authorization_function,
                    execution_authority=execution_authority)
                request_digest = _canonical_digest(request_descriptor)
                previous = db.execute('''SELECT job_id,request_digest,status,
                    compiler_version,plan_digest,verified_groups,
                    authorization_scope_digest
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     self.identity.issuer, self.identity.subject_id,
                     idempotency_key)).fetchone()
                if previous:
                    matches=(tuple(previous['verified_groups'])==
                        self.identity.groups
                        and previous['authorization_scope_digest'] is not None
                        and previous['authorization_scope_digest']==
                        authorization_scope_digest
                        and previous['request_digest']==request_digest)
                    if not matches and function_name in ('consolidation.full.aggregate',
                            'currency.calculation.translation.publish',
                            'currency.translation.publish',
                            'consolidation.full.translated.aggregate'):
                        # A compiler upgrade must not silently replace an accepted
                        # financial request or break replay of identical business pins.
                        from .postgres_consolidation_aggregate import supported_full_compiler
                        from .postgres_currency_calculation_translation import supported_calculation_translation_compiler
                        from .postgres_consolidation_translated import supported_translated_full_compiler
                        from .postgres_currency_publication import supported_translation_compiler
                        compatible={
                            'consolidation.full.aggregate':supported_full_compiler,
                            'currency.translation.publish':supported_translation_compiler,
                            'currency.calculation.translation.publish':supported_calculation_translation_compiler,
                            'consolidation.full.translated.aggregate':supported_translated_full_compiler}[function_name]
                        original_request={**request_descriptor,
                            'compilerVersion':previous['compiler_version'],
                            'planDigest':previous['plan_digest']}
                        matches=(compatible(previous['compiler_version'],
                            previous['plan_digest'],normalized_program) and
                            previous['request_digest']==_canonical_digest(original_request))
                    if not matches: raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT')
                    return {'jobId': previous['job_id'],
                            'status': previous['status'], 'duplicate': True}
                if (state['application_status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                _validate_submission_revisions(state,function_name,
                    expected_metadata_revision,expected_data_revision,
                    expected_policy_revision)
                if function_name == 'facts.projections.cleanup':
                    from .postgres_projection_cleanup import decode_program as decode_cleanup, resolve_target, COMPILER as cleanup_compiler, PLAN_DIGEST as cleanup_plan
                    checked=decode_cleanup(normalized_program)
                    if compiler_version!=cleanup_compiler or plan_digest!=cleanup_plan or resource_class!='long':
                        raise ValueError('CLEANUP_JOB_INVALID')
                    target=resolve_target(db,scope,checked)
                    if any(target[key]!=checked[key] for key in ('targetGeneration','recoveryProgramDigest','schemaEpoch')):
                        raise ValueError('CLEANUP_TARGET_INVALID')
                if function_name == 'facts.projections.rebuild':
                    from .postgres_fact_reconstruction_job import decode_program, compiler_for, COMPILER, PLAN_DIGEST
                    checked = decode_program(normalized_program)
                    if (compiler_version != COMPILER or plan_digest != PLAN_DIGEST
                            or (compiler_version,plan_digest) != compiler_for(checked)
                            or resource_class != 'long'):
                        raise ValueError('RECONSTRUCTION_JOB_INVALID')
                    if (state['commit_revision'] != checked['sourceCommitRevision']
                            or state['schema_epoch'] != checked['schemaEpoch']):
                        raise ValueError('STALE_RECONSTRUCTION_SOURCE')
                if function_name in ('facts.numeric.scale',
                                     'consolidation.nci.period.publish',
                                     'consolidation.nci.period.withdraw',
                                     'facts.expression.calculate',
                                     'facts.planning.spread.equal',
                                     'facts.planning.allocate.weighted',
                                     'facts.planning.group.sum.bulk',
                                     'currency.translation.publish',
                                     'currency.calculation.translation.publish',
                                     'consolidation.full.translated.aggregate',
                                     'consolidation.full.contribute',
                                     'consolidation.full.typed.contribute',
                                     'consolidation.full.aggregate'):
                    result_key = normalized_program.get('resultKey')
                    expected_pointer = normalized_program.get(
                        'expectedPublicationRevision')
                    if (not isinstance(result_key, str)
                            or not _KEY.fullmatch(result_key)
                            or type(expected_pointer) is not int
                            or expected_pointer < 0):
                        raise ValueError('INVALID_CALCULATION_PUBLICATION_PREVIEW')
                    pointer = db.execute('''SELECT published_revision
                        FROM epm.calculation_publication
                        WHERE workspace_id=%s AND application_id=%s
                        AND result_key=%s''',
                        (scope.workspace_id, scope.application_id,
                         result_key)).fetchone()
                    if (pointer['published_revision'] if pointer else 0) != (
                            expected_pointer):
                        raise ValueError('STALE_PUBLICATION_POINTER')
                if function_name=='currency.amount.translate.publish':
                    from .postgres_currency_amount_publication import (
                        decode_program as decode_currency_amount,
                        compiler_for as currency_amount_compiler_for)
                    checked=decode_currency_amount(normalized_program)
                    expected_compiler,expected_plan=currency_amount_compiler_for(checked)
                    if (compiler_version!=expected_compiler
                            or plan_digest!=expected_plan
                            or resource_class!='short'):
                        raise ValueError('CURRENCY_AMOUNT_PUBLICATION_JOB_INVALID')
                    result_key=checked['arguments']['resultKey']
                    pointer=db.execute('''SELECT published_revision FROM epm.calculation_publication
                        WHERE workspace_id=%s AND application_id=%s AND result_key=%s''',
                        (scope.workspace_id,scope.application_id,result_key)).fetchone()
                    if (pointer['published_revision'] if pointer else 0)!=checked['expectedPublicationRevision']:
                        raise ValueError('STALE_PUBLICATION_POINTER')
                if function_name=='facts.numeric.iterate':
                    from .postgres_numeric_iteration import decode_program as decode_iteration,COMPILER as iteration_compiler,PLAN_DIGEST as iteration_plan
                    if compiler_version!=iteration_compiler or plan_digest!=iteration_plan:
                        raise ValueError('NUMERIC_ITERATION_COMPILER_INVALID')
                    decode_iteration(normalized_program)
                if function_name=='rules.numeric_sequence.run':
                    from .postgres_saved_numeric_sequence import validate_run,COMPILER as saved_compiler,PLAN_DIGEST as saved_digest
                    if compiler_version!=saved_compiler or plan_digest!=saved_digest:
                        raise ValueError('ORDERED_RULE_COMPILER_INVALID')
                    PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'rule_run')
                    validate_run(db,scope,normalized_program)
                if function_name == 'facts.expression.calculate':
                    saved_rule = normalized_program.get('savedRule')
                    if saved_rule:
                        PostgresAccessChecker.check_in_transaction(
                            db, self.identity, scope, 'rule_run', function=function_name, arguments=normalized_program)
                        from .postgres_expression_rules import verify_published_rule
                        verify_published_rule(
                            db, scope, saved_rule, normalized_program)
                    input_status = published_input_status(
                        db, scope, normalized_program)
                    if (input_status is not None and
                            not input_status['matchesAtRead']):
                        raise ValueError('STALE_PUBLISHED_INPUT')
                if function_name in ('consolidation.nci.period.publish','consolidation.nci.period.withdraw'):
                    from .postgres_period_nci_publication import (decode_attribution,
                        validate_attribution,enforce_period_attribution_dimensional_security)
                    attribution_plan=decode_attribution(normalized_program)
                    attribution_summary=validate_attribution(db,scope,attribution_plan,state)
                    enforce_period_attribution_dimensional_security(
                        db,self.identity,scope,attribution_plan,attribution_summary)
                if function_name == 'consolidation.full.aggregate':
                    child_status = published_child_status(
                        db, scope, normalized_program)
                    if (child_status is not None and
                            not child_status['matchesAtRead']):
                        raise ValueError('STALE_PUBLISHED_INPUT')
                if function_name == 'consolidation.full.translated.aggregate':
                    from .postgres_consolidation_translated import (
                        decode_translated_full, validate_translated_full)
                    validate_translated_full(
                        db, scope,
                        decode_translated_full(normalized_program))
                if function_name == (
                        'currency.calculation.translation.publish'):
                    from .postgres_currency_calculation_translation import (
                        decode_calculation_translation,
                        validate_calculation_translation)
                    validate_calculation_translation(
                        db,scope,
                        decode_calculation_translation(normalized_program),
                        self.identity,self.dsn)
                pending = db.execute('''SELECT count(*) AS total FROM epm.job
                    WHERE workspace_id=%s AND application_id=%s
                    AND status IN ('accepted','ready','running','staged',
                                   'cancel_requested')''',
                    (scope.workspace_id, scope.application_id)).fetchone()['total']
                if pending >= 100:
                    raise ValueError('APPLICATION_QUEUE_FULL')
                waiting = False
                for predecessor in depends_on_job_ids:
                    dependency = db.execute('''SELECT j.status,j.issuer,j.subject_id,
                        g.result_key,g.generation_id,g.published_revision,
                        p.generation_id AS observed_generation_id,
                        p.published_revision AS observed_published_revision
                        FROM epm.job j
                        LEFT JOIN epm.calculation_generation g
                          ON g.workspace_id=j.workspace_id
                         AND g.application_id=j.application_id
                         AND g.job_id=j.job_id
                        LEFT JOIN epm.calculation_publication p
                          ON p.workspace_id=g.workspace_id
                         AND p.application_id=g.application_id
                         AND p.result_key=g.result_key
                        WHERE j.workspace_id=%s AND j.application_id=%s
                        AND j.job_id=%s''',
                        (scope.workspace_id, scope.application_id,
                         predecessor)).fetchone()
                    published_pin = settled_by_job.get(predecessor)
                    if not _dependency_available(dependency,published_pin,
                            self.identity):
                        raise ValueError('QUEUE_DEPENDENCY_UNAVAILABLE')
                    if dependency['status'] in ('failed','cancelled',
                                                'needs_inspection'):
                        raise ValueError('QUEUE_DEPENDENCY_FAILED')
                    waiting |= dependency['status'] != 'published'
                job_id = uuid.uuid4().hex
                status = 'accepted' if waiting else 'ready'
                if self.identity.issued_at is not None:
                    authority_kind = 'HumanToken'
                elif self.identity.issuer.startswith('urn:openepm:'):
                    authority_kind = 'Technical'
                else:
                    raise ValueError('DURABLE_HUMAN_TOKEN_ISSUED_AT_REQUIRED')
                db.execute('''INSERT INTO epm.job
                    (workspace_id,application_id,job_id,issuer,subject_id,
                     idempotency_key,function_name,normalized_program,
                     compiler_version,program_digest,request_digest,
                     plan_digest,expected_metadata_revision,
                     expected_data_revision,expected_policy_revision,
                     resource_class,status,verified_groups,
                     authorization_scope_digest,python_workflow_id,
                     execution_delegation_id,execution_delegation_version,
                     execution_schedule_id,execution_schedule_version,
                     token_issued_at,authority_kind)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                            %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id, scope.application_id, job_id,
                     self.identity.issuer, self.identity.subject_id,
                     idempotency_key, function_name, Jsonb(normalized_program),
                     compiler_version, program_digest, request_digest,
                     plan_digest, expected_metadata_revision,
                     expected_data_revision, expected_policy_revision,
                     resource_class,status,list(self.identity.groups),
                     authorization_scope_digest,
                     execution_authority['python_workflow_id'] if execution_authority else None,
                     execution_authority['delegation_id'] if execution_authority else None,
                     execution_authority['delegation_version'] if execution_authority else None,
                     execution_authority['schedule_id'] if execution_authority else None,
                     execution_authority['schedule_version'] if execution_authority else None,
                     self.identity.issued_at,authority_kind))
                with db.cursor() as cursor:
                    cursor.executemany('''INSERT INTO epm.job_dependency
                        (workspace_id,application_id,job_id,depends_on_job_id)
                        VALUES (%s,%s,%s,%s)''',
                        [(scope.workspace_id, scope.application_id,
                          job_id, predecessor)
                         for predecessor in depends_on_job_ids])
                return {'jobId': job_id, 'status': status, 'duplicate': False}

    def read(self, scope: ApplicationScope, job_id: str) -> dict:
        if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
            raise ValueError('Job ID must be lowercase UUID hex')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            PostgresNumericFactStore._set_scope(db, scope)
            PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, 'read')
            row = db.execute('''SELECT job_id,status,claim_generation,attempts,
                next_attempt_at,receipt_revision,error_code,result,issuer,subject_id
                FROM epm.job WHERE workspace_id=%s AND application_id=%s
                AND job_id=%s''',
                (scope.workspace_id, scope.application_id, job_id)).fetchone()
            if (row is None or row['issuer'] != self.identity.issuer
                    or row['subject_id'] != self.identity.subject_id):
                raise ValueError('JOB_UNAVAILABLE')
            return {key: value for key, value in row.items()
                    if key not in ('issuer', 'subject_id')}

    def events(self, scope: ApplicationScope, *, after_sequence: int = 0,
               limit: int = 100) -> dict:
        """Page durable owner-visible hints; read(job_id) is authoritative."""
        if (not isinstance(scope, ApplicationScope)
                or type(after_sequence) is not int or after_sequence < 0
                or type(limit) is not int or not 1 <= limit <= 500):
            raise ValueError('An application scope and bounded event cursor are required')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                rows = db.execute('''SELECT sequence,job_id,status,
                    claim_generation,receipt_revision,error_code,occurred_at
                    FROM epm.job_event WHERE workspace_id=%s
                    AND application_id=%s AND issuer=%s AND subject_id=%s
                    AND sequence>%s ORDER BY sequence LIMIT %s''',
                    (scope.workspace_id, scope.application_id,
                     self.identity.issuer, self.identity.subject_id,
                     after_sequence, limit + 1)).fetchall()
                page = rows[:limit]
                return {'events': [{**dict(row),
                                    'occurred_at': row['occurred_at'].isoformat()}
                                   for row in page],
                        'nextSequence': (page[-1]['sequence'] if page
                                         else after_sequence),
                        'hasMore': len(rows) > limit}

    def request_cancel(self, scope: ApplicationScope, job_id: str, *,
                       allow_application_admin: bool = False) -> dict:
        if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
            raise ValueError('Job ID must be lowercase UUID hex')
        if type(allow_application_admin) is not bool:
            raise ValueError('Application-admin cancellation flag must be Boolean')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                row = db.execute('''SELECT status,issuer,subject_id
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id,
                     job_id)).fetchone()
                owner = (row is not None and
                    row['issuer'] == self.identity.issuer and
                    row['subject_id'] == self.identity.subject_id)
                administrator = False
                if row is not None and not owner and allow_application_admin:
                    try:
                        PostgresAccessChecker.check_in_transaction(
                            db,self.identity,scope,'admin')
                        administrator = True
                    except AccessDenied:
                        pass
                if row is None or not (owner or administrator):
                    raise ValueError('JOB_UNAVAILABLE')
                if row['status'] in ('accepted','ready'):
                    status = 'cancelled'
                elif row['status'] in ('running','staged'):
                    status = 'cancel_requested'
                else:
                    status = row['status']
                if status != row['status']:
                    db.execute('''UPDATE epm.job SET status=%s,
                        claim_generation=claim_generation+1,
                        claimant=NULL,lease_until=NULL,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND job_id=%s''',
                        (status, scope.workspace_id,
                         scope.application_id, job_id))
                return {'jobId': job_id, 'status': status}

    def rerun_as_task_controller(self, scope: ApplicationScope, job_id: str, *,
                                 idempotency_key: str,
                                 allow_application_admin: bool = False) -> dict:
        """Admit distinct new work for the bounded direct-write subset.

        Only cancelled/failed direct numeric, text and supporting-detail jobs
        without dependencies or delegated Python authority are reconstructible
        from their authoritative row.  Current revisions and authorization are
        resolved afresh; embedded cell/detail change IDs remain unchanged and
        therefore preserve their ordinary stale-write protection.
        """
        if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
            raise ValueError('Job ID must be lowercase UUID hex')
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(
                idempotency_key):
            raise ValueError('Idempotency key needs 8–128 safe characters')
        if type(allow_application_admin) is not bool:
            raise ValueError('Application-admin rerun flag must be Boolean')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                row = db.execute('''SELECT j.function_name,
                    j.normalized_program,j.compiler_version,j.plan_digest,
                    j.resource_class,j.status,j.issuer,j.subject_id,
                    j.python_workflow_id,(SELECT count(*)
                      FROM epm.job_dependency d
                      WHERE d.workspace_id=j.workspace_id
                        AND d.application_id=j.application_id
                        AND d.job_id=j.job_id) AS deps
                    FROM epm.job j
                    WHERE j.workspace_id=%s AND j.application_id=%s
                      AND j.job_id=%s
                    FOR UPDATE OF j''',
                    (scope.workspace_id, scope.application_id,
                     job_id)).fetchone()
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
                    raise ValueError('JOB_UNAVAILABLE')
                if (row['status'] not in ('failed', 'cancelled')
                        or row['function_name'] not in (
                            _NUMERIC_FUNCTION, _TEXT_FUNCTION,
                            _DETAIL_FUNCTION)
                        or row['python_workflow_id'] is not None
                        or row['deps'] != 0):
                    raise ValueError('JOB_RERUN_NOT_SUPPORTED')
                state = db.execute('''SELECT metadata_revision,data_revision,
                    policy_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id,
                     scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                arguments = {
                    'function_name': row['function_name'],
                    'normalized_program': row['normalized_program'],
                    'compiler_version': row['compiler_version'],
                    'plan_digest': row['plan_digest'],
                    'resource_class': row['resource_class'],
                    'expected_metadata_revision': state['metadata_revision'],
                    'expected_data_revision': state['data_revision'],
                    'expected_policy_revision': state['policy_revision'],
                }
        return self.submit(
            scope, idempotency_key=idempotency_key, **arguments)


def _require_python_job_authority(db,scope,job) -> None:
    workflow_id=job.get('python_workflow_id')
    if workflow_id is None:
        if re.fullmatch(r'py-[0-9a-f]{32}-[1-9][0-9]*',job['idempotency_key']):
            raise ValueError('PYTHON_JOB_EXECUTION_AUTHORITY_MISSING')
        return
    bound=db.execute('''SELECT b.delegation_id,b.delegation_version,
        b.schedule_id,b.schedule_version,w.issuer,w.subject_id,w.build_id
        FROM epm.python_program_workflow w
        JOIN epm.python_program_build b USING(workspace_id,application_id,build_id)
        WHERE w.workspace_id=%s AND w.application_id=%s AND w.workflow_id=%s''',
        (scope.workspace_id,scope.application_id,workflow_id)).fetchone()
    if (bound is None or bound['issuer']!=job['issuer']
            or bound['subject_id']!=job['subject_id']
            or (bound['delegation_id'],bound['delegation_version'],
                bound['schedule_id'],bound['schedule_version']) !=
               (job['execution_delegation_id'],
                job['execution_delegation_version'],job['execution_schedule_id'],
                job['execution_schedule_version'])):
        raise ValueError('PYTHON_JOB_EXECUTION_AUTHORITY_INVALID')
    current=db.execute('''SELECT epm.execution_delegation_is_current(
        %s,%s,%s,%s,%s,%s,%s,%s,%s) AS allowed''',(
        scope.workspace_id,scope.application_id,job['execution_delegation_id'],
        job['execution_delegation_version'],job['issuer'],job['subject_id'],
        'python.program.run',job['execution_schedule_id'],
        job['execution_schedule_version'])).fetchone()
    if not current or current['allowed'] is not True:
        raise ValueError('PYTHON_EXECUTION_DELEGATION_INVALID')


class PostgresNumericJobPublisher:
    """Publish a claimed numeric batch with its effect and receipt atomically."""

    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn = dsn
        self.identity = identity

    def publish(self, claim: dict) -> dict:
        if (not isinstance(claim, dict)
                or not isinstance(claim.get('workspace_id'), str)
                or not isinstance(claim.get('application_id'), str)
                or not isinstance(claim.get('job_id'), str)
                or not _JOB_ID.fullmatch(claim['job_id'])
                or not isinstance(claim.get('claimant'), str)
                or type(claim.get('claim_generation')) is not int):
            raise ValueError('Invalid worker claim')
        if claim.get('function_name') in (
                'facts.numeric.sequence','rules.numeric_sequence.run',
                'facts.numeric.iterate'):
            from .postgres_numeric_sequence import PostgresNumericSequencePublisher
            return PostgresNumericSequencePublisher(
                self.dsn,identity=self.identity).publish(claim)
        scope = ApplicationScope(claim['workspace_id'], claim['application_id'])
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT metadata_revision,data_revision,
                    policy_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                access=PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                control_claim=claim.get('function_name') in _CONTROL_FENCED_NUMERIC_FUNCTIONS
                job = db.execute('''SELECT issuer,subject_id,status,
                    idempotency_key,claim_generation,claimant,lease_until,function_name,
                    normalized_program,program_digest,plan_digest,
                    compiler_version,expected_metadata_revision,
                    expected_data_revision,expected_policy_revision,
                    python_workflow_id,execution_delegation_id,
                    execution_delegation_version,execution_schedule_id,
                    execution_schedule_version
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s''' + ('' if control_claim else ' FOR UPDATE'),
                    (scope.workspace_id, scope.application_id,
                     claim['job_id'])).fetchone()
                if (job is None or job['issuer'] != self.identity.issuer
                        or job['subject_id'] != self.identity.subject_id):
                    raise ValueError('JOB_UNAVAILABLE')
                valid = db.execute('''SELECT %s::timestamptz > clock_timestamp()
                    AS unexpired''', (job['lease_until'],)).fetchone()
                if (job['status'] != 'running'
                        or job['claim_generation'] != claim['claim_generation']
                        or job['claimant'] != claim['claimant']
                        or not valid['unexpired']):
                    raise ValueError('STALE_WORKER_FENCE')
                _require_python_job_authority(db,scope,job)
                iterative=job['function_name']=='facts.numeric.iterate'
                if ((control_claim or job['function_name'] in _CONTROL_FENCED_NUMERIC_FUNCTIONS)
                        and claim.get('function_name') is not None
                        and claim['function_name'] != job['function_name']):
                    raise ValueError('WORKER_CLAIM_FUNCTION_MISMATCH')
                if iterative and not control_claim:
                    raise ValueError('WORKER_CLAIM_FUNCTION_MISMATCH')
                if iterative:
                    from .postgres_numeric_iteration import COMPILER as iteration_compiler,PLAN_DIGEST as iteration_plan,apply as apply_iteration
                saved = job['function_name']=='rules.numeric_sequence.run'
                ordered = job['function_name'] == 'facts.numeric.sequence'
                if ordered:
                    from .postgres_numeric_sequence import (
                        compiler_for as ordered_authority,
                        apply_in_transaction as apply_ordered)
                    ordered_compiler, ordered_digest = ordered_authority(job['normalized_program'])
                if saved:
                    from .postgres_saved_numeric_sequence import COMPILER as saved_compiler,PLAN_DIGEST as saved_digest,apply as apply_saved
                detail=job['function_name']==_DETAIL_FUNCTION
                if (job['function_name'] not in (_NUMERIC_FUNCTION,
                        _DETAIL_FUNCTION,'facts.numeric.sequence',
                        'rules.numeric_sequence.run','facts.numeric.iterate')
                        or job['compiler_version'] != (_DETAIL_COMPILER if detail else iteration_compiler if iterative else saved_compiler if saved else ordered_compiler if ordered else _NUMERIC_COMPILER)
                        or job['plan_digest'] != (_DETAIL_PLAN_DIGEST if detail else iteration_plan if iterative else saved_digest if saved else ordered_digest if ordered else _NUMERIC_PLAN_DIGEST)
                        or job['program_digest'] != _canonical_digest(
                            job['normalized_program'])):
                    raise ValueError('UNSUPPORTED_NUMERIC_JOB_PROGRAM')
                dependency_scoped = job['function_name'] in (
                    _NUMERIC_FUNCTION, _DETAIL_FUNCTION)
                if (state['metadata_revision'] != job['expected_metadata_revision']
                        or (not dependency_scoped and
                            state['data_revision'] != job['expected_data_revision'])
                        or state['policy_revision'] != job['expected_policy_revision']):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                if detail:
                    from .postgres_line_detail import PostgresLineDetailStore
                    coordinate,items,cell_change,detail_change = (
                        _decode_detail_program(job['normalized_program']))
                    receipt=PostgresLineDetailStore(self.dsn,
                        identity=self.identity).apply(scope,coordinate,items,
                        operation_id=claim['job_id'],
                        command_digest=job['program_digest'],
                        actor_id=job['subject_id'],
                        expected_metadata_revision=job['expected_metadata_revision'],
                        expected_data_revision=None,
                        expected_cell_change_id=cell_change,
                        expected_detail_change_id=detail_change,
                        _connection=db)
                    result={'changedCount':receipt.changed_count,
                            'committedRevision':receipt.committed_revision}
                elif iterative:
                    result=apply_iteration(db,scope,job,claim['job_id'],
                        identity=self.identity,workflow_role=access.role)
                elif saved:
                    result=apply_saved(db,scope,job,claim['job_id'],self.identity,
                        workflow_role=access.role)
                elif ordered:
                    result = apply_ordered(db, scope, job, claim['job_id'],
                        identity=self.identity,workflow_role=access.role)
                else:
                    mutations = _decode_numeric_program(job['normalized_program'])
                    receipt = PostgresNumericFactStore(
                        self.dsn, identity=self.identity).apply_in_transaction(
                            db, scope, mutations, operation_id=claim['job_id'],
                            command_digest=job['program_digest'],
                            actor_id=job['subject_id'],
                            expected_metadata_revision=job['expected_metadata_revision'],
                            expected_data_revision=None)
                    result = {'changedCount': receipt.changed_count,
                              'committedRevision': receipt.committed_revision}
                db.execute('''UPDATE epm.job SET status='published',
                    receipt_revision=%s,result=%s,claimant=NULL,
                    lease_until=NULL,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',
                    (result['committedRevision'], Jsonb(result),
                     scope.workspace_id, scope.application_id, claim['job_id']))
                return result


class PostgresTextJobPublisher:
    """Publish a claimed text batch, receipt and job result atomically."""

    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn = dsn
        self.identity = identity

    def publish(self, claim: dict) -> dict:
        if (not isinstance(claim, dict)
                or not isinstance(claim.get('workspace_id'), str)
                or not isinstance(claim.get('application_id'), str)
                or not isinstance(claim.get('job_id'), str)
                or not _JOB_ID.fullmatch(claim['job_id'])
                or not isinstance(claim.get('claimant'), str)
                or type(claim.get('claim_generation')) is not int):
            raise ValueError('Invalid worker claim')
        scope = ApplicationScope(claim['workspace_id'], claim['application_id'])
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT metadata_revision,data_revision,
                    policy_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                job = db.execute('''SELECT issuer,subject_id,status,
                    idempotency_key,claim_generation,claimant,lease_until,function_name,
                    normalized_program,program_digest,plan_digest,
                    compiler_version,expected_metadata_revision,
                    expected_data_revision,expected_policy_revision,
                    python_workflow_id,execution_delegation_id,
                    execution_delegation_version,execution_schedule_id,
                    execution_schedule_version
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id,
                     claim['job_id'])).fetchone()
                if (job is None or job['issuer'] != self.identity.issuer
                        or job['subject_id'] != self.identity.subject_id):
                    raise ValueError('JOB_UNAVAILABLE')
                valid = db.execute('''SELECT %s::timestamptz > clock_timestamp()
                    AS unexpired''', (job['lease_until'],)).fetchone()
                if (job['status'] != 'running'
                        or job['claim_generation'] != claim['claim_generation']
                        or job['claimant'] != claim['claimant']
                        or not valid['unexpired']):
                    raise ValueError('STALE_WORKER_FENCE')
                _require_python_job_authority(db,scope,job)
                if (job['function_name'] != _TEXT_FUNCTION
                        or job['compiler_version'] != _TEXT_COMPILER
                        or job['plan_digest'] != _TEXT_PLAN_DIGEST
                        or job['program_digest'] != _canonical_digest(
                            job['normalized_program'])):
                    raise ValueError('UNSUPPORTED_TEXT_JOB_PROGRAM')
                if (state['metadata_revision'] != job['expected_metadata_revision']
                        or state['policy_revision'] != job['expected_policy_revision']):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                mutations = _decode_text_program(job['normalized_program'])
                receipt = PostgresTextFactStore(
                    self.dsn, identity=self.identity).apply_in_transaction(
                        db, scope, mutations, operation_id=claim['job_id'],
                        command_digest=job['program_digest'],
                        actor_id=job['subject_id'],
                        expected_metadata_revision=job['expected_metadata_revision'],
                        expected_data_revision=None)
                result = {'changedCount': receipt.changed_count,
                          'committedRevision': receipt.committed_revision}
                db.execute('''UPDATE epm.job SET status='published',
                    receipt_revision=%s,result=%s,claimant=NULL,
                    lease_until=NULL,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',
                    (receipt.committed_revision, Jsonb(result),
                     scope.workspace_id, scope.application_id, claim['job_id']))
                return result


class PostgresJobWorker:
    """Fixed server coordinator credential; no client may select this role."""

    def __init__(self, dsn: str):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL worker DSN is required')
        self.dsn = dsn

    @staticmethod
    def _require_active_claim_scope(db, claim: dict) -> None:
        PostgresAccessChecker.lock_workspace(db, claim['workspace_id'])
        state = db.execute('''SELECT w.status AS workspace_status,
            a.status AS application_status,s.processing_mode
            FROM epm.workspace w JOIN epm.application a
              USING (workspace_id)
            JOIN epm.application_state s
              USING (workspace_id,application_id)
            WHERE w.workspace_id=%s AND a.application_id=%s''',
            (claim['workspace_id'],claim['application_id'])).fetchone()
        if (state is None or state[0] != 'Active'
                or state[1] != 'Active' or state[2] != 'Active'):
            raise ValueError('STALE_WORKER_FENCE')

    def refresh_dependencies(self) -> int:
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                configure_lock_wait(db)
                failed = db.execute('''UPDATE epm.job j SET status='failed',
                    error_code='DEPENDENCY_FAILED',
                    updated_at=transaction_timestamp()
                    WHERE j.status='accepted' AND EXISTS (
                        SELECT 1 FROM epm.job_dependency d JOIN epm.job p
                        ON p.workspace_id=d.workspace_id
                        AND p.application_id=d.application_id
                        AND p.job_id=d.depends_on_job_id
                        WHERE d.workspace_id=j.workspace_id
                        AND d.application_id=j.application_id
                        AND d.job_id=j.job_id AND p.status IN
                        ('failed','cancelled','needs_inspection'))''').rowcount
                ready = db.execute('''UPDATE epm.job j SET status='ready',
                    updated_at=transaction_timestamp()
                    WHERE j.status='accepted' AND NOT EXISTS (
                        SELECT 1 FROM epm.job_dependency d JOIN epm.job p
                        ON p.workspace_id=d.workspace_id
                        AND p.application_id=d.application_id
                        AND p.job_id=d.depends_on_job_id
                        WHERE d.workspace_id=j.workspace_id
                        AND d.application_id=j.application_id
                        AND d.job_id=j.job_id AND p.status<>'published')''').rowcount
                return failed + ready

    def claim(self, claimant: str, *, lease_seconds: int = 30,
              resource_class: str = 'short',
              scope: ApplicationScope | None = None,
              function_name: str | None = None,
              function_names: tuple[str, ...] | None = None,
              capacity_limits: tuple[int, int, int] | None = None
              ) -> dict | None:
        if (not isinstance(claimant, str) or not 1 <= len(claimant) <= 200
                or isinstance(lease_seconds, bool)
                or not isinstance(lease_seconds, int)
                or not 5 <= lease_seconds <= 300
                or resource_class not in ('short','medium','long')
                or (scope is not None and not isinstance(scope, ApplicationScope))
                or (function_name is not None and (
                    not isinstance(function_name, str)
                    or not 1 <= len(function_name) <= 200))
                or (function_names is not None and (
                    function_name is not None
                    or not isinstance(function_names, tuple)
                    or not 1 <= len(function_names) <= 64
                    or any(not isinstance(name, str)
                           or not 1 <= len(name) <= 200
                           for name in function_names)))
                or (capacity_limits is not None and (
                    not isinstance(capacity_limits, tuple)
                    or len(capacity_limits) != 3
                    or any(type(limit) is not int or not 1 <= limit <= 10000
                           for limit in capacity_limits)
                    or not (capacity_limits[0] >= capacity_limits[1] >=
                            capacity_limits[2])))):
            raise ValueError('Claimant, lease and work class are invalid')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                configure_lock_wait(db)
                # All worker processes use this short transaction fence, so
                # dispatch order and running-job budgets are decided together.
                db.execute('''SELECT pg_advisory_xact_lock(
                    hashtextextended('epm.worker.dispatch',0))''')
                if capacity_limits is not None:
                    running = db.execute('''SELECT count(*) AS count
                        FROM epm.job WHERE status='running' ''').fetchone()
                    if running['count'] >= capacity_limits[0]:
                        return None
                candidate_query = '''SELECT j.workspace_id,j.application_id,
                    j.job_id
                    FROM epm.job j
                    JOIN epm.application a USING (workspace_id,application_id)
                    JOIN epm.application_state s
                        USING (workspace_id,application_id)
                    JOIN epm.workspace w USING (workspace_id)
                    LEFT JOIN epm.worker_workspace_dispatch dispatch
                        ON dispatch.workspace_id=j.workspace_id
                    WHERE j.status='ready' AND j.resource_class=%s
                    AND (j.next_attempt_at IS NULL OR
                         j.next_attempt_at<=clock_timestamp())
                    AND j.authorization_scope_digest IS NOT NULL
                    AND a.status='Active' AND w.status='Active'
                    AND s.processing_mode='Active'
                    AND (%s::text IS NULL OR
                        (j.workspace_id=%s AND j.application_id=%s))
                    AND (%s::text IS NULL OR j.function_name=%s)
                    AND (%s::text[] IS NULL OR
                        j.function_name=ANY(%s::text[]))
                    AND (%s::int IS NULL OR (SELECT count(*) FROM epm.job active
                        WHERE active.workspace_id=j.workspace_id
                        AND active.status='running') < %s::int)
                    AND (%s::int IS NULL OR (SELECT count(*) FROM epm.job active
                        WHERE active.workspace_id=j.workspace_id
                        AND active.application_id=j.application_id
                        AND active.status='running') < %s::int)
                    AND NOT (j.workspace_id=ANY(%s::text[]))
                    AND NOT (j.job_id=ANY(%s::text[]))
                    ORDER BY dispatch.last_claim_sequence NULLS FIRST,
                        CASE WHEN (j.function_name='facts.projections.rebuild'
                            AND j.compiler_version='fact-projections-rebuild-v2')
                            OR (j.function_name='facts.projections.cleanup'
                            AND j.compiler_version='projection-generations-cleanup-v1')
                            THEN j.updated_at ELSE j.created_at END,
                        j.created_at,j.job_id
                    LIMIT 1'''
                candidate_params = (
                     resource_class, scope.workspace_id if scope else None,
                     scope.workspace_id if scope else None,
                     scope.application_id if scope else None,
                     function_name, function_name,
                     list(function_names) if function_names else None,
                     list(function_names) if function_names else None,
                     capacity_limits[1] if capacity_limits else None,
                     capacity_limits[1] if capacity_limits else None,
                     capacity_limits[2] if capacity_limits else None,
                     capacity_limits[2] if capacity_limits else None)
                skipped_workspaces = []
                skipped_jobs = []
                for _ in range(128):
                    candidate = db.execute(
                        candidate_query,
                        candidate_params + (skipped_workspaces,
                                            skipped_jobs)).fetchone()
                    if candidate is None:
                        return None
                    if not PostgresAccessChecker.try_lock_workspace(
                            db, candidate['workspace_id']):
                        skipped_workspaces.append(candidate['workspace_id'])
                        continue
                    # Reset settlement takes the workspace fence before job
                    # rows. Skip a concurrently locked or changed job and
                    # continue to another ready job without holding it up.
                    row = db.execute('''SELECT workspace_id,application_id,
                        job_id,function_name,normalized_program,
                        program_digest,plan_digest,compiler_version,issuer,
                        subject_id,verified_groups,authorization_scope_digest,
                        token_issued_at,authority_kind,
                        expected_metadata_revision,
                        expected_data_revision,expected_policy_revision,
                        claim_generation,status,resource_class,next_attempt_at,
                        (next_attempt_at IS NULL OR
                         next_attempt_at<=clock_timestamp()) AS retry_due
                        FROM epm.job WHERE workspace_id=%s
                        AND application_id=%s AND job_id=%s
                        FOR UPDATE SKIP LOCKED''',
                        (candidate['workspace_id'],
                         candidate['application_id'],
                         candidate['job_id'])).fetchone()
                    if (row is None or row['status'] != 'ready'
                            or not row['retry_due']
                            or row['resource_class'] != resource_class
                            or (function_name is not None
                                and row['function_name'] != function_name)
                            or (function_names is not None
                                and row['function_name'] not in function_names)):
                        skipped_jobs.append(candidate['job_id'])
                        continue
                    break
                else:
                    return None
                # If quiesce committed first, this READ COMMITTED status
                # recheck sees Maintenance and no claim is published.
                current = db.execute('''SELECT a.status AS application_status,
                    w.status AS workspace_status,s.processing_mode
                    FROM epm.application a
                    JOIN epm.application_state s
                        USING (workspace_id,application_id)
                    JOIN epm.workspace w USING (workspace_id)
                    WHERE a.workspace_id=%s AND a.application_id=%s''',
                    (row['workspace_id'],row['application_id'])).fetchone()
                if (current is None or current['application_status'] != 'Active'
                        or current['workspace_status'] != 'Active'
                        or current['processing_mode'] != 'Active'):
                    return None
                if capacity_limits is not None:
                    counts = db.execute('''SELECT
                        count(*) FILTER (WHERE workspace_id=%s) AS workspace,
                        count(*) FILTER (WHERE workspace_id=%s
                            AND application_id=%s) AS application
                        FROM epm.job WHERE status='running' ''',
                        (row['workspace_id'], row['workspace_id'],
                         row['application_id'])).fetchone()
                    if (counts['workspace'] >= capacity_limits[1]
                            or counts['application'] >= capacity_limits[2]):
                        return None
                generation = row['claim_generation'] + 1
                db.execute('''UPDATE epm.job SET status='running',
                    claim_generation=%s,claimant=%s,
                    lease_until=clock_timestamp()+make_interval(secs=>%s),
                    next_attempt_at=NULL,
                    attempts=attempts+1,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',
                    (generation, claimant, lease_seconds,
                     row['workspace_id'], row['application_id'], row['job_id']))
                db.execute('''INSERT INTO epm.worker_workspace_dispatch
                    (workspace_id,last_claim_sequence,claim_count)
                    VALUES (%s,nextval('epm.worker_dispatch_sequence'),1)
                    ON CONFLICT (workspace_id) DO UPDATE SET
                    last_claim_sequence=EXCLUDED.last_claim_sequence,
                    claim_count=epm.worker_workspace_dispatch.claim_count+1''',
                    (row['workspace_id'],))
                return {**dict(row), 'claim_generation': generation,
                        'claimant': claimant}

    def heartbeat(self, claim: dict, *, lease_seconds: int = 30) -> None:
        if (isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int)
                or not 5 <= lease_seconds <= 300):
            raise ValueError('Lease must be 5–300 seconds')
        with connect_postgres(self.dsn) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                configure_lock_wait(db)
                self._require_active_claim_scope(db, claim)
                updated = db.execute('''UPDATE epm.job SET
                    lease_until=clock_timestamp()+make_interval(secs=>%s),
                    updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s
                    AND claim_generation=%s AND claimant=%s
                    AND status='running' AND lease_until>clock_timestamp()''',
                    (lease_seconds, claim['workspace_id'], claim['application_id'],
                     claim['job_id'], claim['claim_generation'],
                     claim['claimant'])).rowcount
                if not updated:
                    raise ValueError('STALE_WORKER_FENCE')

    def finish_stage(self, claim: dict, *, error_code: str | None = None) -> str:
        if error_code is not None and (
                not isinstance(error_code, str) or not 1 <= len(error_code) <= 200):
            raise ValueError('Error code must be 1–200 characters')
        status = 'failed' if error_code is not None else 'staged'
        with connect_postgres(self.dsn) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                configure_lock_wait(db)
                self._require_active_claim_scope(db, claim)
                updated = db.execute('''UPDATE epm.job SET status=%s,error_code=%s,
                    claimant=NULL,lease_until=NULL,
                    updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s
                    AND claim_generation=%s AND claimant=%s
                    AND status='running' AND lease_until>clock_timestamp()''',
                    (status, error_code, claim['workspace_id'],
                     claim['application_id'], claim['job_id'],
                     claim['claim_generation'], claim['claimant'])).rowcount
                if not updated:
                    raise ValueError('STALE_WORKER_FENCE')
        return status

    def reconcile_claim_failure(self, claim: dict, *, error_code: str,
                                retryable: bool = False, allow_superseded: bool = False) -> str:
        """Fence a failed claim and inspect its receipt before any retry."""
        if (not isinstance(error_code, str) or not _KEY.fullmatch(error_code)
                or not isinstance(retryable, bool)
                or not isinstance(allow_superseded, bool)):
            raise ValueError('A bounded failure code and retry policy are required')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                configure_lock_wait(db)
                row = db.execute('''SELECT status,claim_generation,claimant,
                    attempts,program_digest,subject_id,receipt_revision,function_name,compiler_version
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s FOR UPDATE''',
                    (claim['workspace_id'], claim['application_id'],
                     claim['job_id'])).fetchone()
                if row is None:
                    raise ValueError('JOB_UNAVAILABLE')
                if row['status'] == 'published':
                    receipt = db.execute('''SELECT committed_revision,
                        command_digest,actor_id FROM epm.operation_receipt
                        WHERE workspace_id=%s AND application_id=%s
                        AND operation_id=%s''',
                        (claim['workspace_id'], claim['application_id'],
                         claim['job_id'])).fetchone()
                    if (receipt and row['receipt_revision'] ==
                            receipt['committed_revision'] and
                            row['program_digest'] == receipt['command_digest'] and
                            row['subject_id'] == receipt['actor_id']):
                        return 'published'
                    db.execute('''UPDATE epm.job SET status='needs_inspection',
                        error_code='PUBLISHED_RECEIPT_MISMATCH',
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',
                        (claim['workspace_id'], claim['application_id'],
                         claim['job_id']))
                    return 'needs_inspection'
                staged_reconstruction = _is_staged_compiler(row['function_name'],row['compiler_version'])
                if staged_reconstruction and row['status']=='ready':
                    # An acknowledgement can be lost after a committed quantum
                    # has released its claim. Only native durable proof for
                    # this exact claimant/generation/digest recognizes it.
                    PostgresNumericFactStore._set_scope(db, ApplicationScope(
                        claim['workspace_id'],claim['application_id']))
                    checkpoint_statement = ('''SELECT epm.projection_cleanup_checkpoint_matches(
                        %s,%s,%s,%s,%s,%s) AS matched''' if row['function_name']=='facts.projections.cleanup'
                        else '''SELECT epm.fact_projection_rebuild_checkpoint_matches(
                        %s,%s,%s,%s,%s,%s) AS matched''')
                    matched=db.execute(checkpoint_statement,
                        (claim['workspace_id'],claim['application_id'],claim['job_id'],
                         claim['claimant'],claim['claim_generation'],row['program_digest'])).fetchone()
                    return 'ready' if matched['matched'] else 'stale'
                if allow_superseded and row['status'] in ('cancel_requested','cancelled'):
                    receipt=db.execute('''SELECT 1 FROM epm.operation_receipt WHERE workspace_id=%s
                        AND application_id=%s AND operation_id=%s''',
                        (claim['workspace_id'],claim['application_id'],claim['job_id'])).fetchone()
                    status='needs_inspection' if receipt else 'cancelled'
                    db.execute('''UPDATE epm.job SET status=%s,error_code=%s,updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',
                        (status,'RECEIPT_REQUIRES_PUBLICATION_REVIEW' if receipt else None,
                         claim['workspace_id'],claim['application_id'],claim['job_id']))
                    return status
                if (row['status'] != 'running'
                        or row['claim_generation'] != claim['claim_generation']
                        or row['claimant'] != claim['claimant']):
                    if staged_reconstruction:return 'stale'
                    if allow_superseded:return row['status']
                    raise ValueError('STALE_WORKER_FENCE')
                receipt = db.execute('''SELECT 1 FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s
                    AND operation_id=%s''',
                    (claim['workspace_id'], claim['application_id'],
                     claim['job_id'])).fetchone()
                if receipt:
                    status = 'needs_inspection'
                    reason = 'RECEIPT_REQUIRES_PUBLICATION_REVIEW'
                    retry_after = None
                elif retryable and row['attempts'] < 3:
                    status = 'ready'
                    reason = error_code
                    retry_after = min(30, 2 ** row['attempts'])
                else:
                    status = 'failed'
                    reason = error_code if not retryable else 'RETRY_LIMIT'
                    retry_after = None
                db.execute('''UPDATE epm.job SET status=%s,error_code=%s,
                    claim_generation=claim_generation+1,
                    claimant=NULL,lease_until=NULL,
                    next_attempt_at=CASE WHEN %s::int IS NULL THEN NULL
                        ELSE clock_timestamp()+make_interval(secs=>%s) END,
                    updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',
                    (status, reason, retry_after, retry_after,
                     claim['workspace_id'],
                     claim['application_id'], claim['job_id']))
                return status

    def settle_cancel_requested(self) -> int:
        """Finish cancelled claims only after checking for committed effects."""
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                configure_lock_wait(db)
                rows = db.execute('''SELECT workspace_id,application_id,job_id
                    FROM epm.job WHERE status='cancel_requested'
                    ORDER BY updated_at FOR UPDATE SKIP LOCKED LIMIT 100''').fetchall()
                for row in rows:
                    receipt = db.execute('''SELECT 1 FROM epm.operation_receipt
                        WHERE workspace_id=%s AND application_id=%s
                        AND operation_id=%s''',
                        (row['workspace_id'], row['application_id'],
                         row['job_id'])).fetchone()
                    status = 'needs_inspection' if receipt else 'cancelled'
                    db.execute('''UPDATE epm.job SET status=%s,
                        error_code=%s,updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',
                        (status, 'RECEIPT_REQUIRES_PUBLICATION_REVIEW'
                         if receipt else None, row['workspace_id'],
                         row['application_id'], row['job_id']))
                return len(rows)

    def recover_expired(self) -> int:
        with connect_postgres(self.dsn) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                configure_lock_wait(db)
                rows = db.execute('''SELECT workspace_id,application_id,job_id,
                    program_digest,subject_id,function_name,compiler_version,attempts FROM epm.job
                    WHERE status='running' AND lease_until<=clock_timestamp()
                    ORDER BY lease_until FOR UPDATE SKIP LOCKED
                    LIMIT 100''').fetchall()
                for workspace_id, application_id, job_id, digest, subject, function, compiler, attempts in rows:
                    receipt = db.execute('''SELECT command_digest,actor_id
                        FROM epm.operation_receipt WHERE workspace_id=%s
                        AND application_id=%s AND operation_id=%s''',
                        (workspace_id, application_id, job_id)).fetchone()
                    status = 'needs_inspection' if receipt else 'ready'
                    if receipt and (receipt[0] != digest or receipt[1] != subject):
                        status = 'needs_inspection'
                    retry_limit = not receipt and attempts >= 3
                    retry_after = (None if receipt or retry_limit
                                   else min(30, 2 ** attempts))
                    if retry_limit:
                        status='failed'
                    db.execute('''UPDATE epm.job SET status=%s,
                        claim_generation=claim_generation+1,
                        claimant=NULL,lease_until=NULL,
                        next_attempt_at=CASE WHEN %s::int IS NULL THEN NULL
                            ELSE clock_timestamp()+make_interval(secs=>%s) END,
                        error_code=%s,updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND job_id=%s''',
                        (status, retry_after, retry_after,
                         'RECEIPT_REQUIRES_PUBLICATION_REVIEW'
                         if receipt else ('RETRY_LIMIT' if retry_limit else None),
                         workspace_id, application_id, job_id))
                return len(rows)


class PostgresFixedJobRunner:
    """One fixed worker dispatch step; the server controls polling and budget."""

    _functions = (_NUMERIC_FUNCTION, _TEXT_FUNCTION, _DETAIL_FUNCTION,
                  'facts.composite.batch',
                  'facts.numeric.sequence','rules.numeric_sequence.run','facts.numeric.iterate', 'facts.numeric.scale',
                  'facts.expression.calculate',
                  'facts.planning.spread.equal',
                  'facts.planning.spread.calendar.equal',
                  'facts.planning.allocate.weighted',
                  'facts.planning.rollup.sum',
                  'facts.planning.group.sum',
                  'facts.planning.group.sum.bulk',
                  'currency.amount.translate.publish',
                  'currency.translation.publish',
                  'currency.calculation.translation.publish',
                  'consolidation.full.translated.aggregate',
                  'consolidation.full.contribute',
                  'consolidation.full.typed.contribute',
                  'consolidation.method.contribute',
                  'consolidation.equity.contribution.publish',
                  'consolidation.proportional.contribution.publish',
                  'consolidation.method.total.publish',
                  'consolidation.inventory.unrealized_profit.request',
                  'consolidation.full.aggregate',
                  'consolidation.acquisition.journal.publish',
                  'consolidation.journal.from_calculation.publish',
                  'consolidation.nci.period.publish','consolidation.nci.period.withdraw',
                  'facts.projections.rebuild','facts.projections.cleanup')

    def __init__(self, *, worker_dsn: str, runtime_dsn: str):
        self.worker = PostgresJobWorker(worker_dsn)
        if not isinstance(runtime_dsn, str) or not runtime_dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        self.runtime_dsn = runtime_dsn

    def _reconcile(self,claim,**options):
        if claim.get('function_name') in _CONTROL_FENCED_NUMERIC_FUNCTIONS:
            options['allow_superseded']=True
        return self.worker.reconcile_claim_failure(claim,**options)

    def run_once(self, claimant: str, *,
                 scope: ApplicationScope | None = None,
                 resource_class: str = 'short',
                 capacity_limits: tuple[int, int, int] | None = None
                 ) -> dict | None:
        self.worker.settle_cancel_requested()
        self.worker.refresh_dependencies()
        claim = self.worker.claim(
            claimant, scope=scope, resource_class=resource_class,
            function_names=self._functions,
            capacity_limits=capacity_limits)
        if claim is None:
            return None
        # Issuer/subject were pinned at verified admission. The publisher
        # rechecks their current grant in the effect transaction.
        identity = VerifiedExecutionIdentity(
            claim['issuer'], claim['subject_id'],
            tuple(claim['verified_groups']),
            issued_at=claim['token_issued_at'],
            authorization_scope_digest=claim['authorization_scope_digest'])
        if (claim['authority_kind'] == 'HumanToken'
                and identity.issued_at is None):
            return self._reconcile(claim,
                error_code='TOKEN_ISSUE_TIME_UNAVAILABLE')
        if (claim['authority_kind'] == 'Technical'
                and not identity.issuer.startswith('urn:openepm:')):
            return self._reconcile(claim,error_code='TECHNICAL_AUTHORITY_INVALID')
        if claim['authority_kind'] not in ('HumanToken', 'Technical'):
            return self._reconcile(claim,
                error_code='TOKEN_ISSUE_TIME_UNAVAILABLE')
        try:
            if claim['function_name'] == 'facts.composite.batch':
                from .postgres_composite_fact_batch import PostgresCompositeFactPublisher
                publisher=PostgresCompositeFactPublisher(
                    self.runtime_dsn,identity=identity)
            elif claim['function_name'] == 'facts.projections.cleanup':
                from .postgres_projection_cleanup import PostgresProjectionCleanupPublisher
                publisher=PostgresProjectionCleanupPublisher(
                    self.runtime_dsn,identity=identity,worker=self.worker)
            elif claim['function_name'] == 'facts.projections.rebuild':
                from .postgres_fact_reconstruction_job import PostgresFactReconstructionPublisher
                publisher = PostgresFactReconstructionPublisher(
                    self.runtime_dsn, identity=identity, worker=self.worker)
            elif claim['function_name'] in (_NUMERIC_FUNCTION,_DETAIL_FUNCTION,
                    'facts.numeric.sequence','rules.numeric_sequence.run',
                    'facts.numeric.iterate'):
                publisher = PostgresNumericJobPublisher(
                    self.runtime_dsn, identity=identity)
            elif claim['function_name'] == _TEXT_FUNCTION:
                publisher = PostgresTextJobPublisher(
                    self.runtime_dsn, identity=identity)
            elif claim['function_name'] == 'facts.numeric.scale':
                from .postgres_scale import PostgresScalePublisher
                publisher = PostgresScalePublisher(
                    self.runtime_dsn, identity=identity)
            elif claim['function_name'] == 'facts.expression.calculate':
                if claim.get('compiler_version')==(
                        'typed-numeric-expression-v23'):
                    from .expression_currency_member_set import (
                        PostgresCurrencyMemberSetPublisher)
                    publisher=PostgresCurrencyMemberSetPublisher(
                        self.runtime_dsn,identity=identity)
                else:
                    from .postgres_expression import PostgresExpressionPublisher
                    publisher = PostgresExpressionPublisher(
                        self.runtime_dsn, identity=identity)
            elif claim['function_name'] in (
                    'facts.planning.spread.equal',
                    'facts.planning.spread.calendar.equal'):
                from .postgres_planning_spread import PostgresSpreadPublisher
                publisher = PostgresSpreadPublisher(
                    self.runtime_dsn, identity=identity)
            elif claim['function_name'] == 'facts.planning.allocate.weighted':
                from .postgres_planning_allocation import PostgresAllocationPublisher
                publisher = PostgresAllocationPublisher(
                    self.runtime_dsn, identity=identity)
            elif claim['function_name'] == 'facts.planning.rollup.sum':
                if claim.get('compiler_version')==(
                        'planning-rollup-slice-set-policy-v3'):
                    from .postgres_planning_rollup_slice import (
                        PostgresSliceRollupPublisher)
                    publisher=PostgresSliceRollupPublisher(
                        self.runtime_dsn,identity=identity)
                else:
                    from .postgres_planning_rollup import PostgresRollupPublisher
                    publisher = PostgresRollupPublisher(
                        self.runtime_dsn, identity=identity)
            elif claim['function_name'] == 'facts.planning.group.sum':
                from .postgres_planning_group import PostgresGroupPublisher
                publisher = PostgresGroupPublisher(
                    self.runtime_dsn, identity=identity)
            elif claim['function_name'] == 'facts.planning.group.sum.bulk':
                from .postgres_planning_group_bulk import (
                    PostgresBulkGroupPublisher)
                publisher = PostgresBulkGroupPublisher(
                    self.runtime_dsn, identity=identity)
            elif claim['function_name'] == 'currency.translation.publish':
                from .postgres_currency_publication import (
                    PostgresTranslationPublisher)
                publisher = PostgresTranslationPublisher(
                    self.runtime_dsn, identity=identity)
            elif claim['function_name'] == 'currency.amount.translate.publish':
                from .postgres_currency_amount_publication import PostgresCurrencyAmountPublisher
                publisher = PostgresCurrencyAmountPublisher(
                    self.runtime_dsn, identity=identity)
            elif claim['function_name'] == (
                    'currency.calculation.translation.publish'):
                from .postgres_currency_calculation_translation import (
                    PostgresCalculationTranslationPublisher)
                publisher = PostgresCalculationTranslationPublisher(
                    self.runtime_dsn, identity=identity)
            elif claim['function_name'] == (
                    'consolidation.full.translated.aggregate'):
                from .postgres_consolidation_translated import (
                    PostgresTranslatedFullPublisher)
                publisher = PostgresTranslatedFullPublisher(
                    self.runtime_dsn, identity=identity)
            elif claim['function_name'] in (
                    'consolidation.full.contribute',
                    'consolidation.full.typed.contribute'):
                from .postgres_consolidation_full import (
                    PostgresFullContributionPublisher)
                publisher = PostgresFullContributionPublisher(
                    self.runtime_dsn, identity=identity)
            elif claim['function_name'] == 'consolidation.method.contribute':
                from .postgres_contribution_input import PostgresContributionInputPrivate
                publisher=PostgresContributionInputPrivate(
                    self.runtime_dsn,identity=identity)
            elif claim['function_name'] == 'consolidation.equity.contribution.publish':
                from .postgres_equity_method_publication import PostgresEquityMethodPublication
                publisher=PostgresEquityMethodPublication(
                    self.runtime_dsn,identity=identity)
            elif claim['function_name'] == 'consolidation.proportional.contribution.publish':
                from .postgres_proportional_publication import PostgresProportionalPublication
                publisher=PostgresProportionalPublication(
                    self.runtime_dsn,identity=identity)
            elif claim['function_name'] == 'consolidation.method.total.publish':
                from .postgres_consolidation_method_total import PostgresConsolidationMethodTotal
                publisher=PostgresConsolidationMethodTotal(
                    self.runtime_dsn,identity=identity)
            elif claim['function_name'] == 'consolidation.inventory.unrealized_profit.request':
                from .postgres_inventory_unrealized_publication import PostgresInventoryUnrealizedPublication
                publisher=PostgresInventoryUnrealizedPublication(
                    self.runtime_dsn,identity=identity)
            elif claim['function_name'] == 'consolidation.full.aggregate':
                from .postgres_consolidation_aggregate import (
                    PostgresFullAggregatePublisher)
                publisher = PostgresFullAggregatePublisher(
                    self.runtime_dsn, identity=identity)
            elif claim['function_name'] in ('consolidation.nci.period.publish','consolidation.nci.period.withdraw'):
                from .postgres_period_nci_publication import PostgresPeriodAttributionPublisher
                publisher=PostgresPeriodAttributionPublisher(self.runtime_dsn,identity=identity)
            elif claim['function_name']=='consolidation.acquisition.journal.publish':
                from .postgres_acquisition_journal_effects import PostgresAcquisitionJournalPublisher
                publisher=PostgresAcquisitionJournalPublisher(self.runtime_dsn,identity=identity)
            elif claim['function_name']=='consolidation.journal.from_calculation.publish':
                from .postgres_expression_journal import PostgresExpressionJournalPublisher
                publisher=PostgresExpressionJournalPublisher(
                    self.runtime_dsn,identity=identity)
            else:
                raise ValueError('UNSUPPORTED_JOB_FUNCTION')
            result = publisher.publish(claim)
        except psycopg.errors.NumericValueOutOfRange:
            status = self._reconcile(
                claim, error_code='NUMERIC_OVERFLOW')
            self.worker.refresh_dependencies()
            return {'jobId': claim['job_id'], 'status': status,
                    'errorCode': 'NUMERIC_OVERFLOW'}
        except psycopg.errors.CheckViolation as error:
            reason=('PLANNING_SLICE_LOCKED'
                    if 'PLANNING_SLICE_LOCKED' in str(error)
                    else 'DATABASE_CONSTRAINT')
            status=self._reconcile(
                claim,error_code=reason)
            self.worker.refresh_dependencies()
            return {'jobId':claim['job_id'],'status':status,
                    'errorCode':reason}
        except psycopg.errors.LockNotAvailable:
            status = self._reconcile(
                claim, error_code=BUSY_CODE, retryable=True)
            self.worker.refresh_dependencies()
            return {'jobId': claim['job_id'], 'status': status,
                    'errorCode': BUSY_CODE}
        except psycopg.Error:
            status = self._reconcile(
                claim, error_code='DATABASE_ERROR', retryable=True)
            self.worker.refresh_dependencies()
            return {'jobId': claim['job_id'], 'status': status,
                    'errorCode': 'DATABASE_ERROR'}
        except ValueError as error:
            reason = str(error)
            if reason == 'STALE_WORKER_FENCE':
                if claim['function_name'] in _CONTROL_FENCED_NUMERIC_FUNCTIONS:
                    status = self._reconcile(claim, error_code=reason)
                    self.worker.refresh_dependencies()
                    return {'jobId': claim['job_id'], 'status': status}
                self.worker.settle_cancel_requested()
                return {'jobId': claim['job_id'], 'status': 'stale'}
            code = (reason if re.fullmatch(r'[A-Z][A-Z0-9_]{2,127}', reason)
                    else 'PROGRAM_VALIDATION_FAILED')
            retry_budget = (code in ('RECONSTRUCTION_EXECUTION_BUDGET','CLEANUP_EXECUTION_BUDGET')
                and _is_staged_compiler(claim.get('function_name'),claim.get('compiler_version')))
            status = self._reconcile(
                claim, error_code=code, retryable=retry_budget)
            self.worker.refresh_dependencies()
            return {'jobId': claim['job_id'], 'status': status,
                    'errorCode': code}
        except Exception:
            # A fixed publisher defect or an unexpected dependency failure
            # must not leave the durable claim running until every service
            # restart rediscovers it.  Reconcile through the same receipt
            # fence and bounded three-attempt schedule as database transport
            # failures.  The public outcome exposes only a stable safe code;
            # exception text can contain implementation or payload details.
            # Compatibility/test workers that do not implement the durable
            # reconciliation contract must retain the original unknown
            # outcome.  In particular, never replace a lost-acknowledgement
            # exception with an AttributeError from an unavailable recovery
            # method.
            if not callable(getattr(
                    self.worker, 'reconcile_claim_failure', None)):
                raise
            status = self._reconcile(
                claim, error_code='UNEXPECTED_WORKER_ERROR', retryable=True)
            self.worker.refresh_dependencies()
            return {'jobId': claim['job_id'], 'status': status,
                    'errorCode': 'UNEXPECTED_WORKER_ERROR'}
        self.worker.refresh_dependencies()
        if (_is_staged_compiler(claim['function_name'],claim.get('compiler_version'))
                and result.get('checkpoint') is True):
            return {'jobId':claim['job_id'],'status':'ready',
                    'checkpoint':True,'result':result}
        return {'jobId': claim['job_id'], 'status': 'published',
                'result': result}


class PostgresNumericJobRunner(PostgresFixedJobRunner):
    """Compatibility wrapper that dispatches only numeric mutation batches."""

    _functions = (_NUMERIC_FUNCTION,)
