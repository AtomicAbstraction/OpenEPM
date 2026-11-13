"""Public fixed-core control surface for isolated Python plan builds.

Admission stores source references and typed parameters only.  Authored Python
is executed later by the separately credentialed sandbox worker; this service
has no coordinator credential and cannot seal artifacts.
"""
from __future__ import annotations

from .persistence_contract import ApplicationScope
from .postgres_access import VerifiedIdentity
from .postgres_python_program_repository import (PostgresPythonProgramRepository,
                                                  python_build_id)
from .python_program_execution import BuildRecord


BUILD = 'python.program.build'
TEST = 'python.program.test'


def _wire(record: BuildRecord) -> dict:
    value = {'buildId': record.build_id, 'status': record.status.value,
             'purpose': record.purpose,
             'attempts': record.attempts,
             'claimGeneration': record.claim_generation}
    if record.plan_digest is not None: value['planDigest'] = record.plan_digest
    if record.error_code is not None: value['errorCode'] = record.error_code
    if record.diagnostics is not None: value['diagnostics'] = record.diagnostics
    return value


class PostgresPythonBuildPublic:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        self.identity = identity
        self.repository = PostgresPythonProgramRepository(
            dsn, None, identity=identity)

    def execute(self, scope: ApplicationScope, program: object, *,
                idempotency_key: str) -> dict:
        if (type(program) is not dict
                or set(program) != {'languageVersion','function','arguments'}
                or program.get('languageVersion') != 2
                or program.get('function') not in (BUILD, TEST)
                or type(program.get('arguments')) is not dict):
            raise ValueError('PYTHON_BUILD_ARGUMENTS_INVALID')
        args = program['arguments']
        testing = program['function'] == TEST
        required = {'programId','programSourceToken','parameters',
                    'expectedMetadataRevision','expectedPolicyRevision',
                    'expectedSchemaEpoch'}
        if not testing:
            required |= {'delegationId','delegationStateToken','scheduleId','scheduleStateToken'}
        allowed = (required, required | {'definitionParameters'}) if testing else (required,)
        if set(args) not in allowed:
            raise ValueError('PYTHON_BUILD_ARGUMENTS_INVALID')
        record = self.repository.accept(scope,
            build_id=python_build_id(scope, self.identity, idempotency_key,
                                    schema_epoch=args['expectedSchemaEpoch']),
            program_id=args['programId'],
            program_source_token=args['programSourceToken'],
            parameter_values=args['parameters'], idempotency_key=idempotency_key,
            expected_metadata_revision=args['expectedMetadataRevision'],
            expected_policy_revision=args['expectedPolicyRevision'],
            expected_schema_epoch=args['expectedSchemaEpoch'],
            delegation_id=args.get('delegationId'),
            delegation_state_token=args.get('delegationStateToken'),
            schedule_id=args.get('scheduleId'),schedule_state_token=args.get('scheduleStateToken'),
            purpose='ImpactTest' if testing else 'Plan',
            definition_parameters=args.get('definitionParameters'))
        return {**_wire(record), 'taskId': 'p:' + record.build_id}

    def read(self, scope: ApplicationScope, build_id: str) -> dict:
        return _wire(self.repository.read(scope, build_id))

    def cancel(self, scope: ApplicationScope, build_id: str) -> dict:
        return _wire(self.repository.request_cancel(scope, build_id))
