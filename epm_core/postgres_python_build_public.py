"""Public fixed-core control surface for isolated Python plan builds.

Admission stores source references and typed parameters only.  Authored Python
is executed later by the separately credentialed sandbox worker; this service
has no coordinator credential and cannot seal artifacts.
"""
from __future__ import annotations

from .persistence_contract import ApplicationScope
from .postgres_access import VerifiedIdentity
from .postgres_python_program_repository import (PostgresPythonProgramRepository,
                                                  python_build_id, build_request_digest)
from .python_execution_contract import (
    BUILD as BUILD, BUILD_PURPOSES, TEST as TEST, VALIDATE as VALIDATE, build_result as _wire,
    parse_build_program, validate_build_inputs)


class PostgresPythonBuildPublic:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        self.identity = identity
        self.repository = PostgresPythonProgramRepository(
            dsn, None, identity=identity)

    def execute(self, scope: ApplicationScope, program: object, *,
                idempotency_key: str, replay_only: bool = False,
                _occurrence_admission=None) -> dict | None:
        args = parse_build_program(program)
        purpose = BUILD_PURPOSES[program['function']]
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
            purpose=purpose,
            definition_parameters=args.get('definitionParameters'),
            replay_only=replay_only,_occurrence_admission=_occurrence_admission)
        if record is None:
            return None
        return {**_wire(record), 'taskId': 'p:' + record.build_id}

    def read(self, scope: ApplicationScope, build_id: str) -> dict:
        return _wire(self.repository.read(scope, build_id))

    def read_original(self, scope: ApplicationScope, program: dict, *,
                      idempotency_key: str) -> dict:
        """Read one authenticated original; no acceptance or fresh-source path."""
        args = parse_build_program(program)
        build_id = python_build_id(scope, self.identity, idempotency_key,
            schema_epoch=args['expectedSchemaEpoch'])
        purpose = BUILD_PURPOSES[program['function']]
        parameters, definition_parameters = validate_build_inputs(build_id=build_id,
            program_id=args['programId'], program_source_token=args['programSourceToken'],
            parameter_values=args['parameters'], idempotency_key=idempotency_key,
            expected_metadata_revision=args['expectedMetadataRevision'],
            expected_policy_revision=args['expectedPolicyRevision'],
            expected_schema_epoch=args['expectedSchemaEpoch'],
            delegation_id=args.get('delegationId'), delegation_state_token=args.get('delegationStateToken'),
            schedule_id=args.get('scheduleId'), schedule_state_token=args.get('scheduleStateToken'),
            purpose=purpose, definition_parameters=args.get('definitionParameters'))
        digest = build_request_digest(scope, self.identity, program_id=args['programId'],
            program_source_token=args['programSourceToken'], parameters=parameters,
            delegation_id=args.get('delegationId'), delegation_state_token=args.get('delegationStateToken'),
            schedule_id=args.get('scheduleId'), schedule_state_token=args.get('scheduleStateToken'),
            pins=(args['expectedMetadataRevision'], args['expectedPolicyRevision'], args['expectedSchemaEpoch']),
            idempotency_key=idempotency_key, purpose=purpose, definition_parameters=definition_parameters)
        return _wire(self.repository.read(scope, build_id, expected_request_digest=digest))

    def cancel(self, scope: ApplicationScope, build_id: str) -> dict:
        return _wire(self.repository.request_cancel(scope, build_id))
