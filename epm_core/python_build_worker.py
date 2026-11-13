"""Scope-addressed durable worker for isolated Python plan builds.

Global queue discovery is intentionally absent: schema 0089 scopes the
coordinator role with RLS and provides no worker-only dispatcher.  This worker
can safely consume a build only after a trusted dispatcher supplies its scope
and build ID.  It never receives source or database credentials for the
sandbox; the capability provider mints one short-lived broker token.
"""
from __future__ import annotations

import time
from typing import Protocol
from openepm.diagnostics import SourceValidationError

from .persistence_contract import ApplicationScope
from .postgres_access import (VerifiedIdentity,
                              durable_execution_identity)
from .python_program_execution import (BuildRecord, BuildStatus,
                                       FunctionValidator,
                                       PythonBuildCoordinator)


class BuildCapabilityProvider(Protocol):
    def mint(self, *, scope: ApplicationScope, identity: VerifiedIdentity,
             build_id: str, program_id: str, program_source_token: str,
             environment_id: str, environment_state_token: str,
             environment_profile_version: int,
             claim_generation: int) -> str: ...


class ScopeAddressedBuildRepository(Protocol):
    def worker_context(self, scope: ApplicationScope, build_id: str) -> dict: ...
    def compare_and_set(self, current: BuildRecord,
                        updated: BuildRecord) -> bool: ...
    def store_sealed(self, current: BuildRecord, updated: BuildRecord,
                     plan, *, source_map, build_log) -> bool: ...
    def recover_expired(self, scope: ApplicationScope, build_id: str,
                        *, maximum_attempts: int = 3) -> BuildRecord: ...


class PythonBuildWorker:
    """Run one known build with durable fencing and bounded sandbox effects."""

    def __init__(self, repository: ScopeAddressedBuildRepository, launcher,
                 registry: FunctionValidator, capability_provider,
                 *, worker_id: str, compiler_version: str,
                 clock=None, lease_seconds: int = 90, registry_factory=None,
                 impact_evaluator_factory=None):
        if (not all(hasattr(repository, name) for name in
                    ('worker_context', 'compare_and_set', 'store_sealed',
                     'recover_expired'))
                or not all(hasattr(launcher, name) for name in
                           ('start', 'collect', 'terminate'))
                or not hasattr(registry, 'validate_operation')
                or (registry_factory is not None and not callable(registry_factory))
                or (impact_evaluator_factory is not None and not callable(impact_evaluator_factory))
                or not hasattr(capability_provider, 'mint')
                or type(worker_id) is not str or not worker_id
                or type(compiler_version) is not str or not compiler_version
                or type(lease_seconds) is not int
                or not 65 <= lease_seconds <= 300):
            raise ValueError('PYTHON_BUILD_WORKER_CONFIGURATION_INVALID')
        self.repository = repository
        self.launcher = launcher
        self.capability_provider = capability_provider
        self.worker_id = worker_id
        self.clock = clock or (lambda: int(time.time()))
        self.lease_seconds = lease_seconds
        self.registry_factory = registry_factory
        self.impact_evaluator_factory = impact_evaluator_factory
        self.compiler_version = compiler_version
        self.coordinator = PythonBuildCoordinator(repository, launcher,
            registry, compiler_version=compiler_version)

    def _context(self, scope, build_id):
        value = self.repository.worker_context(scope, build_id)
        required = {'record', 'issuer', 'subjectId', 'programId',
                    'programSourceToken', 'environmentId','environmentStateToken',
                    'environmentProfileVersion',
                    'metadataRevision', 'policyRevision', 'schemaEpoch',
                    'verifiedGroups','authorizationScopeDigest',
                    'tokenIssuedAt','authorityKind','purpose','definitionParameters'}
        if type(value) is not dict or set(value) != required:
            raise ValueError('PYTHON_BUILD_WORK_CONTEXT_INVALID')
        if not isinstance(value['record'], BuildRecord):
            raise ValueError('PYTHON_BUILD_WORK_CONTEXT_INVALID')
        if value['purpose'] != value['record'].purpose:
            raise ValueError('PYTHON_BUILD_WORK_CONTEXT_INVALID')
        if type(value['definitionParameters']) is not dict:
            raise ValueError('PYTHON_BUILD_WORK_CONTEXT_INVALID')
        return value

    def run_one(self, scope: ApplicationScope, build_id: str) -> dict:
        if not isinstance(scope, ApplicationScope):
            raise ValueError('PYTHON_BUILD_SCOPE_INVALID')
        context = self._context(scope, build_id)
        record = context['record']
        if record.status in (BuildStatus.RUNNING,
                             BuildStatus.CANCEL_REQUESTED):
            record = self.repository.recover_expired(scope, build_id)
            if record.status in (BuildStatus.RUNNING,
                                 BuildStatus.CANCEL_REQUESTED):
                return {'buildId': build_id, 'status': record.status.value}
            context = self._context(scope, build_id)
            record = context['record']
        if record.status is BuildStatus.ACCEPTED:
            record = self.coordinator.dispatch(record)
        if record.status is not BuildStatus.READY:
            return {'buildId': build_id, 'status': record.status.value,
                    'planDigest': record.plan_digest}
        now = self.clock()
        if type(now) is not int or now < 0:
            raise ValueError('PYTHON_BUILD_WORKER_TIME_INVALID')
        claimed = record.claim(self.worker_id,
                               lease_until=now + self.lease_seconds)
        if not self.repository.compare_and_set(record, claimed):
            raise ValueError('PYTHON_BUILD_STALE_CONTROL_STATE')
        return self._execute_claim(context, claimed)

    def run_claim(self, scope: ApplicationScope, build_id: str,
                  claim_generation: int) -> dict:
        """Consume one claim created by the worker-only global dispatcher."""
        context = self._context(scope, build_id)
        claimed = context['record']
        if (claimed.status is not BuildStatus.RUNNING
                or claimed.claimant != self.worker_id
                or claimed.claim_generation != claim_generation):
            raise ValueError('PYTHON_BUILD_STALE_CLAIM')
        return self._execute_claim(context, claimed)

    def _execute_claim(self, context: dict, claimed: BuildRecord) -> dict:
        scope, build_id = claimed.scope, claimed.build_id
        identity = durable_execution_identity(context,issuer='issuer',
            subject='subjectId',groups='verifiedGroups',
            scope_digest='authorizationScopeDigest',
            token_issued_at='tokenIssuedAt',authority_kind='authorityKind')
        token = self.capability_provider.mint(scope=scope, identity=identity,
            build_id=build_id, program_id=context['programId'],
            program_source_token=context['programSourceToken'],
            environment_id=context['environmentId'],
            environment_state_token=context['environmentStateToken'],
            environment_profile_version=context['environmentProfileVersion'],
            claim_generation=claimed.claim_generation)
        if type(token) is not str or not token:
            self._settle_failure(claimed, 'PYTHON_BUILD_CAPABILITY_UNAVAILABLE')
            raise ValueError('PYTHON_BUILD_CAPABILITY_UNAVAILABLE')
        try:
            self.launcher.start(build_id=build_id,
                workspace_id=scope.workspace_id,
                application_id=scope.application_id,
                environment_id=context['environmentId'],
                environment_version=context['environmentProfileVersion'],
                capability_token=token,
                claim_generation=claimed.claim_generation,
                cpu_limit=1, memory_mib=512, wall_seconds=60)
            # Renew immediately before the bounded 60-second wait.  The default
            # 90-second lease therefore covers collection and atomic sealing.
            renewed = claimed.renew(self.worker_id, claimed.claim_generation,
                lease_until=self.clock() + self.lease_seconds)
            if not self.repository.compare_and_set(claimed, renewed):
                self.launcher.terminate(build_id=build_id,
                    claim_generation=claimed.claim_generation)
                raise ValueError('PYTHON_BUILD_STALE_CONTROL_STATE')
            coordinator = self.coordinator
            registry = coordinator.registry
            if self.registry_factory is not None:
                registry = self.registry_factory(scope, identity, context)
                if not hasattr(registry, 'validate_operation'):
                    raise ValueError('PYTHON_FUNCTION_REGISTRY_INVALID')
            if self.registry_factory is not None or self.impact_evaluator_factory is not None:
                coordinator = PythonBuildCoordinator(self.repository,
                    self.launcher, registry,
                    compiler_version=self.compiler_version,
                    impact_evaluator=(self.impact_evaluator_factory(scope, identity, context)
                        if self.impact_evaluator_factory is not None else None))
            sealed, plan = coordinator.collect_and_seal(renewed,
                self.worker_id, renewed.claim_generation)
            return {'buildId': build_id, 'status': sealed.status.value,
                    'planDigest': plan.digest}
        except Exception as error:
            latest = self._context(scope, build_id)['record']
            if (latest.status is BuildStatus.CANCEL_REQUESTED
                    and latest.claimant == self.worker_id
                    and latest.claim_generation == claimed.claim_generation):
                try:
                    self.launcher.terminate(build_id=build_id,
                        claim_generation=claimed.claim_generation)
                except ValueError:
                    pass
                cancelled = latest.cancel_claimed(self.worker_id,
                                                  latest.claim_generation)
                self.repository.compare_and_set(latest, cancelled)
            elif (latest.status is BuildStatus.RUNNING
                  and latest.claimant == self.worker_id
                  and latest.claim_generation == claimed.claim_generation):
                code = str(error)
                if isinstance(error, SourceValidationError):
                    self._settle_failure(latest, error.code, diagnostics=error.diagnostics)
                    raise
                if (not isinstance(error, ValueError)
                        or not code.startswith(("PYTHON_SANDBOX_",
                                                "PYTHON_BUILD_",
                                                "PYTHON_IMPACT_",
                                                "BUILDER_"))
                        or len(code) > 100
                        or not code.replace("_", "").isalnum()
                        or code.upper() != code):
                    code = 'PYTHON_BUILD_WORKER_FAILED'
                self._settle_failure(latest, code)
            raise

    def _settle_failure(self, current: BuildRecord, code: str, *, diagnostics=None) -> None:
        failed = current.fail(self.worker_id, current.claim_generation, code,
                              diagnostics=diagnostics)
        if not self.repository.compare_and_set(current, failed):
            raise ValueError('PYTHON_BUILD_STALE_CONTROL_STATE')
