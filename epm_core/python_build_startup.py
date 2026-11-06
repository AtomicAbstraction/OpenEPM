"""Construction boundary for configured Python build workers and brokers."""
from __future__ import annotations

import os
import socket

from .postgres_access import VerifiedIdentity
from .postgres_python_program_repository import PostgresPythonProgramRepository
from .postgres_python_build_validator import PostgresPythonBuildOperationValidator
from .python_build_broker_http import PythonBuildBrokerASGI
from .python_build_capability import (PythonBuildReadBroker,
                                      SignedBuildCapabilityProvider)
from .python_build_deployment import (load_python_build_deployment,
                                      read_secret_text)
from .python_build_worker import PythonBuildWorker
from .python_sandbox_control import UnixSandboxControlClient


class _DeferredValidator:
    def validate_operation(self, *_args, **_kwargs):
        raise ValueError('PYTHON_BUILD_IDENTITY_VALIDATOR_REQUIRED')


def create_python_build_worker(environment, *, executor=None,
                               clock=None, worker_id=None) -> PythonBuildWorker:
    deployment = load_python_build_deployment(environment)
    runtime_dsn = read_secret_text(environment, 'EPM_PG_RUNTIME_DSN_FILE')
    preview_value = read_secret_text(environment, 'EPM_PG_PREVIEW_SECRET_FILE',
                                     maximum=4096)
    try:
        preview_secret = bytes.fromhex(preview_value)
    except ValueError:
        preview_secret = preview_value.encode('utf-8')
    if len(preview_secret) < 32:
        raise ValueError('PYTHON_BUILD_DEPLOYMENT_SECRET_INVALID')
    repository = PostgresPythonProgramRepository(runtime_dsn,
        deployment.coordinator_dsn,
        identity=VerifiedIdentity('urn:openepm:worker', 'python-builder'))
    socket_path = environment.get('EPM_SANDBOX_CONTROL_SOCKET')
    key_path = environment.get('EPM_SANDBOX_CONTROL_KEY_FILE')
    if type(socket_path) is not str or type(key_path) is not str:
        raise ValueError('PYTHON_SANDBOX_CONTROL_CONFIGURATION_INVALID')
    try:
        from pathlib import Path
        target = Path(key_path)
        if not target.is_file() or target.is_symlink():
            raise OSError
        control_key = target.read_bytes()
    except OSError as error:
        raise ValueError('PYTHON_SANDBOX_CONTROL_CONFIGURATION_INVALID') from error
    launcher = UnixSandboxControlClient(socket_path, control_key, clock=clock)
    capability = SignedBuildCapabilityProvider(deployment.capability_key,
                                               clock=clock)
    if worker_id is None:
        worker_id = (socket.gethostname() + ':' + str(os.getpid()) +
                     ':python-build')[:200]
    elif type(worker_id) is not str or not worker_id or len(worker_id) > 200:
        raise ValueError('PYTHON_BUILD_WORKER_CONFIGURATION_INVALID')
    def registry_factory(scope, identity, context):
        return PostgresPythonBuildOperationValidator(runtime_dsn,
            identity=identity, preview_secret=preview_secret,
            metadata_revision=context['metadataRevision'],
            policy_revision=context['policyRevision'],
            schema_epoch=context['schemaEpoch'])
    return PythonBuildWorker(repository, launcher, _DeferredValidator(), capability,
        worker_id=worker_id, compiler_version='openepm-python-v1', clock=clock,
        registry_factory=registry_factory)


def create_python_build_broker(environment) -> PythonBuildBrokerASGI:
    deployment = load_python_build_deployment(environment)
    runtime_dsn = read_secret_text(environment, 'EPM_PG_RUNTIME_DSN_FILE')
    repository = PostgresPythonProgramRepository(runtime_dsn,
        deployment.coordinator_dsn,
        identity=VerifiedIdentity('urn:openepm:broker', 'python-builder'))
    provider = SignedBuildCapabilityProvider(deployment.capability_key)
    return PythonBuildBrokerASGI(PythonBuildReadBroker(
        provider, repository.broker_context))
