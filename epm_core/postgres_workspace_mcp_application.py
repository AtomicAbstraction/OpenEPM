"""Verified workspace-bound MCP facade for the PostgreSQL lifecycle core."""
from __future__ import annotations

from . import application_authorization_migration as auth_migration
from . import postgres_authorization_migration
from . import postgres_workspace_access_review as workspace_review
from .mcp_function_routing import with_mcp_tools

from .postgres_verified_principal import principal_claims
from .postgres_access import (AccessDenied, VerifiedIdentity, assert_lifecycle_role,
                              assert_security_writer_role)
from .postgres_workspace_lifecycle import FUNCTION as CREATE_APPLICATION, PostgresWorkspaceLifecycle
from .postgres_application_purge import PostgresApplicationPurge, catalog as application_purge_catalog
from .postgres_workspace_reset import PostgresWorkspaceResetPreview
from .postgres_security_language import (
    WORKSPACE_FUNCTION, WORKSPACE_GROUP_FUNCTION, WORKSPACE_GROUP_LIST_FUNCTION,
    PostgresSecurityLanguage)
from .postgres_capability_contract import (
    FUNCTION_REGISTRY_FORMAT,function_registry_digest)
from .processing_operation_registry import (
    PROCESSING_REGISTRY_FORMAT,admit_operation,operation_contracts,
    processing_registry_digest)
from .public_program_diagnostics import (
    ProgramValidationError, validate_program_envelope, validate_program_structure)


class PostgresWorkspaceMCPApplication:
    def __init__(self, lifecycle_dsn: str, workspace_id: str,
                 *, security_dsn: str | None = None,
                 reset_secret: bytes | None = None,
                 endpoint_inventory_json: str | None = None):
        if not isinstance(workspace_id, str) or not 1 <= len(workspace_id) <= 200:
            raise ValueError('Fixed workspace ID is required')
        if reset_secret is not None and (not isinstance(reset_secret, bytes)
                                         or len(reset_secret) < 32):
            raise ValueError('A server-owned reset secret of 32+ bytes is required')
        self.lifecycle_dsn, self.workspace_id = lifecycle_dsn, workspace_id
        self.security_dsn = security_dsn or None
        self.reset_secret = reset_secret
        self.endpoint_inventory_json = endpoint_inventory_json

    def assert_runtime_role(self) -> None:
        assert_lifecycle_role(self.lifecycle_dsn)
        if self.security_dsn:
            assert_security_writer_role(self.security_dsn)

    def _lifecycle(self, assertion: str) -> PostgresWorkspaceLifecycle:
        principal = principal_claims(assertion, 'mcp')
        return PostgresWorkspaceLifecycle(self.lifecycle_dsn,
            identity=VerifiedIdentity(
                principal['issuer'], principal['subject'],
                tuple(principal.get('groups', ())), issued_at=principal['issuedAt']))

    def _authorized_lifecycle(self,assertion: str
                              ) -> PostgresWorkspaceLifecycle:
        service=self._lifecycle(assertion)
        service.check(self.workspace_id)
        return service

    def catalog(self, assertion: str) -> dict:
        service = self._lifecycle(assertion)
        active = True
        try:
            service.check(self.workspace_id)
        except AccessDenied:
            active = False
            if not self.reset_secret:
                raise
        functions = service.catalog()['functions'] if active else {}
        if active:
            functions.update(application_purge_catalog())
        if active and self.security_dsn:
            functions.update(PostgresSecurityLanguage.workspace_catalog()
                             ['functions'])
        if not self.reset_secret:
            for name in auth_migration.FUNCTIONS:
                functions.pop(name,None)
        if self.reset_secret:
            reset = PostgresWorkspaceResetPreview(
                self.lifecycle_dsn, identity=service.identity,
                secret=self.reset_secret,
                endpoint_inventory_json=self.endpoint_inventory_json)
            if active:
                if reset.is_operator():
                    functions.update(reset.catalog()['functions'])
            else:
                status = reset.check_owner(self.workspace_id)
                if status != 'Maintenance':
                    raise AccessDenied('WORKSPACE_UNAVAILABLE')
                functions.update(reset.catalog()['functions'])
        functions=with_mcp_tools(functions,scope='workspace')
        contracts=operation_contracts(functions,scope='workspace')
        return {'languageVersion': 2,
                'registryFormat':FUNCTION_REGISTRY_FORMAT,
                'registryDigest':function_registry_digest(functions),
                'processingRegistryFormat':PROCESSING_REGISTRY_FORMAT,
                'processingRegistryDigest':processing_registry_digest(contracts),
                'operationContracts':contracts,
                'listener': {'scope': 'workspace',
                             'workspaceId': self.workspace_id},
                'functions': functions}

    def application_purge(self, assertion: str, program: dict, *,
                           idempotency_key: str | None = None) -> dict:
        admit_operation(program,scope='workspace',handler_boundary='workspace_lifecycle_adapter')
        identity=self._authorized_lifecycle(assertion).identity
        return PostgresApplicationPurge(self.lifecycle_dsn,identity=identity).execute(
            self.workspace_id,program,idempotency_key=idempotency_key)

    def create(self, assertion: str, program: dict, *,
               idempotency_key: str) -> dict:
        validate_program_envelope(program, scope='workspace')
        if program['function'] != CREATE_APPLICATION:
            raise ProgramValidationError('unknown_workspace_function')
        admit_operation(program,scope='workspace',
                        handler_boundary='workspace_lifecycle_adapter')
        lifecycle = self._authorized_lifecycle(assertion)
        validate_program_structure(program, scope='workspace')
        return lifecycle.create(
            self.workspace_id, program, idempotency_key=idempotency_key)

    def _authorized_security(self, assertion: str, program: dict,
                             functions: tuple[str, ...]) -> PostgresSecurityLanguage:
        validate_program_envelope(program, scope='workspace')
        if program['function'] not in functions:
            raise ProgramValidationError('unknown_workspace_function')
        admit_operation(program, scope='workspace', handler_boundary='workspace_security_adapter')
        if not self.security_dsn:
            raise ValueError('POSTGRES_SECURITY_SERVICE_NOT_CONFIGURED')
        identity = self._authorized_lifecycle(assertion).identity
        validate_program_structure(program, scope='workspace')
        return PostgresSecurityLanguage(self.security_dsn, identity=identity)

    def access(self, assertion: str, program: dict, *,
               idempotency_key: str) -> dict:
        security=self._authorized_security(assertion,program,(WORKSPACE_FUNCTION,WORKSPACE_GROUP_FUNCTION,auth_migration.ACTIVATE))
        if program['function']==auth_migration.ACTIVATE:
            return postgres_authorization_migration.execute(self.security_dsn,self.workspace_id,security.identity,
                program,secret=self.reset_secret,operation_id=idempotency_key)
        return security.execute_workspace(self.workspace_id,program,idempotency_key=idempotency_key)

    def read_access(self, assertion: str, program: dict) -> dict:
        security = self._authorized_security(assertion, program,
            (WORKSPACE_GROUP_LIST_FUNCTION, auth_migration.REVIEW, *workspace_review.FUNCTIONS))
        if program['function']==auth_migration.REVIEW:
            return postgres_authorization_migration.execute(self.security_dsn,self.workspace_id,security.identity,
                program,secret=self.reset_secret)
        if program['function'] in workspace_review.FUNCTIONS:
            return workspace_review.read(self.security_dsn,self.workspace_id,security.identity,program,
                                         secret=self.reset_secret or workspace_review.PROCESS_REVIEW_KEY)
        return security.list_workspace_group_access(self.workspace_id, program)

    def prepare_reset(self, assertion: str, program: dict) -> dict:
        admit_operation(program,scope='workspace',
                        handler_boundary='workspace_reset_lifecycle_adapter')
        if not self.reset_secret:
            raise ValueError('POSTGRES_RESET_PREVIEW_NOT_CONFIGURED')
        lifecycle = self._lifecycle(assertion)
        return PostgresWorkspaceResetPreview(
            self.lifecycle_dsn, identity=lifecycle.identity,
            secret=self.reset_secret,
            endpoint_inventory_json=self.endpoint_inventory_json).prepare(
                self.workspace_id, program)

    def transition_reset(self, assertion: str, program: dict, *,
                         idempotency_key: str) -> dict:
        admit_operation(program,scope='workspace',
                        handler_boundary='workspace_reset_lifecycle_adapter')
        if not self.reset_secret:
            raise ValueError('POSTGRES_RESET_NOT_CONFIGURED')
        lifecycle = self._lifecycle(assertion)
        return PostgresWorkspaceResetPreview(
            self.lifecycle_dsn, identity=lifecycle.identity,
            secret=self.reset_secret,
            endpoint_inventory_json=self.endpoint_inventory_json).transition(
                self.workspace_id, program, idempotency_key=idempotency_key)
