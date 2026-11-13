"""Authenticated, platform-operator-bound PostgreSQL V2 MCP facade."""
from __future__ import annotations

from .mcp_function_routing import with_mcp_tools
from .postgres_capability_contract import (
    FUNCTION_REGISTRY_FORMAT,function_registry_digest)
from .processing_operation_registry import (
    PROCESSING_REGISTRY_FORMAT,operation_contracts,processing_registry_digest)

import os

from .postgres_verified_principal import principal_claims
from .postgres_access import VerifiedIdentity, assert_nonowner_role
from .postgres_platform_provision import PostgresPlatformProvisioner
from .keycloak_directory import KeycloakDirectory, KeycloakDirectoryApi
from .postgres_identity_directory import (
    ALL_FUNCTIONS as DIRECTORY_FUNCTIONS,
    READ_FUNCTIONS as DIRECTORY_READ_FUNCTIONS,
    PostgresIdentityDirectory, catalog as directory_catalog,
)


class PostgresPlatformMCPApplication:
    def __init__(self,provision_dsn: str,*,directory=None):
        self.provision_dsn=provision_dsn
        self.directory=directory

    def assert_runtime_role(self) -> None:
        assert_nonowner_role(self.provision_dsn,'epm_provision',
            ('workspace','workspace_access_grant',
             'platform_operator_grant','platform_operation_receipt',
             'identity_directory_state','identity_user_directory_state',
             'identity_group_directory_state',
             'identity_group_membership_state',
             'identity_principal_migration'))

    def _provisioner(self,assertion: str) -> PostgresPlatformProvisioner:
        principal=principal_claims(assertion,'mcp')
        return self._provisioner_for_identity(VerifiedIdentity(
            principal['issuer'],principal['subject'],principal.get('groups',()),
            issued_at=principal['issuedAt']))

    def _provisioner_for_identity(self, identity: VerifiedIdentity
                                  ) -> PostgresPlatformProvisioner:
        return PostgresPlatformProvisioner(self.provision_dsn,identity=identity)

    def _authorize_identity(self,identity: VerifiedIdentity
                            ) -> VerifiedIdentity:
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError('VERIFIED_IDENTITY_REQUIRED')
        self._provisioner_for_identity(identity).check()
        return identity

    def _directory(self,assertion: str) -> PostgresIdentityDirectory:
        principal=principal_claims(assertion,'mcp')
        return self._directory_for_identity(VerifiedIdentity(
            principal['issuer'],principal['subject'],principal.get('groups',()),
            issued_at=principal['issuedAt']))

    def _directory_for_identity(self, identity: VerifiedIdentity
                                ) -> PostgresIdentityDirectory:
        adapter=self.directory or KeycloakDirectory(KeycloakDirectoryApi.from_environment())
        directory_issuer=os.environ.get('EPM_OIDC_ISSUER','').strip()
        if not directory_issuer:
            raise ValueError('EPM_OIDC_ISSUER_REQUIRED')
        return PostgresIdentityDirectory(self.provision_dsn,
            identity=identity,
            directory=adapter,directory_issuer=directory_issuer)

    def catalog(self,assertion: str) -> dict:
        return self.catalog_for_identity(self._provisioner(assertion).identity)

    def catalog_for_identity(self, identity: VerifiedIdentity) -> dict:
        identity=self._authorize_identity(identity)
        service=self._provisioner_for_identity(identity)
        functions={**service.catalog()['functions'],
                   **directory_catalog()['functions']}
        functions=with_mcp_tools(functions,scope='platform')
        contracts=operation_contracts(functions,scope='platform')
        return {'languageVersion':2,
                'registryFormat':FUNCTION_REGISTRY_FORMAT,
                'registryDigest':function_registry_digest(functions),
                'processingRegistryFormat':PROCESSING_REGISTRY_FORMAT,
                'processingRegistryDigest':processing_registry_digest(contracts),
                'operationContracts':contracts,
                'listener':{'scope':'platform'},
                'functions':functions}

    def create(self,assertion: str,program: dict,*,
               idempotency_key: str) -> dict:
        principal=principal_claims(assertion,'mcp')
        return self.create_for_identity(VerifiedIdentity(
            principal['issuer'],principal['subject'],principal.get('groups',()),
            issued_at=principal['issuedAt']),
            program,idempotency_key=idempotency_key)

    def create_for_identity(self,identity: VerifiedIdentity,program: dict,*,
                            idempotency_key: str) -> dict:
        identity=self._authorize_identity(identity)
        if isinstance(program,dict) and program.get('function') in DIRECTORY_FUNCTIONS:
            return self._directory_for_identity(identity).execute(
                program,idempotency_key=idempotency_key)
        return self._provisioner_for_identity(identity).create(
            program,idempotency_key=idempotency_key)

    def read(self,assertion: str,program: dict) -> dict:
        principal=principal_claims(assertion,'mcp')
        return self.read_for_identity(VerifiedIdentity(
            principal['issuer'],principal['subject'],principal.get('groups',()),
            issued_at=principal['issuedAt']),program)

    def read_for_identity(self,identity: VerifiedIdentity,program: dict) -> dict:
        identity=self._authorize_identity(identity)
        if (not isinstance(program,dict)
                or program.get('function') not in DIRECTORY_READ_FUNCTIONS):
            raise ValueError('V2_FUNCTION_MODE_MISMATCH')
        return self._directory_for_identity(identity).read(program)
