"""Authenticated, application-bound MCP façade over the PostgreSQL V2 core.

No caller-provided identity, role, SQL or application scope is accepted. The
listener binds one application; each tool verifies the Access assertion and
the underlying fixed-core operation rechecks the current PostgreSQL grant.
"""
from __future__ import annotations

from . import postgres_resource_access
from . import application_authorization_config as authorization_config
from . import postgres_authorization_config, postgres_authorization_objects, postgres_access_explanation, postgres_authorization_tags, postgres_effective_access
from .mcp_function_routing import with_mcp_tools
from .application_catalog_projection import application_catalog, discover_catalog

import logging
import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row

from .postgres_capability_contract import (
    assert_public_program_admitted, function_registry_digest)
from .postgres_application_capabilities import catalog_access_state
from .postgres_verified_principal import (
    principal_claims, verified_identity_binding_for_assertion)
from .persistence_contract import ApplicationScope
from .postgres_access import (AccessDenied, PostgresAccessChecker,
                              assert_nonowner_role, assert_security_writer_role,
                              VerifiedIdentity)
from .postgres_jobs import PostgresJobQueue, _canonical_digest
from .postgres_tasks import PostgresTaskService
from .postgres_language_v2 import POPULATED_LAYOUT_REQUESTS, PostgresLanguageV2
from .operation_admission_contract import (
    is_signed_operation_id, issue_operation_admission)
from .postgres_processing_limits import lock_busy_boundary
from .processing_operation_registry import admit_operation
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_security_language import PostgresSecurityLanguage
from .postgres_python_environments import ApprovedPythonEnvironment
from .postgres_planning_workflow_policy import FUNCTIONS as CUBE_WRITE_POLICY_FUNCTIONS, LIST as POLICY_LIST, READ as POLICY_READ

LOG = logging.getLogger(__name__)


class PostgresMCPApplication:
    def __init__(self, runtime_dsn: str, scope: ApplicationScope,
                 *, preview_secret: bytes, security_dsn: str | None = None,
                 approved_python_profiles: tuple[ApprovedPythonEnvironment, ...] = ()):
        if not isinstance(runtime_dsn,str) or not runtime_dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(scope,ApplicationScope):
            raise ValueError('A fixed application scope is required')
        if not isinstance(preview_secret,bytes) or len(preview_secret)<32:
            raise ValueError('A server-owned preview secret is required')
        self.runtime_dsn = runtime_dsn
        self.scope = scope
        self.preview_secret = preview_secret
        self.security_dsn = security_dsn or None
        if (not isinstance(approved_python_profiles,tuple)
                or any(not isinstance(item,ApprovedPythonEnvironment)
                       for item in approved_python_profiles)):
            raise ValueError('PYTHON_ENVIRONMENT_CONFIGURATION_INVALID')
        self.approved_python_profiles=approved_python_profiles

    def assert_runtime_role(self) -> None:
        """Fail startup if the listener could bypass application-row policies."""
        assert_nonowner_role(self.runtime_dsn,'epm_runtime',
            ('application','coordinate','numeric_cell_current','source_batch',
             'manual_journal','manual_journal_line','generic_fact_table',
             'generic_fact_current','generic_fact_event'))
        if self.security_dsn:
            assert_security_writer_role(self.security_dsn)

    @staticmethod
    def _identity(assertion: str) -> VerifiedIdentity:
        principal = principal_claims(assertion,'mcp')
        return VerifiedIdentity(principal['issuer'],principal['subject'],
                                principal.get('groups',()), issued_at=principal['issuedAt'])

    def _language_for_identity(
            self,identity: VerifiedIdentity) -> PostgresLanguageV2:
        return PostgresLanguageV2(
            self.runtime_dsn,identity=identity,
            preview_secret=self.preview_secret,
            approved_python_profiles=self.approved_python_profiles)

    def _authorize_program(self,assertion: str,program: dict
                           ) -> VerifiedIdentity:
        """Apply one uniform current-authorization decision at MCP admission.

        Individual fixed-core services retain their transaction/publication
        checks.  This extra boundary ensures no catalogued MCP route can reach
        a specialized adapter before current identity, group, application or
        rule grant, and capability have been resolved by Open EPM. Exact
        dimensional filtering or denial remains in the specialized fixed-core
        transaction because each function owns a different authoritative
        coordinate or selection grammar; this boundary never reimplements it.
        """
        assert_public_program_admitted(program)
        function=program['function']
        specification=PostgresLanguageV2.catalog()['functions'].get(function)
        handler_boundary='fixed_python_application_language'
        if specification is None and self.security_dsn:
            specification=PostgresSecurityLanguage.catalog()[
                'functions'].get(function)
            handler_boundary='application_security_adapter'
        if specification is None:
            raise ValueError('POSTGRES_FUNCTION_NOT_IMPLEMENTED')
        contract=admit_operation(program,scope='application',
            handler_boundary=handler_boundary)
        try:
            return self._authorize_permission(
                assertion,contract['permission'],function=function,
                arguments=program['arguments'])
        except AccessDenied as error:
            if (self.security_dsn and contract['permission'] in
                    ('admin','workspace_admin')):
                try:
                    identity=self._identity(assertion)
                    PostgresSecurityLanguage(
                        self.security_dsn,identity=identity
                    ).record_privileged_denial(self.scope,program,str(error))
                except Exception:
                    LOG.exception('Privileged MCP denial audit failed')
            raise

    def _authorize_permission(self,assertion: str,permission: str,*,
                              function: str|None=None,
                              arguments: dict|None=None, action: str|None=None) -> VerifiedIdentity:
        """Resolve one current application permission before MCP dispatch."""
        identity=self._identity(assertion)
        with connect_postgres(self.runtime_dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,self.scope)
                PostgresAccessChecker.lock_workspace(
                    db,self.scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,identity,self.scope,permission,
                    function=function,arguments=arguments,action=action)
        return identity

    def _authorized_language(self,assertion: str,
                             program: dict) -> PostgresLanguageV2:
        return self._language_for_identity(
            self._authorize_program(assertion,program))

    def _authorized_effect_language(self, assertion: str, program: dict,
                                    operation_id: str | None
                                    ) -> PostgresLanguageV2:
        language = self._authorized_language(assertion, program)
        specification = (PostgresLanguageV2.catalog()["functions"].get(
            program.get("function")) if isinstance(program, dict) else None)
        if (specification is None and self.security_dsn
                and isinstance(program,dict)):
            specification=PostgresSecurityLanguage.catalog()[
                "functions"].get(program.get("function"))
        if (isinstance(specification, dict)
                and specification.get("idempotencyRequired") is True
                and not is_signed_operation_id(operation_id)):
            raise ValueError("OPERATION_ADMISSION_REQUIRED")
        if is_signed_operation_id(operation_id):
            language._validate_signed_operation_id(
                self.scope, program, operation_id)
        return language

    @staticmethod
    def session_identity(assertion: str) -> dict:
        """Return only this verified caller's enrollment-safe identity fields."""
        return verified_identity_binding_for_assertion(assertion, 'mcp')

    @lock_busy_boundary
    def catalog(self, assertion: str, *, discovery: dict | None = None) -> dict:
        identity = self._identity(assertion)
        allowed, state = catalog_access_state(
            self.runtime_dsn, identity, self.scope, secret=self.preview_secret)
        result = application_catalog(PostgresLanguageV2.catalog(),
            security_functions=(PostgresSecurityLanguage.catalog()['functions']
                                if self.security_dsn else {}),
            enabled=state['enabled_capabilities'], allowed=allowed,
            scope=self.scope, state=state)
        result['functions'] = with_mcp_tools(result['functions'], scope='application')
        result['registryDigest'] = function_registry_digest(result['functions'])
        return discover_catalog(result, discovery)

    @lock_busy_boundary
    def read(self, assertion: str, program: dict) -> dict:
        identity=self._authorize_program(assertion,program)
        if program.get('function') in (authorization_config.READ,authorization_config.PREVIEW):
            if not self.security_dsn:
                raise ValueError('POSTGRES_SECURITY_SERVICE_NOT_CONFIGURED')
            return postgres_authorization_config.run_configuration(
                self.security_dsn,self.scope,identity,program,secret=self.preview_secret)
        if (isinstance(program,dict) and program.get('function') in {
                'security.application.access.list',
                'security.application.subject.list', postgres_effective_access.FUNCTION, postgres_authorization_tags.FUNCTION, postgres_authorization_objects.FUNCTION,
                postgres_access_explanation.FUNCTION,postgres_resource_access.FUNCTION,
                'security.application.audit.list',
                'security.application.receipt.read',
                'security.application.group-access.list',
                'security.application.dimension-access.read',
                'security.application.group-dimension-access.read',
                'security.application.dimension-tags.read',
                'security.application.member-tags.read',
                'security.application.dimension-metadata-tags.read',
                'security.application.relationship-tags.read',
                'security.application.dimension-policy.read'}):
            if not self.security_dsn:
                raise ValueError('POSTGRES_SECURITY_SERVICE_NOT_CONFIGURED')
            if program['function'] == postgres_resource_access.FUNCTION:
                return postgres_resource_access.read(self.runtime_dsn,self.scope,identity,program,secret=self.preview_secret)
            if program['function'] == postgres_access_explanation.FUNCTION:
                return postgres_access_explanation.read_explanation(self.runtime_dsn, self.scope, identity, program)
            if program['function'] == postgres_authorization_objects.FUNCTION:
                return postgres_authorization_objects.read_objects(self.security_dsn, self.scope, identity, program)
            if program['function'] == postgres_authorization_tags.FUNCTION:
                return postgres_authorization_tags.read_tags(self.security_dsn, self.scope, identity, program)
            if program['function'] == postgres_effective_access.FUNCTION:
                return postgres_effective_access.read_report(self.security_dsn, self.scope,
                    identity, program, secret=self.preview_secret)
            security = PostgresSecurityLanguage(
                self.security_dsn, identity=identity)
            if program['function']=='security.application.access.list':
                return security.list_application_access(self.scope,program)
            if program['function']=='security.application.subject.list':
                return security.list_application_subjects(self.scope,program)
            if program['function']=='security.application.audit.list':
                return security.list_application_audit(self.scope,program)
            if program['function']=='security.application.receipt.read':
                return security.read_application_receipt(self.scope,program)
            if program['function']=='security.application.group-access.list':
                return security.list_application_group_access(
                    self.scope,program)
            if (program['function']==
                    'security.application.group-dimension-access.read'):
                return security.read_group_dimension_access(
                    self.scope,program)
            if program['function'].endswith('dimension-tags.read'):
                return security.read_dimension_tags(self.scope,program)
            if program['function'].endswith('member-tags.read'):
                return security.read_member_tags(self.scope,program)
            if program['function'].endswith('dimension-metadata-tags.read'):
                return security.read_dimension_metadata_tags(
                    self.scope,program)
            if program['function'].endswith('relationship-tags.read'):
                return security.read_relationship_tags(self.scope,program)
            if '.dimension-policy.' in program['function']:
                return security.read_dimension_policy(self.scope,program)
            return security.read_dimension_access(self.scope,program)
        return self._language_for_identity(identity).execute_read(
            self.scope,program)

    @lock_busy_boundary
    def preview(self, assertion: str, program: dict) -> dict:
        return self._authorized_language(assertion,program).preview(
            self.scope,program)

    @lock_busy_boundary
    def issue_operation_admission(self, assertion: str, program: dict, *,
                                  ttl_seconds: int = 900) -> dict:
        language=self._authorized_language(assertion,program)
        specification=(PostgresLanguageV2.catalog()['functions'].get(
            program.get('function')) if isinstance(program,dict) else None)
        if specification is not None:
            admission=language.issue_operation_admission(
                self.scope,program,ttl_seconds=ttl_seconds)
        else:
            specification=(PostgresSecurityLanguage.catalog()['functions'].get(
                program.get('function')) if self.security_dsn and
                isinstance(program,dict) else None)
            if (not isinstance(specification,dict)
                    or specification.get('idempotencyRequired') is not True):
                raise ValueError('OPERATION_ADMISSION_PROGRAM_INVALID')
            admission=issue_operation_admission(
                self.preview_secret,self.scope,language.identity,
                function=program['function'],
                intent_digest=_canonical_digest(program),
                ttl_seconds=ttl_seconds)
        return {"operationId": admission.operation_id,
                "expiresAt": admission.expires_at,
                "intentDigest": admission.intent_digest}

    @lock_busy_boundary
    def submit(self, assertion: str, program: dict, *,
               preview_token: str, idempotency_key: str,
               depends_on_job_ids: tuple[str,...]=()) -> dict:
        try:
            language = self._authorized_effect_language(assertion,program,idempotency_key)
        except ValueError as error:
            if str(error) != 'OPERATION_ADMISSION_EXPIRED':
                raise
            return self._authorized_language(assertion,program).reconcile_expired_operation(
                self.scope, program, idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids,
                transport=('mcpTool', 'submit_v2_program'),preview_token=preview_token)
        return language.submit(
            self.scope,program,preview_token=preview_token,
            idempotency_key=idempotency_key,
            depends_on_job_ids=depends_on_job_ids)

    @lock_busy_boundary
    def source(self, assertion: str, program: dict) -> dict:
        return self._authorized_language(assertion,program).execute_source(
            self.scope,program)

    @lock_busy_boundary
    def metadata(self, assertion: str, program: dict, *,
                 idempotency_key: str) -> dict:
        try:
            return self._authorized_effect_language(
                assertion,program,idempotency_key).execute_metadata(
                self.scope,program,idempotency_key=idempotency_key)
        except ValueError as error:
            if (str(error) != 'OPERATION_ADMISSION_EXPIRED'
                    or not isinstance(program, dict)
                    or program.get('function') not in POPULATED_LAYOUT_REQUESTS):
                raise
            return self._authorized_language(assertion,program).reconcile_expired_operation(
                self.scope, program, idempotency_key=idempotency_key,
                transport=('mcpTool', 'execute_v2_metadata_program'))

    @lock_busy_boundary
    def ownership(self, assertion: str, program: dict, *,
                  idempotency_key: str) -> dict:
        return self._authorized_effect_language(
            assertion,program,idempotency_key).execute_ownership(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def calendar(self, assertion: str, program: dict, *,
                 idempotency_key: str) -> dict:
        try:
            language = self._authorized_effect_language(assertion,program,idempotency_key)
        except ValueError as error:
            if str(error) != 'OPERATION_ADMISSION_EXPIRED':
                raise
            return self._authorized_language(assertion,program).reconcile_expired_operation(
                self.scope,program,idempotency_key=idempotency_key,
                transport=('mcpTool','execute_v2_calendar_program'))
        return language.execute_calendar(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def application_access(self, assertion: str, program: dict, *,
                           idempotency_key: str) -> dict:
        if not self.security_dsn:
            raise ValueError('POSTGRES_SECURITY_SERVICE_NOT_CONFIGURED')
        identity=self._authorized_effect_language(
            assertion,program,idempotency_key).identity
        if program.get('function') == authorization_config.APPLY:
            return postgres_authorization_config.run_configuration(
                self.security_dsn,self.scope,identity,program,
                operation_id=idempotency_key,secret=self.preview_secret)
        return PostgresSecurityLanguage(self.security_dsn,
            identity=identity).execute(
                self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def rule_access(self, assertion: str, program: dict, *,
                    idempotency_key: str) -> dict:
        if not self.security_dsn:
            raise ValueError('POSTGRES_SECURITY_SERVICE_NOT_CONFIGURED')
        identity=self._authorized_effect_language(
            assertion,program,idempotency_key).identity
        return PostgresSecurityLanguage(self.security_dsn,
            identity=identity).execute_rule(
                self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def policy_draft(self, assertion: str, program: dict, *,
                     idempotency_key: str) -> dict:
        return self._authorized_effect_language(
            assertion,program,idempotency_key).execute_policy_draft(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def period_nci_basis(self,assertion: str,program: dict,*,idempotency_key: str) -> dict:
        return self._authorized_effect_language(assertion,program,idempotency_key).execute_period_nci_basis(self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def period_policy_governance(self,assertion: str,program: dict,*,idempotency_key: str) -> dict:
        return self._authorized_effect_language(assertion,program,idempotency_key).execute_period_policy_governance(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def period_policy_case_record(self,assertion: str,program: dict,*,idempotency_key: str) -> dict:
        return self._authorized_effect_language(assertion,program,idempotency_key).execute_period_policy_case_record(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def policy_case_record(self, assertion: str, program: dict, *,
                           idempotency_key: str) -> dict:
        return self._authorized_effect_language(assertion,program,idempotency_key).execute_policy_case_record(
            self.scope, program, idempotency_key=idempotency_key)

    @lock_busy_boundary
    def policy_case_review(self, assertion: str, program: dict, *,
                           idempotency_key: str) -> dict:
        return self._authorized_effect_language(assertion,program,idempotency_key).execute_policy_case_review(
            self.scope, program, idempotency_key=idempotency_key)

    @lock_busy_boundary
    def policy_source_artifact(self, assertion: str, program: dict, *,
                               idempotency_key: str) -> dict:
        return self._authorized_effect_language(assertion,program,idempotency_key).execute_policy_source_artifact(
            self.scope, program, idempotency_key=idempotency_key)

    @lock_busy_boundary
    def policy_approval(self,assertion: str,program: dict,*,
                         idempotency_key: str) -> dict:
        return self._authorized_effect_language(assertion,program,idempotency_key).execute_policy_approval(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def policy_activation(self,assertion: str,program: dict,*,
                           idempotency_key: str) -> dict:
        return self._authorized_effect_language(assertion,program,idempotency_key).execute_policy_activation(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def application_decision(self, assertion: str, program: dict, *,
                             idempotency_key: str) -> dict:
        try:
            language = self._authorized_effect_language(assertion,program,idempotency_key)
        except ValueError as error:
            if str(error) != 'OPERATION_ADMISSION_EXPIRED':
                raise
            return self._authorized_language(assertion,program).reconcile_expired_operation(
                self.scope,program,idempotency_key=idempotency_key,
                transport=('mcpTool','execute_v2_application_decision'))
        return language.execute_application_decision(
            self.scope, program, idempotency_key=idempotency_key)

    @lock_busy_boundary
    def expression_rule(self, assertion: str, program: dict, *,
                        idempotency_key: str) -> dict:
        try:
            language = self._authorized_effect_language(assertion,program,idempotency_key)
        except ValueError as error:
            if str(error) != 'OPERATION_ADMISSION_EXPIRED':
                raise
            return self._authorized_language(assertion,program).reconcile_expired_operation(
                self.scope,program,idempotency_key=idempotency_key,
                transport=('mcpTool','execute_v2_expression_rule_program'))
        return language.execute_expression_rule(self.scope, program, idempotency_key=idempotency_key)

    @lock_busy_boundary
    def application_schedule(self, assertion: str, program: dict, *,
                             idempotency_key: str | None = None) -> dict:
        try:
            language = self._authorized_effect_language(assertion,program,idempotency_key)
        except ValueError as error:
            if str(error) != 'OPERATION_ADMISSION_EXPIRED':
                raise
            return self._authorized_language(assertion,program).reconcile_expired_operation(
                self.scope,program,idempotency_key=idempotency_key,
                transport=('mcpTool', 'execute_v2_application_schedule'))
        return language.execute_application_schedule(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def application_assignment(self, assertion: str, program: dict, *,
                               idempotency_key: str | None = None) -> dict:
        try:
            language = self._authorized_effect_language(assertion,program,idempotency_key)
        except ValueError as error:
            if str(error) != 'OPERATION_ADMISSION_EXPIRED':
                raise
            return self._authorized_language(assertion,program).reconcile_expired_operation(
                self.scope,program,idempotency_key=idempotency_key,
                transport=('mcpTool', 'execute_v2_application_assignment'))
        return language.execute_application_assignment(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def application_workflow(self, assertion: str, program: dict, *,
                             idempotency_key: str | None = None) -> dict:
        try:
            language = self._authorized_effect_language(assertion,program,idempotency_key)
        except ValueError as error:
            if str(error) != 'OPERATION_ADMISSION_EXPIRED':
                raise
            return self._authorized_language(assertion,program).reconcile_expired_operation(
                self.scope,program,idempotency_key=idempotency_key,
                transport=('mcpTool', 'execute_v2_application_workflow'))
        return language.execute_application_workflow(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def application_workflow_occurrence(self, assertion: str, program: dict, *,
            idempotency_key: str | None = None) -> dict:
        try:
            language = self._authorized_effect_language(assertion,program,idempotency_key)
        except ValueError as error:
            if str(error) != 'OPERATION_ADMISSION_EXPIRED':
                raise
            return self._authorized_language(assertion,program).reconcile_expired_operation(
                self.scope,program,idempotency_key=idempotency_key,
                transport=('mcpTool', 'execute_v2_application_workflow_occurrence'))
        return language.execute_application_workflow_occurrence(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def python_program(self, assertion: str, program: dict, *,
                       idempotency_key: str) -> dict:
        try:
            language=self._authorized_effect_language(assertion,program,idempotency_key)
        except ValueError as error:
            if str(error)!='OPERATION_ADMISSION_EXPIRED':
                raise
            return self._authorized_language(assertion,program).reconcile_expired_operation(
                self.scope,program,idempotency_key=idempotency_key,
                transport=('mcpTool','execute_v2_python_program_registry'))
        return language.execute_python_program(
            self.scope, program, idempotency_key=idempotency_key)

    @lock_busy_boundary
    def python_build(self, assertion: str, program: dict, *,
                     idempotency_key: str) -> dict:
        try:
            language=self._authorized_effect_language(assertion,program,idempotency_key)
        except ValueError as error:
            if str(error)!='OPERATION_ADMISSION_EXPIRED':
                raise
            return self._authorized_language(assertion,program).reconcile_expired_operation(
                self.scope,program,idempotency_key=idempotency_key,
                transport=('mcpTool','execute_v2_python_program_build'))
        return language.execute_python_build(
            self.scope, program, idempotency_key=idempotency_key)

    @lock_busy_boundary
    def python_build_read(self, assertion: str, build_id: str | None = None, *,
                          original_request: dict | None = None) -> dict:
        identity=self._authorize_permission(assertion,'read',action='rules.test')
        return self._language_for_identity(identity).read_python_build(
            self.scope,build_id,original_request=original_request)

    @lock_busy_boundary
    def python_build_artifact_read(self, assertion: str, *, build_id: str,
                                   section: str,
                                   cursor: str | None = None) -> dict:
        identity=self._authorize_permission(assertion,'read',action='rules.test')
        return self._language_for_identity(identity).read_python_build_artifact(
            self.scope, build_id=build_id, section=section, cursor=cursor)

    @lock_busy_boundary
    def python_build_cancel(self, assertion: str, build_id: str) -> dict:
        identity=self._authorize_permission(assertion,'write')
        return self._language_for_identity(identity).cancel_python_build(
            self.scope,build_id)

    @lock_busy_boundary
    def python_run(self, assertion: str, program: dict, *,
                   idempotency_key: str) -> dict:
        try:
            language=self._authorized_effect_language(assertion,program,idempotency_key)
        except ValueError as error:
            if str(error)!='OPERATION_ADMISSION_EXPIRED':
                raise
            return self._authorized_language(assertion,program).reconcile_expired_operation(
                self.scope,program,idempotency_key=idempotency_key,
                transport=('mcpTool','execute_v2_python_program_run'))
        return language.execute_python_run(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def python_workflow_read(self, assertion: str, workflow_id: str | None = None, *,
                             original_request: dict | None = None) -> dict:
        identity=self._authorize_permission(assertion,'read')
        return self._language_for_identity(identity).read_python_workflow(
            self.scope,workflow_id,original_request=original_request)

    @lock_busy_boundary
    def python_workflow_cancel(self, assertion: str, workflow_id: str) -> dict:
        identity=self._authorize_permission(assertion,'write')
        return self._language_for_identity(identity).cancel_python_workflow(
            self.scope,workflow_id)

    @lock_busy_boundary
    def execution_delegation(self,assertion: str,program: dict,*,
                             idempotency_key: str) -> dict:
        try:
            language=self._authorized_effect_language(assertion,program,idempotency_key)
        except ValueError as error:
            if str(error)!='OPERATION_ADMISSION_EXPIRED':
                raise
            return self._authorized_language(assertion,program).reconcile_expired_operation(
                self.scope,program,idempotency_key=idempotency_key,
                transport=('mcpTool','execute_v2_execution_delegation'))
        return language.execute_execution_delegation(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def planning_workflow_policy(self,assertion: str,program: dict,*,
                                 idempotency_key: str|None=None) -> dict:
        function = program.get('function') if isinstance(program, dict) else None
        if not isinstance(function, str) or function not in CUBE_WRITE_POLICY_FUNCTIONS:
            assert_public_program_admitted(program)
            raise ValueError('PLANNING_POLICY_FUNCTION_NOT_ALLOWED')
        if function in (POLICY_READ, POLICY_LIST):
            if idempotency_key is not None:
                raise ValueError('PLANNING_POLICY_READ_OPERATION_ID_INVALID')
            return self._authorized_language(assertion,program).execute_read(
                self.scope,program)
        return self._authorized_effect_language(assertion,program,idempotency_key).execute_planning_workflow_policy(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def statement_definition(self,assertion: str,program: dict,*,
                             idempotency_key: str|None=None) -> dict:
        return self._authorized_effect_language(assertion,program,idempotency_key).execute_statement_definition(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def planning_operation_policy(self, assertion: str, program: dict, *,
                                  idempotency_key: str | None = None) -> dict:
        return self._authorized_effect_language(assertion,program,idempotency_key).execute_planning_operation_policy(
            self.scope, program, idempotency_key=idempotency_key)

    @lock_busy_boundary
    def inventory_unrealized_schedule(self,assertion: str,program: dict,*,
                                      idempotency_key: str|None=None) -> dict:
        return self._authorized_effect_language(assertion,program,idempotency_key).execute_inventory_unrealized_schedule(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def cancel_expression_sequence(self, assertion: str,
                                   program: dict) -> dict:
        return self._authorized_language(assertion,program).cancel_expression_sequence(
            self.scope, program)

    @lock_busy_boundary
    def cancel_full_sequence(self, assertion: str, program: dict) -> dict:
        return self._authorized_language(assertion,program).cancel_full_sequence(
            self.scope, program)

    @lock_busy_boundary
    def journal(self, assertion: str, program: dict, *,
                idempotency_key: str) -> dict:
        return self._authorized_effect_language(assertion,program,idempotency_key).execute_journal(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def ic_elimination(self, assertion: str, program: dict, *,
                       idempotency_key: str) -> dict:
        return self._authorized_effect_language(assertion,program,idempotency_key).execute_ic_elimination(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def apply_planning_lock(self,assertion: str,program: dict,*,
                            preview_token: str,
                            idempotency_key: str) -> dict:
        try:
            language=self._authorized_effect_language(assertion,program,idempotency_key)
        except ValueError as error:
            if str(error) != 'OPERATION_ADMISSION_EXPIRED':
                raise
            return self._authorized_language(assertion,program).reconcile_expired_operation(
                self.scope,program,idempotency_key=idempotency_key,preview_token=preview_token,
                transport=('mcpTool', 'apply_v2_cube_write_scope_transition'))
        replay=language.replay_planning_lock(
            self.scope,program,idempotency_key=idempotency_key)
        if replay is not None:
            return replay
        return language.apply_planning_lock(
            self.scope,program,preview_token=preview_token,
            idempotency_key=idempotency_key)

    @lock_busy_boundary
    def job(self, assertion: str, job_id: str | None = None, *,
            operation_id: str | None = None) -> dict:
        identity=self._authorize_permission(assertion,'read',function='facts.numeric.batch')
        return PostgresJobQueue(self.runtime_dsn,identity=identity).read(
            self.scope,job_id,operation_id=operation_id)

    @lock_busy_boundary
    def events(self, assertion: str, *, after_sequence: int=0,
               limit: int=100) -> dict:
        identity=self._authorize_permission(assertion,'read',function='facts.numeric.batch')
        return PostgresJobQueue(self.runtime_dsn,identity=identity).events(
            self.scope,after_sequence=after_sequence,limit=limit)

    @lock_busy_boundary
    def cancel(self, assertion: str, job_id: str) -> dict:
        identity=self._authorize_permission(assertion,'write',function='facts.numeric.batch')
        return PostgresJobQueue(
            self.runtime_dsn,identity=identity).request_cancel(
                self.scope,job_id)

    def tasks(self, assertion: str, *, after_sequence: int=0,
              limit: int=100, attention_only: bool=False) -> dict:
        identity=self._authorize_permission(assertion,'read')
        return PostgresTaskService(self.runtime_dsn,
            identity=identity).list(
                self.scope,after_sequence=after_sequence,limit=limit,
                attention_only=attention_only)

    def task(self, assertion: str, task_id: str, *, after_event: int=0,
             event_limit: int=100) -> dict:
        identity=self._authorize_permission(assertion,'read')
        return PostgresTaskService(self.runtime_dsn,
            identity=identity).read(
                self.scope,task_id,after_event=after_event,
                event_limit=event_limit)

    def task_logs(self, assertion: str, task_id: str, *,
                  after_event: int=0, event_limit: int=100,
                  after_character: int=0,
                  character_limit: int=16_384) -> dict:
        identity=self._authorize_permission(assertion,'read')
        return PostgresTaskService(self.runtime_dsn,
            identity=identity).logs(
                self.scope, task_id, after_event=after_event,
                event_limit=event_limit, after_character=after_character,
                character_limit=character_limit)
