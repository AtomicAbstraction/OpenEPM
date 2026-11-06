"""Authenticated, application-bound MCP façade over the PostgreSQL V2 core.

No caller-provided identity, role, SQL or application scope is accepted. The
listener binds one application; each tool verifies the Access assertion and
the underlying fixed-core operation rechecks the current PostgreSQL grant.
"""
from __future__ import annotations

import logging
import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row

from .postgres_capability_contract import (
    FUNCTION_REGISTRY_FORMAT, assert_public_program_admitted, filter_catalog,
    function_registry_digest)
from .postgres_application_capabilities import _state as capability_state
from .postgres_verified_principal import (
    principal_claims, verified_identity_binding_for_assertion)
from .persistence_contract import ApplicationScope
from .postgres_access import (AccessDenied, PostgresAccessChecker,
                              assert_nonowner_role, assert_security_writer_role,
                              VerifiedIdentity)
from .postgres_jobs import PostgresJobQueue
from .postgres_tasks import PostgresTaskService
from .postgres_language_v2 import PostgresLanguageV2
from .postgres_processing_limits import lock_busy_boundary, policy as processing_policy
from .processing_operation_registry import (
    PROCESSING_REGISTRY_FORMAT, admit_operation, operation_contracts)
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_security_language import PostgresSecurityLanguage
from .postgres_python_environments import ApprovedPythonEnvironment

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
                              arguments: dict|None=None) -> VerifiedIdentity:
        """Resolve one current application permission before MCP dispatch."""
        identity=self._identity(assertion)
        with connect_postgres(self.runtime_dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,self.scope)
                PostgresAccessChecker.lock_workspace(
                    db,self.scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,identity,self.scope,permission,
                    function=function,arguments=arguments)
        return identity

    def _authorized_language(self,assertion: str,
                             program: dict) -> PostgresLanguageV2:
        return self._language_for_identity(
            self._authorize_program(assertion,program))

    @staticmethod
    def session_identity(assertion: str) -> dict:
        """Return only this verified caller's enrollment-safe identity fields."""
        return verified_identity_binding_for_assertion(assertion, 'mcp')

    @lock_busy_boundary
    def catalog(self, assertion: str) -> dict:
        identity = self._identity(assertion)
        with connect_postgres(self.runtime_dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,self.scope)
                checker = PostgresAccessChecker.check_in_transaction
                checker(db,identity,self.scope,'read')
                allowed={'read'}
                for permission in ('write','admin','workspace_admin','rule_design',
                                   'rule_publish','rule_run'):
                    if permission.startswith('rule_') and 'write' not in allowed:
                        continue
                    try:
                        checker(db,identity,self.scope,permission)
                        allowed.add(permission)
                    except AccessDenied:
                        pass
                state=capability_state(db,self.scope)
                if state is None: raise AccessDenied('APPLICATION_UNAVAILABLE')
                enabled=state['enabled_capabilities']
                capability_revision=state['capability_revision']
                security_revision=state['security_revision']
        catalog = filter_catalog(PostgresLanguageV2.catalog(),enabled)
        if self.security_dsn:
            catalog['functions'].update(
                PostgresSecurityLanguage.catalog()['functions'])
        functions = {name:spec for name,spec in catalog['functions'].items()
                     if spec['permission'] in allowed}
        contracts=operation_contracts(functions,scope='application')
        return {'languageVersion':2,
                'registryFormat':FUNCTION_REGISTRY_FORMAT,
                'registryDigest':function_registry_digest(functions),
                'processingRegistryFormat':PROCESSING_REGISTRY_FORMAT,
                'operationContracts':contracts,
                'processingPolicy':processing_policy(),
                'listener':{'scope':'application',
                            'workspaceId':self.scope.workspace_id,
                            'applicationId':self.scope.application_id},
                'enabledCapabilities':sorted(enabled),
                'capabilityRevision':capability_revision,
                'securityRevision':security_revision,
                'functions':functions}

    @lock_busy_boundary
    def read(self, assertion: str, program: dict) -> dict:
        identity=self._authorize_program(assertion,program)
        if (isinstance(program,dict) and program.get('function') in {
                'security.application.access.list',
                'security.application.audit.list',
                'security.application.receipt.read',
                'security.application.group-access.list',
                'security.application.dimension-access.read',
                'security.application.group-dimension-access.read',
                'security.application.dimension-tags.read',
                'security.application.member-tags.read',
                'security.application.dimension-metadata-tags.read',
                'security.application.relationship-tags.read',
                'security.application.dimension-policy.version.read',
                'security.application.dimension-policy.version.list',
                'security.application.dimension-policy.active.read'}):
            if not self.security_dsn:
                raise ValueError('POSTGRES_SECURITY_SERVICE_NOT_CONFIGURED')
            security = PostgresSecurityLanguage(
                self.security_dsn, identity=identity)
            if program['function']=='security.application.access.list':
                return security.list_application_access(self.scope,program)
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
    def submit(self, assertion: str, program: dict, *,
               preview_token: str, idempotency_key: str,
               depends_on_job_ids: tuple[str,...]=()) -> dict:
        return self._authorized_language(assertion,program).submit(
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
        return self._authorized_language(assertion,program).execute_metadata(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def generic(self, assertion: str, program: dict, *,
                idempotency_key: str) -> dict:
        return self._authorized_language(assertion,program).execute_generic(
            self.scope, program, idempotency_key=idempotency_key)

    @lock_busy_boundary
    def ownership(self, assertion: str, program: dict, *,
                  idempotency_key: str) -> dict:
        return self._authorized_language(assertion,program).execute_ownership(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def calendar(self, assertion: str, program: dict, *,
                 idempotency_key: str) -> dict:
        return self._authorized_language(assertion,program).execute_calendar(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def application_access(self, assertion: str, program: dict, *,
                           idempotency_key: str) -> dict:
        if not self.security_dsn:
            raise ValueError('POSTGRES_SECURITY_SERVICE_NOT_CONFIGURED')
        identity=self._authorize_program(assertion,program)
        return PostgresSecurityLanguage(self.security_dsn,
            identity=identity).execute(
                self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def rule_access(self, assertion: str, program: dict, *,
                    idempotency_key: str) -> dict:
        if not self.security_dsn:
            raise ValueError('POSTGRES_SECURITY_SERVICE_NOT_CONFIGURED')
        identity=self._authorize_program(assertion,program)
        return PostgresSecurityLanguage(self.security_dsn,
            identity=identity).execute_rule(
                self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def policy_draft(self, assertion: str, program: dict, *,
                     idempotency_key: str) -> dict:
        return self._authorized_language(assertion,program).execute_policy_draft(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def period_nci_basis(self,assertion: str,program: dict,*,idempotency_key: str) -> dict:
        return self._authorized_language(assertion,program).execute_period_nci_basis(self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def period_policy_governance(self,assertion: str,program: dict,*,idempotency_key: str) -> dict:
        return self._authorized_language(assertion,program).execute_period_policy_governance(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def period_policy_case_record(self,assertion: str,program: dict,*,idempotency_key: str) -> dict:
        return self._authorized_language(assertion,program).execute_period_policy_case_record(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def policy_case_record(self, assertion: str, program: dict, *,
                           idempotency_key: str) -> dict:
        return self._authorized_language(assertion,program).execute_policy_case_record(
            self.scope, program, idempotency_key=idempotency_key)

    @lock_busy_boundary
    def policy_case_review(self, assertion: str, program: dict, *,
                           idempotency_key: str) -> dict:
        return self._authorized_language(assertion,program).execute_policy_case_review(
            self.scope, program, idempotency_key=idempotency_key)

    @lock_busy_boundary
    def policy_source_artifact(self, assertion: str, program: dict, *,
                               idempotency_key: str) -> dict:
        return self._authorized_language(assertion,program).execute_policy_source_artifact(
            self.scope, program, idempotency_key=idempotency_key)

    @lock_busy_boundary
    def policy_approval(self,assertion: str,program: dict,*,
                         idempotency_key: str) -> dict:
        return self._authorized_language(assertion,program).execute_policy_approval(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def policy_activation(self,assertion: str,program: dict,*,
                           idempotency_key: str) -> dict:
        return self._authorized_language(assertion,program).execute_policy_activation(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def expression_rule(self, assertion: str, program: dict, *,
                        idempotency_key: str) -> dict:
        return self._authorized_language(assertion,program).execute_expression_rule(
            self.scope, program, idempotency_key=idempotency_key)

    @lock_busy_boundary
    def application_schedule(self, assertion: str, program: dict, *,
                             idempotency_key: str | None = None) -> dict:
        return self._authorized_language(assertion,program).execute_application_schedule(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def application_assignment(self, assertion: str, program: dict, *,
                               idempotency_key: str | None = None) -> dict:
        return self._authorized_language(assertion,program).execute_application_assignment(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def application_workflow(self, assertion: str, program: dict, *,
                             idempotency_key: str | None = None) -> dict:
        return self._authorized_language(assertion,program).execute_application_workflow(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def application_workflow_occurrence(self, assertion: str, program: dict, *,
            idempotency_key: str | None = None) -> dict:
        return self._authorized_language(assertion,program).execute_application_workflow_occurrence(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def python_program(self, assertion: str, program: dict, *,
                       idempotency_key: str) -> dict:
        return self._authorized_language(assertion,program).execute_python_program(
            self.scope, program, idempotency_key=idempotency_key)

    @lock_busy_boundary
    def python_build(self, assertion: str, program: dict, *,
                     idempotency_key: str) -> dict:
        return self._authorized_language(assertion,program).execute_python_build(
            self.scope, program, idempotency_key=idempotency_key)

    @lock_busy_boundary
    def python_build_read(self, assertion: str, build_id: str) -> dict:
        identity=self._authorize_permission(assertion,'read')
        return self._language_for_identity(identity).read_python_build(
            self.scope,build_id)

    @lock_busy_boundary
    def python_build_artifact_read(self, assertion: str, *, build_id: str,
                                   section: str,
                                   cursor: str | None = None) -> dict:
        identity=self._authorize_permission(assertion,'read')
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
        return self._authorized_language(assertion,program).execute_python_run(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def python_workflow_read(self, assertion: str, workflow_id: str) -> dict:
        identity=self._authorize_permission(assertion,'read')
        return self._language_for_identity(identity).read_python_workflow(
            self.scope,workflow_id)

    @lock_busy_boundary
    def python_workflow_cancel(self, assertion: str, workflow_id: str) -> dict:
        identity=self._authorize_permission(assertion,'write')
        return self._language_for_identity(identity).cancel_python_workflow(
            self.scope,workflow_id)

    @lock_busy_boundary
    def execution_delegation(self,assertion: str,program: dict,*,
                             idempotency_key: str) -> dict:
        return self._authorized_language(assertion,program).execute_execution_delegation(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def planning_workflow_policy(self,assertion: str,program: dict,*,
                                 idempotency_key: str|None=None) -> dict:
        return self._authorized_language(assertion,program).execute_planning_workflow_policy(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def statement_definition(self,assertion: str,program: dict,*,
                             idempotency_key: str|None=None) -> dict:
        return self._authorized_language(assertion,program).execute_statement_definition(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def planning_operation_policy(self, assertion: str, program: dict, *,
                                  idempotency_key: str | None = None) -> dict:
        return self._authorized_language(assertion,program).execute_planning_operation_policy(
            self.scope, program, idempotency_key=idempotency_key)

    @lock_busy_boundary
    def inventory_unrealized_schedule(self,assertion: str,program: dict,*,
                                      idempotency_key: str|None=None) -> dict:
        return self._authorized_language(assertion,program).execute_inventory_unrealized_schedule(
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
        return self._authorized_language(assertion,program).execute_journal(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def ic_elimination(self, assertion: str, program: dict, *,
                       idempotency_key: str) -> dict:
        return self._authorized_language(assertion,program).execute_ic_elimination(
            self.scope,program,idempotency_key=idempotency_key)

    @lock_busy_boundary
    def apply_planning_lock(self,assertion: str,program: dict,*,
                            preview_token: str) -> dict:
        return self._authorized_language(assertion,program).apply_planning_lock(
            self.scope,program,preview_token=preview_token)

    @lock_busy_boundary
    def job(self, assertion: str, job_id: str) -> dict:
        identity=self._authorize_permission(assertion,'read')
        return PostgresJobQueue(self.runtime_dsn,identity=identity).read(
            self.scope,job_id)

    @lock_busy_boundary
    def events(self, assertion: str, *, after_sequence: int=0,
               limit: int=100) -> dict:
        identity=self._authorize_permission(assertion,'read')
        return PostgresJobQueue(self.runtime_dsn,identity=identity).events(
            self.scope,after_sequence=after_sequence,limit=limit)

    @lock_busy_boundary
    def cancel(self, assertion: str, job_id: str) -> dict:
        identity=self._authorize_permission(assertion,'write')
        return PostgresJobQueue(
            self.runtime_dsn,identity=identity).request_cancel(
                self.scope,job_id)

    def tasks(self, assertion: str, *, after_sequence: int=0,
              limit: int=100) -> dict:
        identity=self._authorize_permission(assertion,'read')
        return PostgresTaskService(self.runtime_dsn,
            identity=identity).list(
                self.scope,after_sequence=after_sequence,limit=limit)

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

    def interrupt_task(self, assertion: str, task_id: str) -> dict:
        identity=self._authorize_permission(assertion,'write')
        return PostgresTaskService(self.runtime_dsn,
            identity=identity).interrupt(self.scope,task_id)

    def rerun_task(self, assertion: str, task_id: str, *,
                   idempotency_key: str) -> dict:
        identity=self._authorize_permission(assertion,'write')
        return PostgresTaskService(self.runtime_dsn,
            identity=identity).rerun(
                self.scope, task_id, idempotency_key=idempotency_key)
