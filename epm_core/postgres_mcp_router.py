"""One authenticated MCP entry point for many PostgreSQL applications.

Only discovery uses the cross-application read credential. Every selected
application operation delegates to the scoped fixed-core facade, which checks
the verified identity and current grants inside its own effect transaction.
"""
from __future__ import annotations

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row

from .postgres_verified_principal import (
    principal_claims, verified_identity_binding_for_assertion)
from .persistence_contract import ApplicationScope
from .postgres_access import (PostgresAccessChecker, VerifiedIdentity,
                              assert_nonowner_role)
from .authorization_principal import principals_for_identity
from .postgres_mcp_application import PostgresMCPApplication
from .postgres_capacity_metrics import PostgresCapacityMetrics
from .postgres_python_environments import ApprovedPythonEnvironment


class PostgresMCPRouter:
    def __init__(self,access_dsn: str,runtime_dsn: str,*,preview_secret: bytes,
                 security_dsn: str | None = None,
                 approved_python_profiles: tuple[ApprovedPythonEnvironment,...] = ()):
        if not isinstance(access_dsn,str) or not access_dsn:
            raise ValueError('PostgreSQL discovery DSN is required')
        if not isinstance(runtime_dsn,str) or not runtime_dsn:
            raise ValueError('PostgreSQL runtime DSN is required')
        if not isinstance(preview_secret,bytes) or len(preview_secret)<32:
            raise ValueError('Server-owned preview secret is required')
        self.access_dsn=access_dsn
        self.runtime_dsn=runtime_dsn
        self.preview_secret=preview_secret
        self.security_dsn=security_dsn or None
        if (not isinstance(approved_python_profiles,tuple)
                or any(not isinstance(item,ApprovedPythonEnvironment)
                       for item in approved_python_profiles)):
            raise ValueError('PYTHON_ENVIRONMENT_CONFIGURATION_INVALID')
        self.approved_python_profiles=approved_python_profiles

    def assert_runtime_roles(self) -> None:
        assert_nonowner_role(self.access_dsn,'epm_access',
            ('workspace','application','workspace_access_grant',
             'application_access_grant','workspace_group_access_grant',
             'application_group_access_grant'))
        with connect_postgres(self.access_dsn,row_factory=dict_row) as db:
            row=db.execute('''SELECT r.rolcreaterole,r.rolcreatedb,
                r.rolreplication,
                pg_has_role(current_user,'epm_runtime','member') AS runtime,
                pg_has_role(current_user,'epm_security','member') AS security,
                pg_has_role(current_user,'epm_lifecycle','member') AS lifecycle,
                pg_has_role(current_user,'epm_provision','member') AS provision,
                has_schema_privilege(current_user,'epm','CREATE') AS can_create,
                EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n
                    ON n.oid=c.relnamespace WHERE n.nspname='epm'
                    AND c.relkind IN ('r','p','v')
                    AND (has_table_privilege(current_user,c.oid,'INSERT')
                      OR has_table_privilege(current_user,c.oid,'UPDATE')
                      OR has_table_privilege(current_user,c.oid,'DELETE')
                      OR has_table_privilege(current_user,c.oid,'TRUNCATE')))
                    AS can_write
                FROM pg_roles r WHERE r.rolname=current_user''').fetchone()
            if (not row or any(row.values())):
                raise ValueError('POSTGRES_ROUTER_ACCESS_ROLE_TOO_BROAD')
        PostgresMCPApplication(self.runtime_dsn,
            ApplicationScope('startup-check','startup-check'),
            preview_secret=self.preview_secret,
            security_dsn=self.security_dsn,
            approved_python_profiles=self.approved_python_profiles).assert_runtime_role()

    @staticmethod
    def _identity(assertion: str) -> VerifiedIdentity:
        principal=principal_claims(assertion,'mcp')
        return VerifiedIdentity(principal['issuer'],principal['subject'],
                                principal.get('groups',()), issued_at=principal['issuedAt'])

    def list_applications(self,assertion: str,*,after: dict | None=None,
                          limit: int=100) -> dict:
        return self.list_applications_for_identity(
            self._identity(assertion),after=after,limit=limit)

    @staticmethod
    def session_identity(assertion: str) -> dict:
        """Return only this verified caller's enrollment-safe identity fields."""
        return verified_identity_binding_for_assertion(assertion, 'mcp')

    def list_applications_for_identity(self,identity: VerifiedIdentity,*,
                                       after: dict | None=None,
                                       limit: int=100) -> dict:
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError('Verified identity is required')
        # Validate the server-verified token principal shape before the
        # database current-state fence resolves its managed groups.
        principals_for_identity(identity)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('Application list limit must be 1–100')
        if after is None:
            after_workspace,after_app='',''
        elif (isinstance(after,dict)
                and set(after)=={'workspaceId','applicationId'}
                and all(isinstance(value,str) and 1 <= len(value) <= 200
                        for value in after.values())):
            after_workspace=after['workspaceId']
            after_app=after['applicationId']
        else:
            raise ValueError('Invalid application list continuation')
        with connect_postgres(self.access_dsn,row_factory=dict_row) as db:
            groups=list(PostgresAccessChecker.current_groups_in_transaction(
                db, identity))
            rows=db.execute('''SELECT a.workspace_id,w.name AS workspace_name,
                a.application_id,a.name,a.kind,a.status
                FROM epm.application a JOIN epm.workspace w
                ON w.workspace_id=a.workspace_id
                WHERE a.status<>'Deleting' AND w.status<>'Deleting'
                AND (a.workspace_id,a.application_id)>(%s,%s)
                AND (EXISTS (SELECT 1 FROM epm.workspace_access_grant wg
                    WHERE wg.workspace_id=a.workspace_id AND wg.issuer=%s
                    AND wg.subject_id=%s AND wg.role='Administrator')
                 OR EXISTS (SELECT 1 FROM epm.workspace_group_access_grant wgg
                    WHERE wgg.workspace_id=a.workspace_id AND wgg.issuer=%s
                    AND wgg.group_id=ANY(%s::text[])
                    AND wgg.role='Administrator')
                 OR EXISTS (SELECT 1 FROM epm.application_access_grant ag
                    WHERE ag.workspace_id=a.workspace_id
                    AND ag.application_id=a.application_id
                    AND ag.issuer=%s AND ag.subject_id=%s)
                 OR EXISTS (SELECT 1 FROM epm.application_group_access_grant agg
                    WHERE agg.workspace_id=a.workspace_id
                    AND agg.application_id=a.application_id
                    AND agg.issuer=%s AND agg.group_id=ANY(%s::text[])))
                ORDER BY a.workspace_id,a.application_id LIMIT %s''',
                (after_workspace,after_app,identity.issuer,identity.subject_id,
                 identity.issuer,groups,identity.issuer,identity.subject_id,
                 identity.issuer,groups,limit+1)).fetchall()
        visible=rows[:limit]
        applications=[{'workspaceId':row['workspace_id'],
                       'workspaceName':row['workspace_name'],
                       'applicationId':row['application_id'],
                       'name':row['name'],'kind':row['kind'],
                       'status':row['status']} for row in visible]
        next_after=({'workspaceId':visible[-1]['workspace_id'],
                     'applicationId':visible[-1]['application_id']}
                    if len(rows)>limit else None)
        return {'applications':applications,'nextAfter':next_after}

    def _application(self,workspace_id: str,application_id: str
                     ) -> PostgresMCPApplication:
        if (not isinstance(workspace_id,str) or not 1 <= len(workspace_id) <= 200
                or not isinstance(application_id,str)
                or not 1 <= len(application_id) <= 200):
            raise ValueError('Application scope IDs are required')
        return PostgresMCPApplication(self.runtime_dsn,
            ApplicationScope(workspace_id,application_id),
            preview_secret=self.preview_secret,
            security_dsn=self.security_dsn,
            approved_python_profiles=self.approved_python_profiles)

    def catalog(self,assertion: str,workspace_id: str,
                application_id: str) -> dict:
        result=self._application(workspace_id,application_id).catalog(assertion)
        result['listener']['scope']='routed_application'
        return result

    def read(self,assertion: str,workspace_id: str,application_id: str,
             program: dict) -> dict:
        return self._application(workspace_id,application_id).read(
            assertion,program)

    def capacity_metrics_for_identity(self,identity: VerifiedIdentity,
                                      workspace_id: str,application_id: str) -> dict:
        return PostgresCapacityMetrics(self.runtime_dsn).read(
            identity,ApplicationScope(workspace_id,application_id))

    def capacity_metrics(self,assertion: str,workspace_id: str,
                         application_id: str) -> dict:
        return self.capacity_metrics_for_identity(
            self._identity(assertion),workspace_id,application_id)

    def preview(self,assertion: str,workspace_id: str,application_id: str,
                program: dict) -> dict:
        return self._application(workspace_id,application_id).preview(
            assertion,program)

    def submit(self,assertion: str,workspace_id: str,application_id: str,
               program: dict,*,preview_token: str,idempotency_key: str,
               depends_on_job_ids: tuple[str,...]=()) -> dict:
        return self._application(workspace_id,application_id).submit(
            assertion,program,preview_token=preview_token,
            idempotency_key=idempotency_key,
            depends_on_job_ids=depends_on_job_ids)

    def cancel_expression_sequence(self, assertion: str,
                                   workspace_id: str,
                                   application_id: str,
                                   program: dict) -> dict:
        return self._application(workspace_id, application_id).cancel_expression_sequence(
            assertion, program)

    def cancel_full_sequence(self, assertion: str, workspace_id: str,
                             application_id: str, program: dict) -> dict:
        return self._application(workspace_id, application_id).cancel_full_sequence(
            assertion, program)

    def source(self,assertion: str,workspace_id: str,application_id: str,
               program: dict) -> dict:
        return self._application(workspace_id,application_id).source(
            assertion,program)

    def metadata(self,assertion: str,workspace_id: str,application_id: str,
                 program: dict,*,idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).metadata(
            assertion,program,idempotency_key=idempotency_key)

    def python_program(self,assertion: str,workspace_id: str,
                       application_id: str,program: dict,*,
                       idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).python_program(
            assertion,program,idempotency_key=idempotency_key)

    def python_build(self,assertion: str,workspace_id: str,
                     application_id: str,program: dict,*,
                     idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).python_build(
            assertion,program,idempotency_key=idempotency_key)

    def python_build_read(self,assertion: str,workspace_id: str,
                          application_id: str,build_id: str) -> dict:
        return self._application(workspace_id,application_id).python_build_read(
            assertion,build_id)

    def python_build_artifact_read(self, assertion: str, workspace_id: str,
                                   application_id: str, *, build_id: str,
                                   section: str,
                                   cursor: str | None = None) -> dict:
        return self._application(workspace_id, application_id
            ).python_build_artifact_read(assertion, build_id=build_id,
                                         section=section, cursor=cursor)

    def python_build_cancel(self,assertion: str,workspace_id: str,
                            application_id: str,build_id: str) -> dict:
        return self._application(workspace_id,application_id).python_build_cancel(
            assertion,build_id)

    def python_run(self,assertion: str,workspace_id: str,
                   application_id: str,program: dict,*,
                   idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).python_run(
            assertion,program,idempotency_key=idempotency_key)

    def python_workflow_read(self,assertion: str,workspace_id: str,
                             application_id: str,workflow_id: str) -> dict:
        return self._application(workspace_id,application_id).python_workflow_read(
            assertion,workflow_id)

    def python_workflow_cancel(self,assertion: str,workspace_id: str,
                               application_id: str,workflow_id: str) -> dict:
        return self._application(workspace_id,application_id).python_workflow_cancel(
            assertion,workflow_id)

    def execution_delegation(self, assertion: str, workspace_id: str,
                             application_id: str, program: dict, *,
                             idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).execution_delegation(
            assertion,program,idempotency_key=idempotency_key)

    def generic(self,assertion: str,workspace_id: str,application_id: str,
                program: dict,*,idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).generic(
            assertion,program,idempotency_key=idempotency_key)

    def ownership(self,assertion: str,workspace_id: str,application_id: str,
                  program: dict,*,idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).ownership(
            assertion,program,idempotency_key=idempotency_key)

    def journal(self,assertion: str,workspace_id: str,application_id: str,
                program: dict,*,idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).journal(
            assertion,program,idempotency_key=idempotency_key)

    def ic_elimination(self,assertion: str,workspace_id: str,
                       application_id: str,program: dict,*,
                       idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).ic_elimination(
            assertion,program,idempotency_key=idempotency_key)

    def calendar(self,assertion: str,workspace_id: str,application_id: str,
                 program: dict,*,idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).calendar(
            assertion,program,idempotency_key=idempotency_key)

    def application_access(self,assertion: str,workspace_id: str,
                           application_id: str,program: dict,*,
                           idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).application_access(
            assertion,program,idempotency_key=idempotency_key)

    def rule_access(self,assertion: str,workspace_id: str,
                    application_id: str,program: dict,*,
                    idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).rule_access(
            assertion,program,idempotency_key=idempotency_key)

    def policy_draft(self,assertion: str,workspace_id: str,application_id: str,
                     program: dict,*,idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).policy_draft(
            assertion,program,idempotency_key=idempotency_key)

    def planning_workflow_policy(
            self,assertion: str,workspace_id: str,application_id: str,
            program: dict,*,idempotency_key: str|None=None) -> dict:
        return self._application(
            workspace_id,application_id).planning_workflow_policy(
                assertion,program,idempotency_key=idempotency_key)

    def statement_definition(
            self,assertion: str,workspace_id: str,application_id: str,
            program: dict,*,idempotency_key: str|None=None) -> dict:
        return self._application(
            workspace_id,application_id).statement_definition(
                assertion,program,idempotency_key=idempotency_key)

    def planning_operation_policy(
            self, assertion: str, workspace_id: str, application_id: str,
            program: dict, *, idempotency_key: str | None = None) -> dict:
        return self._application(
            workspace_id, application_id).planning_operation_policy(
                assertion, program, idempotency_key=idempotency_key)

    def inventory_unrealized_schedule(
            self,assertion: str,workspace_id: str,application_id: str,
            program: dict,*,idempotency_key: str|None=None) -> dict:
        return self._application(
            workspace_id,application_id).inventory_unrealized_schedule(
                assertion,program,idempotency_key=idempotency_key)

    def period_nci_basis(self,assertion: str,workspace_id: str,application_id: str,program: dict,*,idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).period_nci_basis(assertion,program,idempotency_key=idempotency_key)

    def period_policy_governance(self,assertion: str,workspace_id: str,application_id: str,program: dict,*,idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).period_policy_governance(
            assertion,program,idempotency_key=idempotency_key)

    def period_policy_case_record(self,assertion: str,workspace_id: str,application_id: str,program: dict,*,idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).period_policy_case_record(
            assertion,program,idempotency_key=idempotency_key)

    def policy_case_record(self, assertion: str, workspace_id: str,
                           application_id: str, program: dict, *,
                           idempotency_key: str) -> dict:
        return self._application(workspace_id, application_id).policy_case_record(
            assertion, program, idempotency_key=idempotency_key)

    def policy_case_review(self, assertion: str, workspace_id: str,
                           application_id: str, program: dict, *,
                           idempotency_key: str) -> dict:
        return self._application(workspace_id, application_id).policy_case_review(
            assertion, program, idempotency_key=idempotency_key)

    def policy_source_artifact(self, assertion: str, workspace_id: str,
                               application_id: str, program: dict, *,
                               idempotency_key: str) -> dict:
        return self._application(workspace_id,
                                 application_id).policy_source_artifact(
            assertion, program, idempotency_key=idempotency_key)

    def policy_approval(self,assertion: str,workspace_id: str,
                        application_id: str,program: dict,*,
                        idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).policy_approval(
            assertion,program,idempotency_key=idempotency_key)

    def policy_activation(self,assertion: str,workspace_id: str,
                          application_id: str,program: dict,*,
                          idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).policy_activation(
            assertion,program,idempotency_key=idempotency_key)

    def expression_rule(self, assertion: str, workspace_id: str,
                        application_id: str, program: dict, *,
                        idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).expression_rule(
            assertion, program, idempotency_key=idempotency_key)

    def application_schedule(self,assertion: str,workspace_id: str,
                             application_id: str,program: dict,*,
                             idempotency_key: str|None=None) -> dict:
        return self._application(workspace_id,application_id).application_schedule(
            assertion,program,idempotency_key=idempotency_key)

    def application_assignment(self,assertion: str,workspace_id: str,
                               application_id: str,program: dict,*,
                               idempotency_key: str|None=None) -> dict:
        return self._application(
            workspace_id,application_id).application_assignment(
                assertion,program,idempotency_key=idempotency_key)

    def application_workflow(self,assertion: str,workspace_id: str,
                             application_id: str,program: dict,* ,
                             idempotency_key: str|None=None) -> dict:
        return self._application(
            workspace_id,application_id).application_workflow(
                assertion,program,idempotency_key=idempotency_key)

    def application_workflow_occurrence(self,assertion: str,workspace_id: str,
            application_id: str,program: dict,* ,
            idempotency_key: str|None=None) -> dict:
        return self._application(
            workspace_id,application_id).application_workflow_occurrence(
                assertion,program,idempotency_key=idempotency_key)

    def planning_transition(self,assertion: str,workspace_id: str,
                            application_id: str,program: dict,*,
                            preview_token: str) -> dict:
        return self._application(workspace_id,application_id).apply_planning_lock(
            assertion,program,preview_token=preview_token)

    def job(self,assertion: str,workspace_id: str,application_id: str,
            job_id: str) -> dict:
        return self._application(workspace_id,application_id).job(
            assertion,job_id)

    def events(self,assertion: str,workspace_id: str,application_id: str,*,
               after_sequence: int=0,limit: int=100) -> dict:
        return self._application(workspace_id,application_id).events(
            assertion,after_sequence=after_sequence,limit=limit)

    def cancel(self,assertion: str,workspace_id: str,application_id: str,
               job_id: str) -> dict:
        return self._application(workspace_id,application_id).cancel(
            assertion,job_id)

    def tasks(self,assertion: str,workspace_id: str,application_id: str,*,
              after_sequence: int=0,limit: int=100) -> dict:
        return self._application(workspace_id,application_id).tasks(
            assertion,after_sequence=after_sequence,limit=limit)

    def task(self,assertion: str,workspace_id: str,application_id: str,
             task_id: str,*,after_event: int=0,event_limit: int=100) -> dict:
        return self._application(workspace_id,application_id).task(
            assertion,task_id,after_event=after_event,event_limit=event_limit)

    def task_logs(self,assertion: str,workspace_id: str,application_id: str,
                  task_id: str,*,after_event: int=0,event_limit: int=100,
                  after_character: int=0,
                  character_limit: int=16_384) -> dict:
        return self._application(workspace_id,application_id).task_logs(
            assertion,task_id,after_event=after_event,event_limit=event_limit,
            after_character=after_character,character_limit=character_limit)

    def interrupt_task(self,assertion: str,workspace_id: str,
                       application_id: str,task_id: str) -> dict:
        return self._application(workspace_id,application_id).interrupt_task(
            assertion,task_id)

    def rerun_task(self,assertion: str,workspace_id: str,
                   application_id: str,task_id: str,*,
                   idempotency_key: str) -> dict:
        return self._application(workspace_id,application_id).rerun_task(
            assertion,task_id,idempotency_key=idempotency_key)
