"""Multi-application PostgreSQL V2 MCP routing through fixed-core checks."""
from __future__ import annotations

import logging
import os
from mcp.server import MCPServer
from epm_core.postgres_mcp_execution import bounded_tool
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from epm_core.mcp_diagnostics import DiagnosticToolError
from openepm.diagnostics import SourceValidationError
import psycopg
from epm_core.postgres_processing_limits import BUSY_CODE

from epm_core.postgres_auth import AuthError,access_token
from epm_core.deployment_secrets import configured_hex_bytes, configured_text
from epm_core.postgres_mcp_router import PostgresMCPRouter
from epm_core.postgres_python_environment_startup import load_python_environment_profiles
from epm_core.published_skill_delivery import (
    bootstrap_instructions, read_published_skill, register_skill_resources,
)


LOG=logging.getLogger(__name__)
server=MCPServer('Open EPM PostgreSQL V2 Router',instructions=bootstrap_instructions(
    'Discover only applications granted to your verified identity. Select '
    'workspaceId and applicationId for each typed V2 program. The fixed core '
    'rechecks current grants and scope in every read or effect transaction. '
    'For effects, request a short-lived operation admission bound to the exact '
    'selected application, actor and typed intent before execution. '
    'No caller-supplied role, SQL or Python execution is accepted.'))
register_skill_resources(server)


def _optional_secret(direct_name: str, file_name: str) -> str | None:
    if os.environ.get(direct_name) or os.environ.get(file_name):
        return configured_text(os.environ, direct_name, file_name)
    return None


def router() -> PostgresMCPRouter:
    secret=configured_hex_bytes(os.environ,
        'EPM_PG_PREVIEW_SECRET_HEX','EPM_PG_PREVIEW_SECRET_FILE')
    return PostgresMCPRouter(
        configured_text(os.environ, 'EPM_PG_ACCESS_DSN',
                        'EPM_PG_ACCESS_DSN_FILE'),
        configured_text(os.environ, 'EPM_PG_RUNTIME_DSN',
                        'EPM_PG_RUNTIME_DSN_FILE'),
        preview_secret=secret,
        security_dsn=_optional_secret('EPM_PG_SECURITY_DSN',
                                      'EPM_PG_SECURITY_DSN_FILE'),
        approved_python_profiles=load_python_environment_profiles(os.environ))


def _startup_role_check():
    router().assert_runtime_roles()


def _assertion(ctx: Context) -> str:
    try:
        headers=ctx.headers or {}
    except (AttributeError,ValueError):
        headers={}
    return access_token(headers)


def _call(operation):
    try:
        return operation()
    except SourceValidationError as error:
        raise DiagnosticToolError(error.diagnostics) from None
    except (AuthError,ValueError) as error:
        raise ToolError(str(error)) from error
    except psycopg.errors.LockNotAvailable as error:
        raise ToolError(BUSY_CODE + '; no new job is implied; retry the same request key') from error
    except psycopg.Error as error:
        LOG.exception('PostgreSQL routed MCP operation failed')
        raise ToolError('POSTGRES_OPERATION_FAILED; inspect the durable job '
                        'or batch status before retrying') from error


@bounded_tool(server)
def read_openepm_published_skill(ctx: Context, part: str = 'manifest',
                                 chunk_index: int | None = None) -> dict:
    """Read the packaged skill manifest, content or one verified chunk."""
    return read_published_skill(part, chunk_index)


@bounded_tool(server)
def read_v2_session_identity(ctx: Context) -> dict:
    """Read only the authenticated caller's verified enrollment binding."""
    return _call(lambda:router().session_identity(_assertion(ctx)))


@bounded_tool(server)
def list_v2_applications(ctx: Context,after: dict | None=None,
                         limit: int=100) -> dict:
    """Page applications currently granted to your verified identity."""
    return _call(lambda:router().list_applications(
        _assertion(ctx),after=after,limit=limit))


@bounded_tool(server)
def list_v2_functions(workspace_id: str,application_id: str,
                      ctx: Context) -> dict:
    """Discover currently granted functions in one selected application."""
    return _call(lambda:router().catalog(
        _assertion(ctx),workspace_id,application_id))


@bounded_tool(server)
def read_v2_program(workspace_id: str,application_id: str,
                    program: dict,ctx: Context) -> dict:
    """Execute a bounded scoped read program."""
    return _call(lambda:router().read(
        _assertion(ctx),workspace_id,application_id,program))


@bounded_tool(server)
def read_v2_capacity_metrics(workspace_id: str,application_id: str,
                             ctx: Context) -> dict:
    """Read bounded administrator-only operational metrics for one application."""
    return _call(lambda:router().capacity_metrics(
        _assertion(ctx),workspace_id,application_id))


@bounded_tool(server)
def preview_v2_program(workspace_id: str,application_id: str,
                       program: dict,ctx: Context) -> dict:
    """Preview a revision-pinned scoped write program."""
    return _call(lambda:router().preview(
        _assertion(ctx),workspace_id,application_id,program))


@bounded_tool(server)
def issue_v2_operation_admission(workspace_id: str, application_id: str,
                                 program: dict, ctx: Context,
                                 ttl_seconds: int = 900) -> dict:
    """Issue a short-lived identity bound to caller, application and write intent."""
    return _call(lambda:router().issue_operation_admission(
        _assertion(ctx), workspace_id, application_id, program,
        ttl_seconds=ttl_seconds))


@bounded_tool(server)
def submit_v2_program(workspace_id: str,application_id: str,
                      program: dict,preview_token: str,idempotency_key: str,
                      ctx: Context,
                      depends_on_job_ids: list[str] | None=None) -> dict:
    """Apply a previewed atomic program or admit its catalogued durable job."""
    return _call(lambda:router().submit(
        _assertion(ctx),workspace_id,application_id,program,
        preview_token=preview_token,idempotency_key=idempotency_key,
        depends_on_job_ids=tuple(depends_on_job_ids or ())))


@bounded_tool(server)
def execute_v2_source_program(workspace_id: str,application_id: str,
                              program: dict,ctx: Context) -> dict:
    """Run a staged-source or transfer lifecycle step, including import status reads, in one application."""
    return _call(lambda:router().source(
        _assertion(ctx),workspace_id,application_id,program))


@bounded_tool(server)
def execute_v2_metadata_program(workspace_id: str,application_id: str,
                                program: dict,idempotency_key: str,
                                ctx: Context) -> dict:
    """Execute a typed metadata or currency-settings program in one application."""
    return _call(lambda:router().metadata(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


@bounded_tool(server)
def execute_v2_python_program_registry(workspace_id: str,application_id: str,
                                       program: dict,idempotency_key: str,
                                       ctx: Context) -> dict:
    """Save, publish or deactivate Python builder source; never executes it."""
    return _call(lambda:router().python_program(_assertion(ctx),workspace_id,
        application_id,program,idempotency_key=idempotency_key))


@bounded_tool(server)
def execute_v2_python_program_build(workspace_id: str,application_id: str,
                                    program: dict,idempotency_key: str,
                                    ctx: Context) -> dict:
    """Admit an isolated durable build; accepts no Python source or SQL."""
    return _call(lambda:router().python_build(_assertion(ctx),workspace_id,
        application_id,program,idempotency_key=idempotency_key))


@bounded_tool(server)
def read_v2_python_program_build(workspace_id: str,application_id: str,
                                 build_id: str,ctx: Context) -> dict:
    """Read one caller-owned technical build and sealed-plan digest."""
    return _call(lambda:router().python_build_read(_assertion(ctx),workspace_id,
        application_id,build_id))


@bounded_tool(server)
def read_v2_python_program_build_artifact(workspace_id: str,
        application_id: str, build_id: str, section: str, ctx: Context,
        cursor: str | None = None) -> dict:
    """Read one bounded page from a caller-owned sealed build artifact."""
    return _call(lambda: router().python_build_artifact_read(
        _assertion(ctx), workspace_id, application_id, build_id=build_id,
        section=section, cursor=cursor))


@bounded_tool(server)
def cancel_v2_python_program_build(workspace_id: str,application_id: str,
                                   build_id: str,ctx: Context) -> dict:
    """Cancel one caller-owned build without publishing business effects."""
    return _call(lambda:router().python_build_cancel(_assertion(ctx),workspace_id,
        application_id,build_id))


@bounded_tool(server)
def execute_v2_python_program_run(workspace_id: str,application_id: str,
                                  program: dict,idempotency_key: str,
                                  ctx: Context) -> dict:
    """Advance a sealed plan through fixed previews/jobs; accepts no code or SQL."""
    return _call(lambda:router().python_run(_assertion(ctx),workspace_id,
        application_id,program,idempotency_key=idempotency_key))


@bounded_tool(server)
def read_v2_python_program_workflow(workspace_id: str,application_id: str,
                                    workflow_id: str,ctx: Context) -> dict:
    """Read durable child jobs and committed unit receipts."""
    return _call(lambda:router().python_workflow_read(_assertion(ctx),workspace_id,
        application_id,workflow_id))


@bounded_tool(server)
def cancel_v2_python_program_workflow(workspace_id: str,application_id: str,
                                      workflow_id: str,ctx: Context) -> dict:
    """Cancel pending work without hiding already committed atomic units."""
    return _call(lambda:router().python_workflow_cancel(_assertion(ctx),workspace_id,
        application_id,workflow_id))


@bounded_tool(server)
def execute_v2_execution_delegation(workspace_id: str,application_id: str,
                                    program: dict,idempotency_key: str,
                                    ctx: Context) -> dict:
    """Create or revoke one scoped execution delegation through fixed core."""
    return _call(lambda:router().execution_delegation(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


@bounded_tool(server)
def execute_v2_cube_write_policy(
        workspace_id: str,application_id: str,program: dict,ctx: Context,
        idempotency_key: str|None=None) -> dict:
    """Manage domain-neutral cube write policies in one selected application."""
    return _call(lambda:router().planning_workflow_policy(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


# Private compatibility adapter; replaced by cube.write.policy.*.
def execute_v2_planning_workflow_policy(
        workspace_id: str,application_id: str,program: dict,ctx: Context,
        idempotency_key: str|None=None) -> dict:
    """Interpret retained planning policy programs privately."""
    return _call(lambda:router().planning_workflow_policy(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def execute_v2_statement_definition(
        workspace_id: str,application_id: str,program: dict,ctx: Context,
        idempotency_key: str|None=None) -> dict:
    """Manage one active immutable structural statement definition."""
    return _call(lambda:router().statement_definition(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


# Private compatibility adapter; replaced by generic application rules.
def execute_v2_planning_operation_policy(
        workspace_id: str, application_id: str, program: dict, ctx: Context,
        idempotency_key: str | None = None) -> dict:
    """Interpret retained planning-operation policy versions privately."""
    return _call(lambda: router().planning_operation_policy(
        _assertion(ctx), workspace_id, application_id, program,
        idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def execute_v2_inventory_unrealized_schedule(
        workspace_id: str,application_id: str,program: dict,ctx: Context,
        idempotency_key: str|None=None) -> dict:
    """Manage one application's versioned optional inventory-profit schedule."""
    return _call(lambda:router().inventory_unrealized_schedule(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


@bounded_tool(server)
def execute_v2_application_decision(workspace_id: str,application_id: str,
                                    program: dict,idempotency_key: str,
                                    ctx: Context) -> dict:
    """Create, revise or withdraw shared application-admin decision context."""
    return _call(lambda:router().application_decision(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


@bounded_tool(server)
def execute_v2_expression_rule_program(workspace_id: str,
                                       application_id: str,program: dict,
                                       idempotency_key: str,ctx: Context) -> dict:
    """Save, publish, run or cancel a scoped immutable generic rule workflow."""
    return _call(lambda:router().expression_rule(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


@bounded_tool(server)
def execute_v2_application_schedule(
        workspace_id: str,application_id: str,program: dict,ctx: Context,
        idempotency_key: str|None=None) -> dict:
    """Manage immutable generic rule schedules; worker controls stay private."""
    return _call(lambda:router().application_schedule(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


@bounded_tool(server)
def execute_v2_application_assignment(
        workspace_id: str,application_id: str,program: dict,ctx: Context,
        idempotency_key: str|None=None) -> dict:
    """Manage one current domain-neutral assignment set; no access is granted."""
    return _call(lambda:router().application_assignment(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


@bounded_tool(server)
def execute_v2_application_workflow(
        workspace_id: str,application_id: str,program: dict,ctx: Context,
        idempotency_key: str|None=None) -> dict:
    """Manage immutable generic workflows; occurrence controls stay separate."""
    return _call(lambda:router().application_workflow(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


@bounded_tool(server)
def execute_v2_application_workflow_occurrence(
        workspace_id: str,application_id: str,program: dict,ctx: Context,
        idempotency_key: str|None=None) -> dict:
    """Operate a generic workflow occurrence; internal validators stay private."""
    return _call(lambda:router().application_workflow_occurrence(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


@bounded_tool(server)
def cancel_v2_expression_sequence(workspace_id: str,
                                  application_id: str,
                                  program: dict, ctx: Context) -> dict:
    """Cancel a caller-owned expression-rule sequence in one application."""
    return _call(lambda:router().cancel_expression_sequence(
        _assertion(ctx), workspace_id, application_id, program))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def cancel_v2_full_sequence(workspace_id: str, application_id: str,
                            program: dict, ctx: Context) -> dict:
    """Cancel a caller-owned multilevel Full sequence in one application."""
    return _call(lambda:router().cancel_full_sequence(
        _assertion(ctx), workspace_id, application_id, program))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def execute_v2_ownership_program(workspace_id: str,application_id: str,
                                 program: dict,idempotency_key: str,
                                 ctx: Context) -> dict:
    """Set or clear an explicit scoped ownership input."""
    return _call(lambda:router().ownership(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def execute_v2_journal_program(workspace_id: str,application_id: str,
                               program: dict,idempotency_key: str,
                               ctx: Context) -> dict:
    """Post/reverse a manual journal or exactly reverse an acquisition journal."""
    return _call(lambda:router().journal(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def execute_v2_ic_elimination_program(workspace_id: str,application_id: str,
                                      program: dict,idempotency_key: str,
                                      ctx: Context) -> dict:
    """Publish or withdraw one parent-scoped unreviewed IC offset."""
    return _call(lambda:router().ic_elimination(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


@bounded_tool(server)
def execute_v2_calendar_program(workspace_id: str,application_id: str,
                                program: dict,idempotency_key: str,
                                ctx: Context) -> dict:
    """Set an explicit scoped fiscal period through fixed validation."""
    return _call(lambda:router().calendar(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


@bounded_tool(server)
def set_v2_application_access(workspace_id: str,application_id: str,
                              program: dict,idempotency_key: str,
                              ctx: Context) -> dict:
    """Run a catalogued scoped security write with separate credentials."""
    return _call(lambda:router().application_access(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


@bounded_tool(server)
def set_v2_rule_access(workspace_id: str,application_id: str,
                       program: dict,idempotency_key: str,
                       ctx: Context) -> dict:
    """Set or revoke one subject's scoped rule permissions."""
    return _call(lambda:router().rule_access(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def create_v2_policy_draft(workspace_id: str,application_id: str,
                           program: dict,idempotency_key: str,
                           ctx: Context) -> dict:
    """Record an immutable, application-scoped consolidation policy draft."""
    return _call(lambda:router().policy_draft(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def execute_v2_period_nci_basis_program(workspace_id: str,application_id: str,program: dict,idempotency_key: str,ctx: Context) -> dict:
    """Declare or revoke a policy-bound financial source basis; does not post NCI."""
    return _call(lambda:router().period_nci_basis(_assertion(ctx),workspace_id,application_id,program,idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def execute_v2_period_nci_policy_program(workspace_id: str,application_id: str,program: dict,idempotency_key: str,ctx: Context) -> dict:
    """Review, approve, activate or withdraw period policy evidence; no operational NCI posting."""
    return _call(lambda:router().period_policy_governance(
        _assertion(ctx),workspace_id,application_id,program,idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def record_v2_policy_period_nci_cases(workspace_id: str,application_id: str,program: dict,
                                      idempotency_key: str,ctx: Context) -> dict:
    """Record domain-separated period-NCI technical evidence; never acquisition approval or posting."""
    return _call(lambda:router().period_policy_case_record(
        _assertion(ctx),workspace_id,application_id,program,idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def record_v2_policy_acquisition_cases(workspace_id: str,
                                       application_id: str, program: dict,
                                       idempotency_key: str,
                                       ctx: Context) -> dict:
    """Store matched technical cases for one scoped application."""
    return _call(lambda:router().policy_case_record(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def review_v2_policy_acquisition_cases(workspace_id: str,
                                       application_id: str, program: dict,
                                       idempotency_key: str,
                                       ctx: Context) -> dict:
    """Record a distinct-identity review for one scoped case bundle."""
    return _call(lambda:router().policy_case_review(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def execute_v2_policy_activation(workspace_id: str,application_id: str,
                                  program: dict,idempotency_key: str,
                                  ctx: Context) -> dict:
    """Activate/withdraw one scoped approved policy variant through fixed code."""
    return _call(lambda:router().policy_activation(_assertion(ctx),workspace_id,
        application_id,program,idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def approve_v2_policy_acquisition_cases(workspace_id: str,application_id: str,
                                        program: dict,idempotency_key: str,
                                        ctx: Context) -> dict:
    """Approve exact reviewed evidence under a distinct workspace administrator."""
    return _call(lambda:router().policy_approval(_assertion(ctx),workspace_id,
        application_id,program,idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def capture_v2_policy_source_artifact(workspace_id: str,
                                      application_id: str, program: dict,
                                      idempotency_key: str,
                                      ctx: Context) -> dict:
    """Capture immutable source bytes for one scoped application."""
    return _call(lambda:router().policy_source_artifact(
        _assertion(ctx),workspace_id,application_id,program,
        idempotency_key=idempotency_key))


@bounded_tool(server)
def apply_v2_cube_write_scope_transition(
        workspace_id: str,application_id: str,
        program: dict,preview_token: str,idempotency_key: str,
        ctx: Context) -> dict:
    """Apply one reviewed domain-neutral cube write-scope transition."""
    return _call(lambda:router().planning_transition(
        _assertion(ctx),workspace_id,application_id,program,
        preview_token=preview_token,idempotency_key=idempotency_key))


@bounded_tool(server)
def read_v2_job(workspace_id: str,application_id: str,job_id: str,
                ctx: Context) -> dict:
    """Read your durable job status in the selected application."""
    return _call(lambda:router().job(
        _assertion(ctx),workspace_id,application_id,job_id))


@bounded_tool(server)
def read_v2_events(workspace_id: str,application_id: str,ctx: Context,
                   after_sequence: int=0,limit: int=100) -> dict:
    """Page your durable job events in the selected application."""
    return _call(lambda:router().events(
        _assertion(ctx),workspace_id,application_id,
        after_sequence=after_sequence,limit=limit))


@bounded_tool(server)
def cancel_v2_job(workspace_id: str,application_id: str,job_id: str,
                  ctx: Context) -> dict:
    """Request cancellation of your queued job in one application."""
    return _call(lambda:router().cancel(
        _assertion(ctx),workspace_id,application_id,job_id))


@bounded_tool(server)
def list_v2_tasks(workspace_id: str,application_id: str,ctx: Context,
                  after_sequence: int=0,limit: int=100) -> dict:
    """Page authorized durable tasks in one selected application."""
    return _call(lambda:router().tasks(
        _assertion(ctx),workspace_id,application_id,
        after_sequence=after_sequence,limit=limit))


@bounded_tool(server)
def read_v2_task(workspace_id: str,application_id: str,task_id: str,
                 ctx: Context,after_event: int=0,
                 event_limit: int=100) -> dict:
    """Read one authorized task and its bounded immutable event page."""
    return _call(lambda:router().task(
        _assertion(ctx),workspace_id,application_id,task_id,
        after_event=after_event,event_limit=event_limit))


@bounded_tool(server)
def read_v2_task_logs(workspace_id: str,application_id: str,task_id: str,
                      ctx: Context,after_event: int=0,event_limit: int=100,
                      after_character: int=0,
                      character_limit: int=16_384) -> dict:
    """Page authorized lifecycle diagnostics and native bounded task output."""
    return _call(lambda:router().task_logs(
        _assertion(ctx),workspace_id,application_id,task_id,
        after_event=after_event,event_limit=event_limit,
        after_character=after_character,character_limit=character_limit))
