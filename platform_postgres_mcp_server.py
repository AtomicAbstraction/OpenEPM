"""Application-bound PostgreSQL V2 MCP listener (separate from the V1 service).

Run only behind the authenticated HTTP gate in platform_postgres_mcp_http.py.
The tools accept application-language programs and opaque IDs, never SQL.
"""
from __future__ import annotations

import logging
import os
from mcp.server import MCPServer
from epm_core.postgres_mcp_execution import bounded_tool
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError

import psycopg
from epm_core.postgres_processing_limits import BUSY_CODE

from epm_core.postgres_auth import AuthError, access_token
from epm_core.persistence_contract import ApplicationScope
from epm_core.postgres_mcp_application import PostgresMCPApplication
from epm_core.postgres_python_environment_startup import load_python_environment_profiles


LOG = logging.getLogger(__name__)
server = MCPServer('Open EPM PostgreSQL V2',instructions=(
    'This listener is bound to one application. Discover the versioned '
    'function catalog, then submit only structured application-language '
    'programs. Preview write programs and submit their signed preview; '
    'read jobs and durable events for results. Use metadata.* for bounded '
    'cube setup and facts.source.* for staged numeric loads. Business changes are executed by the '
    'fixed server; no SQL or Python execution tool is available.'))


def application() -> PostgresMCPApplication:
    workspace = os.environ.get('EPM_PG_WORKSPACE_ID','')
    app = os.environ.get('EPM_PG_APPLICATION_ID','')
    dsn = os.environ.get('EPM_PG_RUNTIME_DSN','')
    secret_hex = os.environ.get('EPM_PG_PREVIEW_SECRET_HEX','')
    try:
        secret = bytes.fromhex(secret_hex)
    except ValueError as error:
        raise RuntimeError('Invalid PostgreSQL MCP preview secret') from error
    return PostgresMCPApplication(
        dsn,ApplicationScope(workspace,app),preview_secret=secret,
        security_dsn=os.environ.get('EPM_PG_SECURITY_DSN'),
        approved_python_profiles=load_python_environment_profiles(os.environ))


def _startup_role_check():
    application().assert_runtime_role()


def _assertion(ctx: Context) -> str:
    try:
        headers = ctx.headers or {}
    except (AttributeError,ValueError):
        headers = {}
    return access_token(headers)


def _call(operation):
    try:
        return operation()
    except (AuthError,ValueError) as error:
        raise ToolError(str(error)) from error
    except psycopg.errors.LockNotAvailable as error:
        raise ToolError(BUSY_CODE + '; no new job is implied; retry the same request key') from error
    except psycopg.Error as error:
        LOG.exception('PostgreSQL MCP operation failed')
        raise ToolError('POSTGRES_OPERATION_FAILED; inspect the durable job '
                        'or batch status before retrying') from error


@bounded_tool(server)
def read_v2_session_identity(ctx: Context) -> dict:
    """Read only the authenticated caller's verified enrollment binding."""
    return _call(lambda:application().session_identity(_assertion(ctx)))


@bounded_tool(server)
def list_v2_functions(ctx: Context) -> dict:
    """Discover the granted functions on this exact application listener."""
    return _call(lambda:application().catalog(_assertion(ctx)))


@bounded_tool(server)
def read_v2_program(program: dict,ctx: Context) -> dict:
    """Run a catalogued bounded read program."""
    return _call(lambda:application().read(_assertion(ctx),program))


@bounded_tool(server)
def preview_v2_program(program: dict,ctx: Context) -> dict:
    """Validate a catalogued durable program and sign a revision-pinned preview."""
    return _call(lambda:application().preview(_assertion(ctx),program))


@bounded_tool(server)
def submit_v2_program(program: dict,preview_token: str,
                      idempotency_key: str,ctx: Context,
                      depends_on_job_ids: list[str] | None=None) -> dict:
    """Apply a previewed atomic program or admit its catalogued durable job."""
    return _call(lambda:application().submit(
        _assertion(ctx),program,preview_token=preview_token,
        idempotency_key=idempotency_key,
        depends_on_job_ids=tuple(depends_on_job_ids or ())))


@bounded_tool(server)
def execute_v2_source_program(program: dict,ctx: Context) -> dict:
    """Run one catalogued staged-source begin/append/seal/preview/publish step."""
    return _call(lambda:application().source(_assertion(ctx),program))


@bounded_tool(server)
def execute_v2_metadata_program(program: dict,idempotency_key: str,
                                ctx: Context) -> dict:
    """Apply typed metadata or unreviewed currency-settings programs."""
    return _call(lambda:application().metadata(
        _assertion(ctx),program,idempotency_key=idempotency_key))


@bounded_tool(server)
def execute_v2_expression_rule_program(program: dict,idempotency_key: str,
                                       ctx: Context) -> dict:
    """Save, publish, run or cancel an immutable generic rule workflow."""
    return _call(lambda:application().expression_rule(
        _assertion(ctx),program,idempotency_key=idempotency_key))


@bounded_tool(server)
def execute_v2_python_program_registry(program: dict,idempotency_key: str,
                                       ctx: Context) -> dict:
    """Save, publish or deactivate Python builder source; never executes it."""
    return _call(lambda:application().python_program(
        _assertion(ctx),program,idempotency_key=idempotency_key))


@bounded_tool(server)
def execute_v2_python_program_build(program: dict,idempotency_key: str,
                                    ctx: Context) -> dict:
    """Admit an isolated durable build; accepts no Python source or SQL."""
    return _call(lambda:application().python_build(
        _assertion(ctx),program,idempotency_key=idempotency_key))


@bounded_tool(server)
def read_v2_python_program_build(build_id: str,ctx: Context) -> dict:
    """Read one caller-owned technical build and sealed-plan digest."""
    return _call(lambda:application().python_build_read(_assertion(ctx),build_id))


@bounded_tool(server)
def read_v2_python_program_build_artifact(build_id: str, section: str,
                                          ctx: Context,
                                          cursor: str | None = None) -> dict:
    """Read one bounded page from a caller-owned sealed build artifact."""
    return _call(lambda: application().python_build_artifact_read(
        _assertion(ctx), build_id=build_id, section=section, cursor=cursor))


@bounded_tool(server)
def cancel_v2_python_program_build(build_id: str,ctx: Context) -> dict:
    """Cancel one caller-owned build without publishing business effects."""
    return _call(lambda:application().python_build_cancel(_assertion(ctx),build_id))


@bounded_tool(server)
def execute_v2_python_program_run(program: dict,idempotency_key: str,
                                  ctx: Context) -> dict:
    """Advance a sealed plan through fixed previews/jobs; accepts no code or SQL."""
    return _call(lambda:application().python_run(
        _assertion(ctx),program,idempotency_key=idempotency_key))


@bounded_tool(server)
def read_v2_python_program_workflow(workflow_id: str,ctx: Context) -> dict:
    """Read durable child jobs and committed unit receipts."""
    return _call(lambda:application().python_workflow_read(
        _assertion(ctx),workflow_id))


@bounded_tool(server)
def cancel_v2_python_program_workflow(workflow_id: str,ctx: Context) -> dict:
    """Cancel pending work without hiding already committed atomic units."""
    return _call(lambda:application().python_workflow_cancel(
        _assertion(ctx),workflow_id))


@bounded_tool(server)
def execute_v2_execution_delegation(program: dict,idempotency_key: str,
                                    ctx: Context) -> dict:
    """Create or revoke scoped authority for unattended fixed-core work."""
    return _call(lambda:application().execution_delegation(
        _assertion(ctx),program,idempotency_key=idempotency_key))


@bounded_tool(server)
def execute_v2_cube_write_policy(
        program: dict,ctx: Context,
        idempotency_key: str|None=None) -> dict:
    """Manage immutable domain-neutral cube write-policy versions."""
    return _call(lambda:application().planning_workflow_policy(
        _assertion(ctx),program,idempotency_key=idempotency_key))


# Private compatibility adapter; replaced by cube.write.policy.*.
def execute_v2_planning_workflow_policy(
        program: dict,ctx: Context,
        idempotency_key: str|None=None) -> dict:
    """Interpret retained planning policy programs privately."""
    return _call(lambda:application().planning_workflow_policy(
        _assertion(ctx),program,idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def execute_v2_statement_definition(
        program: dict,ctx: Context,
        idempotency_key: str|None=None) -> dict:
    """Manage one active immutable structural statement definition."""
    return _call(lambda:application().statement_definition(
        _assertion(ctx),program,idempotency_key=idempotency_key))


# Private compatibility adapter; replaced by generic application rules.
def execute_v2_planning_operation_policy(
        program: dict, ctx: Context,
        idempotency_key: str | None = None) -> dict:
    """Interpret retained planning-operation policy versions privately."""
    return _call(lambda: application().planning_operation_policy(
        _assertion(ctx), program, idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def execute_v2_inventory_unrealized_schedule(
        program: dict,ctx: Context,
        idempotency_key: str|None=None) -> dict:
    """Manage a versioned optional inventory-profit expression schedule."""
    return _call(lambda:application().inventory_unrealized_schedule(
        _assertion(ctx),program,idempotency_key=idempotency_key))


@bounded_tool(server)
def cancel_v2_expression_sequence(program: dict, ctx: Context) -> dict:
    """Cancel a caller-owned durable expression-rule sequence."""
    return _call(lambda:application().cancel_expression_sequence(
        _assertion(ctx), program))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def cancel_v2_full_sequence(program: dict, ctx: Context) -> dict:
    """Cancel a caller-owned durable multilevel Full sequence."""
    return _call(lambda:application().cancel_full_sequence(
        _assertion(ctx), program))


@bounded_tool(server)
def execute_v2_generic_fact_program(program: dict,idempotency_key: str,
                                    ctx: Context) -> dict:
    """Create a generic table or set/delete one opaque JSON fact through V2."""
    return _call(lambda:application().generic(
        _assertion(ctx),program,idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def execute_v2_ownership_program(program: dict,idempotency_key: str,
                                 ctx: Context) -> dict:
    """Set or clear an explicit period-sensitive ownership input."""
    return _call(lambda:application().ownership(
        _assertion(ctx),program,idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def execute_v2_journal_program(program: dict,idempotency_key: str,
                               ctx: Context) -> dict:
    """Post/reverse a manual journal or exactly reverse an acquisition journal."""
    return _call(lambda:application().journal(
        _assertion(ctx),program,idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def execute_v2_ic_elimination_program(program: dict,idempotency_key: str,
                                      ctx: Context) -> dict:
    """Publish or withdraw a bounded unreviewed IC balance offset."""
    return _call(lambda:application().ic_elimination(
        _assertion(ctx),program,idempotency_key=idempotency_key))


@bounded_tool(server)
def execute_v2_calendar_program(program: dict,idempotency_key: str,
                                ctx: Context) -> dict:
    """Set an explicit Year/Period date range and ordinal."""
    return _call(lambda:application().calendar(
        _assertion(ctx),program,idempotency_key=idempotency_key))


@bounded_tool(server)
def set_v2_application_access(program: dict,idempotency_key: str,
                              ctx: Context) -> dict:
    """Run a catalogued application-security write through its fixed writer."""
    return _call(lambda:application().application_access(
        _assertion(ctx),program,idempotency_key=idempotency_key))


@bounded_tool(server)
def set_v2_rule_access(program: dict,idempotency_key: str,
                       ctx: Context) -> dict:
    """Set or revoke one subject's rule design, publish and run grants."""
    return _call(lambda:application().rule_access(
        _assertion(ctx),program,idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def create_v2_policy_draft(program: dict,idempotency_key: str,
                           ctx: Context) -> dict:
    """Record an immutable effective-dated draft; does not execute accounting."""
    return _call(lambda:application().policy_draft(
        _assertion(ctx),program,idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def execute_v2_period_nci_basis_program(program: dict,idempotency_key: str,ctx: Context) -> dict:
    """Declare or revoke a policy-bound financial source basis; does not post NCI."""
    return _call(lambda:application().period_nci_basis(_assertion(ctx),program,idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def execute_v2_period_nci_policy_program(program: dict,idempotency_key: str,ctx: Context) -> dict:
    """Review, approve, activate or withdraw period policy evidence; no operational NCI posting."""
    return _call(lambda:application().period_policy_governance(
        _assertion(ctx),program,idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def record_v2_policy_period_nci_cases(program: dict,idempotency_key: str,ctx: Context) -> dict:
    """Record period-NCI technical cases separately from acquisition authority; never approves posting."""
    return _call(lambda:application().period_policy_case_record(
        _assertion(ctx),program,idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def record_v2_policy_acquisition_cases(program: dict,
                                       idempotency_key: str,
                                       ctx: Context) -> dict:
    """Store matched technical acquisition cases, without accounting approval."""
    return _call(lambda:application().policy_case_record(
        _assertion(ctx),program,idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def review_v2_policy_acquisition_cases(program: dict,
                                       idempotency_key: str,
                                       ctx: Context) -> dict:
    """Record a distinct-identity review, never accounting activation."""
    return _call(lambda:application().policy_case_review(
        _assertion(ctx),program,idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def execute_v2_policy_activation(program: dict,idempotency_key: str,
                                  ctx: Context) -> dict:
    """Activate or withdraw an exact approved variant under workspace authority."""
    return _call(lambda:application().policy_activation(
        _assertion(ctx),program,idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def approve_v2_policy_acquisition_cases(program: dict,idempotency_key: str,
                                        ctx: Context) -> dict:
    """Record workspace-governed approval, with activation still separate."""
    return _call(lambda:application().policy_approval(
        _assertion(ctx),program,idempotency_key=idempotency_key))


# Private compatibility adapter; deliberately absent from fresh MCP discovery.
def capture_v2_policy_source_artifact(program: dict,
                                      idempotency_key: str,
                                      ctx: Context) -> dict:
    """Store version-labelled source bytes with a verified content digest."""
    return _call(lambda:application().policy_source_artifact(
        _assertion(ctx),program,idempotency_key=idempotency_key))


@bounded_tool(server)
def apply_v2_cube_write_scope_transition(program: dict,preview_token: str,
                                         ctx: Context) -> dict:
    """Commit one reviewed domain-neutral cube write-scope transition."""
    return _call(lambda:application().apply_planning_lock(
        _assertion(ctx),program,preview_token=preview_token))


# Private compatibility adapters; replaced by cube.write.scope.*.
def apply_v2_planning_lock(program: dict,preview_token: str,
                           ctx: Context) -> dict:
    return _call(lambda:application().apply_planning_lock(
        _assertion(ctx),program,preview_token=preview_token))


def apply_v2_planning_transition(program: dict,preview_token: str,
                                 ctx: Context) -> dict:
    return _call(lambda:application().apply_planning_lock(
        _assertion(ctx),program,preview_token=preview_token))


@bounded_tool(server)
def read_v2_job(job_id: str,ctx: Context) -> dict:
    """Read your authoritative durable job status and receipt revision."""
    return _call(lambda:application().job(_assertion(ctx),job_id))


@bounded_tool(server)
def read_v2_events(ctx: Context,after_sequence: int=0,
                   limit: int=100) -> dict:
    """Page your durable application job transitions."""
    return _call(lambda:application().events(
        _assertion(ctx),after_sequence=after_sequence,limit=limit))


@bounded_tool(server)
def cancel_v2_job(job_id: str,ctx: Context) -> dict:
    """Request cancellation of one of your jobs before publication."""
    return _call(lambda:application().cancel(_assertion(ctx),job_id))


@bounded_tool(server)
def list_v2_tasks(ctx: Context,after_sequence: int=0,
                  limit: int=100) -> dict:
    """Page your durable tasks, or application tasks as an administrator."""
    return _call(lambda:application().tasks(
        _assertion(ctx),after_sequence=after_sequence,limit=limit))


@bounded_tool(server)
def read_v2_task(task_id: str,ctx: Context,after_event: int=0,
                 event_limit: int=100) -> dict:
    """Read one authorized task and its bounded immutable event page."""
    return _call(lambda:application().task(
        _assertion(ctx),task_id,after_event=after_event,event_limit=event_limit))


@bounded_tool(server)
def read_v2_task_logs(task_id: str,ctx: Context,after_event: int=0,
                      event_limit: int=100,after_character: int=0,
                      character_limit: int=16_384) -> dict:
    """Page authorized lifecycle diagnostics and native bounded task output."""
    return _call(lambda:application().task_logs(
        _assertion(ctx),task_id,after_event=after_event,event_limit=event_limit,
        after_character=after_character,character_limit=character_limit))


@bounded_tool(server)
def interrupt_v2_task(task_id: str,ctx: Context) -> dict:
    """Cooperatively interrupt a task; committed effects are never undone."""
    return _call(lambda:application().interrupt_task(
        _assertion(ctx),task_id))


@bounded_tool(server)
def rerun_v2_task(task_id: str,idempotency_key: str,ctx: Context) -> dict:
    """Create distinct new work from a supported terminal task; never resume or undo."""
    return _call(lambda:application().rerun_task(
        _assertion(ctx),task_id,idempotency_key=idempotency_key))
