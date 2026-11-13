"""One reviewed mapping from public functions to their MCP entrypoints.

These are applicable tool names, not permission grants or an automatic retry
plan. Tool input schemas define the envelope; a preview and submit pair keeps
its existing explicit lifecycle. The mapping is shared by authenticated
catalog discovery and generated public documentation.
"""
from __future__ import annotations

def application_tools(name, specification):
    """Document the public dispatcher paths selected by the fixed MCP adapters."""
    from epm_core.postgres_import_execution import PUBLIC_FUNCTIONS as import_functions
    from epm_core.postgres_transfer_orchestration import PUBLIC_FUNCTIONS as transfer_functions

    read = specification["mode"] in {"read", "read_only"}
    if name in import_functions or name in transfer_functions or name.startswith("facts.source."):
        return ("execute_v2_source_program",)
    if name.startswith("cube.write.policy."):
        return ("execute_v2_cube_write_policy",)
    if name.startswith("schedule."):
        return ("execute_v2_application_schedule",)
    if name.startswith("application.decision."):
        return ("read_v2_program",) if read else ("execute_v2_application_decision",)
    if name.startswith(("application.assignment.", "application.workflow.")):
        if name.startswith("application.assignment."):
            tool = "execute_v2_application_assignment"
        elif name.startswith(("application.workflow.occurrence.", "application.workflow.activity.")) \
                or name == "application.workflow.worklist":
            tool = "execute_v2_application_workflow_occurrence"
        else:
            tool = "execute_v2_application_workflow"
        return (tool, "read_v2_program") if read else (tool,)
    if read or name.startswith(("cube.aggregate.", "facts.cube.aggregate.",
                                "facts.cube.resolved.",
                                "metadata.layout.populated.")) or name == "cube.selection.seal":
        return ("read_v2_program",)
    if name == "metadata.calendar.period.set":
        return ("execute_v2_calendar_program",)
    if (name.startswith("metadata.") or name.startswith("grid.definition.")
            or name.startswith("source.evidence.")):
        return ("execute_v2_metadata_program",)
    if name.startswith("security.application."):
        return ("set_v2_application_access",)
    if name.startswith("security.rule."):
        return ("set_v2_rule_access",)
    if name.startswith("execution.delegation."):
        return ("execute_v2_execution_delegation",)
    if name in {"python.program.build", "python.program.test"}:
        return ("execute_v2_python_program_build",)
    if name == "python.program.run":
        return ("execute_v2_python_program_run",)
    if name.startswith("python."):
        return ("execute_v2_python_program_registry",)
    if name == "rules.expression.sequence.cancel":
        return ("cancel_v2_expression_sequence",)
    if name.startswith("cube.write.scope.") and specification["previewRequired"]:
        return ("preview_v2_program", "apply_v2_cube_write_scope_transition")
    if specification["previewRequired"]:
        return ("preview_v2_program", "issue_v2_operation_admission",
                "submit_v2_program")
    if name.startswith(("application.rule.", "rules.", "calculated.member.")):
        return ("execute_v2_expression_rule_program",)
    if name == "calculation.recalculate.request":
        return ("execute_v2_expression_rule_program",)
    raise ValueError(f"No reviewed public tool dispatch for {name}")


def public_dispatch(application, workspace, reset, platform):
    from epm_core.postgres_identity_directory import READ_FUNCTIONS

    result = {name: application_tools(name, spec) for name, spec in application.items()}
    for name in workspace:
        if name.startswith("workspace.application.purge."):
            tool = "execute_v2_application_purge"
        elif name == "workspace.application.create":
            tool = "execute_v2_workspace_program"
        elif name == "security.workspace.group-access.list":
            tool = "read_v2_workspace_access"
        elif name.startswith("security.workspace."):
            tool = "set_v2_workspace_access"
        elif name == "workspace.reset.prepare":
            tool = "prepare_v2_workspace_reset"
        elif name.startswith("workspace.reset."):
            tool = "transition_v2_workspace_reset"
        else:
            raise ValueError(f"No reviewed workspace tool dispatch for {name}")
        result[name] = (tool,)
    result.update({name: ("apply_v2_workspace_reset",) for name in reset})
    result.update({name: ("read_v2_platform_program" if name in READ_FUNCTIONS
                          else "execute_v2_platform_program",) for name in platform})
    return result



def with_mcp_tools(functions: dict, *, scope: str) -> dict:
    """Project routing onto an already-authorized catalog without mutating it."""
    if scope == 'application':
        dispatch = public_dispatch(functions, {}, {}, {})
    elif scope == 'workspace':
        reset = {name: value for name, value in functions.items()
                 if name == 'workspace.reset.apply'}
        workspace = {name: value for name, value in functions.items()
                     if name != 'workspace.reset.apply'}
        dispatch = public_dispatch({}, workspace, reset, {})
    elif scope == 'platform':
        dispatch = public_dispatch({}, {}, {}, functions)
    else:
        raise ValueError('MCP_FUNCTION_ROUTE_SCOPE_INVALID')
    return {name: {**specification, 'mcpTools': list(dispatch[name])}
            for name, specification in functions.items()}
