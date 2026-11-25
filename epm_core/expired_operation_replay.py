"""Closed native replay owners and their actually supported public transports.

These profiles select existing fixed lookup branches; they never grant access,
resolve a receipt generically or make a missing original into new work.
"""
from copy import deepcopy


_PROFILES = {}


def _declare(functions, owner, native_owner, browser_path, mcp_tool=None):
    for function in functions:
        if function in _PROFILES:
            raise ValueError('EXPIRED_REPLAY_PROFILE_DUPLICATE')
        _PROFILES[function] = {'owner': owner, 'nativeOwner': native_owner,
            'browserPath': browser_path, 'mcpTool': mcp_tool}


_declare(('facts.numeric.batch', 'facts.text.batch'), 'batch',
    'PostgresJobQueue.replay_batch', '/api/submit', 'submit_v2_program')
_declare(('facts.line-detail.replace',), 'detail',
    'PostgresJobQueue.replay_batch', '/api/submit', 'submit_v2_program')
_declare(('calculated.member.materialize',), 'calculated-member',
    'PostgresJobQueue.replay_calculated_member', '/api/submit', 'submit_v2_program')
_declare(('facts.planning.spread.equal', 'facts.planning.spread.calendar.equal'), 'spread',
    'PostgresLanguageV2.replay_spread', '/api/submit', 'submit_v2_program')
_declare(('facts.source.begin',), 'source-begin', 'PostgresSourceBatch.replay_begin', '/api/source-load')
_declare(('facts.source.csv.append',), 'source-csv-append', 'PostgresSourceBatch.append_csv', '/api/source-load')
_declare(('facts.source.seal',), 'source-seal', 'PostgresSourceBatch.seal', '/api/source-load')
_declare(('facts.source.manifest.attach',), 'source-manifest', 'PostgresSourceUploadManifest.create', '/api/source-load')
_declare(('facts.source.publish',), 'source-publish', 'PostgresSourceBatch.replay_publication', '/api/source-action')
_declare(('facts.transfer.import.request',), 'import', 'PostgresImportExecution.replay', '/api/source-load')
_declare(('facts.transfer.export.request',), 'export', 'PostgresTransferOrchestration.execute', '/api/export')
_declare(('facts.planning.scenario.copy.prepare',), 'scenario-copy', 'PostgresScenarioCopy.prepare', '/api/source-action')
_declare(('facts.slice.copy.prepare',), 'scenario-copy', 'PostgresScenarioCopy.prepare', '/api/source-action')
_declare(('python.program.build', 'python.program.test', 'python.program.validate'), 'python-build',
    'PostgresPythonProgramRepository.accept', '/api/python-build', 'execute_v2_python_program_build')
_declare(('python.program.run',), 'python-run',
    'PostgresPythonWorkflowStore.replay', '/api/python-run', 'execute_v2_python_program_run')
_declare(('calculation.recalculate.request',), 'calculation-recalculate',
    'PostgresCalculationInspection.recalculate', None, 'execute_v2_expression_rule_program')
_declare(('application.rule.run',), 'application-rule-run',
    'PostgresApplicationRuleRun.replay', '/api/rule-action', 'execute_v2_expression_rule_program')
_declare(('schedule.save', 'schedule.activate', 'schedule.deactivate'), 'schedule',
    'PostgresApplicationSchedules.execute', '/api/application-schedule', 'execute_v2_application_schedule')
_declare(('execution.delegation.create', 'execution.delegation.revoke'),
    'execution-delegation', 'PostgresExecutionDelegations.execute',
    '/api/execution-delegation', 'execute_v2_execution_delegation')
_declare(('python.schedule.save', 'python.schedule.activate', 'python.schedule.deactivate',
    'python.schedule.run', 'python.schedule.occurrence.cancel'),
    'python-schedule', 'PostgresPythonSchedules.execute',
    '/api/python-schedule', 'execute_v2_python_program_registry')
_declare(('application.assignment.save', 'application.assignment.activate',
    'application.assignment.deactivate'), 'assignment-definition',
    'PostgresApplicationAssignments.execute', '/api/application-assignment',
    'execute_v2_application_assignment')
_declare(('application.workflow.save', 'application.workflow.activate',
    'application.workflow.deactivate'), 'workflow-definition',
    'PostgresApplicationWorkflows.execute', '/api/application-workflow',
    'execute_v2_application_workflow')
_declare(('application.workflow.occurrence.start', 'application.workflow.activity.complete',
    'application.workflow.activity.return', 'application.workflow.occurrence.cancel'), 'workflow-occurrence',
    'PostgresApplicationWorkflowOccurrences.execute_program', '/api/application-workflow-occurrence',
    'execute_v2_application_workflow_occurrence')
_declare(('cube.write.scope.lock', 'cube.write.scope.submit', 'cube.write.scope.approve',
    'cube.write.scope.reopen'), 'cube-write-scope', 'PostgresPlanningLocks.replay',
    '/api/planning-action', 'apply_v2_cube_write_scope_transition')
_declare(('application.decision.create', 'application.decision.replace', 'application.decision.withdraw'),
    'application-decision', 'PostgresApplicationDecisions.replay',
    '/api/application-decision', 'execute_v2_application_decision')
_declare(('metadata.calendar.period.set',), 'calendar-period',
    'PostgresCalendarPeriods.replay', '/api/metadata-action', 'execute_v2_calendar_program')
_declare(('metadata.layout.populated.replace.request',), 'layout-replacement-request',
    'PostgresPopulatedLayoutReplacements.execute', '/api/metadata-action', 'execute_v2_metadata_program')
_declare(('metadata.layout.populated.activate.request',), 'layout-activation-request',
    'PostgresPopulatedLayoutActivation.execute', '/api/metadata-action', 'execute_v2_metadata_program')


def replay_owner_profile(function: str) -> dict | None:
    return deepcopy(_PROFILES.get(function))


def expired_admission_recovery(function: str, permission: str) -> dict:
    profile = replay_owner_profile(function)
    if profile is None:
        return {'supported': False,
            'recovery': 'Use the function-specific authorized status or receipt read. An expired admission does not permit a new effect.'}
    if profile['mcpTool'] is None:
        boundary = ('Browser source packet only at the named path; this does not introduce an expired '
                    'outer-admission contract for MCP source tools.')
    elif profile['browserPath'] is None:
        boundary = 'Use the named MCP tool with the exact original packet.'
    else:
        boundary = 'Use the same effect endpoint/tool and exact original packet. Receipt reads remain separately authorized.'
    return {'supported': True, 'strategy': 'lookup_original_accepted_intent_only',
        'nativeOwner': profile['nativeOwner'],
        'currentNativePermission': permission,
        'originalBinding': 'Exact signed operation identity, scope, actor and unchanged program; original dependencies and sent preview stay unchanged.',
        'missingOriginal': 'OPERATION_ADMISSION_EXPIRED; no new work, staging, build or publication',
        'renewAdmission': False,
        'transports': {'browserPath': profile['browserPath'], 'mcpTool': profile['mcpTool']},
        'transportBoundary': boundary}
