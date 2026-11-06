"""Transport-neutral discovery of the server's MCP execution policy."""
TOOL_SECONDS = 30
TERMINATION_SECONDS = 1
PROCESSES_PER_LISTENER = 8
CONTROL_PROCESSES_PER_LISTENER = 2
# The rendered web surface fans a single browser action into several fixed-core
# reads.  Each isolated web child imports the complete application language, so
# allowing the generic eight-process MCP pool here needlessly multiplies memory
# on a one-server deployment and can make macOS/Colima kill a child mid-request.
# Keep enough parallelism for one interactive browser while retaining the
# larger listener pool for MCP clients and workers.
WEB_PROCESSES_PER_LISTENER = 2
AUTHENTICATION_SECONDS = 8
STARTUP_SECONDS = 30
HTTP_POST_SECONDS = 45
TIMEOUT_RESPONSE_SECONDS = 1
MAX_REQUEST_BYTES = 12_000_000
MAX_RESPONSE_BYTES = 64_000_000
DEADLINE_CODE = 'MCP_TOOL_DEADLINE_OUTCOME_UNKNOWN'
CAPACITY_CODE = 'MCP_TOOL_CAPACITY_NOT_DISPATCHED'
FAILURE_CODE = 'MCP_TOOL_PROCESS_FAILED_OUTCOME_UNKNOWN'


def tool_execution_policy():
    return {'executionSeconds': TOOL_SECONDS,
        'terminationGraceSeconds': TERMINATION_SECONDS,
        'processesPerListener': PROCESSES_PER_LISTENER,
        'scope': 'MCP tool execution and process-slot waiting; excludes HTTP authentication/startup',
        'deadlineCode': DEADLINE_CODE, 'capacityCode': CAPACITY_CODE,
        'timeoutImpliesRollback': False, 'automaticRetry': False,
        'databaseSessionLimits': 'remaining budget at connection creation; shorter settings preserved',
        'databaseDisconnectCheckMilliseconds': 100,
        'clientDisconnectImpliesRollback': False,
        'retry': 'inspect durable status; reuse the original request key and exact program'}


def http_admission_policy():
    return {'authenticationSeconds': AUTHENTICATION_SECONDS,
        'startupSeconds': STARTUP_SECONDS,
        'controlProcessesPerListener': CONTROL_PROCESSES_PER_LISTENER,
        'reservedFromBusinessTools': True,
        'terminationGraceSeconds': TERMINATION_SECONDS,
        'unavailableStatus': 503, 'invalidIdentityStatus': 401,
        'unavailableCode': 'HTTP_AUTHENTICATION_UNAVAILABLE_RETRY',
        'postSeconds': HTTP_POST_SECONDS,
        'timeoutResponseSeconds': TIMEOUT_RESPONSE_SECONDS,
        'postDeadlineCode': 'HTTP_REQUEST_DEADLINE_OUTCOME_UNKNOWN',
        'scope': 'HTTP identity verification, cooperative POST envelope/delivery and pre-listen role checks'}
