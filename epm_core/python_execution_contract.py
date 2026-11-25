"""Native public Python execution shapes and their discovery projection.

This pure owner contains no database, admission, authorization or executor.
Repositories retain currentness, authority and idempotency decisions. Schemas
describe these same request fields and wire records, never application policy.
"""
from copy import deepcopy
import json
import re

from .current_object_contract import is_state_token
from .postgres_numeric_catalog import obj, program_schema

BUILD = 'python.program.build'
TEST = 'python.program.test'
VALIDATE = 'python.program.validate'
RUN = 'python.program.run'
BUILD_PURPOSES = {BUILD: 'Plan', TEST: 'ImpactTest', VALIDATE: 'Validation'}
FUNCTIONS = frozenset((*BUILD_PURPOSES, RUN))
DIALECT = 'https://json-schema.org/draft/2020-12/schema'
ID_PATTERN = r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}'
AUTHORITY_ID_PATTERN = r'[A-Za-z0-9._-]{1,200}'
KEY_PATTERN = r'[A-Za-z0-9._-]{8,128}'
HEX32_PATTERN = r'[0-9a-f]{32}'
HEX64_PATTERN = r'[0-9a-f]{64}'
PINS = ('expectedMetadataRevision', 'expectedPolicyRevision', 'expectedSchemaEpoch')
COMMON_FIELDS = ('programId', 'programSourceToken', 'parameters', *PINS)
AUTHORITY_FIELDS = ('delegationId', 'delegationStateToken', 'scheduleId', 'scheduleStateToken')
MAX_DEFINITION_PARAMETER_BYTES = 1_048_576

# This describes the existing WorkflowRecord projection; it does not estimate
# physical effects or add a second durable count/uncertainty owner.
WORKFLOW_COUNT_GUIDANCE = (
    'committedUnits counts receipt-confirmed committed checkpoints. '
    'remainingUnits counts declared units without a confirmed checkpoint receipt; '
    'these may be unstarted, cancelled or unresolved, including a child whose '
    'effect already committed but is not yet proven in this workflow. '
    'These are not exact totals of physical effects or a rollback report. '
    'cancel_requested means cancellation reconciliation is still pending; '
    'parked recovery is identified by the current task latestEvent diagnostic.')


def _matches(value, pattern):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def canonical_json(value: object, code: str) -> bytes:
    """Existing native canonicalization, including rejection of JSON floats."""
    def reject(item):
        if isinstance(item, float):
            raise ValueError(code)
        if isinstance(item, dict):
            if any(type(key) is not str for key in item):
                raise ValueError(code)
            for child in item.values():
                reject(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                reject(child)
        elif item is not None and type(item) not in (str, int, bool):
            raise ValueError(code)
    reject(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError(code) from error


def parse_build_program(program):
    if (type(program) is not dict
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program.get('languageVersion')) is not int
            or program['languageVersion'] != 2
            or type(program.get('function')) is not str
            or program['function'] not in BUILD_PURPOSES
            or type(program.get('arguments')) is not dict):
        raise ValueError('PYTHON_BUILD_ARGUMENTS_INVALID')
    testing = program['function'] == TEST
    required = set(COMMON_FIELDS)
    if program['function'] == BUILD:
        required.update(AUTHORITY_FIELDS)
    allowed = (required, required | {'definitionParameters'}) if testing else (required,)
    if set(program['arguments']) not in allowed:
        raise ValueError('PYTHON_BUILD_ARGUMENTS_INVALID')
    return program['arguments']


def validate_build_inputs(*, build_id, program_id, program_source_token,
        parameter_values, idempotency_key, expected_metadata_revision,
        expected_policy_revision, expected_schema_epoch, delegation_id,
        delegation_state_token, schedule_id, schedule_state_token,
        rerun_of_build_id=None, purpose='Plan', definition_parameters=None):
    """Validate the repository admission shape without changing its digest."""
    definition_parameters = {} if definition_parameters is None else definition_parameters
    if (not _matches(build_id, HEX32_PATTERN) or not _matches(program_id, ID_PATTERN)
            or not is_state_token(program_source_token)
            or not _matches(idempotency_key, KEY_PATTERN)
            or type(parameter_values) is not dict
            or purpose not in ('Plan', 'Validation', 'ImpactTest')
            or type(definition_parameters) is not dict
            or (purpose != 'ImpactTest' and definition_parameters)
            or (purpose == 'Plan' and (not _matches(delegation_id, AUTHORITY_ID_PATTERN)
                or not is_state_token(delegation_state_token)))
            or (purpose != 'Plan' and any(value is not None for value in
                (delegation_id, delegation_state_token, schedule_id, schedule_state_token)))
            or ((schedule_id is None) != (schedule_state_token is None))
            or (schedule_id is not None and not _matches(schedule_id, AUTHORITY_ID_PATTERN))
            or (schedule_state_token is not None and not is_state_token(schedule_state_token))
            or (rerun_of_build_id is not None and not _matches(rerun_of_build_id, HEX32_PATTERN))):
        raise ValueError('PYTHON_BUILD_ARGUMENTS_INVALID')
    pins = (expected_metadata_revision, expected_policy_revision, expected_schema_epoch)
    if any(type(value) is not int or value < 0 for value in pins):
        raise ValueError('PYTHON_BUILD_PINS_INVALID')
    parameters = json.loads(canonical_json(parameter_values, 'PYTHON_BUILD_PARAMETERS_INVALID'))
    definition_bytes = canonical_json(definition_parameters, 'PYTHON_DEFINITION_PARAMETERS_INVALID')
    if len(definition_bytes) > MAX_DEFINITION_PARAMETER_BYTES:
        raise ValueError('PYTHON_DEFINITION_PARAMETERS_INVALID')
    return parameters, json.loads(definition_bytes)


def parse_run_program(program, idempotency_key):
    if (type(program) is not dict
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program.get('languageVersion')) is not int
            or program['languageVersion'] != 2 or program.get('function') != RUN
            or type(program.get('arguments')) is not dict
            or set(program['arguments']) != {'buildId'}
            or not _matches(program['arguments']['buildId'], HEX32_PATTERN)
            or not _matches(idempotency_key, KEY_PATTERN)):
        raise ValueError('PYTHON_RUN_ARGUMENTS_INVALID')
    return program['arguments']['buildId']


def parse_historical_read(identifier, original_request, *, build=False):
    """One existing ID or one exact signed original, never both selectors.

    This validates structure only. Authentication and native READ authority
    remain separate; an original request never confers execution permission.
    """
    code = 'PYTHON_BUILD_READ_ARGUMENTS_INVALID' if build else 'PYTHON_WORKFLOW_READ_ARGUMENTS_INVALID'
    if original_request is None:
        if not _matches(identifier, HEX32_PATTERN):
            raise ValueError(code)
        return None
    if (identifier is not None or type(original_request) is not dict
            or set(original_request) != {'program', 'idempotencyKey'}
            or not _matches(original_request['idempotencyKey'],
                r'oa1_[0-9a-z]{1,13}_[0-9a-f]{32}_[A-Za-z0-9_-]{43}')):
        raise ValueError(code)
    program = original_request['program']
    if build:
        parse_build_program(program)
    else:
        parse_run_program(program, original_request['idempotencyKey'])
    return original_request


def build_result(record):
    value = {'buildId': record.build_id, 'status': record.status.value,
             'purpose': record.purpose, 'attempts': record.attempts,
             'claimGeneration': record.claim_generation}
    if record.plan_digest is not None:
        value['planDigest'] = record.plan_digest
    if record.error_code is not None:
        value['errorCode'] = record.error_code
    if record.diagnostics is not None:
        value['diagnostics'] = record.diagnostics
    return value


def workflow_result(record):
    return {'workflowId': record.workflow_id, 'buildId': record.build_id,
        'planDigest': record.plan_digest, 'status': record.status.value,
        'unitCount': record.unit_count, 'committedUnits': record.committed_units,
        'remainingUnits': record.remaining_units,
        'checkpoints': [{'ordinal': item.ordinal, 'jobId': item.job_id,
            'committed': item.committed, 'receiptId': item.receipt_id}
            for item in record.checkpoints]}


def _string(pattern):
    # Unlike $, this end assertion cannot accept a final newline. It works in
    # both ECMA JSON Schema regexes and Python's native fullmatch semantics.
    return {'type': 'string', 'pattern': '^(?:' + pattern + r')(?![\s\S])'}


def build_result_schema(*, purpose=None, task=False):
    from .python_program_execution import BuildStatus
    from openepm.diagnostics import diagnostic_payload_schema, SourceValidationError
    fields = {'buildId': _string(HEX32_PATTERN),
        'status': {'enum': [item.value for item in BuildStatus]},
        'purpose': {'const': purpose} if purpose else {'enum': ['Plan', 'Validation', 'ImpactTest']},
        'attempts': {'type': 'integer', 'minimum': 0},
        'claimGeneration': {'type': 'integer', 'minimum': 0},
        'planDigest': _string(HEX64_PATTERN), 'errorCode': _string(ID_PATTERN),
        'diagnostics': diagnostic_payload_schema()}
    required = ['buildId', 'status', 'purpose', 'attempts', 'claimGeneration']
    if task:
        fields['taskId'] = _string('p:' + HEX32_PATTERN)
        required.append('taskId')
    result = obj(fields, required)
    result['allOf'] = [
        {'if': {'properties': {'status': {'const': 'sealed'}}},
         'then': {'required': ['planDigest']}, 'else': {'not': {'required': ['planDigest']}}},
        {'if': {'properties': {'status': {'const': 'failed'}}},
         'then': {'required': ['errorCode']}, 'else': {'not': {'required': ['errorCode']}}},
        {'if': {'required': ['diagnostics']}, 'then': {'properties': {
            'status': {'const': 'failed'}, 'errorCode': {'const': SourceValidationError.code}}}}]
    return result


def workflow_result_schema():
    from .python_program_execution import WorkflowStatus, MAX_OPERATIONS
    count = {'type': 'integer', 'minimum': 0, 'maximum': MAX_OPERATIONS}
    checkpoint = obj({'ordinal': {**count, 'minimum': 1}, 'jobId': _string(ID_PATTERN),
        'committed': {'type': 'boolean'},
        'receiptId': {'anyOf': [_string(ID_PATTERN), {'type': 'null'}]}})
    checkpoint['allOf'] = [{'if': {'properties': {'committed': {'const': True}}},
        'then': {'properties': {'receiptId': _string(ID_PATTERN)}},
        'else': {'properties': {'receiptId': {'type': 'null'}}}}]
    value = obj({'workflowId': _string(HEX32_PATTERN), 'buildId': _string(HEX32_PATTERN),
        'planDigest': _string(HEX64_PATTERN), 'status': {'enum': [item.value for item in WorkflowStatus]},
        'unitCount': {**count, 'minimum': 1},
        'committedUnits': {**count, 'description':
            'Number of receipt-confirmed committed checkpoints; not a scan of all physical child effects.'},
        'remainingUnits': {**count, 'description':
            'Declared units without a confirmed checkpoint receipt: may be unstarted, cancelled or unresolved, including an independently committed child.'},
        'checkpoints': {'type': 'array', 'maxItems': MAX_OPERATIONS, 'items': checkpoint}})
    value['description'] = WORKFLOW_COUNT_GUIDANCE
    return value


def historical_read_contract(*, build=False):
    functions = BUILD_PURPOSES if build else (RUN,)
    programs = []
    for function in functions:
        schema = execution_program_contract(function, _include_history=False)['programSchema']
        # Each embedded program is its own schema resource, so recursive
        # parameter references keep their original owner-defined $defs.
        schema['$id'] = 'urn:openepm:historical-read:' + function
        if '$defs' in schema:
            # MCP's Pydantic schema projection reserves local $ref for its
            # own models. A local dynamic anchor carries this same recursive
            # JSON value grammar without an external schema fetch or copy.
            schema['$defs']['parameterValue']['$dynamicAnchor'] = 'parameterValue'
            def anchor_refs(value):
                if isinstance(value, dict):
                    if value.get('$ref') == '#/$defs/parameterValue':
                        value.pop('$ref')
                        value['$dynamicRef'] = '#parameterValue'
                    for child in value.values():
                        anchor_refs(child)
                elif isinstance(value, list):
                    for child in value:
                        anchor_refs(child)
            anchor_refs(schema)
        programs.append(schema)
    original = obj({'program': {'anyOf': programs}, 'idempotencyKey':
        _string(r'oa1_[0-9a-z]{1,13}_[0-9a-f]{32}_[A-Za-z0-9_-]{43}')})
    identifier = 'buildId' if build else 'workflowId'
    return {'tool': 'read_v2_python_program_build' if build else 'read_v2_python_program_workflow',
        'browserPath': '/api/python-build' if build else '/api/python-run',
        'browserAction': 'read', 'originalRequestSchema': original,
        'selectorSchema': {'$schema': DIALECT, 'oneOf': [
            obj({identifier: _string(HEX32_PATTERN)}), obj({'originalRequest': original})]},
        'authority': 'Current READ, original issuer/subject and retained native authorization scope. Signed original authentication is independent of admission expiry and grants no execution authority.',
        'missingOriginal': 'PYTHON_BUILD_UNAVAILABLE' if build else 'PYTHON_WORKFLOW_UNAVAILABLE',
        'effects': 'Read existing evidence only; never create, build, seal, advance, rebase or renew admission.'}


def execution_program_contract(function, *, _include_history=True):
    if function not in FUNCTIONS:
        return None
    defs = None
    if function == RUN:
        arguments = obj({'buildId': _string(HEX32_PATTERN)})
        example = {'buildId': 'c' * 32}
        result = workflow_result_schema()
    else:
        value = {'$ref': '#/$defs/parameterValue'}
        parameters = {'type': 'object', 'additionalProperties': value}
        defs = {'parameterValue': {'anyOf': [
            {'type': ['null', 'boolean', 'string', 'integer']},
            {'type': 'array', 'items': value}, parameters]}}
        fields = {'programId': _string(ID_PATTERN), 'programSourceToken': _string(HEX64_PATTERN),
            'parameters': parameters, **{pin: {'type': 'integer', 'minimum': 0} for pin in PINS}}
        example = {'programId': 'example.plan', 'programSourceToken': 'a' * 64,
            'parameters': {}, **dict(zip(PINS, (1, 2, 3)))}
        required = list(COMMON_FIELDS)
        if function == BUILD:
            fields.update({'delegationId': _string(AUTHORITY_ID_PATTERN),
                'delegationStateToken': _string(HEX64_PATTERN),
                'scheduleId': {'anyOf': [_string(AUTHORITY_ID_PATTERN), {'type': 'null'}]},
                'scheduleStateToken': {'anyOf': [_string(HEX64_PATTERN), {'type': 'null'}]}})
            required.extend(AUTHORITY_FIELDS)
            example.update({'delegationId': 'delegation-1', 'delegationStateToken': 'b' * 64,
                            'scheduleId': None, 'scheduleStateToken': None})
        elif function == TEST:
            fields['definitionParameters'] = {'anyOf': [parameters, {'type': 'null'}]}
            example['definitionParameters'] = {}
        arguments = obj(fields, required)
        if function == BUILD:
            arguments['allOf'] = [{'if': {'properties': {'scheduleId': {'type': 'null'}}},
                'then': {'properties': {'scheduleStateToken': {'type': 'null'}}},
                'else': {'properties': {'scheduleStateToken': _string(HEX64_PATTERN)}}}]
        result = build_result_schema(purpose=BUILD_PURPOSES[function], task=True)
    schema = program_schema(function, arguments, defs)
    contract = {'schemaCoverage': 'program-and-result', 'schemaDialect': DIALECT,
        'programSchema': schema, 'resultSchemaScope': 'envelope',
        'resultSchema': {'$schema': DIALECT, **obj({'languageVersion': {'type': 'integer', 'const': 2},
            'function': {'const': function}, 'result': result})},
        'programContract': {'owner': 'python_execution_contract',
            'examples': [{'name': 'Exact ' + function + ' envelope',
                'program': {'languageVersion': 2, 'function': function, 'arguments': deepcopy(example)},
                'binding': ('Bind the exact current source token and application revisions. Review the caller-owned '
                            'sealed Validation and its PlanSummary before activation.' if function == VALIDATE else
                    'Synthetic references only. Read the current saved source, application pins and execution delegation; use returned IDs/tokens. Run uses the original caller-owned sealed buildId.')}],
            'semanticRules': [
                'Counts, revisions and integer parameter values are strict JSON integers, not booleans or floating-point tokens. Decimal business inputs use their declared string type.',
                'Parameter names and types belong to the current saved source declaration. The native owner rejects incompatible values; a structural schema is not authority or source validation.',
                'Test uses saved source and a private ImpactTest build. It never publishes business effects and is not a universal activation prerequisite. Explicit null definitionParameters is the same as omission; canonical definitionParameters bytes are limited to 1048576.',
                'Validate queues static Validation of the exact saved source for a designer or publisher. It does not change the source, grant permission, perform a live impact test or publish business effects. Activate separately using the exact caller-owned current build.',
                'Build requires current execution delegation and exact source/context pins. Both schedule fields are present; a direct build supplies null for both.',
                'Changed Save retires the old executable owner. Retained build evidence does not make that source executable. Run checks current source, delegation and authority against the original sealed build.',
                'Build taskId is p: plus buildId. ' + WORKFLOW_COUNT_GUIDANCE,
                'Sealed Test dispatch/read returns technical state and planDigest, not an inline Impact artifact. Read bounded section Impact through read_v2_python_program_build_artifact.',
                'Named build read/cancel tools return the base technical object without taskId or a V2 envelope; named workflow read/cancel tools return the workflow object without a V2 envelope.'],
            'recovery': 'Retain the exact original admitted packet and route. An expired admission permits only existing-original lookup under current native authorization; missing original is refused. Never renew, rebuild or rebase to reconcile an unknown outcome. Known-ID reads are separately authorized.'}}
    if _include_history:
        contract['programContract']['historicalRead'] = historical_read_contract(build=function != RUN)
    return contract
