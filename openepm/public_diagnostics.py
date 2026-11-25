"""Dependency-free vocabulary for repairing discovered application programs.

The server checks structural paths and bounds against the actual schema.
Clients check the wire shape and retain only the fields used for repair.
"""
from __future__ import annotations

import re


CATALOG_DISCOVERY_FORMAT = 'openepm-catalog-discovery-diagnostics-v1'
CATALOG_QUERY_INVALID = 'CATALOG_DISCOVERY_ARGUMENTS_INVALID'
CATALOG_CONTINUATION_INVALID = 'CATALOG_CONTINUATION_INVALID'
CATALOG_CONTINUATION_STALE = 'CATALOG_CONTINUATION_STALE_RESTART_DISCOVERY'
CATALOG_AUTHORIZATION_STALE = 'CATALOG_AUTHORIZATION_STALE'
CATALOG_DISCOVERY_CODES = frozenset((
    CATALOG_QUERY_INVALID, CATALOG_CONTINUATION_INVALID, CATALOG_CONTINUATION_STALE,
    CATALOG_AUTHORIZATION_STALE))
_QUERY_FIELDS = {
    '$.discovery': 'an object with only the supported discovery fields for its view',
    '$.discovery.view': 'one of full, summary or functions',
    '$.discovery.limit': 'an integer from 1 to 100',
    '$.discovery.family': 'a returned family name or null',
    '$.discovery.function': 'an exact function name or null',
}

PROGRAM_FORMAT = 'openepm-program-diagnostics-v1'
PROGRAM_CODE = 'APPLICATION_PROGRAM_INVALID'
REPAIR_CODES = CATALOG_DISCOVERY_CODES | {PROGRAM_CODE}
_REDISCOVERY_RECOVERY = (
    'Read current authorized application discovery and rebuild the program from a returned contract. '
    'If an earlier effect has an unknown outcome, inspect its original durable status first.')
_WORKSPACE_REDISCOVERY_RECOVERY = (
    'Use list_v2_workspace_functions on the current authorized workspace listener. '
    'Rebuild the program from the returned contract and keep any original request key.')
_VIOLATIONS = {
    'object': ('$', 'object', 'Send one structured application-language program.'),
    'fields': ('$', 'languageVersion, function and arguments only',
               'Use the exact envelope from the discovered function example.'),
    'version': ('$.languageVersion', 'integer 2', _REDISCOVERY_RECOVERY),
    'workspace_version': ('$.languageVersion', 'integer 2', _WORKSPACE_REDISCOVERY_RECOVERY),
    'platform_version': ('$.languageVersion', 'integer 2',
                         'Use list_v2_platform_functions on the current authorized platform listener.'),
    'function': ('$.function', 'nonempty string',
                 'Use a function name from current authorized discovery.'),
    'unknown_function': ('$.function', 'a function from current authorized discovery',
                         _REDISCOVERY_RECOVERY),
    'unknown_workspace_function': ('$.function', 'a function from current authorized discovery',
                                   _WORKSPACE_REDISCOVERY_RECOVERY),
    'arguments': ('$.arguments', 'object',
                  'Send the arguments object, including {} for a no-argument read.'),
    'json': ('$.arguments', 'bounded JSON values',
             'Remove non-JSON values and use the discovered argument contract.'),
}
STRUCTURAL_RECOVERY = {
    'type': 'Use the field type in the current discovered program contract.',
    'required': 'Supply this required field using the current discovered example.',
    'additionalProperties': 'Remove fields not declared by the current program contract.',
    'contract': 'Use a value matching the current discovered field contract.',
}
STRUCTURAL_EXPECTATIONS = {
    'contract': 'a value matching the discovered field contract',
    'required': 'a required field',
    'additionalProperties': 'only the declared fields',
    'const': 'the constant specified by the discovered contract',
    'enum': 'one of the values listed in the discovered contract',
    'pattern': 'a string matching the discovered field format',
    'anyOf': 'one of the declared field shapes',
    'oneOf': 'exactly one declared field shape',
}
STRUCTURAL_BOUNDS = {
    'minimum': 'a number at least',
    'maximum': 'a number at most',
    'minLength': 'a string with minimum length',
    'maxLength': 'a string with maximum length',
    'minItems': 'an array with minimum items',
    'maxItems': 'an array with maximum items',
    'minProperties': 'an object with minimum properties',
    'maxProperties': 'an object with maximum properties',
}
_JSON_TYPES = frozenset(('array', 'boolean', 'integer', 'null', 'number', 'object', 'string'))
_PROGRAM_PATH = re.compile(
    r'\$(?:\.(?:languageVersion|function)|\.arguments(?:\.[A-Za-z_][A-Za-z_0-9]*|\[\*\])*)?\Z')
_INTEGER = re.compile(r'(?:0|-?[1-9][0-9]{0,19})\Z')


def catalog_diagnostic(code: str, path: str) -> dict:
    if code == CATALOG_QUERY_INVALID and path in _QUERY_FIELDS:
        expected = _QUERY_FIELDS[path]
        recovery = 'Correct the discovery query. Use the functions view for filters and paging.'
    elif path == '$.discovery.after' and code == CATALOG_CONTINUATION_INVALID:
        expected = 'the exact next value from the preceding catalogue page'
        recovery = 'Pass the exact next value from the preceding page, or start again without after.'
    elif path == '$.discovery.after' and code == CATALOG_CONTINUATION_STALE:
        expected = 'a continuation matching the current authorized catalogue and filters'
        recovery = 'Start discovery again without after. Replace the earlier pages with the current catalogue.'
    elif path == '$.discovery' and code == CATALOG_AUTHORIZATION_STALE:
        expected = 'one current access decision for the application catalogue'
        recovery = 'Access changed during discovery. Start discovery again without after in the same application.'
    else:
        raise ValueError('CATALOG_DISCOVERY_DIAGNOSTIC_INVALID')
    return {'format': CATALOG_DISCOVERY_FORMAT, 'code': code, 'path': path,
            'expected': expected, 'recovery': recovery}


def validate_catalog_discovery_diagnostic(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError('CATALOG_DISCOVERY_DIAGNOSTIC_INVALID')
    code, path = value.get('code'), value.get('path')
    if not isinstance(code, str) or not isinstance(path, str):
        raise ValueError('CATALOG_DISCOVERY_DIAGNOSTIC_INVALID')
    canonical = catalog_diagnostic(code, path)
    if canonical != value:
        raise ValueError('CATALOG_DISCOVERY_DIAGNOSTIC_INVALID')
    return canonical


def program_diagnostic(violation: str) -> dict:
    if not isinstance(violation, str) or violation not in _VIOLATIONS:
        raise ValueError('PROGRAM_DIAGNOSTIC_INVALID')
    path, expected, recovery = _VIOLATIONS[violation]
    return {'format': PROGRAM_FORMAT, 'violation': violation, 'path': path,
            'expected': expected, 'recovery': recovery}


def _valid_structural_expectation(keyword: str, expected: str) -> bool:
    if keyword == 'type':
        types = expected.split(' or ')
        return set(types) <= _JSON_TYPES and types == sorted(set(types))
    if keyword in STRUCTURAL_BOUNDS:
        prefix = STRUCTURAL_BOUNDS[keyword] + ' '
        return expected.startswith(prefix) and _INTEGER.fullmatch(expected[len(prefix):]) is not None
    return STRUCTURAL_EXPECTATIONS.get(keyword) == expected


def repair_fields(payload: object, *, requested_function: object = None) -> dict | None:
    """Project a recognized MCP diagnostic without copying its free-text message."""
    if not isinstance(payload, dict) or set(payload) != {'code', 'message', 'details'}:
        return None
    code, value = payload['code'], payload['details']
    if (not isinstance(code, str) or not isinstance(payload['message'], str)
            or not isinstance(value, dict)):
        return None
    try:
        if code in CATALOG_DISCOVERY_CODES:
            expected = validate_catalog_discovery_diagnostic(value)
            if expected['code'] != code:
                return None
        elif code == PROGRAM_CODE and value.get('violation') != 'structure':
            if value != program_diagnostic(value.get('violation')):
                return None
        elif code == PROGRAM_CODE:
            if (set(value) != {'format', 'violation', 'function', 'path', 'keyword', 'expected', 'recovery'}
                    or value['format'] != PROGRAM_FORMAT):
                return None
            function, path, keyword, expected = (
                value[key] for key in ('function', 'path', 'keyword', 'expected'))
            if (not isinstance(function, str) or function != requested_function
                    or not isinstance(path, str)
                    or len(path) > 500 or _PROGRAM_PATH.fullmatch(path) is None
                    or not isinstance(keyword, str) or not isinstance(expected, str)
                    or len(expected) > 128 or not _valid_structural_expectation(keyword, expected)
                    or value['recovery'] != STRUCTURAL_RECOVERY.get(keyword, STRUCTURAL_RECOVERY['contract'])):
                return None
        else:
            return None
    except ValueError:
        return None
    return {key: value[key] for key in ('path', 'expected', 'recovery')}
