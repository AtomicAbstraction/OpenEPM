"""Canonical read-only mixed-method placement coverage contract."""
from __future__ import annotations

import re
from .postgres_jobs import _canonical_digest
from .current_object_contract import require_state_token

FUNCTION = 'consolidation.method.coverage.inspect'
_ID = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_MEMBER = re.compile(r'[A-Za-z0-9._-]{1,200}\Z')
_JOB = re.compile(r'[0-9a-f]{32}\Z')
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_METHODS = {'Full', 'Equity', 'Proportional'}


def compile_coverage(program: object) -> dict:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or program.get('languageVersion') != 2
            or program.get('function') != FUNCTION
            or not isinstance(program.get('arguments'), dict)):
        raise ValueError('METHOD_COVERAGE_PROGRAM_INVALID')
    args = program['arguments']
    required = {'methodPreviewProgram', 'expectedMethodPreviewDigest',
                'publicationPins', 'expectedDataRevision'}
    if (set(args) != required
            or not isinstance(args['methodPreviewProgram'], dict)
            or args['methodPreviewProgram'].get('function') !=
                'consolidation.ownership.method.preview'
            or not isinstance(args['expectedMethodPreviewDigest'], str)
            or not _HEX.fullmatch(args['expectedMethodPreviewDigest'])
            or type(args['expectedDataRevision']) is not int
            or args['expectedDataRevision'] < 0
            or not isinstance(args['publicationPins'], list)
            or len(args['publicationPins']) > 200):
        raise ValueError('METHOD_COVERAGE_ARGUMENTS_INVALID')
    pins, relationships = [], set()
    for value in args['publicationPins']:
        base = {'relationshipId', 'method', 'resultKey', 'resultStateToken'}
        typed = {'currencyDimensionId', 'currencyMemberId'}
        if (not isinstance(value, dict) or value.get('method') not in _METHODS
                or (set(value) not in ((base,base|typed)
                    if value.get('method')=='Full' else (base|typed,)))
                or not isinstance(value.get('relationshipId'), str)
                or not _MEMBER.fullmatch(value['relationshipId'])
                or value['relationshipId'] in relationships
                or not isinstance(value.get('resultKey'), str)
                or not _ID.fullmatch(value['resultKey'])
                or any(not isinstance(value.get(key), str)
                       or not value[key] or len(value[key]) > 200
                       for key in typed & set(value))):
            raise ValueError('METHOD_COVERAGE_PIN_INVALID')
        require_state_token(value['resultStateToken'],
                            error='METHOD_COVERAGE_PIN_INVALID')
        relationships.add(value['relationshipId'])
        pins.append(dict(value))
    pins.sort(key=lambda item: item['relationshipId'])
    return {'version': 1,
            'methodPreviewProgram': args['methodPreviewProgram'],
            'expectedMethodPreviewDigest': args['expectedMethodPreviewDigest'],
            'expectedDataRevision': args['expectedDataRevision'],
            'publicationPins': pins}


def coverage_digest(plan: dict, placements: list[dict]) -> str:
    return _canonical_digest({'plan': plan, 'placements': placements})
