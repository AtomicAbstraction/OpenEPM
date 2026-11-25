"""Dependency-free projection of explicit owner-supplied wire schemas.

Core discovery and SDK verification use this same projection. It does not infer
grammar from prose, carry a function allowlist or authorize an operation.
"""
from copy import deepcopy


def structural_contract_projection(specification: dict) -> dict:
    nested = specification.get('programContract', {})
    program = specification.get('programSchema', nested.get('programSchema'))
    result = specification.get('resultSchema', nested.get('resultSchema'))
    result_scope = specification.get('resultSchemaScope', nested.get('resultSchemaScope'))
    has_program = isinstance(program, dict)
    has_result = isinstance(result, dict) and result_scope in ('envelope', 'result')
    schemas = {}
    if has_program:
        schemas['programSchema'] = deepcopy(program)
        arguments = program.get('properties', {}).get('arguments')
        if isinstance(arguments, dict):
            schemas['argumentSchema'] = {'$schema': program.get('$schema'),
                **deepcopy(arguments), **({'$defs': deepcopy(program['$defs'])}
                                         if '$defs' in program else {})}
    if has_result:
        schemas['resultSchema'] = deepcopy(result)
        schemas['resultSchemaScope'] = result_scope
    return {
        'schemaCoverage': ('program-and-result' if has_program and has_result else
                           'program-only' if has_program else 'descriptive-only'),
        'schemaDialect': program.get('$schema') if has_program else None,
        'structuralSchemas': schemas,
        # v3 SDKs bind these historical fields to descriptions. Preserve that
        # compatibility while explicitly distinguishing the new wire grammar.
        'argumentSchema': deepcopy(specification['arguments']),
        'argumentSchemaScope': 'descriptive',
        'optionalArguments': deepcopy(specification.get('optionalArguments', {})),
        'resultSchema': specification['result'],
        'resultSchemaScope': 'descriptive'}
