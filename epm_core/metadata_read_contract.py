"""Structural wire contracts owned by the existing metadata read repository.

These describe shape, not metadata resolution, currentness or authorization.
PostgresMetadataStore remains authoritative for trimmed references, active IDs,
ambiguity, current grants and transaction revision fences.
"""
from .postgres_numeric_catalog import obj, program_schema


FUNCTIONS = frozenset(('metadata.dimension.list', 'metadata.dimension.resolve',
                      'metadata.member.list', 'metadata.member.resolve'))
DIALECT = 'https://json-schema.org/draft/2020-12/schema'
METADATA_PAGE_TOKEN_SCHEMA = {'type': 'string', 'pattern': r'^[0-9]{1,12}\.[0-9a-f]{64}$'}


def metadata_read_program_contract(function: str) -> dict | None:
    if function not in FUNCTIONS:
        return None
    revision = {'type': 'integer', 'minimum': 0}
    page_token = METADATA_PAGE_TOKEN_SCHEMA
    identifier = {'type': 'string', 'minLength': 1, 'maxLength': 200}
    reference = {'type': 'string', 'minLength': 1,
        'description': 'The native resolver trims whitespace, then requires 1–200 characters. Use a stable ID from discovery or an unambiguous active name.'}
    dimension = obj({'dimension_id': identifier, 'name': identifier,
        'model_role': {'type': ['string', 'null']},
        'status': {'enum': ['Active', 'Inactive']},
        'short_description': {'type': 'string'}, 'detailed_description': {'type': 'string'}})
    member_fields = {'dimension_id': identifier, 'member_id': identifier, 'name': identifier,
        'status': {'enum': ['Active', 'Inactive']},
        'short_description': {'type': 'string'}, 'detailed_description': {'type': 'string'},
        'numeric_value_kind': {'enum': ['amount', 'ratio', None]}}
    member = obj(member_fields)
    member_page = obj({**member_fields,
        'aggregation_operator': {'enum': ['Add', 'Subtract', 'Ignore', 'NeverAggregate', 'Formula']},
        'custom_values': {'type': 'object', 'additionalProperties': True}})
    examples = []
    if function.endswith('.resolve'):
        fields = {'reference': reference}
        example = {'reference': 'custom-axis' if function == 'metadata.dimension.resolve' else 'member-a'}
        if function == 'metadata.member.resolve':
            fields = {'dimension': reference, **fields}
            example = {'dimension': 'custom-axis', **example}
        arguments = obj(fields)
        result = dimension if function == 'metadata.dimension.resolve' else member
        examples.append({'name': 'Resolve an ID obtained from the current metadata page',
                         'program': {'languageVersion': 2, 'function': function, 'arguments': example},
                         'binding': 'Replace fixture IDs with IDs returned by the preceding authorized list call.'})
    else:
        is_dimension = function == 'metadata.dimension.list'
        anchor = 'afterDimensionId' if is_dimension else 'afterMemberId'
        next_anchor = 'nextAfterDimensionId' if is_dimension else 'nextAfterMemberId'
        fields = {'limit': {'type': 'integer', 'minimum': 1, 'maximum': 500, 'default': 100},
            anchor: {'anyOf': [reference, {'type': 'null'}]},
            'expectedPageToken': page_token,
            'expectedMetadataRevision': {'anyOf': [revision, {'type': 'null'}]}}
        if not is_dimension:
            fields = {'dimension': reference, **fields}
        arguments = obj(fields, [] if is_dimension else ['dimension'])
        arguments['allOf'] = [{'if': {'required': [anchor], 'properties': {anchor: {'type': 'string'}}},
            'then': {'required': ['expectedMetadataRevision'],
                     'properties': {'expectedMetadataRevision': revision}}},
            {'if': {'required': ['expectedPageToken']},
             'then': {'required': [anchor, 'expectedMetadataRevision'],
                      'properties': {anchor: {'type': 'string'},
                                     'expectedMetadataRevision': revision}}}]
        result_fields = {'rows': {'type': 'array', 'maxItems': 500,
                                 'items': dimension if is_dimension else member_page},
            'metadataRevision': revision, 'hasMore': {'type': 'boolean'},
            next_anchor: {'anyOf': [identifier, {'type': 'null'}]}}
        if not is_dimension:
            result_fields = {'dimensionId': identifier, **result_fields}
        result = obj({**result_fields, 'nextPageToken': {'anyOf': [page_token, {'type': 'null'}]}},
                     list(result_fields))
        first = {'limit': 100} if is_dimension else {'dimension': 'custom-axis', 'limit': 100}
        examples.append({'name': 'Read the first bounded metadata page',
            'program': {'languageVersion': 2, 'function': function, 'arguments': first}})
        examples.append({'name': 'Continue at the exact prior metadata revision',
            'program': {'languageVersion': 2, 'function': function, 'arguments': {
                **first, anchor: 'custom-axis' if is_dimension else 'member-a', 'expectedMetadataRevision': 1}},
            'binding': 'Use the previous nextAfter ID and metadataRevision. If the page returned nextPageToken, copy its exact value to expectedPageToken.'})
    return {'schemaCoverage': 'program-and-result', 'schemaDialect': DIALECT,
        'programSchema': program_schema(function, arguments),
        'resultSchema': {'$schema': DIALECT, **obj({
            'languageVersion': {'type': 'integer', 'const': 2},
            'function': {'type': 'string', 'const': function}, 'result': result})},
        'resultSchemaScope': 'envelope',
        'programContract': {'examples': examples,
            'owner': 'PostgresMetadataStore',
            'semanticRules': [
                'Structural schema does not prove an ID exists, a name is unique, a revision is current or a grant is valid. Native read validation remains authoritative.',
                'List reads include authorized Active and Inactive rows; resolve selects authorized Active rows. Stable IDs take precedence over case-insensitive names within the visible set.',
                'Reference whitespace is trimmed by the resolver. The native trimmed 1–200 character bound remains enforced; the schema does not impose an incompatible raw-string maximum.',
                'The active dimensional policy filters pages before the row limit or refuses the complete selection under reject_all. MemberReference attribute values pointing to restricted metadata are omitted.',
                'A continuation under an active dimensional policy requires the prior opaque nextPageToken. Retain the original limit and scope for that continuation.',
                'A non-null page anchor requires the exact previous metadataRevision. The core rechecks current application access before returning a result or a reference-resolution error.'],
            'recovery': 'On a stale revision, missing or stale continuation token, or METADATA_DIRECTORY_READ_AUTHORIZATION_STALE, start from the first page under current access. On unknown/ambiguous reference, select an explicit stable ID from authorized discovery.'}}


def read_contract(function, arguments, result, *, owner, examples, semantic_rules=(),
                  definitions=None, result_scope='envelope'):
    """Project an owner's exact read wire shape; never execute or authorize it."""
    from copy import deepcopy
    program = program_schema(function, deepcopy(arguments))
    if definitions:
        program['$defs'] = deepcopy(definitions)
    result_schema = deepcopy(result)
    if result_scope == 'envelope':
        result_schema = obj({'languageVersion': {'type': 'integer', 'const': 2},
                             'function': {'type': 'string', 'const': function},
                             'result': result_schema})
    return {'schemaCoverage': 'program-and-result', 'schemaDialect': DIALECT,
        'programSchema': program,
        'resultSchema': {'$schema': DIALECT,
            **({'$defs': deepcopy(definitions)} if definitions else {}), **result_schema},
        'resultSchemaScope': result_scope,
        'programContract': {'owner': owner,
            'examples': deepcopy(examples), 'semanticRules': list(semantic_rules),
            'recovery': ('Rediscover the current authorized contract after a structural error. '
                'Use native current-authority and continuation/state errors to refresh the '
                'same owner; a schema does not authorize a read or repair a stale token.')}}


def read_example(function, arguments, *, name, binding):
    return {'name': name, 'program': {'languageVersion': 2,
        'function': function, 'arguments': arguments}, 'binding': binding}


def metadata_mutation_receipt_schema():
    revision = {'type': 'integer', 'minimum': 0}
    return obj({'operationId': {'type': 'string', 'minLength': 1, 'maxLength': 200},
        'committedRevision': revision, 'changedCount': revision})


def additional_metadata_read_program_contract(function):
    """The two remaining list readers on PostgresMetadataStore."""
    if function not in ('metadata.relationship.list', 'metadata.security-tag.list'):
        return None
    identifier = {'type': 'string', 'minLength': 1, 'maxLength': 200}
    reference = {'type': 'string', 'minLength': 1}
    nullable_id = {'anyOf': [identifier, {'type': 'null'}]}
    revision = {'type': 'integer', 'minimum': 0}
    status = {'enum': ['Active', 'Inactive', None]}
    fields = {'dimension': reference, 'status': status,
              'limit': {'type': 'integer', 'minimum': 1, 'maximum': 500}}
    result = {'dimensionId': identifier, 'metadataRevision': revision,
              'status': status, 'hasMore': {'type': 'boolean'}}
    if function == 'metadata.relationship.list':
        fields['hierarchyId'] = nullable_id
        arguments = {'oneOf': [obj(fields, ['dimension']),
            obj({'cursor': {'type': 'string', 'minLength': 1}})]}
        row = obj({key: identifier for key in ('relationship_id', 'dimension_id',
            'hierarchy_id', 'parent_member_id', 'child_member_id')} | {
            'name': {'type': 'string'}, 'short_description': {'type': 'string'},
            'detailed_description': {'type': 'string'},
            'semantic_description': {'type': 'string'},
            'semantic_tag': {'type': ['string', 'null']},
            'status': {'enum': ['Active', 'Inactive']},
            'custom_values': {'type': 'object', 'additionalProperties': True},
            'aggregation_operator_override': {'enum': [None, 'Add', 'Subtract',
                'Ignore', 'NeverAggregate', 'Formula']}})
        result.update({'hierarchyId': nullable_id, 'nextAfterRelationshipId': nullable_id,
            'nextCursor': {'type': ['string', 'null']}})
    else:
        fields.update({'afterTagId': {'anyOf': [reference, {'type': 'null'}]},
            'expectedMetadataRevision': {'anyOf': [revision, {'type': 'null'}]}})
        arguments = obj(fields, ['dimension'])
        arguments['allOf'] = [{'if': {'required': ['afterTagId'],
            'properties': {'afterTagId': {'type': 'string'}}},
            'then': {'required': ['expectedMetadataRevision'],
                     'properties': {'expectedMetadataRevision': revision}}}]
        row = obj({'dimension_id': identifier, 'tag_id': identifier,
            'display_name': {'type': 'string'}, 'short_description': {'type': 'string'},
            'semantic_description': {'type': 'string'},
            'status': {'enum': ['Active', 'Inactive']}})
        result['nextAfterTagId'] = nullable_id
    result['rows'] = {'type': 'array', 'maxItems': 500, 'items': row}
    result_schema = obj(result)
    semantic_rules = [
        'Native reference trimming, current application grants and metadata revision fences remain authoritative.',
        'The core rechecks current application access before returning a page. On METADATA_DIRECTORY_READ_AUTHORIZATION_STALE, start from the first page under current access.',
    ]
    if function == 'metadata.relationship.list':
        result_schema['allOf'] = [{
            'if': {'properties': {'hierarchyId': {'type': 'null'}}},
            'then': {'properties': {'rows': {'maxItems': 0}, 'hasMore': {'const': False},
                'nextCursor': {'type': 'null'}, 'nextAfterRelationshipId': {'type': 'null'}}}}]
        semantic_rules.extend([
            'Relationship rows describe current edge records. Read the hierarchy state for build currentness. Continue with the returned signed cursor alone.',
            'Current dimensional READ applies to the relationship and both endpoints before paging. Protected cursors expire and are bound to the effective scope.',
            'A relationship page for a dimension without a default hierarchy has a null hierarchyId, no rows, and no continuation.',
        ])
    else:
        semantic_rules.append('Security-tag continuation requires the exact prior metadata revision.')
    return read_contract(function, arguments, result_schema, owner='PostgresMetadataStore',
        examples=[read_example(function, {'dimension': 'custom-axis', 'limit': 100},
            name='Read a bounded current metadata page',
            binding='Use a dimension ID from the current authorized dimension list.')],
        semantic_rules=semantic_rules)
