"""Public generic axis-member copy contract owned by source staging.

The operation proposes an exact source batch. It neither publishes facts nor
chooses a business scenario policy, axis meaning, merge mode or target.
"""
from copy import deepcopy

FUNCTION = 'facts.slice.copy.prepare'
STATUS_READ = 'facts.slice.copy.status.read'
STATUS_UNAVAILABLE = 'SCENARIO_COPY_STATUS_UNAVAILABLE'
OPERATION_KEY_PATTERN = r'[A-Za-z0-9._-]{8,128}'
FIELDS = frozenset(('dimensionId', 'sourceMemberId', 'targetMemberId',
    'filterMembers', 'mode', 'expectedMetadataRevision',
    'expectedDataRevision', 'idempotencyKey'))

def _operation_key_schema():
    return {'type': 'string', 'pattern': '^' + OPERATION_KEY_PATTERN + r'(?![\s\S])'}


def _batch_fields():
    return {'batchId': {'type': 'string', 'pattern': '^[0-9a-f]{32}$'},
        'status': {'enum': ['staging', 'ready', 'published', 'failed', 'cancelled']},
        'rowCount': {'type': 'integer', 'minimum': 0, 'maximum': 100000},
        'contentDigest': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'}}


def status_read_contract():
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj

    specification = read_contract(STATUS_READ, obj({'operationId': _operation_key_schema()}),
        obj(_batch_fields()), owner='PostgresScenarioCopy', examples=[
            read_example(STATUS_READ, {'operationId': 'copy-example-001'},
                name='Read the original staged copy after a lost response',
                binding='Use the retained prepare operation identity. For a signed Browser request use the server-issued admission ID. For a source program use its retained idempotencyKey. Keep the original application scope.')],
        semantic_rules=[
            'This read needs the original verified issuer and subject, current application READ and visibility of every staged source and target coordinate.',
            'The operation identity is a lookup key. An expired admission can identify the recorded batch. This read cannot stage, preview, cancel or publish a copy.',
            'If effective access changes during the read, CUBE_READ_AUTHORIZATION_STALE leaves the outcome unconfirmed. Refresh current access and check the same operation identity.',
            'SCENARIO_COPY_STATUS_UNAVAILABLE leaves the outcome unconfirmed. Use only the exact original request for any permitted retry.'])
    specification['programContract']['recovery'] = (
        'Keep the original operation identity. A ready batch still needs a separately authorized, current preview and explicit publication.')
    return specification


def catalog() -> dict:
    from .postgres_numeric_catalog import obj

    identifier = {'type': 'string', 'minLength': 1, 'maxLength': 200}
    arguments = {'type': 'object', 'additionalProperties': False,
        'required': sorted(FIELDS), 'properties': {
            'dimensionId': identifier, 'sourceMemberId': identifier, 'targetMemberId': identifier,
            'filterMembers': {'type': 'object', 'maxProperties': 31,
                'propertyNames': identifier, 'additionalProperties': identifier},
            'mode': {'enum': ['merge', 'replace']},
            'expectedMetadataRevision': {'type': 'integer', 'minimum': 0},
            'expectedDataRevision': {'type': 'integer', 'minimum': 0},
            'idempotencyKey': _operation_key_schema()}}
    program = {'$schema': 'https://json-schema.org/draft/2020-12/schema',
        'type': 'object', 'additionalProperties': False,
        'required': ['languageVersion', 'function', 'arguments'],
        'properties': {'languageVersion': {'type': 'integer', 'const': 2}, 'function': {'const': FUNCTION},
            'arguments': arguments}}
    result = obj({**_batch_fields(), 'duplicate': {'type': 'boolean'}})
    envelope = {'$schema': 'https://json-schema.org/draft/2020-12/schema',
        'type': 'object', 'additionalProperties': False,
        'required': ['languageVersion', 'function', 'result'], 'properties': {
            'languageVersion': {'const': 2}, 'function': {'const': FUNCTION}, 'result': result}}
    example = {'languageVersion': 2, 'function': FUNCTION, 'arguments': {
        'dimensionId': 'chosen-axis', 'sourceMemberId': 'source-member',
        'targetMemberId': 'target-member', 'filterMembers': {}, 'mode': 'merge',
        'expectedMetadataRevision': 1, 'expectedDataRevision': 0, 'idempotencyKey': 'copy-example-001'}}
    return deepcopy({FUNCTION: {
        'mode': 'durable_staging', 'permission': 'write',
        'arguments': {'dimensionId': 'active fact axis stable ID',
            'sourceMemberId': 'active source member stable ID on the selected axis',
            'targetMemberId': 'distinct active target member stable ID on the same axis',
            'filterMembers': 'explicit equality filters on other active fact axes; omitted fact axes cover all members',
            'mode': 'explicit merge or exact-target-scope replace',
            'expectedMetadataRevision': 'current nonnegative metadata revision',
            'expectedDataRevision': 'current nonnegative raw data revision',
            'idempotencyKey': 'original 8–128 safe-character operation identity'},
        'result': 'ready numeric/text/supporting-detail source batch with immutable copy provenance',
        'previewRequired': False, 'idempotencyRequired': True, 'workClass': 'bounded_write',
        'schemaCoverage': 'program-and-result', 'schemaDialect': program['$schema'],
        'programSchema': program, 'resultSchema': envelope, 'resultSchemaScope': 'envelope',
        'programContract': {'examples': [example],
            'recovery': 'Read facts.slice.copy.status.read using the original operation identity. The returned batch ID identifies the separate preview and subsequent publication receipt.',
            'exampleBinding': 'Resolve active fact axes, member IDs and current revisions first. Bind the intended filters and explicit merge or replace policy before preparing.',
            'semanticPreconditions': ['source and target differ on one explicit fact axis',
                'Currency-role dimensions are contextual and cannot be used as a copy axis or filter',
                'filterMembers excludes the copied axis', 'all present source coordinates require current READ',
                'all explicit and implicit clear targets require current WRITE',
                'preview and publication recheck READ on the original staged source coordinates',
                'prepare preserves source facts; preview and publish use the returned source batch',
                'metadata/data/current authority are fenced; exact replay never rebases source']}},
        STATUS_READ: {'mode': 'read_only', 'permission': 'read',
            'arguments': {'operationId': 'original source program or signed Browser admission identity'},
            'result': 'owned batch identity, state, exact staged row count and content digest',
            'previewRequired': False, 'idempotencyRequired': False, 'workClass': 'short',
            **status_read_contract()}})
