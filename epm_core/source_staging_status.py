"""Shared source staging contracts and exact read-only recovery."""
from .operation_admission_contract import (
    authenticate_operation_admission, signed_operation_id_schema,
)
from .postgres_jobs import _canonical_digest
from .postgres_source_batch import PostgresSourceBatch
from .postgres_source_upload_manifest import (
    ATTACH as MANIFEST, PostgresSourceUploadManifest, manifest_argument_schema,
    manifest_example_arguments,
)

READ = 'facts.source.staging.read'
BEGIN = 'facts.source.begin'
APPEND = 'facts.source.csv.append'
TYPED_APPEND = 'facts.source.append'
SEAL = 'facts.source.seal'
FUNCTIONS = frozenset((BEGIN, APPEND, SEAL, MANIFEST, TYPED_APPEND))

_CHUNK_FIELDS = ('batchId', 'chunkIndex', 'rowCount', 'contentDigest')
_FIELDS = {
    BEGIN: ('batchId', 'status', 'rowCount', 'contentDigest'),
    APPEND: _CHUNK_FIELDS,
    SEAL: ('batchId', 'status', 'rowCount', 'contentDigest'),
    MANIFEST: ('batchId', 'requestKey', 'schemaVersion', 'contentDigest', 'manifestDigest'),
    TYPED_APPEND: _CHUNK_FIELDS,
}


def _argument_schemas():
    from .postgres_numeric_catalog import obj

    key = {'type': 'string', 'pattern': r'^[A-Za-z0-9._-]{8,128}(?![\s\S])'}
    identifier = {'type': 'string', 'minLength': 1, 'maxLength': 200}
    batch = {'type': 'string', 'pattern': r'^[0-9a-f]{32}(?![\s\S])'}
    digest = {'type': 'string', 'pattern': r'^[0-9a-f]{64}(?![\s\S])'}
    revision = {'type': 'integer', 'minimum': 0}
    begin = obj({'idempotencyKey': key, 'mode': {'enum': ['merge', 'replace']},
        'scopeMembers': {'type': 'object', 'maxProperties': 32,
                         'propertyNames': identifier, 'additionalProperties': identifier},
        'scopeAll': {'type': 'boolean'}, 'expectedMetadataRevision': revision,
        'expectedDataRevision': revision})
    begin.update({'if': {'properties': {'scopeAll': {'const': True}}},
        'then': {'properties': {'scopeMembers': {'maxProperties': 0}}},
        'else': {'properties': {'scopeMembers': {'minProperties': 1}}}})
    chunk = {'batchId': batch, 'chunkIndex': {'type': 'integer', 'minimum': 0, 'maximum': 999}}
    decimal = {'type': 'string', 'description': 'Exact decimal string. The source owner checks precision and scale.'}
    member = {'type': 'string', 'minLength': 1}
    coordinate = {'type': 'object', 'minProperties': 1, 'propertyNames': member,
                  'additionalProperties': member}
    line = obj({'description': {'type': 'string', 'minLength': 1, 'maxLength': 80}, 'decimal': decimal})
    literal = {'oneOf': [obj({'type': {'const': 'AmountLiteral'}, 'decimal': decimal}),
        obj({'type': {'const': 'TextLiteral'}, 'text': {'type': 'string', 'maxLength': 32768}}),
        obj({'type': {'const': 'LineDetailLiteral'},
             'items': {'type': 'array', 'maxItems': 500, 'items': line}})]}
    row = obj({'members': coordinate, 'value': literal, 'sourceRef': identifier})
    return {
        BEGIN: begin,
        APPEND: obj({**chunk,
            'csvText': {'type': 'string', 'description': 'One CSV chunk. The native owner checks the UTF-8 bytes and records.'}}),
        SEAL: obj({'batchId': batch, 'expectedRows': {**revision, 'maximum': 100000},
                   'expectedContentDigest': digest}),
        MANIFEST: manifest_argument_schema(MANIFEST),
        TYPED_APPEND: obj({**chunk, 'rows': {'type': 'array', 'minItems': 1, 'maxItems': 500, 'items': row}}),
    }


_ARGUMENT_SCHEMAS = _argument_schemas()


def _result_fields():
    seal = _ARGUMENT_SCHEMAS[SEAL]['properties']
    manifest = _ARGUMENT_SCHEMAS[MANIFEST]['properties']
    return {'batchId': seal['batchId'], 'contentDigest': seal['expectedContentDigest'],
        'manifestDigest': seal['expectedContentDigest'],
        'status': {'enum': ['staging', 'ready', 'published', 'failed', 'cancelled']},
        'rowCount': {'type': 'integer', 'minimum': 0, 'maximum': 100000},
        'chunkIndex': _ARGUMENT_SCHEMAS[APPEND]['properties']['chunkIndex'],
        'requestKey': manifest['requestKey'], 'schemaVersion': manifest['schemaVersion'],
        'duplicate': {'type': 'boolean'}}


_EXAMPLE_ARGUMENTS = {
    BEGIN: {'idempotencyKey': 'example-source-begin', 'mode': 'merge',
            'scopeMembers': {}, 'scopeAll': True,
            'expectedMetadataRevision': 1, 'expectedDataRevision': 0},
    APPEND: {'batchId': 'a' * 32, 'chunkIndex': 0,
             'csvText': 'axis.Account,literalType,value,sourceRef\nRevenue,AmountLiteral,1,example'},
    SEAL: {'batchId': 'a' * 32, 'expectedRows': 1, 'expectedContentDigest': 'b' * 64},
    MANIFEST: manifest_example_arguments(MANIFEST),
    TYPED_APPEND: {'batchId': 'a' * 32, 'chunkIndex': 0, 'rows': [
        {'members': {'Account': 'Revenue'}, 'sourceRef': 'example-row',
         'value': {'type': 'LineDetailLiteral', 'items': [{'description': 'Item 1', 'decimal': '1.00'}]}}]},
}


def batch_staging_program_contract(function: str) -> dict:
    from .metadata_read_contract import read_contract as project, read_example
    from .postgres_numeric_catalog import obj

    fields = _result_fields()
    result = {key: fields[key] for key in _FIELDS[function]}
    rules = ['Current application WRITE is required. Staging alone preserves business facts.']
    if function == BEGIN:
        result['duplicate'] = fields['duplicate']
        name = 'Open a source batch for an explicit merge or replace'
        binding = 'Read metadataRevision and dataRevision from application.state.read. Choose a fresh idempotencyKey and confirm the precise scope.'
        rules.append('Use scopeAll=true with an empty scopeMembers object. Otherwise specify at least one stable-ID equality filter.')
    elif function == APPEND:
        result['duplicate'] = fields['duplicate']
        name = 'Stage one ordered CSV chunk'
        binding = 'Use the returned batch ID and next zero-based chunk index. Replace the example CSV with the exact header for every active fact axis.'
        rules.extend(['A chunk contains 1–500 rows and at most 8,000,000 UTF-8 bytes. The owner also limits the normalized staged payload.',
                      'Exact replay observes the current cumulative row count and digest. A changed acknowledged chunk is refused.'])
    elif function == TYPED_APPEND:
        result['duplicate'] = fields['duplicate']
        name = 'Stage one ordered chunk of typed source rows'
        binding = ('Use the returned batch ID and next zero-based chunk index. '
                   'Bind every active fact axis, choose the typed literal and preserve ordered supporting detail.')
        rules.extend(['Amounts and supporting-detail amounts cross the boundary as decimal strings.',
                      'An explicit empty text string and an empty supporting-detail list represent present values.',
                      'The native owner validates the complete coordinate, byte bound and ordered chunk digest.'])
    else:
        assert function == SEAL
        result['status'] = {'const': 'ready'}
        name = 'Seal the complete staged batch'
        binding = 'Use the last acknowledged cumulative rowCount and contentDigest. Supply the empty-source digest for a deliberately empty batch.'
        rules.append('Only the exact acknowledged row count and content digest can produce a ready batch.')
    contract = project(function, _ARGUMENT_SCHEMAS[function], obj(result), owner='PostgresSourceBatch',
        examples=[read_example(function, _EXAMPLE_ARGUMENTS[function], name=name, binding=binding)],
        semantic_rules=rules)
    contract['programContract']['recovery'] = ('For an uncertain outcome, call facts.source.staging.read with the exact '
        'original program and its original Browser admission ID when one was used.')
    return contract


def read_contract():
    from .metadata_read_contract import read_contract as project, read_example
    from .postgres_numeric_catalog import obj

    inputs = [obj({'languageVersion': {'type': 'integer', 'const': 2},
                  'function': {'const': function}, 'arguments': schema})
              for function, schema in _ARGUMENT_SCHEMAS.items()]
    fields = _result_fields()
    return project(READ, obj({'originalProgram': {'oneOf': inputs},
        'operationId': signed_operation_id_schema()}, ['originalProgram']),
        {'oneOf': [obj({'originalFunction': {'const': function},
                       'outcome': obj({key: fields[key] for key in keys})})
                   for function, keys in _FIELDS.items()]},
        owner='PostgresSourceBatch and PostgresSourceUploadManifest',
        examples=[read_example(READ, {'originalProgram': {'languageVersion': 2,
            'function': function, 'arguments': args}},
            name=f'Read the recorded {function} step',
            binding='Replace the complete example program with the exact submitted staging program. For Browser admission also supply its original server-issued operationId.')
            for function, args in _EXAMPLE_ARGUMENTS.items()],
        semantic_rules=[
            'Supply the exact original begin, typed or CSV append, seal or manifest program in the same application. Native source clients use the original embedded identifiers.',
            'A signed operationId authenticates the Browser program, scope and caller even after admission expires.',
            'Current application WRITE and the original staged batch or manifest owner are required. This read cannot stage or publish any row.',
            'SOURCE_STAGING_STATUS_UNAVAILABLE leaves the original unconfirmed. A changed payload or newer acknowledged batch progress requires separate investigation.',
        ])


def catalog():
    return {READ: {'mode': 'read', 'permission': 'write',
        'arguments': {'originalProgram': 'exact original begin, typed or CSV append, seal or manifest program',
                      'operationId': 'signed Browser admission identity, when used for submission'},
        'result': 'original function and bounded observed acknowledgement',
        'previewRequired': False, 'idempotencyRequired': False, 'workClass': 'short',
        **read_contract()}}


def numeric_import_spec(function, specification):
    """Project the bounded numeric source contract for an assigned importer."""
    from copy import deepcopy
    from .application_authorization_actions import GROUP_SOURCE_IMPORT_FUNCTIONS

    if function not in GROUP_SOURCE_IMPORT_FUNCTIONS:
        return specification
    spec = deepcopy(specification)
    spec['sourceImportProfile'] = 'numeric_merge'
    contract = spec['programContract']
    contract['semanticRules'] = [
        'The caller owns the external numeric input. Every destination requires current assignment-bound fact write and read access, plus the application import duty.',
        'Each submitted chunk and the reviewed publication are atomic. Only the supplied coordinates can change.',
    ]
    arguments = spec['programSchema']['properties']['arguments']['properties']
    result = spec['resultSchema']['properties']['result']

    def narrow(name, args):
        if name == BEGIN:
            args['mode'] = {'const': 'merge'}
            args['scopeAll'] = {'const': True}
            args['scopeMembers']['maxProperties'] = 0
        if name == TYPED_APPEND:
            row = args['rows']['items']['properties']
            row['value'] = next(kind for kind in row['value']['oneOf']
                                if kind['properties']['type'].get('const') == 'AmountLiteral')

    narrow(function, arguments)
    for example in contract['examples']:
        program = example['program']
        if function == READ:
            program = program['arguments']['originalProgram']
        if program['function'] == TYPED_APPEND:
            program['arguments']['rows'][0]['value'] = {'type': 'AmountLiteral', 'decimal': '1.00'}
            example['binding'] = 'Supply stable member IDs for every fact dimension and exact decimal strings for amounts.'
        if function == BEGIN:
            example['name'] = 'Open a numeric source merge for the listed coordinates'
        if function == 'facts.source.cancel':
            example['binding'] = 'Use your original numeric source batch ID.'
    if function == BEGIN:
        spec['arguments'].update(mode='merge', scopeMembers='empty object',
            scopeAll='true; only the explicit input coordinates can change')
    if function == TYPED_APPEND:
        spec['arguments']['rows'] = '1–500 complete coordinate rows with an AmountLiteral'
    if function == APPEND:
        spec['arguments']['csvText'] = '1–500 full-coordinate UTF-8 CSV rows with literalType AmountLiteral'
    if function == READ:
        spec['arguments']['originalProgram'] = 'exact original begin, typed or CSV append, or seal program'
        spec['publicationRecovery'] = 'facts.source.publish'
        contract['recovery'] = 'For an uncertain numeric publication, retry the original signed facts.source.publish packet. If current planning rules block new writes, the original completed publication can still return its receipt under current destination permissions.'
        alternatives = arguments['originalProgram']['oneOf']
        alternatives[:] = [option for option in alternatives if option['properties']['function']['const'] != MANIFEST]
        for option in alternatives:
            fields = option['properties']
            narrow(fields['function']['const'], fields['arguments']['properties'])
        result['oneOf'] = [option for option in result['oneOf'] if option['properties']['originalFunction']['const'] != MANIFEST]
        contract['examples'] = [item for item in contract['examples']
            if item['program']['arguments']['originalProgram']['function'] != MANIFEST]
    if function in ('facts.source.preview', 'facts.source.publish'):
        result['properties'].update(mode={'const': 'merge'}, clearCount={'const': 0})
    if function == 'facts.source.preview':
        arguments['allowWarnings'] = {'const': False}
        spec['optionalArguments']['allowWarnings'] = 'false, or omit'
        review = result['properties']['review']['properties']
        review.update(mode={'const': 'merge'}, scopeAll={'const': True},
                      scopeMembers={'type': 'object', 'maxProperties': 0}, periodSelection={'type': 'null'})
        examples = review['examples']['items']['oneOf']
        review['examples']['items'] = next(option for option in examples if
            option['properties']['valueKind']['const'] == 'numeric' and option['properties']['action']['const'] == 'set')
    if function == 'facts.source.publish':
        contract['recovery'] = 'Retry the original publication with its original batch ID and exact signed preview. Current destination rights are rechecked before a receipt can be returned.'
    return spec


def replay_stage(dsn, scope, identity, preview_secret, program, *, operation_id=None):
    """Use the same native replay owner for lookup and expired effect recovery."""
    if (type(program) is not dict or set(program) != {'languageVersion','function','arguments'}
            or type(program['languageVersion']) is not int or program['languageVersion'] != 2
            or type(program['function']) is not str or program['function'] not in FUNCTIONS
            or type(program['arguments']) is not dict):
        raise ValueError('SOURCE_STAGING_PROGRAM_INVALID')
    function, args = program['function'], program['arguments']
    if set(args) != set(_ARGUMENT_SCHEMAS[function]['properties']):
        raise ValueError('SOURCE_STAGING_ARGUMENTS_INVALID')
    if function == MANIFEST:
        return PostgresSourceUploadManifest(dsn, identity=identity).create(
            scope, args['batchId'], request_key=operation_id or args['requestKey'],
            origin_kind=args['originKind'], origin_ref=args['originRef'],
            schema_version=args['schemaVersion'], declared_schema=args['schema'],
            content_digest=args['contentDigest'], replay_only=True)
    source = PostgresSourceBatch(dsn, identity=identity, preview_secret=preview_secret)
    if function == BEGIN:
        return source.replay_begin(
            scope, idempotency_key=operation_id or args['idempotencyKey'],
            mode=args['mode'], scope_members=args['scopeMembers'], scope_all=args['scopeAll'],
            expected_metadata_revision=args['expectedMetadataRevision'],
            expected_data_revision=args['expectedDataRevision'])
    if function == APPEND:
        return source.append_csv(scope, args['batchId'], chunk_index=args['chunkIndex'],
                                 csv_text=args['csvText'], replay_only=True)
    if function == TYPED_APPEND:
        return source.append_typed(scope, args['batchId'], chunk_index=args['chunkIndex'],
                                  rows=args['rows'], replay_only=True)
    return source.seal(scope, args['batchId'], expected_rows=args['expectedRows'],
                       expected_content_digest=args['expectedContentDigest'], replay_only=True)


def read_status(dsn, scope, identity, preview_secret, program):
    if (type(program) is not dict or set(program) != {'languageVersion','function','arguments'}
            or type(program['languageVersion']) is not int or program['languageVersion'] != 2
            or program['function'] != READ or type(program['arguments']) is not dict):
        raise ValueError('SOURCE_STAGING_PROGRAM_INVALID')
    args = program['arguments']
    if set(args) not in ({'originalProgram'}, {'originalProgram','operationId'}):
        raise ValueError('SOURCE_STAGING_ARGUMENTS_INVALID')
    original = args['originalProgram']
    if type(original) is not dict or type(original.get('function')) is not str:
        raise ValueError('SOURCE_STAGING_PROGRAM_INVALID')
    operation_id = args.get('operationId')
    if 'operationId' in args:
        authenticate_operation_admission(preview_secret, scope, identity,
            operation_id=operation_id, function=original['function'],
            intent_digest=_canonical_digest(original))
    result = replay_stage(dsn, scope, identity, preview_secret, original,
                          operation_id=operation_id)
    if result is None:
        raise ValueError('SOURCE_STAGING_STATUS_UNAVAILABLE')
    function = original['function']
    return {'originalFunction': function, 'outcome': {key: result[key] for key in _FIELDS[function]}}
