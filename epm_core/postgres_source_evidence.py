"""Typed application source-evidence objects.

This replaces opaque generic tables with one fixed object graph. Collections,
documents and records have stable identities and current-state tokens. Records
may bind a full cube observation coordinate; those reads and writes pass the
same dimensional policy as facts. Arbitrary executable content is never
accepted.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
from typing import Any

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .dimensional_security_policy import AccessKind
from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_dimensional_security_enforcement import (
    authorize_coordinates, authorized_read_page, filter_read_rows)
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .operation_admission_contract import is_signed_operation_id


COLLECTION_SAVE = 'source.evidence.collection.save'
COLLECTION_DELETE = 'source.evidence.collection.delete'
COLLECTION_READ = 'source.evidence.collection.read'
COLLECTION_LIST = 'source.evidence.collection.list'
DOCUMENT_SAVE = 'source.evidence.document.save'
DOCUMENT_DELETE = 'source.evidence.document.delete'
DOCUMENT_READ = 'source.evidence.document.read'
DOCUMENT_LIST = 'source.evidence.document.list'
RECORD_SAVE = 'source.evidence.record.save'
RECORD_DELETE = 'source.evidence.record.delete'
RECORD_READ = 'source.evidence.record.read'
RECORD_LIST = 'source.evidence.record.list'
WRITE_FUNCTIONS = frozenset((COLLECTION_SAVE, COLLECTION_DELETE,
    DOCUMENT_SAVE, DOCUMENT_DELETE, RECORD_SAVE, RECORD_DELETE))
READ_FUNCTIONS = frozenset((COLLECTION_READ, COLLECTION_LIST,
    DOCUMENT_READ, DOCUMENT_LIST, RECORD_READ, RECORD_LIST))
FUNCTIONS = WRITE_FUNCTIONS | READ_FUNCTIONS

_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z')
_TYPE = re.compile(r'[A-Za-z][A-Za-z0-9._:-]{0,99}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_MEDIA = re.compile(r'[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,63}\Z')
_KINDS = frozenset(('ObservationContext', 'SourceModel', 'SourceRecords'))
_POINTER_KEYS = frozenset(('jsonPointer', 'page', 'line', 'column', 'cell', 'url'))
_RESERVED_PROPERTIES = frozenset(('collectionId', 'recordId', 'recordType',
    'documentId', 'observationMembers', 'sourcePointer', 'stateToken'))
_CURSOR_TTL = 900
_CURSOR_MAX_BYTES = 32768
_CURSOR_FORMAT = 'openepm-source-evidence-cursor-v2'
READ_AUTHORIZATION_STALE = 'SOURCE_EVIDENCE_READ_AUTHORIZATION_STALE'
WRITE_AUTHORIZATION_STALE = 'SOURCE_EVIDENCE_WRITE_AUTHORIZATION_STALE'


def catalog() -> dict:
    common_write = {'mode': 'durable_write', 'permission': 'write',
        'previewRequired': False, 'idempotencyRequired': True,
        'workClass': 'bounded_write'}
    common_read = {'mode': 'read', 'permission': 'read',
        'previewRequired': False, 'idempotencyRequired': False,
        'workClass': 'short'}
    return {
        COLLECTION_SAVE: {**common_write, 'arguments': {
            'collectionId': 'stable application-scoped ID',
            'name': 'business display name',
            'collectionKind': 'ObservationContext, SourceModel or SourceRecords',
            'description': 'bounded business purpose',
            'expectedStateToken': 'empty for create; exact token for replacement',
            'expectedMetadataRevision': 'current nonnegative metadata revision'},
            'result': 'commit receipt and new collection state token'},
        COLLECTION_DELETE: {**common_write, 'arguments': {
            'collectionId': 'stable application-scoped ID',
            'expectedStateToken': 'exact current state token',
            'expectedMetadataRevision': 'current nonnegative metadata revision'},
            'result': 'physical retirement receipt; referenced collections block'},
        COLLECTION_READ: {**common_read, 'arguments': {
            'collectionId': 'stable application-scoped ID'},
            'result': 'current typed collection'},
        COLLECTION_LIST: {**common_read, 'arguments': {
            'limit': 'optional 1–500 on the first page',
            'cursor': 'opaque signed continuation; the only continuation argument'},
            'result': 'bounded current typed collections'},
        DOCUMENT_SAVE: {**common_write, 'arguments': {
            'collectionId': 'owning collection ID', 'documentId': 'stable document ID',
            'title': 'source title', 'mediaType': 'lowercase MIME type',
            'sourceUri': 'bounded source locator or empty',
            'sourceRevision': 'immutable external revision identity',
            'contentDigest': 'SHA-256 of exact external source bytes',
            'expectedStateToken': 'empty for create; exact token for replacement',
            'expectedMetadataRevision': 'current nonnegative metadata revision'},
            'result': 'commit receipt and new document state token'},
        DOCUMENT_DELETE: {**common_write, 'arguments': {
            'collectionId': 'owning collection ID', 'documentId': 'document ID',
            'expectedStateToken': 'exact current state token',
            'expectedMetadataRevision': 'current nonnegative metadata revision'},
            'result': 'physical retirement receipt; referenced documents block'},
        DOCUMENT_READ: {**common_read, 'arguments': {
            'collectionId': 'owning collection ID', 'documentId': 'document ID'},
            'result': 'current typed document'},
        DOCUMENT_LIST: {**common_read, 'arguments': {
            'collectionId': 'owning collection ID', 'limit': 'optional 1–500',
            'cursor': 'opaque signed continuation; the only continuation argument'},
            'result': 'bounded current typed documents'},
        RECORD_SAVE: {**common_write, 'arguments': {
            'collectionId': 'owning collection ID', 'recordId': 'stable record ID',
            'recordType': 'bounded business classification',
            'documentId': 'optional document in the same collection',
            'observationMembers': 'empty or one full stable-ID coordinate',
            'sourcePointer': 'closed JSON/page/line/column/cell/URL pointer',
            'properties': 'bounded inert business properties without reserved fields',
            'expectedStateToken': 'empty for create; exact token for replacement',
            'expectedMetadataRevision': 'current nonnegative metadata revision'},
            'result': 'commit receipt and new record state token'},
        RECORD_DELETE: {**common_write, 'arguments': {
            'collectionId': 'owning collection ID', 'recordId': 'record ID',
            'expectedStateToken': 'exact current state token',
            'expectedMetadataRevision': 'current nonnegative metadata revision'},
            'result': 'physical retirement receipt'},
        RECORD_READ: {**common_read, 'arguments': {
            'collectionId': 'owning collection ID', 'recordId': 'record ID'},
            'result': 'current typed record if dimensionally readable'},
        RECORD_LIST: {**common_read, 'arguments': {
            'collectionId': 'owning collection ID', 'recordType': 'optional classification',
            'limit': 'optional 1–500 on the first page',
            'cursor': 'opaque signed continuation; the only continuation argument'},
            'result': 'bounded typed records filtered by current dimensional read policy'},
    }


def _schema_pattern(pattern: re.Pattern) -> dict:
    body = pattern.pattern.removesuffix(r'\Z')
    return {'type': 'string', 'pattern': rf'^{body}(?![\s\S])'}


def _record_wire_schema(identifier: dict) -> tuple[dict, dict, dict, dict]:
    from .metadata_read_contract import obj

    text = {'type': 'string'}
    positive = {'type': 'integer', 'minimum': 1}
    pointer = obj({'page': positive, 'line': positive, 'column': {'anyOf': [positive, text]},
                   'cell': text, 'url': text, 'jsonPointer': text}, [])
    value = {'$ref': '#/$defs/evidenceValue'}
    definitions = {'evidenceValue': {'anyOf': [
        {'type': ['string', 'integer', 'boolean', 'null']},
        {'type': 'array', 'items': value}, {'type': 'object', 'additionalProperties': value},
    ]}}
    members = {'type': 'object', 'maxProperties': 128, 'propertyNames': identifier,
               'additionalProperties': identifier}
    properties = {'type': 'object', 'additionalProperties': value}
    return members, pointer, properties, definitions


def read_program_contract(function: str) -> dict:
    from .metadata_read_contract import obj, read_contract, read_example

    if function not in READ_FUNCTIONS:
        raise ValueError('SOURCE_EVIDENCE_READ_FUNCTION_INVALID')

    identifier = _schema_pattern(_ID)
    digest = _schema_pattern(_DIGEST)
    text = {'type': 'string'}
    revision = {'type': 'integer', 'minimum': 0}
    cursor = {'type': 'string', 'minLength': 1, 'maxLength': _CURSOR_MAX_BYTES}
    collection, document, record = 'source-records', 'report-document', 'observation-1'
    args = {'collectionId': collection}
    required = {'collectionId': identifier}
    fields = {**required, 'stateToken': digest, 'metadataRevision': revision,
              'updatedAt': {'type': 'string', 'format': 'date-time'}}
    definitions = None

    if function in (COLLECTION_READ, COLLECTION_LIST):
        label = 'collection'
        fields.update(name=text, collectionKind={'enum': sorted(_KINDS)}, description=text)
    elif function in (DOCUMENT_READ, DOCUMENT_LIST):
        label = 'document'
        if function == DOCUMENT_READ:
            args['documentId'], required['documentId'] = document, identifier
        fields.update(documentId=identifier, title=text, mediaType=text, sourceUri=text,
                      sourceRevision=text, contentDigest=digest)
    else:
        label = 'record'
        if function == RECORD_READ:
            args['recordId'], required['recordId'] = record, identifier
        members, pointer, properties, definitions = _record_wire_schema(identifier)
        fields.update(recordId=identifier, recordType=text,
                      documentId={'anyOf': [identifier, {'type': 'null'}]},
                      members=members, sourcePointer=pointer, properties=properties,
                      contentDigest=digest)

    rules = ['Read within the current authorized application. The server rechecks access and metadata before returning the result.']
    if function.endswith('.list'):
        first = {} if function == COLLECTION_LIST else required
        optional = {'limit': {'type': 'integer', 'minimum': 1, 'maximum': 500}}
        if function == RECORD_LIST:
            optional['recordType'] = {'anyOf': [_schema_pattern(_TYPE), {'type': 'null'}]}
        arguments = {'oneOf': [obj({**first, **optional}, list(first)), obj({'cursor': cursor})]}
        first_example = {} if function == COLLECTION_LIST else args
        examples = [
            read_example(function, {**first_example, 'limit': 25},
                name=f'List current source evidence {label}s',
                binding='Use the selected application. For documents or records use a collectionId returned by collection discovery.'),
            read_example(function, {'cursor': 'example-cursor'}, name=f'Continue the {label} list',
                binding='Pass the exact returned nextCursor as the only argument. A null nextCursor means the list is exhausted.'),
        ]
        result = {**obj({'metadataRevision': revision, 'items': {
            'type': 'array', 'maxItems': 500, 'items': obj(fields)},
            'nextCursor': {'anyOf': [cursor, {'type': 'null'}]}, 'hasMore': {'type': 'boolean'}}),
                  'oneOf': [
                      {'properties': {'hasMore': {'const': True}, 'nextCursor': cursor}},
                      {'properties': {'hasMore': {'const': False}, 'nextCursor': {'type': 'null'}}},
                  ]}
        rules.append('Continue with the last page token. The server binds it to this query, application, caller and current authority.')
    else:
        arguments, result = obj(required), obj(fields)
        examples = [read_example(function, args, name=f'Inspect one current source evidence {label}',
            binding='Use exact stable IDs from the authorized collection, document or record list.')]
    if function in (RECORD_READ, RECORD_LIST):
        rules.append('Records with a cube coordinate follow dimensional read policy. Unbound metadata records follow application read authority.')
    if function == RECORD_LIST:
        rules.append('The page and continuation describe visible records. An exhausted list has no further visible records.')
    contract = read_contract(function, arguments, result, owner='PostgresSourceEvidence.read',
        definitions=definitions, examples=examples, semantic_rules=rules)
    contract['programContract']['recovery'] = (
        'On SOURCE_EVIDENCE_CURSOR_STALE or SOURCE_EVIDENCE_CURSOR_INVALID, restart at the first page. '
        'If access changed, refresh the application catalogue and repeat the original inspection under current authority.')
    return contract


def write_program_contract(function: str) -> dict:
    from .metadata_read_contract import obj, read_contract, read_example
    from .operation_admission_contract import signed_operation_id_schema

    if function not in WRITE_FUNCTIONS:
        raise ValueError('SOURCE_EVIDENCE_WRITE_FUNCTION_INVALID')
    identifier = _schema_pattern(_ID)
    digest = _schema_pattern(_DIGEST)
    revision = {'type': 'integer', 'minimum': 0}
    save = function.endswith('.save')
    label = function.split('.')[2]
    fields = {'collectionId': identifier, 'expectedMetadataRevision': revision,
              'expectedStateToken': {'anyOf': [{'const': ''}, digest]} if save else digest}
    request = {'collectionId': 'source-records', 'expectedMetadataRevision': 1,
               'expectedStateToken': '' if save else 'a' * 64}
    if label != 'collection':
        fields[label + 'Id'] = identifier
        request[label + 'Id'] = 'report-document' if label == 'document' else 'observation-1'

    def text(maximum, minimum=0):
        return {'type': 'string', 'minLength': minimum, 'maxLength': maximum,
                'pattern': r'^[^\x00-\x1f\x7f]*(?![\s\S])'}

    definitions = None
    if function == COLLECTION_SAVE:
        fields.update(name=text(200, 1), collectionKind={'enum': sorted(_KINDS)}, description=text(2000))
        request.update(name='Planning source evidence', collectionKind='SourceRecords', description='Reviewed source context')
    elif function == DOCUMENT_SAVE:
        fields.update(title=text(500, 1), mediaType=_schema_pattern(_MEDIA), sourceUri=text(4096),
                      sourceRevision=text(500, 1), contentDigest=digest)
        request.update(title='Source report', mediaType='application/pdf', sourceUri='',
                       sourceRevision='published-report-1', contentDigest='b' * 64)
    elif function == RECORD_SAVE:
        members, pointer, properties, definitions = _record_wire_schema(identifier)
        fields.update(recordType=_schema_pattern(_TYPE),
                      documentId={'anyOf': [identifier, {'type': 'null'}]},
                      observationMembers=members, sourcePointer=pointer, properties={
                          **properties, 'maxProperties': 1000, 'propertyNames': {
                              'type': 'string', 'minLength': 1, 'maxLength': 200,
                              'not': {'enum': sorted(_RESERVED_PROPERTIES)}}})
        request.update(recordType='Observation', documentId='report-document',
                       observationMembers={}, sourcePointer={'page': 4},
                       properties={'exactValue': '123.0000', 'unit': 'USD'})

    rules = [
        'Admit the exact program with issue_v2_operation_admission in the current application. '
        'Pass the returned operationId as idempotency_key to execute_v2_metadata_program.',
        'Save and retirement return a receipt with the resulting metadata and commit revisions. Read the object separately for its current content.',
        'Exact replay under current application write authority returns the original receipt and revisions with duplicate set to true.',
    ]
    pins = ('Bind expectedMetadataRevision to the current application revision. '
            'Read the current object for its exact expectedStateToken.')
    if save:
        examples = [
            read_example(function, request, name=f'Save a new source evidence {label}',
                binding='Use a new stable ID in the chosen application and an empty expectedStateToken. '
                        'Bind the current metadata revision and any current owning collection or document IDs.'),
            read_example(function, {**request, 'expectedStateToken': 'a' * 64},
                name=f'Replace a reviewed source evidence {label}',
                binding=pins + ' Preserve its stable ID and supply the complete reviewed replacement.'),
        ]
        if function == DOCUMENT_SAVE:
            rules.append('Supply the immutable external revision and the SHA-256 digest of the exact source bytes.')
        if function == RECORD_SAVE:
            rules.append('Supply empty observationMembers for unbound metadata or the complete current cube coordinate. '
                         'For a bound record, the core checks the old and new coordinates. '
                         'Record properties are inert JSON with exact decimals represented by strings.')
    else:
        examples = [read_example(function, request, name=f'Retire an approved source evidence {label}',
            binding=pins + ' Review the intended retirement before admission.')]
        rules.append('The core refuses retirement of a collection or document with current references.')

    result = obj({'function': {'const': function}, 'collectionId': identifier, 'objectId': identifier,
                  'stateToken': digest if save else {'type': 'null'}, 'metadataRevision': revision,
                  'committedRevision': revision, 'operationId': signed_operation_id_schema(),
                  'impactDigest': digest, 'duplicate': {'type': 'boolean'}})
    contract = read_contract(function, obj(fields), result, owner='PostgresSourceEvidence.execute',
        definitions=definitions, examples=examples, semantic_rules=rules)
    contract['programContract']['recovery'] = (
        'After an uncertain response, check application.operation.receipt.read with the original operationId. '
        'Replay only the original program and key. On a state conflict or stale revision, read the current source '
        'object and application state before reviewing a new admission. If write authority changes, refresh the application catalogue.')
    return contract


def _id(value: object, error: str = 'SOURCE_EVIDENCE_ID_INVALID') -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(error)
    return value


def _text(value: object, limit: int, *, required: bool = False) -> str:
    if (not isinstance(value, str) or len(value) > limit
            or any(ord(character) < 32 or ord(character) == 127
                   for character in value)
            or (required and (not value.strip() or value != value.strip()))):
        raise ValueError('SOURCE_EVIDENCE_TEXT_INVALID')
    return value


def _token(value: object, *, allow_empty: bool = False) -> str:
    if value == '' and allow_empty:
        return ''
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError('SOURCE_EVIDENCE_STATE_TOKEN_INVALID')
    return value


def _revision(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError('STALE_METADATA_REVISION')
    return value


def _json(value: object, *, depth: int = 0) -> object:
    if depth > 12:
        raise ValueError('SOURCE_EVIDENCE_PROPERTIES_INVALID')
    if value is None or type(value) in (bool, int, str):
        if isinstance(value, str) and ('\x00' in value or len(value) > 65536):
            raise ValueError('SOURCE_EVIDENCE_PROPERTIES_INVALID')
        return value
    if isinstance(value, list):
        if len(value) > 10000:
            raise ValueError('SOURCE_EVIDENCE_PROPERTIES_INVALID')
        return [_json(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > 1000 or any(not isinstance(key, str)
                or not key or len(key) > 200 or '\x00' in key for key in value):
            raise ValueError('SOURCE_EVIDENCE_PROPERTIES_INVALID')
        return {key: _json(item, depth=depth + 1)
                for key, item in sorted(value.items())}
    raise ValueError('SOURCE_EVIDENCE_PROPERTIES_INVALID')


def _program(program: object, function: str, fields: set[str],
             optional: set[str] = frozenset()) -> dict:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or program.get('languageVersion') != 2
            or program.get('function') != function
            or not isinstance(program.get('arguments'), dict)
            or not fields <= set(program['arguments'])
            or set(program['arguments']) - (fields | optional)):
        raise ValueError('SOURCE_EVIDENCE_PROGRAM_INVALID')
    return program['arguments']


def _members(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > 128:
        raise ValueError('SOURCE_EVIDENCE_COORDINATE_INVALID')
    result = {}
    for dimension, member in sorted(value.items()):
        result[_id(dimension, 'SOURCE_EVIDENCE_COORDINATE_INVALID')] = _id(
            member, 'SOURCE_EVIDENCE_COORDINATE_INVALID')
    return result


def _pointer(value: object) -> dict:
    if not isinstance(value, dict) or set(value) - _POINTER_KEYS:
        raise ValueError('SOURCE_EVIDENCE_POINTER_INVALID')
    result = {}
    for key, item in sorted(value.items()):
        if key in ('page', 'line'):
            if type(item) is not int or item < 1:
                raise ValueError('SOURCE_EVIDENCE_POINTER_INVALID')
        elif key == 'column':
            if (type(item) is not int or item < 1) and (
                    not isinstance(item, str) or not 1 <= len(item) <= 100):
                raise ValueError('SOURCE_EVIDENCE_POINTER_INVALID')
        else:
            limit = 4096 if key in ('url', 'jsonPointer') else 200
            # RFC 6901 defines the empty string as the whole-document pointer.
            # Other textual pointers must identify a nonempty location.
            _text(item, limit, required=key != 'jsonPointer')
        result[key] = item
    return result


def _authority_digest(db, identity, scope, function, access) -> str:
    dimensional = (resolve_effective_dimensional_scope(
        db, identity, scope, access=access, function=function).scope_digest
        if function in (RECORD_READ, RECORD_LIST, RECORD_SAVE, RECORD_DELETE) else None)
    return _canonical_digest({'role': access.role, 'administrator': access.workspace_administrator,
                              'groups': access.groups, 'dimensionalScope': dimensional})


class PostgresSourceEvidence:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 cursor_secret: bytes):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        if not isinstance(cursor_secret, bytes) or len(cursor_secret) < 32:
            raise ValueError('SOURCE_EVIDENCE_CURSOR_SECRET_INVALID')
        self.dsn, self.identity = dsn, identity
        self.cursor_secret = cursor_secret

    def _pack_cursor(self, value: dict) -> str:
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode('ascii')
        signature = hmac.new(self.cursor_secret, raw, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(raw + signature).decode('ascii')

    def _unpack_cursor(self, token: object, scope: ApplicationScope,
                       function: str) -> dict:
        try:
            if (not isinstance(token, str)
                    or not 1 <= len(token) <= _CURSOR_MAX_BYTES):
                raise ValueError()
            packed = base64.b64decode(token, altchars=b'-_', validate=True)
            if len(packed) <= 32:
                raise ValueError()
            raw, signature = packed[:-32], packed[-32:]
            expected = hmac.new(self.cursor_secret, raw, hashlib.sha256).digest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError()
            value = json.loads(raw)
            if (not isinstance(value, dict)
                    or set(value) != {'format', 'function', 'scope', 'identity', 'query',
                                     'after', 'metadataRevision',
                                     'securityRevision', 'authorityDigest', 'expires'}
                    or value['format'] != _CURSOR_FORMAT
                    or value['function'] != function
                    or value['scope'] != [scope.workspace_id,
                                          scope.application_id]
                    or value['identity'] != [self.identity.issuer,
                                             self.identity.subject_id]
                    or not isinstance(value['query'], dict)
                    or not isinstance(value['after'], str)
                    or type(value['metadataRevision']) is not int
                    or type(value['securityRevision']) is not int
                    or not isinstance(value['authorityDigest'], str)
                    or _DIGEST.fullmatch(value['authorityDigest']) is None
                    or type(value['expires']) is not int
                    or value['expires'] <= time.time()):
                raise ValueError()
            return value
        except (ValueError, TypeError, KeyError, binascii.Error,
                UnicodeError, json.JSONDecodeError) as error:
            raise ValueError('SOURCE_EVIDENCE_CURSOR_INVALID') from error

    @staticmethod
    def _write_payload(function: str, program: dict) -> tuple[dict, int, str]:
        base = {'expectedStateToken', 'expectedMetadataRevision'}
        if function == COLLECTION_SAVE:
            args = _program(program, function, base | {'collectionId', 'name',
                'collectionKind', 'description'})
            kind = args['collectionKind']
            if kind not in _KINDS:
                raise ValueError('SOURCE_EVIDENCE_COLLECTION_KIND_INVALID')
            payload = {'collectionId': _id(args['collectionId']),
                'name': _text(args['name'], 200, required=True),
                'collectionKind': kind,
                'description': _text(args['description'], 2000)}
        elif function == COLLECTION_DELETE:
            args = _program(program, function,
                base | {'collectionId'})
            payload = {'collectionId': _id(args['collectionId'])}
        elif function == DOCUMENT_SAVE:
            args = _program(program, function, base | {'collectionId',
                'documentId', 'title', 'mediaType', 'sourceUri',
                'sourceRevision', 'contentDigest'})
            if not isinstance(args['mediaType'], str) or not _MEDIA.fullmatch(args['mediaType']):
                raise ValueError('SOURCE_EVIDENCE_MEDIA_TYPE_INVALID')
            if not isinstance(args['contentDigest'], str) or not _DIGEST.fullmatch(args['contentDigest']):
                raise ValueError('SOURCE_EVIDENCE_CONTENT_DIGEST_INVALID')
            payload = {'collectionId': _id(args['collectionId']),
                'documentId': _id(args['documentId']),
                'title': _text(args['title'], 500, required=True),
                'mediaType': args['mediaType'],
                'sourceUri': _text(args['sourceUri'], 4096),
                'sourceRevision': _text(args['sourceRevision'], 500, required=True),
                'contentDigest': args['contentDigest']}
        elif function == DOCUMENT_DELETE:
            args = _program(program, function,
                base | {'collectionId', 'documentId'})
            payload = {'collectionId': _id(args['collectionId']),
                'documentId': _id(args['documentId'])}
        elif function == RECORD_SAVE:
            args = _program(program, function, base | {'collectionId',
                'recordId', 'recordType', 'documentId', 'observationMembers',
                'sourcePointer', 'properties'})
            if not isinstance(args['recordType'], str) or not _TYPE.fullmatch(args['recordType']):
                raise ValueError('SOURCE_EVIDENCE_RECORD_TYPE_INVALID')
            document = args['documentId']
            if document is not None:
                document = _id(document)
            properties = _json(args['properties'])
            if not isinstance(properties, dict) or set(properties) & _RESERVED_PROPERTIES:
                raise ValueError('SOURCE_EVIDENCE_PROPERTIES_INVALID')
            payload = {'collectionId': _id(args['collectionId']),
                'recordId': _id(args['recordId']),
                'recordType': args['recordType'], 'documentId': document,
                'observationMembers': _members(args['observationMembers']),
                'sourcePointer': _pointer(args['sourcePointer']),
                'properties': properties}
            payload['contentDigest'] = _canonical_digest(payload)
        elif function == RECORD_DELETE:
            args = _program(program, function,
                base | {'collectionId', 'recordId'})
            payload = {'collectionId': _id(args['collectionId']),
                'recordId': _id(args['recordId'])}
        else:
            raise ValueError('SOURCE_EVIDENCE_PROGRAM_INVALID')
        return payload, _revision(args['expectedMetadataRevision']), _token(
            args['expectedStateToken'], allow_empty=function in {
                COLLECTION_SAVE, DOCUMENT_SAVE, RECORD_SAVE})

    @staticmethod
    def _state_token(function: str, payload: dict) -> str:
        return _canonical_digest({'objectModel': 'openepm-source-evidence-v1',
            'function': function.removesuffix('.save'), 'payload': payload})

    @staticmethod
    def _validate_coordinate(db, scope: ApplicationScope,
                             members: dict[str, str]) -> None:
        if not members:
            return
        rows = db.execute('''SELECT dimension_id FROM epm.dimension
            WHERE workspace_id=%s AND application_id=%s AND status='Active'
            AND model_role IS DISTINCT FROM 'Currency' ORDER BY dimension_id''',
            (scope.workspace_id, scope.application_id)).fetchall()
        dimensions = {row['dimension_id'] for row in rows}
        if set(members) != dimensions:
            raise ValueError('SOURCE_EVIDENCE_COORDINATE_GRAIN_MISMATCH')
        supplied = [{'dimension_id': axis, 'member_id': member}
                    for axis, member in members.items()]
        invalid = db.execute('''SELECT 1 FROM jsonb_to_recordset(%s::jsonb)
            i(dimension_id text,member_id text) LEFT JOIN epm.member m
            ON m.workspace_id=%s AND m.application_id=%s
            AND m.dimension_id=i.dimension_id AND m.member_id=i.member_id
            AND m.status='Active' WHERE m.member_id IS NULL LIMIT 1''',
            (Jsonb(supplied), scope.workspace_id,
             scope.application_id)).fetchone()
        if invalid:
            raise ValueError('SOURCE_EVIDENCE_COORDINATE_MEMBER_UNAVAILABLE')

    def execute(self, scope: ApplicationScope, program: dict, *,
                idempotency_key: str) -> dict:
        function = program.get('function') if isinstance(program, dict) else None
        if function not in WRITE_FUNCTIONS:
            raise ValueError('SOURCE_EVIDENCE_PROGRAM_INVALID')
        if not is_signed_operation_id(idempotency_key):
            raise ValueError('OPERATION_ADMISSION_REQUIRED')
        payload, expected_revision, expected_token = self._write_payload(
            function, program)
        state_token = (None if function.endswith('.delete') else
                       self._state_token(function, payload))
        digest = _canonical_digest(program)
        keys = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write', function=function, arguments=program['arguments'])
                authority = _authority_digest(db, self.identity, scope, function, access)

                def recheck_authority():
                    current = PostgresAccessChecker.check_in_transaction(
                        db, self.identity, scope, 'write', function=function, arguments=program['arguments'])
                    if (current != access
                            or _authority_digest(db, self.identity, scope, function, current) != authority):
                        raise ValueError(WRITE_AUTHORIZATION_STALE)

                state = db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.commit_revision FROM epm.application_state s
                    JOIN epm.application a USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s''',
                    keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                prior = db.execute('''SELECT command_digest,actor_id,committed_revision,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (*keys, idempotency_key)).fetchone()
                if prior:
                    if prior['command_digest'] != digest or prior['actor_id'] != self.identity.subject_id:
                        raise ValueError('SOURCE_EVIDENCE_IDEMPOTENCY_CONFLICT')
                    PostgresNumericFactStore._require_replay_impact(
                        db, scope, idempotency_key, prior)
                    recheck_authority()
                    return {**prior['result'], 'duplicate': True}
                if state['status'] != 'Active' or state['processing_mode'] != 'Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if state['metadata_revision'] != expected_revision:
                    raise ValueError('STALE_METADATA_REVISION')
                table, id_column, id_value = (
                    ('source_evidence_collection', 'collection_id', payload['collectionId'])
                    if function.startswith('source.evidence.collection.') else
                    ('source_evidence_document', 'document_id', payload['documentId'])
                    if function.startswith('source.evidence.document.') else
                    ('source_evidence_record', 'record_id', payload['recordId']))
                where = '''workspace_id=%s AND application_id=%s AND collection_id=%s'''
                values = (*keys, payload['collectionId'])
                if table != 'source_evidence_collection':
                    where += ' AND '+id_column+'=%s'
                    values += (id_value,)
                current = db.execute('SELECT state_token'+(
                    ',observation_members AS members'
                    if table == 'source_evidence_record' else '')+' FROM epm.'+table+
                    ' WHERE '+where+' FOR UPDATE', values).fetchone()
                if table != 'source_evidence_collection':
                    parent = db.execute('''SELECT 1
                        FROM epm.source_evidence_collection
                        WHERE workspace_id=%s AND application_id=%s
                        AND collection_id=%s''',
                        (*keys, payload['collectionId'])).fetchone()
                    if parent is None:
                        raise ValueError(
                            'SOURCE_EVIDENCE_COLLECTION_UNAVAILABLE')
                if (function == RECORD_SAVE
                        and payload.get('documentId') is not None):
                    document = db.execute('''SELECT 1
                        FROM epm.source_evidence_document
                        WHERE workspace_id=%s AND application_id=%s
                        AND collection_id=%s AND document_id=%s''',
                        (*keys, payload['collectionId'],
                         payload['documentId'])).fetchone()
                    if document is None:
                        raise ValueError(
                            'SOURCE_EVIDENCE_DOCUMENT_UNAVAILABLE')
                if table == 'source_evidence_record':
                    new_members = payload.get('observationMembers', {})
                    self._validate_coordinate(db, scope, new_members)
                    protected = [new_members]
                    if current is not None and current['members'] != new_members:
                        protected.append(current['members'])
                    authorize_coordinates(db, self.identity, scope,
                        (Coordinate.from_mapping(members) for members in protected if members),
                        kind=AccessKind.WRITE, expected_access=access)
                if function.endswith('.save'):
                    if current is None and expected_token != '':
                        raise ValueError('SOURCE_EVIDENCE_OBJECT_UNAVAILABLE')
                    if current is not None and current['state_token'] != expected_token:
                        raise ValueError('SOURCE_EVIDENCE_STATE_STALE')
                    if current is not None and current['state_token'] == state_token:
                        raise ValueError('SOURCE_EVIDENCE_OBJECT_UNCHANGED')
                else:
                    if current is None:
                        raise ValueError('SOURCE_EVIDENCE_OBJECT_UNAVAILABLE')
                    if current['state_token'] != expected_token:
                        raise ValueError('SOURCE_EVIDENCE_STATE_STALE')
                    if table == 'source_evidence_collection':
                        if db.execute('''SELECT 1 FROM epm.source_evidence_document
                            WHERE workspace_id=%s AND application_id=%s
                            AND collection_id=%s UNION ALL SELECT 1 FROM
                            epm.source_evidence_record WHERE workspace_id=%s
                            AND application_id=%s AND collection_id=%s LIMIT 1''',
                            (*keys, payload['collectionId'], *keys,
                             payload['collectionId'])).fetchone():
                            raise ValueError('SOURCE_EVIDENCE_COLLECTION_REFERENCED')
                    if table == 'source_evidence_document' and db.execute(
                            '''SELECT 1 FROM epm.source_evidence_record
                            WHERE workspace_id=%s AND application_id=%s
                            AND collection_id=%s AND document_id=%s LIMIT 1''',
                            (*keys, payload['collectionId'],
                             payload['documentId'])).fetchone():
                        raise ValueError('SOURCE_EVIDENCE_DOCUMENT_REFERENCED')
                revision = state['metadata_revision'] + 1
                commit = state['commit_revision'] + 1
                existed = current is not None
                object_type = ('source-evidence-collection'
                    if table == 'source_evidence_collection' else
                    'source-evidence-document'
                    if table == 'source_evidence_document' else
                    'source-evidence-record')
                from .postgres_calculation_impact import object_impact
                impact = object_impact(source_kind='metadata',
                    operation_id=idempotency_key, causal_revision=commit,
                    domain='application', object_type=object_type,
                    object_id=(('sha256:' + _canonical_digest({
                        'collectionId': payload['collectionId'],
                        'objectId': id_value}))
                        if table != 'source_evidence_collection' else id_value),
                    change=('delete' if function.endswith('.delete') else
                            'update' if existed else 'insert'),
                    reason='definition_changed',
                    old_presence='present' if existed else 'absent',
                    new_presence=('absent' if function.endswith('.delete')
                                  else 'present'))
                result = {'function': function, 'collectionId': payload['collectionId'],
                    'objectId': id_value, 'stateToken': state_token,
                    'metadataRevision': revision, 'committedRevision': commit,
                    'operationId': idempotency_key,
                    'impactDigest': impact.digest}
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,command_digest,
                     actor_id,committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys, idempotency_key, digest,
                     self.identity.subject_id, commit, Jsonb(result)))
                if function == COLLECTION_SAVE:
                    db.execute('''INSERT INTO epm.source_evidence_collection
                        (workspace_id,application_id,collection_id,name,collection_kind,
                         description,state_token,metadata_revision,updated_issuer,
                         updated_subject_id,updated_operation_id) VALUES
                        (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT(workspace_id,application_id,collection_id) DO UPDATE SET
                         name=excluded.name,collection_kind=excluded.collection_kind,
                         description=excluded.description,state_token=excluded.state_token,
                         metadata_revision=excluded.metadata_revision,
                         updated_issuer=excluded.updated_issuer,
                         updated_subject_id=excluded.updated_subject_id,
                         updated_operation_id=excluded.updated_operation_id,
                         updated_at=transaction_timestamp()''',
                        (*keys, payload['collectionId'], payload['name'],
                         payload['collectionKind'], payload['description'], state_token,
                         revision, self.identity.issuer, self.identity.subject_id,
                         idempotency_key))
                elif function == DOCUMENT_SAVE:
                    db.execute('''INSERT INTO epm.source_evidence_document
                        (workspace_id,application_id,collection_id,document_id,title,
                         media_type,source_uri,source_revision,content_digest,state_token,
                         metadata_revision,updated_issuer,updated_subject_id,updated_operation_id)
                        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT(workspace_id,application_id,collection_id,document_id)
                        DO UPDATE SET title=excluded.title,media_type=excluded.media_type,
                         source_uri=excluded.source_uri,source_revision=excluded.source_revision,
                         content_digest=excluded.content_digest,state_token=excluded.state_token,
                         metadata_revision=excluded.metadata_revision,
                         updated_issuer=excluded.updated_issuer,
                         updated_subject_id=excluded.updated_subject_id,
                         updated_operation_id=excluded.updated_operation_id,
                         updated_at=transaction_timestamp()''',
                        (*keys, payload['collectionId'], payload['documentId'],
                         payload['title'], payload['mediaType'], payload['sourceUri'],
                         payload['sourceRevision'], payload['contentDigest'], state_token,
                         revision, self.identity.issuer, self.identity.subject_id,
                         idempotency_key))
                elif function == RECORD_SAVE:
                    db.execute('''INSERT INTO epm.source_evidence_record
                        (workspace_id,application_id,collection_id,record_id,record_type,
                         document_id,observation_members,source_pointer,properties,
                         content_digest,state_token,metadata_revision,updated_issuer,
                         updated_subject_id,updated_operation_id) VALUES
                        (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT(workspace_id,application_id,collection_id,record_id)
                        DO UPDATE SET record_type=excluded.record_type,
                         document_id=excluded.document_id,
                         observation_members=excluded.observation_members,
                         source_pointer=excluded.source_pointer,properties=excluded.properties,
                         content_digest=excluded.content_digest,state_token=excluded.state_token,
                         metadata_revision=excluded.metadata_revision,
                         updated_issuer=excluded.updated_issuer,
                         updated_subject_id=excluded.updated_subject_id,
                         updated_operation_id=excluded.updated_operation_id,
                         updated_at=transaction_timestamp()''',
                        (*keys, payload['collectionId'], payload['recordId'],
                         payload['recordType'], payload['documentId'],
                         Jsonb(payload['observationMembers']), Jsonb(payload['sourcePointer']),
                         Jsonb(payload['properties']), payload['contentDigest'], state_token,
                         revision, self.identity.issuer, self.identity.subject_id,
                         idempotency_key))
                else:
                    db.execute('DELETE FROM epm.'+table+' WHERE '+where, values)
                db.execute('''UPDATE epm.application_state SET commit_revision=%s,
                    metadata_revision=%s WHERE workspace_id=%s AND application_id=%s''',
                    (commit, revision, *keys))
                from .postgres_calculation_impact import record_calculation_impact
                record_calculation_impact(db, scope,
                    operation_id=idempotency_key, impact=impact)
                recheck_authority()
                return {**result, 'duplicate': False}

    @staticmethod
    def _public(row: dict) -> dict:
        result = {''.join((part if index == 0 else part.title())
                          for index, part in enumerate(key.split('_'))): value
                  for key, value in row.items()
                  if key not in {'updated_issuer', 'updated_subject_id',
                                 'updated_operation_id'}}
        result['updatedAt'] = result['updatedAt'].isoformat()
        return result

    def read(self, scope: ApplicationScope, program: dict) -> dict:
        if (not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or program.get('languageVersion') != 2
                or not isinstance(program.get('arguments'), dict)):
            raise ValueError('SOURCE_EVIDENCE_PROGRAM_INVALID')
        function = program.get('function') if isinstance(program, dict) else None
        if function not in READ_FUNCTIONS:
            raise ValueError('SOURCE_EVIDENCE_PROGRAM_INVALID')
        list_function = function.endswith('.list')
        raw_arguments = (program.get('arguments')
                         if isinstance(program, dict) else None)
        cursor = None
        if list_function and isinstance(raw_arguments, dict) \
                and set(raw_arguments) == {'cursor'}:
            cursor = self._unpack_cursor(raw_arguments['cursor'], scope,
                                         function)
            args = cursor['query']
            after = cursor['after']
        else:
            if function in (COLLECTION_READ, COLLECTION_LIST):
                required = set() if list_function else {'collectionId'}
                optional = {'limit'} if list_function else set()
            elif function in (DOCUMENT_READ, DOCUMENT_LIST):
                required = {'collectionId'} | (
                    set() if list_function else {'documentId'})
                optional = {'limit'} if list_function else set()
            else:
                required = {'collectionId'} | (
                    set() if list_function else {'recordId'})
                optional = ({'limit', 'recordType'}
                            if list_function else set())
            args = _program(program, function, required, optional)
            after = ''
        limit = args.get('limit', 100)
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError('SOURCE_EVIDENCE_PAGE_LIMIT_INVALID')
        collection = _id(args['collectionId']) if 'collectionId' in args else None
        if after:
            _id(after, 'SOURCE_EVIDENCE_CURSOR_INVALID')
        record_type = args.get('recordType')
        if record_type is not None and (
                not isinstance(record_type, str)
                or not _TYPE.fullmatch(record_type)):
            raise ValueError('SOURCE_EVIDENCE_RECORD_TYPE_INVALID')
        query = dict(args)
        keys = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=function, arguments=query)
                authority = _authority_digest(db, self.identity, scope, function, access)
                state = db.execute('''SELECT metadata_revision,security_revision
                    FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''', keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if cursor and (
                        cursor['metadataRevision'] != state['metadata_revision']
                        or cursor['securityRevision'] != state['security_revision']
                        or cursor['authorityDigest'] != authority):
                    raise ValueError('SOURCE_EVIDENCE_CURSOR_STALE')
                has_more, next_after = False, None
                if function == COLLECTION_READ:
                    rows = db.execute('''SELECT collection_id,name,collection_kind,
                        description,state_token,metadata_revision,updated_at
                        FROM epm.source_evidence_collection WHERE workspace_id=%s
                        AND application_id=%s AND collection_id=%s''',
                        (*keys, collection)).fetchall()
                elif function == COLLECTION_LIST:
                    rows = db.execute('''SELECT collection_id,name,collection_kind,
                        description,state_token,metadata_revision,updated_at
                        FROM epm.source_evidence_collection WHERE workspace_id=%s
                        AND application_id=%s AND collection_id>%s
                        ORDER BY collection_id LIMIT %s''', (*keys, after, limit + 1)).fetchall()
                elif function == DOCUMENT_READ:
                    document = _id(args['documentId'])
                    rows = db.execute('''SELECT collection_id,document_id,title,media_type,
                        source_uri,source_revision,content_digest,state_token,
                        metadata_revision,updated_at FROM epm.source_evidence_document
                        WHERE workspace_id=%s AND application_id=%s
                        AND collection_id=%s AND document_id=%s''',
                        (*keys, collection, document)).fetchall()
                elif function == DOCUMENT_LIST:
                    rows = db.execute('''SELECT collection_id,document_id,title,media_type,
                        source_uri,source_revision,content_digest,state_token,
                        metadata_revision,updated_at FROM epm.source_evidence_document
                        WHERE workspace_id=%s AND application_id=%s
                        AND collection_id=%s AND document_id>%s
                        ORDER BY document_id LIMIT %s''',
                        (*keys, collection, after, limit + 1)).fetchall()
                else:
                    record = (_id(args['recordId'])
                              if function == RECORD_READ else None)

                    def fetch_records(page_after, page_limit):
                        return db.execute('''SELECT collection_id,record_id,record_type,
                            document_id,observation_members AS members,source_pointer,
                            properties,content_digest,state_token,metadata_revision,updated_at
                            FROM epm.source_evidence_record WHERE workspace_id=%s
                            AND application_id=%s AND collection_id=%s
                            AND (%s::text IS NULL OR record_id=%s)
                            AND record_id COLLATE "C">%s AND (%s::text IS NULL OR record_type=%s)
                            ORDER BY record_id COLLATE "C" LIMIT %s''',
                            (*keys, collection, record, record, page_after,
                             record_type, record_type, page_limit)).fetchall()

                    if list_function:
                        rows, has_more, next_after = authorized_read_page(
                            db, self.identity, scope, after=after, limit=limit,
                            fetch=fetch_records, cursor_key=lambda row: row['record_id'],
                            expected_access=access, allow_unbound=True)
                    else:
                        rows = filter_read_rows(db, self.identity, scope, fetch_records(after, 1),
                                                expected_access=access, allow_unbound=True)
                if function in (COLLECTION_LIST, DOCUMENT_LIST):
                    has_more = len(rows) > limit
                    rows = rows[:limit]
                    if has_more:
                        next_after = rows[-1]['collection_id' if function == COLLECTION_LIST else 'document_id']
                current_access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=function, arguments=query)
                if (current_access != access
                        or _authority_digest(db, self.identity, scope, function, current_access) != authority):
                    raise ValueError(READ_AUTHORIZATION_STALE)
                end = db.execute('''SELECT metadata_revision,security_revision
                    FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''', keys).fetchone()
                if end is None or end != state:
                    raise ValueError('METADATA_CHANGED_DURING_READ')
        if not list_function:
            if not rows:
                raise ValueError('SOURCE_EVIDENCE_OBJECT_UNAVAILABLE')
            return {**self._public(dict(rows[0])),
                    'metadataRevision': state['metadata_revision']}
        items = [self._public(dict(row)) for row in rows]
        next_cursor = None
        if has_more:
            next_cursor = self._pack_cursor({
                'format': _CURSOR_FORMAT,
                'function': function,
                'scope': [scope.workspace_id, scope.application_id],
                'identity': [self.identity.issuer, self.identity.subject_id],
                'query': query, 'after': next_after,
                'metadataRevision': state['metadata_revision'],
                'securityRevision': state['security_revision'],
                'authorityDigest': authority,
                'expires': (cursor['expires'] if cursor
                            else int(time.time()) + _CURSOR_TTL)})
        return {'metadataRevision': state['metadata_revision'], 'items': items,
                'nextCursor': next_cursor, 'hasMore': has_more}
