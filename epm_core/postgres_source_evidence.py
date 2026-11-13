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
    authorize_coordinate, filter_read_rows)
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
            'result': 'current typed collection and new state token'},
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
            'result': 'current typed document and new state token'},
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
            'result': 'current typed record and new state token'},
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
                    or set(value) != {'function', 'scope', 'identity', 'query',
                                     'after', 'metadataRevision',
                                     'securityRevision', 'expires'}
                    or value['function'] != function
                    or value['scope'] != [scope.workspace_id,
                                          scope.application_id]
                    or value['identity'] != [self.identity.issuer,
                                             self.identity.subject_id]
                    or not isinstance(value['query'], dict)
                    or not isinstance(value['after'], str)
                    or type(value['metadataRevision']) is not int
                    or type(value['securityRevision']) is not int
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
                state = db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.commit_revision FROM epm.application_state s
                    JOIN epm.application a USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s''',
                    keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                prior = db.execute('''SELECT command_digest,committed_revision,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (*keys, idempotency_key)).fetchone()
                if prior:
                    if prior['command_digest'] != digest:
                        raise ValueError('SOURCE_EVIDENCE_IDEMPOTENCY_CONFLICT')
                    PostgresNumericFactStore._require_replay_impact(
                        db, scope, idempotency_key, prior)
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
                    for members in protected:
                        if members:
                            authorize_coordinate(db, self.identity, scope,
                                Coordinate.from_mapping(members),
                                kind=AccessKind.WRITE)
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
                return {**result, 'duplicate': False}

    @staticmethod
    def _public(row: dict) -> dict:
        result = {''.join((part if index == 0 else part.title())
                          for index, part in enumerate(key.split('_'))): value
                  for key, value in row.items()
                  if key not in {'updated_issuer', 'updated_subject_id',
                                 'updated_operation_id'}}
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
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                state = db.execute('''SELECT metadata_revision,security_revision
                    FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''', keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if cursor and (
                        cursor['metadataRevision'] != state['metadata_revision']
                        or cursor['securityRevision'] != state['security_revision']):
                    raise ValueError('SOURCE_EVIDENCE_CURSOR_STALE')
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
                    rows = db.execute('''SELECT collection_id,record_id,record_type,
                        document_id,observation_members AS members,source_pointer,
                        properties,content_digest,state_token,metadata_revision,updated_at
                        FROM epm.source_evidence_record WHERE workspace_id=%s
                        AND application_id=%s AND collection_id=%s
                        AND (%s::text IS NULL OR record_id=%s)
                        AND record_id>%s AND (%s::text IS NULL OR record_type=%s)
                        ORDER BY record_id LIMIT %s''',
                        (*keys, collection, record, record, after,
                         record_type, record_type, (1 if record else limit + 1))).fetchall()
                    if record:
                        rows = filter_read_rows(db, self.identity, scope, rows)
                raw_has_more = False
                raw_after = None
                if list_function:
                    raw_has_more = len(rows) > limit
                    raw_page = rows[:limit]
                    if raw_has_more:
                        raw_after = raw_page[-1][
                            'collection_id' if function == COLLECTION_LIST else
                            'document_id' if function == DOCUMENT_LIST else
                            'record_id']
                    rows = (filter_read_rows(db, self.identity, scope, raw_page)
                            if function == RECORD_LIST else raw_page)
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
        if raw_has_more:
            next_cursor = self._pack_cursor({
                'function': function,
                'scope': [scope.workspace_id, scope.application_id],
                'identity': [self.identity.issuer, self.identity.subject_id],
                'query': query, 'after': raw_after,
                'metadataRevision': state['metadata_revision'],
                'securityRevision': state['security_revision'],
                'expires': (cursor['expires'] if cursor
                            else int(time.time()) + _CURSOR_TTL)})
        return {'metadataRevision': state['metadata_revision'], 'items': items,
                'nextCursor': next_cursor, 'hasMore': next_cursor is not None}
