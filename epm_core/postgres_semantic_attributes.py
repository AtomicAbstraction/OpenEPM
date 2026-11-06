"""Defined, typed semantic metadata values on PostgreSQL members and relationships.

Definitions and values use the existing scoped metadata tables. Every write
passes through a fixed operation, current grant, metadata revision and receipt.
No client may submit arbitrary columns or SQL.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, NumericCell
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore


CREATE = 'metadata.semantic_column.create'
UPDATE = 'metadata.semantic_column.update'
SET = 'metadata.member.attribute.set'
LIST = 'metadata.semantic_column.list'
READ = 'metadata.member.attributes.read'
REL_CREATE = 'metadata.relationship.semantic_column.create'
REL_UPDATE = 'metadata.relationship.semantic_column.update'
REL_SET = 'metadata.relationship.attribute.set'
REL_LIST = 'metadata.relationship.semantic_column.list'
REL_READ = 'metadata.relationship.attributes.read'
_TYPES = {'Text', 'Decimal', 'Boolean', 'MemberReference'}
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')


def _id(value: object) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 200
            or not value.strip() or '\x00' in value):
        raise ValueError('SEMANTIC_ID_INVALID')
    return value


def _text(value: object, limit: int, *, required: bool = False) -> str:
    if (not isinstance(value, str) or len(value) > limit
            or '\x00' in value or (required and not value.strip())):
        raise ValueError('SEMANTIC_TEXT_INVALID')
    return value


def _slot(value: object, maximum: int = 30) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError('SEMANTIC_SLOT_INVALID')
    return value


def _slot_key(value: int) -> str:
    return f'Custom{value:02d}'


def _program(program: object, function: str, required: set[str],
             optional: set[str] = frozenset()) -> dict:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != function
            or not isinstance(program['arguments'], dict)
            or not required <= set(program['arguments'])
            or set(program['arguments']) - (required | optional)):
        raise ValueError('SEMANTIC_PROGRAM_INVALID')
    return program['arguments']


class PostgresSemanticAttributes:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    @staticmethod
    def _definition(args: dict, *, maximum_slot: int = 30) -> dict:
        dimension = _id(args['dimensionId'])
        slot = _slot(args['slot'], maximum_slot)
        name = _text(args['displayName'], 200, required=True)
        kind = args['valueType']
        if not isinstance(kind, str) or kind not in _TYPES:
            raise ValueError('SEMANTIC_VALUE_TYPE_INVALID')
        choices = args.get('allowedValues', [])
        if (not isinstance(choices, list) or len(choices) > 100
                or any(not isinstance(value, str)
                       or not 1 <= len(value) <= 200
                       or '\x00' in value for value in choices)
                or len(set(choices)) != len(choices)
                or (choices and kind != 'Text')):
            raise ValueError('SEMANTIC_ALLOWED_VALUES_INVALID')
        reference = args.get('referenceDimensionId')
        if kind == 'MemberReference':
            reference = _id(reference)
        elif reference is not None:
            raise ValueError('SEMANTIC_REFERENCE_DIMENSION_INVALID')
        return {'dimensionId': dimension, 'slot': slot,
                'displayName': name,
                'semanticDefinition': _text(
                    args['semanticDefinition'], 2000, required=True),
                'populationGuidance': _text(
                    args['populationGuidance'], 2000),
                'restrictions': _text(args['restrictions'], 2000),
                'valueType': kind, 'allowedValues': choices,
                'referenceDimensionId': reference}

    @staticmethod
    def _description_update(args: dict, *, maximum_slot: int = 30) -> dict:
        return {'dimensionId': _id(args['dimensionId']),
                'slot': _slot(args['slot'], maximum_slot),
                'displayName': _text(args['displayName'], 200, required=True),
                'semanticDefinition': _text(
                    args['semanticDefinition'], 2000, required=True),
                'populationGuidance': _text(
                    args['populationGuidance'], 2000),
                'restrictions': _text(args['restrictions'], 2000)}

    @staticmethod
    def _value(db, scope: ApplicationScope, definition: dict,
               supplied: object) -> object:
        if supplied is None:
            return None
        properties = definition['properties']
        kind = properties.get('valueType')
        if kind == 'Text':
            value = _text(supplied, 2000)
            if (properties.get('allowedValues') and
                    value not in properties['allowedValues']):
                raise ValueError('MEMBER_ATTRIBUTE_CHOICE_INVALID')
            return value
        if kind == 'Boolean':
            if type(supplied) is not bool:
                raise ValueError('MEMBER_ATTRIBUTE_VALUE_INVALID')
            return supplied
        if kind == 'Decimal':
            if not isinstance(supplied, str):
                raise ValueError('MEMBER_ATTRIBUTE_DECIMAL_STRING_REQUIRED')
            try:
                number = Decimal(supplied)
                NumericCell(True, number, '')
            except (InvalidOperation, ValueError) as error:
                raise ValueError('MEMBER_ATTRIBUTE_DECIMAL_INVALID') from error
            return format(number, '.8f')
        if kind == 'MemberReference':
            member = _id(supplied)
            found = db.execute('''SELECT 1 FROM epm.member
                WHERE workspace_id=%s AND application_id=%s
                AND dimension_id=%s AND member_id=%s AND status='Active' ''',
                (scope.workspace_id, scope.application_id,
                 properties.get('referenceDimensionId'), member)).fetchone()
            if found is None:
                raise ValueError('SEMANTIC_REFERENCE_MEMBER_UNAVAILABLE')
            return member
        raise ValueError('SEMANTIC_VALUE_TYPE_INVALID')

    def execute(self, scope: ApplicationScope, program: dict, *,
                idempotency_key: str) -> dict:
        if not isinstance(scope, ApplicationScope):
            raise ValueError('Application scope is required')
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(
                idempotency_key):
            raise ValueError('SEMANTIC_IDEMPOTENCY_KEY_INVALID')
        function = program.get('function') if isinstance(program, dict) else None
        relationship = function in (REL_CREATE, REL_UPDATE, REL_SET)
        if function in (CREATE, REL_CREATE):
            args = _program(program, function, {
                'dimensionId', 'slot', 'displayName',
                'semanticDefinition', 'populationGuidance',
                'restrictions', 'valueType', 'expectedMetadataRevision'},
                {'allowedValues', 'referenceDimensionId'})
            payload = self._definition(
                args, maximum_slot=20 if relationship else 30)
        elif function in (UPDATE, REL_UPDATE):
            args = _program(program, function, {
                'dimensionId', 'slot', 'displayName',
                'semanticDefinition', 'populationGuidance',
                'restrictions', 'expectedMetadataRevision'})
            payload = self._description_update(
                args, maximum_slot=20 if relationship else 30)
        elif function in (SET, REL_SET):
            entity_id = ('relationshipId' if relationship else 'memberId')
            args = _program(program, function, {'dimensionId', entity_id,
                'slot', 'value', 'expectedMetadataRevision'})
            payload = {'dimensionId': _id(args['dimensionId']),
                entity_id: _id(args[entity_id]),
                'slot': _slot(args['slot'], 20 if relationship else 30),
                'value': args['value']}
            if (payload['value'] is not None
                    and type(payload['value']) is not bool
                    and not isinstance(payload['value'], str)):
                raise ValueError('MEMBER_ATTRIBUTE_VALUE_INVALID')
            if isinstance(payload['value'], str):
                _text(payload['value'], 2000)
        else:
            raise ValueError('SEMANTIC_PROGRAM_INVALID')
        expected = args['expectedMetadataRevision']
        if type(expected) is not int or expected < 0:
            raise ValueError('STALE_METADATA_REVISION')
        digest = _canonical_digest(program)
        payload_digest = _canonical_digest({
            'scope': [scope.workspace_id, scope.application_id],
            'identity': [self.identity.issuer, self.identity.subject_id],
            'payload': payload, 'expectedMetadataRevision': expected})
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                state = db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.commit_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin')
                prior = db.execute('''SELECT command_digest,
                    committed_revision,result FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s
                    AND operation_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     idempotency_key)).fetchone()
                if prior:
                    if (prior['command_digest'] != digest or
                            prior['result'].get('payloadDigest') !=
                            payload_digest):
                        raise ValueError('SEMANTIC_IDEMPOTENCY_CONFLICT')
                    return {'operationId': idempotency_key,
                            'committedRevision': prior['committed_revision'],
                            'metadataRevision': prior['result'][
                                'metadataRevision'], 'duplicate': True}
                if (state['status'] != 'Active' or
                        state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if state['metadata_revision'] != expected:
                    raise ValueError('STALE_METADATA_REVISION')
                keys = (scope.workspace_id, scope.application_id)
                entity = 'relationship' if relationship else 'member'
                semantic_scope = 'Relationship' if relationship else 'Member'
                if function in (CREATE, REL_CREATE, UPDATE, REL_UPDATE):
                    dimension = db.execute('''SELECT 1 FROM epm.dimension
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND status='Active' ''',
                        (*keys, payload['dimensionId'])).fetchone()
                    if dimension is None:
                        raise ValueError('ACTIVE_DIMENSION_REQUIRED')
                    reference = payload.get('referenceDimensionId')
                    if reference is not None:
                        ref = db.execute('''SELECT 1 FROM epm.dimension
                            WHERE workspace_id=%s AND application_id=%s
                            AND dimension_id=%s AND status='Active' ''',
                            (*keys, reference)).fetchone()
                        if ref is None:
                            raise ValueError('SEMANTIC_REFERENCE_DIMENSION_UNAVAILABLE')
                    collision = db.execute('''SELECT slot
                        FROM epm.semantic_column
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND scope=%s
                        AND lower(display_name)=lower(%s) LIMIT 1''',
                        (*keys, payload['dimensionId'],
                         semantic_scope,
                         payload['displayName'])).fetchone()
                    if collision:
                        if (function in (CREATE, REL_CREATE) or
                                collision['slot'] != payload['slot']):
                            raise ValueError('SEMANTIC_DISPLAY_NAME_EXISTS')
                    current = db.execute('''SELECT display_name,
                        semantic_definition,population_guidance,restrictions
                        FROM epm.semantic_column
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND scope=%s AND slot=%s''',
                        (*keys, payload['dimensionId'],
                         semantic_scope,
                         payload['slot'])).fetchone()
                    if function in (CREATE, REL_CREATE):
                        if current:
                            raise ValueError('SEMANTIC_SLOT_EXISTS')
                        occupied = db.execute('''SELECT 1 FROM epm.'''+entity+'''
                            WHERE workspace_id=%s AND application_id=%s
                            AND dimension_id=%s AND custom_values ? %s LIMIT 1''',
                            (*keys, payload['dimensionId'],
                             _slot_key(payload['slot']))).fetchone()
                        if occupied:
                            raise ValueError('SEMANTIC_SLOT_ALREADY_POPULATED')
                        db.execute('''INSERT INTO epm.semantic_column
                            (workspace_id,application_id,dimension_id,scope,
                             slot,display_name,semantic_definition,
                             population_guidance,restrictions,properties)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                            (*keys, payload['dimensionId'],semantic_scope,
                             payload['slot'],
                             payload['displayName'],
                             payload['semanticDefinition'],
                             payload['populationGuidance'],
                             payload['restrictions'], Jsonb({
                                 'valueType': payload['valueType'],
                                 'allowedValues': payload['allowedValues'],
                                 'referenceDimensionId': reference})))
                    else:
                        if current is None:
                            raise ValueError('SEMANTIC_COLUMN_UNDEFINED')
                        if all(current[column] == payload[field]
                               for column, field in (
                                   ('display_name', 'displayName'),
                                   ('semantic_definition', 'semanticDefinition'),
                                   ('population_guidance', 'populationGuidance'),
                                   ('restrictions', 'restrictions'))):
                            raise ValueError('SEMANTIC_DEFINITION_UNCHANGED')
                        db.execute('''UPDATE epm.semantic_column SET
                            display_name=%s,semantic_definition=%s,
                            population_guidance=%s,restrictions=%s,
                            updated_at=transaction_timestamp()
                            WHERE workspace_id=%s AND application_id=%s
                            AND dimension_id=%s AND scope=%s AND slot=%s''',
                            (payload['displayName'],
                             payload['semanticDefinition'],
                             payload['populationGuidance'],
                             payload['restrictions'], *keys,
                             payload['dimensionId'], semantic_scope,
                             payload['slot']))
                else:
                    definition = db.execute('''SELECT properties
                        FROM epm.semantic_column WHERE workspace_id=%s
                        AND application_id=%s AND dimension_id=%s
                        AND scope=%s AND slot=%s''',
                        (*keys, payload['dimensionId'], semantic_scope,
                         payload['slot'])).fetchone()
                    if definition is None:
                        raise ValueError('SEMANTIC_COLUMN_UNDEFINED')
                    entity_id = ('relationshipId' if relationship else
                                 'memberId')
                    id_column = ('relationship_id' if relationship else
                                 'member_id')
                    record = db.execute('''SELECT custom_values
                        FROM epm.'''+entity+''' WHERE workspace_id=%s
                        AND application_id=%s AND dimension_id=%s
                        AND '''+id_column+'''=%s AND status='Active'
                        FOR UPDATE''',
                        (*keys, payload['dimensionId'],
                         payload[entity_id])).fetchone()
                    if record is None:
                        raise ValueError('ACTIVE_RELATIONSHIP_REQUIRED'
                                         if relationship else
                                         'ACTIVE_MEMBER_REQUIRED')
                    value = self._value(db, scope, definition,
                                        payload['value'])
                    column = _slot_key(payload['slot'])
                    values = dict(record['custom_values'])
                    before = values.get(column)
                    if value is None:
                        values.pop(column, None)
                    else:
                        values[column] = value
                    if before == value:
                        raise ValueError('MEMBER_ATTRIBUTE_UNCHANGED')
                    db.execute('''UPDATE epm.'''+entity+''' SET custom_values=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND '''+id_column+'''=%s''',
                        (Jsonb(values), *keys, payload['dimensionId'],
                         payload[entity_id]))
                commit = state['commit_revision'] + 1
                revision = state['metadata_revision'] + 1
                db.execute('''UPDATE epm.application_state SET
                    commit_revision=%s,metadata_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (commit, revision, *keys))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                     command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys, idempotency_key, digest,
                     self.identity.subject_id, commit, Jsonb({
                         'function': function,
                         'metadataRevision': revision,
                         'payloadDigest': payload_digest})))
                return {'operationId': idempotency_key,
                        'committedRevision': commit,
                        'metadataRevision': revision,
                        'duplicate': False}

    def read(self, scope: ApplicationScope, program: dict) -> dict:
        if not isinstance(scope, ApplicationScope):
            raise ValueError('Application scope is required')
        function = program.get('function') if isinstance(program, dict) else None
        relationship = function in (REL_LIST, REL_READ)
        if function in (LIST, REL_LIST):
            args = _program(program, function, {'dimensionId'})
        elif function in (READ, REL_READ):
            args = _program(program, function, {'dimensionId',
                'relationshipId' if relationship else 'memberId'})
        else:
            raise ValueError('SEMANTIC_PROGRAM_INVALID')
        dimension = _id(args['dimensionId'])
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                start = db.execute('''SELECT metadata_revision FROM
                    epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if start is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                active = db.execute('''SELECT 1 FROM epm.dimension
                    WHERE workspace_id=%s AND application_id=%s
                    AND dimension_id=%s AND status='Active' ''',
                    (scope.workspace_id, scope.application_id,
                     dimension)).fetchone()
                if active is None:
                    raise ValueError('ACTIVE_DIMENSION_REQUIRED')
                record = None
                if function in (READ, REL_READ):
                    entity = 'relationship' if relationship else 'member'
                    id_column = ('relationship_id' if relationship else
                                 'member_id')
                    entity_id = _id(args['relationshipId' if relationship else
                                         'memberId'])
                    columns_sql = ('''parent_member_id,child_member_id,
                        custom_values''' if relationship else
                        'name,custom_values')
                    record = db.execute('''SELECT '''+columns_sql+'''
                        FROM epm.'''+entity+''' WHERE workspace_id=%s
                        AND application_id=%s AND dimension_id=%s
                        AND '''+id_column+'''=%s AND status='Active' ''',
                        (scope.workspace_id,scope.application_id,
                         dimension,entity_id)).fetchone()
                    if record is None:
                        raise ValueError('ACTIVE_RELATIONSHIP_REQUIRED'
                                         if relationship else
                                         'ACTIVE_MEMBER_REQUIRED')
                columns = db.execute('''SELECT slot,display_name,
                    semantic_definition,population_guidance,restrictions,
                    properties FROM epm.semantic_column
                    WHERE workspace_id=%s AND application_id=%s
                    AND dimension_id=%s AND scope=%s
                    ORDER BY slot''',
                    (scope.workspace_id,scope.application_id,
                     dimension,
                     'Relationship' if relationship else 'Member')).fetchall()
                end = db.execute('''SELECT metadata_revision FROM
                    epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if end is None or end['metadata_revision'] != (
                        start['metadata_revision']):
                    raise ValueError('METADATA_CHANGED_DURING_READ')
        base = {'dimensionId': dimension,
                'metadataRevision': start['metadata_revision']}
        definitions = [{**dict(row), 'key': _slot_key(row['slot'])}
                       for row in columns]
        if function in (LIST, REL_LIST):
            return {**base, 'columns': definitions}
        values = record['custom_values']
        entity_context = ({'relationshipId': entity_id,
                           'parentMemberId': record['parent_member_id'],
                           'childMemberId': record['child_member_id']}
                          if relationship else
                          {'memberId': entity_id,
                           'memberName': record['name']})
        return {**base, **entity_context,
                'attributes': [{**definition,
                    'value': values.get(definition['key'])}
                    for definition in definitions],
                'undefinedKeys': sorted(set(values) - {
                    definition['key'] for definition in definitions})}
