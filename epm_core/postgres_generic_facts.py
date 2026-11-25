"""Fixed PostgreSQL CRUD for application-owned, nonfinancial JSON facts.

Opaque generic series are deliberately separate from typed EPM coordinates.
Every write passes through a V2 program, current grant, application-state lock,
expected revision/change ID, immutable event and atomic operation receipt.

For planning editability only, a value key has a deterministic guard coordinate:
``GenericFactTable=<tableId>`` and
``GenericFactSeriesDigest=sha256(UTF-8 seriesKey)``. Generic Set maps to ``Set``
and Generic Delete maps to ``Clear``. Scoped cube locks cannot accidentally
match these synthetic axes; an authoritative whole-application lock still does.
"""
from __future__ import annotations

from hashlib import sha256
import base64
import binascii
from contextlib import contextmanager
import hmac
import json
import re
import time
from uuid import uuid4

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope,Coordinate
from .postgres_access import AccessGroupsChanged, PostgresAccessChecker, VerifiedIdentity
from .postgres_numeric_store import PostgresNumericFactStore


CREATE = 'facts.generic.table.create'
UPDATE = 'facts.generic.table.update'
TABLE_DELETE = 'facts.generic.table.delete'
LIST = 'facts.generic.table.list'
SET = 'facts.generic.value.set'
DELETE = 'facts.generic.value.delete'
BULK = 'facts.generic.value.bulk'
READ = 'facts.generic.value.read'
SCAN = 'facts.generic.value.scan'
SNAPSHOT_SCAN = 'facts.generic.value.snapshot.scan'
READ_FUNCTIONS = frozenset((LIST, READ, SCAN, SNAPSHOT_SCAN))
READ_AUTHORIZATION_STALE = 'GENERIC_FACT_READ_AUTHORIZATION_STALE'
MAX_TABLE_PAGE = 100
MAX_VALUE_PAGE = 200
MAX_SERIES_KEY = 1000
MAX_CURSOR = 8192
_CURSOR_FORMAT = 'openepm-generic-snapshot-v2'
_ID = re.compile(r'[0-9a-f]{32}\Z')

# Generic facts intentionally do not have a validated cube coordinate.  Keep
# this distinction machine-readable so clients cannot mistake an application-
# scoped JSON record for data protected by cube member-tag policy.  The
# synthetic planning coordinate used below is only an editability/lock guard;
# it does not turn table IDs or series digests into metadata members.
GENERIC_FACT_DATA_CONTRACT = {
    'dataModel': 'application_non_dimensional_json',
    'authorizationModel': 'application_grant_and_rls',
    'dimensionalSecurity': 'not_applicable_no_cube_coordinate',
    'planningControlModel': 'synthetic_guard_coordinate_only',
}


def generic_read_program_contract(function: str) -> dict:
    from .metadata_read_contract import obj, read_contract, read_example

    identifier = {'type': 'string', 'pattern': r'^[0-9a-f]{32}(?![\s\S])'}
    key = {'type': 'string', 'minLength': 1, 'maxLength': MAX_SERIES_KEY}
    cursor = {'type': 'string', 'minLength': 1, 'maxLength': MAX_CURSOR}
    value = {'type': ['object', 'array', 'string', 'number', 'boolean']}
    last_revision = {'type': 'integer', 'minimum': 1}
    revision = {'type': 'integer', 'minimum': 0}
    boolean = {'type': 'boolean'}
    table = obj({
        'table_id': identifier, 'name': {'type': 'string', 'minLength': 1, 'maxLength': 200},
        'short_description': {'type': 'string', 'maxLength': 500},
        'semantic_definition': {'type': 'string', 'minLength': 1, 'maxLength': 2000},
        'status': {'enum': ['Active', 'Inactive']},
    })
    row = obj({'series_key': key, 'value': value, 'change_id': identifier,
               'last_revision': last_revision})
    table_binding = 'Use a table_id from facts.generic.table.list in the selected application.'
    sample_id = '0123456789abcdef0123456789abcdef'
    sample_key = 'item-a'
    rules = [
        'Generic facts are application-scoped JSON records with opaque series keys. Access is governed by the application grant.',
        'The server checks current table availability and READ access for every request.',
    ]

    if function == READ:
        arguments = obj({'tableId': identifier, 'seriesKey': key})
        result = obj({'tableId': identifier, 'seriesKey': key, 'exists': boolean,
                      'value': {}, 'changeId': {'type': 'string'},
                      'lastRevision': {'type': ['integer', 'null']}})
        result.update({
            'if': {'properties': {'exists': {'const': True}}},
            'then': {'properties': {'value': value, 'changeId': identifier,
                                    'lastRevision': last_revision}},
            'else': {'properties': {'value': {'type': 'null'}, 'changeId': {'const': ''},
                                    'lastRevision': {'type': 'null'}}},
        })
        examples = [read_example(function, {'tableId': sample_id, 'seriesKey': sample_key},
            name='Read one generic value', binding=table_binding + ' Supply the exact series key.')]
        rules.append('exists distinguishes an absent record from a present JSON false, zero, empty string or empty collection.')
    else:
        page_limit = MAX_TABLE_PAGE if function == LIST else MAX_VALUE_PAGE
        bounds = {'type': 'integer', 'minimum': 1, 'maximum': page_limit}
        if function == LIST:
            anchor_name, next_name, anchor, example = (
                'afterTableId', 'nextAfterTableId', identifier, sample_id)
            shared = {}
            fields = {}
            page_row = table
            first_binding = 'Select the authorized application and start with afterTableId null.'
            rules.append('Table discovery lists current Active and Inactive tables. Each page is a live directory read.')
        elif function == SCAN:
            anchor_name, next_name, anchor, example = (
                'afterSeriesKey', 'nextAfterSeriesKey', key, sample_key)
            shared = {'tableId': identifier}
            fields = dict(shared)
            page_row = row
            first_binding = table_binding
            rules.append('A current scan reads live values. Use facts.generic.value.snapshot.scan to retain one committed cut across pages.')
        elif function == SNAPSHOT_SCAN:
            anchor_name, next_name, anchor, example = ('cursor', 'nextCursor', cursor, 'example-cursor')
            shared = {'tableId': identifier}
            fields = {**shared, 'snapshotRevision': revision, 'metadataRevision': revision}
            page_row = row
            first_binding = table_binding + ' Start with cursor null.'
            rules.append('The continuation pins one committed revision. Copy the signed cursor, retaining the original table, limit, application and verified identity. Metadata changes invalidate the page sequence.')
        else:
            raise ValueError('V2_GENERIC_FACT_FUNCTION_UNSUPPORTED')
        optional_anchor = {'anyOf': [anchor, {'type': 'null'}]}
        arguments = obj({**shared, 'limit': bounds, anchor_name: optional_anchor})
        result = obj({**fields, 'rows': {'type': 'array', 'items': page_row, 'maxItems': page_limit},
                      'hasMore': boolean, next_name: optional_anchor})
        result.update({
            'if': {'properties': {'hasMore': {'const': True}}},
            'then': {'properties': {'rows': {'minItems': 1}, next_name: anchor}},
            'else': {'properties': {next_name: {'type': 'null'}}},
        })
        first = {**({'tableId': sample_id} if shared else {}), 'limit': 1, anchor_name: None}
        examples = [read_example(function, first, name='Read the first page', binding=first_binding),
                    read_example(function, {**first, anchor_name: example}, name='Read the next page',
                        binding=f'Use {next_name} from the previous page as {anchor_name}; keep the same scope and limit.')]

    contract = read_contract(function, arguments, result, owner='PostgresGenericFacts.read',
                             examples=examples, semantic_rules=rules)
    contract['programContract']['recovery'] = (
        'If access changes, rediscover the authorized application and retry the exact lookup or restart paging. '
        'Use current table discovery after an unavailable table, and restart a snapshot with a null cursor after metadata changes or cursor expiry.')
    return contract


def _planning_coordinate(table_id: str,series_key: str) -> Coordinate:
    return Coordinate.from_mapping({
        'GenericFactTable':table_id,
        'GenericFactSeriesDigest':sha256(series_key.encode('utf-8')).hexdigest()})


def _program(program: object, function: str, fields: set[str]) -> dict:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != function
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != fields):
        raise ValueError('V2_GENERIC_FACT_ARGUMENTS_INVALID')
    return program['arguments']


def _text(value: object, *, maximum: int, label: str) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= maximum
            or value != value.strip()):
        raise ValueError(label + '_INVALID')
    return value


def _nonnegative(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(label + '_INVALID')
    return value


def _validate_publication_base(current_revision: int,
                               expected_revision: int) -> None:
    """Allow an older reviewed base; reject a base the server never reached.

    Target change IDs, acquired locks and prepared-input revalidation remain
    authoritative for overlap. Treating this application-wide counter as a
    target fence would reject unrelated public writes.
    """
    if expected_revision > current_revision:
        raise ValueError('STALE_DATA_REVISION')


class PostgresGenericFacts:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 cursor_secret: bytes | None = None):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        if cursor_secret is not None and (not isinstance(cursor_secret,bytes)
                                          or len(cursor_secret) < 32):
            raise ValueError('GENERIC_CURSOR_SECRET_INVALID')
        self.dsn, self.identity = dsn, identity
        self.cursor_secret = cursor_secret

    @staticmethod
    def catalog() -> dict:
        functions = {CREATE: {'mode': 'atomic_write', 'permission': 'admin',
            'arguments': {'name': 'unique application-local name',
                          'shortDescription': 'text up to 500 characters',
                          'semanticDefinition': 'text up to 2000 characters',
                          'expectedMetadataRevision': 'nonnegative integer'},
            'result': 'new table ID and atomic metadata receipt',
            'previewRequired': False, 'idempotencyRequired': True,
            'workClass': 'short'},
            UPDATE: {'mode': 'atomic_write', 'permission': 'admin',
            'arguments': {'tableId': 'registered generic table ID',
                          'name': 'unique application-local name',
                          'shortDescription': 'text up to 500 characters',
                          'semanticDefinition': 'text up to 2000 characters',
                          'status': 'Active or Inactive',
                          'expectedMetadataRevision': 'nonnegative integer'},
            'result': 'updated table and atomic metadata receipt',
            'previewRequired': False, 'idempotencyRequired': True,
            'workClass': 'short'},
            TABLE_DELETE: {'mode': 'atomic_write', 'permission': 'admin',
            'arguments': {'tableId': 'registered generic table ID',
                          'expectedMetadataRevision': 'nonnegative integer'},
            'result': 'retired empty table with retained event provenance',
            'previewRequired': False, 'idempotencyRequired': True,
            'workClass': 'short'},
            SET: {'mode': 'atomic_write', 'permission': 'write',
            'arguments': {'tableId': 'registered generic table ID',
                          'seriesKey': 'opaque key up to 1000 characters',
                          'value': 'finite non-null JSON up to 100000 characters',
                          'expectedChangeId': 'current change ID or empty',
                          'expectedDataRevision': 'initially current nonnegative integer; later disjoint commits are revalidated'},
            'result': 'new change ID and atomic data/event receipt',
            'previewRequired': False, 'idempotencyRequired': True,
            'workClass': 'short'},
            DELETE: {'mode': 'atomic_write', 'permission': 'write',
            'arguments': {'tableId': 'registered generic table ID',
                          'seriesKey': 'opaque key up to 1000 characters',
                          'expectedChangeId': 'current change ID',
                          'expectedDataRevision': 'initially current nonnegative integer; later disjoint commits are revalidated'},
            'result': 'deletion and atomic data/event receipt',
            'previewRequired': False, 'idempotencyRequired': True,
            'workClass': 'short'},
            BULK: {'mode': 'atomic_write', 'permission': 'write',
            'arguments': {'tableId': 'registered generic table ID',
                          'changes': '1–100 distinct Set/Delete series changes',
                          'expectedDataRevision': 'initially current nonnegative integer; later disjoint commits are revalidated'},
            'result': 'one revision and receipt for all value events',
            'previewRequired': False, 'idempotencyRequired': True,
            'workClass': 'short'},
            LIST: {'mode': 'read', 'permission': 'read',
            'arguments': {'afterTableId': 'optional exclusive table ID',
                          'limit': '1–100'}, 'result': 'bounded table page',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'},
            READ: {'mode': 'read', 'permission': 'read',
            'arguments': {'tableId': 'registered generic table ID',
                          'seriesKey': 'opaque key'},
            'result': 'current value and change ID or explicit absence',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'},
            SCAN: {'mode': 'read', 'permission': 'read',
            'arguments': {'tableId': 'registered generic table ID',
                          'afterSeriesKey': 'optional exclusive key',
                          'limit': '1–200'},
            'result': 'bounded current-value page',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'},
            SNAPSHOT_SCAN: {'mode': 'read', 'permission': 'read',
            'arguments': {'tableId': 'registered generic table ID',
                          'limit': '1–200',
                          'cursor': 'null initially, then signed page cursor'},
            'result': 'bounded page pinned to one committed revision',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'}}
        return {name: {**specification, **GENERIC_FACT_DATA_CONTRACT,
                       **(generic_read_program_contract(name) if name in READ_FUNCTIONS else {})}
                for name, specification in functions.items()}

    def execute(self, scope: ApplicationScope, program: dict, *,
                idempotency_key: str) -> dict:
        if not isinstance(program, dict):
            raise ValueError('V2_GENERIC_FACT_ARGUMENTS_INVALID')
        function = program.get('function')
        if function in (CREATE, UPDATE):
            args = _program(program, function, {'name','shortDescription',
                'semanticDefinition','expectedMetadataRevision'} |
                ({'tableId','status'} if function == UPDATE else set()))
            name = _text(args['name'], maximum=200, label='FACT_TABLE_NAME')
            description = args['shortDescription']
            if not isinstance(description, str) or len(description) > 500:
                raise ValueError('FACT_TABLE_DESCRIPTION_INVALID')
            meaning = _text(args['semanticDefinition'], maximum=2000,
                            label='FACT_TABLE_SEMANTICS')
            revision = _nonnegative(args['expectedMetadataRevision'],
                                    'EXPECTED_METADATA_REVISION')
            if function == UPDATE:
                table_id = args['tableId']
                if not isinstance(table_id,str) or not _ID.fullmatch(table_id):
                    raise ValueError('FACT_TABLE_ID_INVALID')
                if args['status'] not in ('Active','Inactive'):
                    raise ValueError('FACT_TABLE_STATUS_INVALID')
        elif function == TABLE_DELETE:
            args = _program(program, TABLE_DELETE,
                {'tableId','expectedMetadataRevision'})
            table_id = args['tableId']
            if not isinstance(table_id,str) or not _ID.fullmatch(table_id):
                raise ValueError('FACT_TABLE_ID_INVALID')
            revision = _nonnegative(args['expectedMetadataRevision'],
                                    'EXPECTED_METADATA_REVISION')
        elif function in (SET, DELETE, BULK):
            fields = ({'tableId','changes','expectedDataRevision'}
                      if function == BULK else
                      {'tableId','seriesKey','expectedChangeId',
                       'expectedDataRevision'} |
                      ({'value'} if function == SET else set()))
            args = _program(program, function, fields)
            table_id = args['tableId']
            if not isinstance(table_id, str) or not _ID.fullmatch(table_id):
                raise ValueError('FACT_TABLE_ID_INVALID')
            revision = _nonnegative(args['expectedDataRevision'],
                                    'EXPECTED_DATA_REVISION')
            changes = args['changes'] if function == BULK else [{
                'action':'Set' if function == SET else 'Delete',
                'seriesKey':args['seriesKey'],
                'expectedChangeId':args['expectedChangeId'],
                **({'value':args['value']} if function == SET else {})}]
            if (not isinstance(changes,list) or not 1 <= len(changes) <= 100):
                raise ValueError('GENERIC_FACT_BATCH_SIZE_INVALID')
            seen = set()
            total_bytes = 0
            for change in changes:
                if not isinstance(change,dict) or change.get('action') not in ('Set','Delete'):
                    raise ValueError('GENERIC_FACT_CHANGE_INVALID')
                if set(change) != ({'action','seriesKey','expectedChangeId','value'}
                                   if change['action'] == 'Set' else
                                   {'action','seriesKey','expectedChangeId'}):
                    raise ValueError('GENERIC_FACT_CHANGE_INVALID')
                series_key = _text(change['seriesKey'],maximum=1000,
                                   label='FACT_SERIES_KEY')
                if series_key in seen:
                    raise ValueError('GENERIC_FACT_DUPLICATE_SERIES')
                seen.add(series_key)
                expected_change = change['expectedChangeId']
                if (not isinstance(expected_change,str) or
                    (expected_change and not _ID.fullmatch(expected_change))):
                    raise ValueError('EXPECTED_CHANGE_ID_INVALID')
                if change['action'] == 'Set':
                    if change['value'] is None:
                        raise ValueError('GENERIC_FACT_VALUE_REQUIRED')
                    try:
                        encoded = json.dumps(change['value'],sort_keys=True,
                            separators=(',',':'),ensure_ascii=False,
                            allow_nan=False)
                    except (TypeError,ValueError) as error:
                        raise ValueError('GENERIC_FACT_JSON_INVALID') from error
                    total_bytes += len(encoded.encode())
                    if len(encoded) > 100000:
                        raise ValueError('GENERIC_FACT_VALUE_TOO_LARGE')
            if total_bytes > 350000:
                raise ValueError('GENERIC_FACT_BATCH_TOO_LARGE')
        else:
            raise ValueError('V2_GENERIC_FACT_FUNCTION_UNSUPPORTED')
        if (not isinstance(idempotency_key, str)
                or not 1 <= len(idempotency_key) <= 200):
            raise ValueError('IDEMPOTENCY_KEY_INVALID')
        digest = sha256(json.dumps(program, sort_keys=True,
            separators=(',', ':'), ensure_ascii=False,
            allow_nan=False).encode()).hexdigest()
        if function in (SET,DELETE,BULK):
            return self._execute_values(scope,function,table_id,changes,
                revision,idempotency_key,digest)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'admin')
                state = db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.commit_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                prior_receipt = db.execute('''SELECT command_digest,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id,scope.application_id,
                     idempotency_key)).fetchone()
                if prior_receipt:
                    if prior_receipt['command_digest'] != digest:
                        raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    return prior_receipt['result']
                if state['status'] != 'Active' or state['processing_mode'] != 'Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if state['metadata_revision'] != revision:
                    raise ValueError('STALE_METADATA_REVISION')
                if function == CREATE:
                    table_id = uuid4().hex
                    db.execute('''INSERT INTO epm.generic_fact_table
                        (workspace_id,application_id,table_id,name,
                         short_description,semantic_definition)
                        VALUES (%s,%s,%s,%s,%s,%s)''',
                        (scope.workspace_id,scope.application_id,table_id,
                         name,description,meaning))
                    status = 'Active'
                elif function == UPDATE:
                    status = args['status']
                    changed = db.execute('''UPDATE epm.generic_fact_table
                        SET name=%s,short_description=%s,
                        semantic_definition=%s,status=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND table_id=%s AND status<>'Deleted' ''',
                        (name,description,meaning,status,
                         scope.workspace_id,scope.application_id,
                         table_id)).rowcount
                    if changed != 1:
                        raise ValueError('FACT_TABLE_UNAVAILABLE')
                else:
                    table = db.execute('''SELECT status FROM
                        epm.generic_fact_table WHERE workspace_id=%s
                        AND application_id=%s AND table_id=%s FOR UPDATE''',
                        (scope.workspace_id,scope.application_id,
                         table_id)).fetchone()
                    if table is None or table['status'] == 'Deleted':
                        raise ValueError('FACT_TABLE_UNAVAILABLE')
                    populated = db.execute('''SELECT 1 FROM
                        epm.generic_fact_current WHERE workspace_id=%s
                        AND application_id=%s AND table_id=%s LIMIT 1''',
                        (scope.workspace_id,scope.application_id,
                         table_id)).fetchone()
                    if populated:
                        raise ValueError('FACT_TABLE_NOT_EMPTY')
                    db.execute('''UPDATE epm.generic_fact_table SET
                        status='Deleted',updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND table_id=%s''',(scope.workspace_id,
                        scope.application_id,table_id))
                    status = 'Deleted'
                result = {'tableId':table_id,'status':status,
                    'metadataRevision':revision+1}
                if function != TABLE_DELETE:
                    result['name'] = name
                db.execute('''UPDATE epm.application_state SET
                    metadata_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (revision+1,state['commit_revision']+1,
                     scope.workspace_id,scope.application_id))
                result['committedRevision'] = state['commit_revision']+1
                provenance = {'version': 1,
                    'encoding': 'generic-event-references-v1',
                    'languageVersion': 2, 'function': function,
                    'issuer': self.identity.issuer,
                    'subjectId': self.identity.subject_id}
                receipt = (scope.workspace_id, scope.application_id,
                    idempotency_key, digest, self.identity.subject_id,
                    state['commit_revision']+1, Jsonb(result))
                # Metadata arguments are small and have no immutable value
                # event to reference. Preserve the validated authored shape.
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                     command_digest,actor_id,committed_revision,result,provenance)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)''',
                    (*receipt, Jsonb({**provenance, 'arguments': args})))
                return result

    def _execute_values(self,scope,function,table_id,changes,expected_revision,
                        idempotency_key,digest):
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')

                def receipt():
                    return db.execute('''SELECT command_digest,result
                        FROM epm.operation_receipt WHERE workspace_id=%s
                        AND application_id=%s AND operation_id=%s''',
                        (scope.workspace_id,scope.application_id,
                         idempotency_key)).fetchone()

                def replay(prior):
                    if prior['command_digest'] != digest:
                        raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    return prior['result']

                def application_state(lock=False):
                    suffix=' FOR UPDATE OF s' if lock else ''
                    return db.execute('''SELECT a.status,s.processing_mode,
                        s.metadata_revision,s.data_revision,s.commit_revision
                        FROM epm.application_state s JOIN epm.application a
                        USING(workspace_id,application_id)
                        WHERE s.workspace_id=%s AND s.application_id=%s'''+suffix,
                        (scope.workspace_id,scope.application_id)).fetchone()

                initial=application_state()
                prior=receipt()
                if prior:return replay(prior)
                # The client revision is an admission boundary, not a global
                # publication lock.  A prior disjoint public write may have
                # advanced the application revision while every target in
                # this request remains unchanged.  Reject impossible future
                # revisions here; deterministic target locks and prepared
                # change-id revalidation below decide genuine overlap.
                PostgresNumericFactStore._validate_state(
                    initial,initial['metadata_revision'] if initial else 0,
                    None)
                _validate_publication_base(
                    initial['data_revision'], expected_revision)
                self._lock_value_points(db,scope,table_id,changes)
                table=db.execute('''SELECT status FROM epm.generic_fact_table
                    WHERE workspace_id=%s AND application_id=%s
                    AND table_id=%s''',(scope.workspace_id,
                    scope.application_id,table_id)).fetchone()
                if table is None or table['status']!='Active':
                    raise ValueError('FACT_TABLE_UNAVAILABLE')
                from .postgres_generic_batch import prepare
                prepared=prepare(db,scope,table_id,changes)

                state=application_state(True)
                prior=receipt()
                if prior:return replay(prior)
                # The request had to be current before preparation.  A later
                # global revision advance is safe only if every actual target,
                # table and current policy revalidates below.
                PostgresNumericFactStore._validate_state(
                    state,state['metadata_revision'] if state else 0,None)
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')
                table=db.execute('''SELECT status FROM epm.generic_fact_table
                    WHERE workspace_id=%s AND application_id=%s
                    AND table_id=%s''',(scope.workspace_id,
                    scope.application_id,table_id)).fetchone()
                if table is None or table['status']!='Active':
                    raise ValueError('FACT_TABLE_UNAVAILABLE')
                from .postgres_planning_write_guard import enforce_active_planning_policy
                policy=enforce_active_planning_policy(db,scope,writes=tuple((
                    _planning_coordinate(table_id,change['seriesKey']),
                    'Set' if change['action']=='Set' else 'Clear')
                    for change in changes),workflow_role=access.role)
                from .postgres_generic_batch import (
                    publish_prepared,recheck_prepared_inputs)
                recheck_prepared_inputs(db,scope,table_id,prepared)
                committed=state['commit_revision']+1
                results=publish_prepared(db,scope,table_id,prepared,
                    revision=committed,operation_id=idempotency_key,
                    actor_id=self.identity.subject_id)
                data_revision=state['data_revision']+1
                result=({'tableId':table_id,'changes':results,
                    'dataRevision':data_revision} if function==BULK else
                    {'tableId':table_id,**results[0],
                     'dataRevision':data_revision})
                result['planningPolicy']=policy
                result['committedRevision']=committed
                db.execute('''UPDATE epm.application_state SET
                    data_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (data_revision,committed,scope.workspace_id,
                     scope.application_id))
                provenance={'version':1,
                    'encoding':'generic-event-references-v2',
                    'languageVersion':2,'function':function,
                    'issuer':self.identity.issuer,
                    'subjectId':self.identity.subject_id}
                references=[{'action':change['action'],
                    'seriesKey':change['seriesKey'],
                    'expectedChangeId':change['expectedChangeId']}
                    for change in changes]
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                     command_digest,actor_id,committed_revision,result,provenance)
                    SELECT %s,%s,%s,%s,%s,%s,%s,
                        %s::jsonb || jsonb_build_object('arguments',
                            jsonb_build_object('tableId',%s::text,
                                'expectedDataRevision',%s::bigint,
                                'publicationBaseDataRevision',%s::bigint,
                                'changes',jsonb_agg(
                                    input.change || jsonb_build_object(
                                        'eventId',event.event_id)
                                    || CASE WHEN input.change->>'action'='Set'
                                        THEN jsonb_build_object(
                                            'valueField','after_value')
                                        ELSE '{}'::jsonb END
                                    ORDER BY input.ordinal)))
                    FROM jsonb_array_elements(%s::jsonb)
                        WITH ORDINALITY AS input(change,ordinal)
                    LEFT JOIN epm.generic_fact_event event
                      ON event.workspace_id=%s AND event.application_id=%s
                     AND event.operation_id=%s AND event.table_id=%s
                     AND event.series_key=input.change->>'seriesKey' ''',
                    (scope.workspace_id,scope.application_id,idempotency_key,
                     digest,self.identity.subject_id,committed,Jsonb(result),
                     Jsonb(provenance),table_id,expected_revision,
                     state['data_revision'],
                     Jsonb(references),scope.workspace_id,
                     scope.application_id,idempotency_key,table_id))
                return result

    @staticmethod
    def _lock_value_points(db,scope,table_id,changes):
        keys=tuple(sorted('epm.pov.generic:'+json.dumps(
            [scope.workspace_id,scope.application_id,table_id,
             change['seriesKey']],separators=(',',':'),ensure_ascii=False)
            for change in changes))
        db.execute('''SELECT pg_advisory_xact_lock(hashtextextended(key,0))
            FROM unnest(%s::text[]) key ORDER BY key''',(list(keys),))

    @contextmanager
    def _current_read(self, db, scope: ApplicationScope):
        with db.transaction():
            db.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY')
            PostgresNumericFactStore._set_scope(db, scope)
            check = PostgresAccessChecker.check_in_transaction
            opening = check(db, self.identity, scope, 'read')
            response_error = None
            try:
                yield
            except ValueError as error:
                # An unavailable table can disclose state too. Recheck access
                # before releasing either a result or a bounded owner error.
                response_error = error
            try:
                current = check(db, self.identity, scope, 'read', expected_groups=opening.groups)
            except AccessGroupsChanged:
                raise ValueError(READ_AUTHORIZATION_STALE) from None
            if current != opening:
                raise ValueError(READ_AUTHORIZATION_STALE)
            if response_error is not None:
                raise response_error

    def read(self, scope: ApplicationScope, program: dict) -> dict:
        if not isinstance(program, dict):
            raise ValueError('V2_GENERIC_FACT_ARGUMENTS_INVALID')
        function = program.get('function')
        if function == LIST:
            args = _program(program, LIST, {'afterTableId','limit'})
            after = args['afterTableId']
            if after is not None and (not isinstance(after, str)
                                      or not _ID.fullmatch(after)):
                raise ValueError('FACT_TABLE_CURSOR_INVALID')
            limit = args['limit']
            if type(limit) is not int or not 1 <= limit <= MAX_TABLE_PAGE:
                raise ValueError('FACT_PAGE_LIMIT_INVALID')
        elif function == READ:
            args = _program(program, READ, {'tableId','seriesKey'})
        elif function == SCAN:
            args = _program(program, SCAN,
                            {'tableId','afterSeriesKey','limit'})
            after = args['afterSeriesKey']
            if after is not None:
                _text(after,maximum=MAX_SERIES_KEY,label='FACT_SERIES_KEY')
            limit = args['limit']
            if type(limit) is not int or not 1 <= limit <= MAX_VALUE_PAGE:
                raise ValueError('FACT_PAGE_LIMIT_INVALID')
        elif function == SNAPSHOT_SCAN:
            args = _program(program,SNAPSHOT_SCAN,{'tableId','limit','cursor'})
            limit = args['limit']
            if type(limit) is not int or not 1 <= limit <= MAX_VALUE_PAGE:
                raise ValueError('FACT_PAGE_LIMIT_INVALID')
            if self.cursor_secret is None:
                raise ValueError('GENERIC_CURSOR_SECRET_INVALID')
            cursor = args['cursor']
            if cursor is not None:
                payload = self._unpack_cursor(cursor,scope)
                if (payload['tableId'] != args['tableId'] or
                    payload['limit'] != limit):
                    raise ValueError('GENERIC_CURSOR_INVALID')
                after = payload['after']
                snapshot_revision = payload['snapshotRevision']
                metadata_revision = payload['metadataRevision']
            else:
                after = ''
                snapshot_revision = None
                metadata_revision = None
        else:
            raise ValueError('V2_GENERIC_FACT_FUNCTION_UNSUPPORTED')
        if function in (READ,SCAN,SNAPSHOT_SCAN):
            table_id = args['tableId']
            if not isinstance(table_id,str) or not _ID.fullmatch(table_id):
                raise ValueError('FACT_TABLE_ID_INVALID')
        if function == READ:
            _text(args['seriesKey'],maximum=MAX_SERIES_KEY,label='FACT_SERIES_KEY')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with self._current_read(db, scope):
                if function == LIST:
                    rows=db.execute('''SELECT table_id,name,
                        short_description,semantic_definition,status
                        FROM epm.generic_fact_table WHERE workspace_id=%s
                        AND application_id=%s AND status<>'Deleted'
                        AND (%s::text IS NULL
                        OR table_id>%s) ORDER BY table_id LIMIT %s''',
                        (scope.workspace_id,scope.application_id,
                         after,after,limit+1)).fetchall()
                    return {'rows':[dict(row) for row in rows[:limit]],
                            'hasMore':len(rows)>limit,
                            'nextAfterTableId':rows[limit-1]['table_id']
                            if len(rows)>limit else None}
                if function == SNAPSHOT_SCAN:
                    state=db.execute('''SELECT metadata_revision,
                        commit_revision FROM epm.application_state
                        WHERE workspace_id=%s AND application_id=%s''',
                        (scope.workspace_id,scope.application_id)).fetchone()
                    if state is None:
                        raise ValueError('APPLICATION_UNAVAILABLE')
                    if metadata_revision is not None and metadata_revision != state['metadata_revision']:
                        raise ValueError('STALE_METADATA_REVISION')
                    if snapshot_revision is None:
                        snapshot_revision=state['commit_revision']
                    if snapshot_revision > state['commit_revision']:
                        raise ValueError('GENERIC_CURSOR_INVALID')
                    metadata_revision=state['metadata_revision']
                table=db.execute('''SELECT 1 FROM epm.generic_fact_table
                    WHERE workspace_id=%s AND application_id=%s
                    AND table_id=%s AND status<>'Deleted' ''',
                    (scope.workspace_id,scope.application_id,
                     table_id)).fetchone()
                if table is None:
                    raise ValueError('FACT_TABLE_UNAVAILABLE')
                if function == SNAPSHOT_SCAN:
                    rows=db.execute('''SELECT series_key,
                        after_value AS value,
                        resulting_change_id AS change_id,
                        committed_revision AS last_revision
                        FROM (SELECT DISTINCT ON (series_key) series_key,
                            after_value,resulting_change_id,
                            committed_revision,action
                            FROM epm.generic_fact_event
                            WHERE workspace_id=%s AND application_id=%s
                            AND table_id=%s AND committed_revision<=%s
                            AND series_key>%s
                            ORDER BY series_key,committed_revision DESC,
                                event_id DESC) latest
                        WHERE action<>'Delete'
                        ORDER BY series_key LIMIT %s''',
                        (scope.workspace_id,scope.application_id,table_id,
                         snapshot_revision,after,limit+1)).fetchall()
                    final_metadata=db.execute('''SELECT metadata_revision FROM epm.application_state
                        WHERE workspace_id=%s AND application_id=%s''',
                        (scope.workspace_id,scope.application_id)).fetchone()
                    if final_metadata is None or final_metadata['metadata_revision']!=metadata_revision:
                        raise ValueError('STALE_METADATA_REVISION')
                    page=[dict(row) for row in rows[:limit]]
                    next_cursor=(self._pack_cursor(scope, {
                        'tableId':table_id,'limit':limit,
                        'after':page[-1]['series_key'],
                        'snapshotRevision':snapshot_revision,
                        'metadataRevision':metadata_revision,
                        'expiresAt':int(time.time())+3600})
                        if len(rows)>limit else None)
                    return {'tableId':table_id,'rows':page,
                            'snapshotRevision':snapshot_revision,
                            'metadataRevision':metadata_revision,
                            'hasMore':len(rows)>limit,
                            'nextCursor':next_cursor}
                if function == READ:
                    row=db.execute('''SELECT value,change_id,last_revision
                        FROM epm.generic_fact_current WHERE workspace_id=%s
                        AND application_id=%s AND table_id=%s
                        AND series_key=%s''',
                        (scope.workspace_id,scope.application_id,table_id,
                         args['seriesKey'])).fetchone()
                    return {'tableId':table_id,'seriesKey':args['seriesKey'],
                            'exists':row is not None,
                            'value':row['value'] if row else None,
                            'changeId':row['change_id'] if row else '',
                            'lastRevision':row['last_revision'] if row else None}
                rows=db.execute('''SELECT series_key,value,change_id,
                    last_revision FROM epm.generic_fact_current
                    WHERE workspace_id=%s AND application_id=%s AND table_id=%s
                    AND (%s::text IS NULL OR series_key>%s)
                    ORDER BY series_key LIMIT %s''',
                    (scope.workspace_id,scope.application_id,table_id,
                     after,after,limit+1)).fetchall()
                return {'tableId':table_id,
                        'rows':[dict(row) for row in rows[:limit]],
                        'hasMore':len(rows)>limit,
                        'nextAfterSeriesKey':rows[limit-1]['series_key']
                        if len(rows)>limit else None}

    def _cursor_context_digest(self, scope: ApplicationScope) -> str:
        context = [scope.workspace_id, scope.application_id,
                   self.identity.issuer, self.identity.subject_id]
        return sha256(json.dumps(context, separators=(',', ':'),
                                ensure_ascii=False).encode()).hexdigest()

    def _pack_cursor(self, scope: ApplicationScope, pins: dict) -> str:
        # Encode the anchor's UTF-8 bytes so JSON escaping cannot inflate a
        # valid series key past the size accepted on the next request.
        payload = {**pins,
            'format': _CURSOR_FORMAT, 'contextDigest': self._cursor_context_digest(scope),
            'after': base64.urlsafe_b64encode(pins['after'].encode()).decode()}
        raw=json.dumps(payload,sort_keys=True,separators=(',',':')).encode()
        signature=hmac.new(self.cursor_secret,raw,sha256).digest()
        return base64.urlsafe_b64encode(raw+signature).decode()

    def _unpack_cursor(self,token: object,scope: ApplicationScope) -> dict:
        if not isinstance(token,str) or not 1<=len(token)<=MAX_CURSOR:
            raise ValueError('GENERIC_CURSOR_INVALID')
        try:
            packed=base64.b64decode(token,altchars=b'-_',validate=True)
            raw,signature=packed[:-32],packed[-32:]
            if not hmac.compare_digest(
                hmac.new(self.cursor_secret,raw,sha256).digest(),signature):
                raise ValueError('Signature mismatch')
            payload=json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError('Missing cursor fields')
            pins = {'tableId', 'limit', 'after', 'snapshotRevision', 'metadataRevision', 'expiresAt'}
            if payload.get('format') == _CURSOR_FORMAT:
                if (set(payload) != pins | {'format', 'contextDigest'} or
                        payload['contextDigest'] != self._cursor_context_digest(scope)):
                    raise ValueError('Cursor binding mismatch')
                payload['after'] = base64.b64decode(payload['after'], altchars=b'-_',
                                                     validate=True).decode()
            elif (set(payload) != pins | {'scope', 'identity'} or
                    payload['scope'] != [scope.workspace_id, scope.application_id] or
                    payload['identity'] != [self.identity.issuer, self.identity.subject_id]):
                raise ValueError('Cursor binding mismatch')
        except (ValueError,TypeError,binascii.Error) as error:
            raise ValueError('GENERIC_CURSOR_INVALID') from error
        if (not isinstance(payload['tableId'],str) or
            not _ID.fullmatch(payload['tableId']) or
            not isinstance(payload['after'],str) or
            not 1<=len(payload['after'])<=MAX_SERIES_KEY or
            type(payload['limit']) is not int or
            not 1<=payload['limit']<=MAX_VALUE_PAGE or
            type(payload['snapshotRevision']) is not int or
            payload['snapshotRevision']<0 or
            type(payload['metadataRevision']) is not int or
            payload['metadataRevision']<0 or
            type(payload['expiresAt']) is not int or
            payload['expiresAt']<time.time()):
            raise ValueError('GENERIC_CURSOR_INVALID')
        return payload
