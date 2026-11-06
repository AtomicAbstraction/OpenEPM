"""Fixed, typed AccountType and Entity DefCurrency metadata on V2 members."""
from __future__ import annotations

import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore


ACCOUNT_SET = 'financial.account.type.set'
ENTITY_SET = 'financial.entity.currency.set'
READ = 'financial.member.policy.read'
_TYPES = frozenset((
    'REVENUE','EXPENSE','ASSET','LIABILITY','BALANCE','FLOW',
    'CURRENCYRATE','GROUPLABEL','BALANCERECURRING','DYNAMIC'))
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')


def _id(value: object) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 200
            or value != value.strip() or '\x00' in value):
        raise ValueError('FINANCIAL_MEMBER_ID_INVALID')
    return value


def _program(raw: object, function: str) -> dict:
    if (not isinstance(raw, dict)
            or set(raw) != {'languageVersion', 'function', 'arguments'}
            or type(raw['languageVersion']) is not int
            or raw['languageVersion'] != 2
            or raw['function'] != function
            or not isinstance(raw['arguments'], dict)):
        raise ValueError('V2_FINANCIAL_MEMBER_PROGRAM_INVALID')
    args = raw['arguments']
    if function == ACCOUNT_SET:
        if set(args) != {'accountMemberId','accountType',
                         'expectedMetadataRevision'}:
            raise ValueError('V2_FINANCIAL_MEMBER_ARGUMENTS_INVALID')
        _id(args['accountMemberId'])
        if (args['accountType'] is not None and
                (not isinstance(args['accountType'], str) or
                 args['accountType'] not in _TYPES)):
            raise ValueError('FINANCIAL_ACCOUNT_TYPE_INVALID')
    elif function == ENTITY_SET:
        if set(args) != {'entityMemberId','currencyMemberId',
                         'expectedMetadataRevision'}:
            raise ValueError('V2_FINANCIAL_MEMBER_ARGUMENTS_INVALID')
        _id(args['entityMemberId'])
        if args['currencyMemberId'] is not None:
            _id(args['currencyMemberId'])
    elif function == READ:
        if set(args) != {'dimensionRole','memberId'} or args[
                'dimensionRole'] not in ('Account','Entity'):
            raise ValueError('V2_FINANCIAL_MEMBER_ARGUMENTS_INVALID')
        _id(args['memberId'])
    else:
        raise ValueError('V2_FINANCIAL_MEMBER_PROGRAM_INVALID')
    if function != READ and (type(args['expectedMetadataRevision']) is not int
            or args['expectedMetadataRevision'] < 0):
        raise ValueError('STALE_METADATA_REVISION')
    return args


def _dimension(db, keys: tuple[str, str], role: str) -> str:
    rows = db.execute('''SELECT dimension_id FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s
        AND model_role=%s AND status='Active' ''',
        (*keys,role)).fetchall()
    if len(rows) != 1:
        raise ValueError('FINANCIAL_MODEL_ROLE_UNAVAILABLE')
    return rows[0]['dimension_id']


class PostgresFinancialMemberPolicy:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def execute(self, scope: ApplicationScope, raw: dict, *,
                idempotency_key: str) -> dict:
        if not isinstance(scope, ApplicationScope):
            raise ValueError('Application scope is required')
        function = raw.get('function') if isinstance(raw, dict) else None
        if function not in (ACCOUNT_SET,ENTITY_SET):
            raise ValueError('V2_FINANCIAL_MEMBER_PROGRAM_INVALID')
        args = _program(raw, function)
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(
                idempotency_key):
            raise ValueError('FINANCIAL_IDEMPOTENCY_KEY_INVALID')
        keys = (scope.workspace_id, scope.application_id)
        digest = _canonical_digest(raw)
        payload_digest = _canonical_digest({'scope':keys,
            'identity':(self.identity.issuer,self.identity.subject_id),
            'program':raw})
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                state = db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.commit_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''', keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin')
                prior = db.execute('''SELECT command_digest,
                    committed_revision,result FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s
                    AND operation_id=%s''',
                    (*keys,idempotency_key)).fetchone()
                if prior:
                    if (prior['command_digest'] != digest or
                            prior['result'].get('payloadDigest') !=
                            payload_digest):
                        raise ValueError('FINANCIAL_IDEMPOTENCY_CONFLICT')
                    return {'operationId':idempotency_key,
                            'committedRevision':prior['committed_revision'],
                            'metadataRevision':prior['result'][
                                'metadataRevision'], 'duplicate':True}
                if (state['status'] != 'Active' or
                        state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if state['metadata_revision'] != args[
                        'expectedMetadataRevision']:
                    raise ValueError('STALE_METADATA_REVISION')
                role = 'Account' if function == ACCOUNT_SET else 'Entity'
                dimension_id = _dimension(db, keys, role)
                member_id = (args['accountMemberId'] if role == 'Account'
                             else args['entityMemberId'])
                member = db.execute('''SELECT financial_account_type,
                    entity_default_currency_member_id FROM epm.member
                    WHERE workspace_id=%s AND application_id=%s
                    AND dimension_id=%s AND member_id=%s
                    AND status='Active' FOR UPDATE''',
                    (*keys,dimension_id,member_id)).fetchone()
                if member is None:
                    raise ValueError('ACTIVE_FINANCIAL_MEMBER_REQUIRED')
                column = ('financial_account_type' if role == 'Account' else
                          'entity_default_currency_member_id')
                value = (args['accountType'] if role == 'Account' else
                         args['currencyMemberId'])
                if role == 'Entity' and value is not None:
                    currency_dimension = _dimension(db,keys,'Currency')
                    if not db.execute('''SELECT 1 FROM epm.member
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND member_id=%s
                        AND status='Active' ''',
                        (*keys,currency_dimension,value)).fetchone():
                        raise ValueError('ENTITY_DEFAULT_CURRENCY_UNAVAILABLE')
                if member[column] == value:
                    raise ValueError('FINANCIAL_MEMBER_POLICY_UNCHANGED')
                # Both SQL identifiers are fixed by the validated function.
                db.execute('''UPDATE epm.member SET '''+column+'''=%s,
                    updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                    AND dimension_id=%s AND member_id=%s''',
                    (value,*keys,dimension_id,member_id))
                revision = state['metadata_revision'] + 1
                commit = state['commit_revision'] + 1
                db.execute('''UPDATE epm.application_state SET
                    metadata_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (revision,commit,*keys))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                     command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys,idempotency_key,digest,
                     self.identity.subject_id,commit,Jsonb({
                        'function':function,'metadataRevision':revision,
                        'payloadDigest':payload_digest})))
                return {'operationId':idempotency_key,
                        'committedRevision':commit,
                        'metadataRevision':revision,'duplicate':False}

    def read(self, scope: ApplicationScope, raw: dict) -> dict:
        args = _program(raw, READ)
        if not isinstance(scope, ApplicationScope):
            raise ValueError('Application scope is required')
        keys = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                state = db.execute('''SELECT metadata_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE''',keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                dimension_id = _dimension(db,keys,args['dimensionRole'])
                member = db.execute('''SELECT name,financial_account_type,
                    entity_default_currency_member_id FROM epm.member
                    WHERE workspace_id=%s AND application_id=%s
                    AND dimension_id=%s AND member_id=%s
                    AND status='Active' ''',
                    (*keys,dimension_id,args['memberId'])).fetchone()
                if member is None:
                    raise ValueError('ACTIVE_FINANCIAL_MEMBER_REQUIRED')
                return {'dimensionRole':args['dimensionRole'],
                    'dimensionId':dimension_id,'memberId':args['memberId'],
                    'memberName':member['name'],
                    'accountType':member['financial_account_type']
                        if args['dimensionRole']=='Account' else None,
                    'defaultCurrencyMemberId':member[
                        'entity_default_currency_member_id']
                        if args['dimensionRole']=='Entity' else None,
                    'metadataRevision':state['metadata_revision']}
