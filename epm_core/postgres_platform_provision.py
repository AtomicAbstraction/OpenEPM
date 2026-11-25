"""Verified platform-operator provisioning of blank PostgreSQL workspaces."""
from __future__ import annotations

from datetime import timezone
from hashlib import sha256
import json
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .postgres_access import AccessDenied, PostgresAccessChecker, VerifiedIdentity


FUNCTION = 'platform.workspace.create'
OPERATION_RECEIPT_READ = 'platform.operation.receipt.read'


def platform_operation_actor_digest(identity: VerifiedIdentity) -> str:
    return sha256((identity.issuer+'\0'+identity.subject_id).encode()).hexdigest()


def compile_create_workspace(program: object) -> tuple[str, str]:
    if (not isinstance(program,dict)
            or set(program) != {'languageVersion','function','arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != FUNCTION
            or not isinstance(program['arguments'],dict)
            or set(program['arguments']) != {'workspaceId','name'}):
        raise ValueError('V2_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
    workspace_id, name = (program['arguments']['workspaceId'],
                          program['arguments']['name'])
    if (not isinstance(workspace_id,str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}',workspace_id)
            or not isinstance(name,str) or not 1 <= len(name) <= 200
            or name != name.strip() or '\0' in name):
        raise ValueError('V2_WORKSPACE_CREATE_INVALID')
    return workspace_id,name


def compile_operation_receipt_read(program: object) -> str:
    if (type(program) is not dict
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != OPERATION_RECEIPT_READ
            or type(program['arguments']) is not dict
            or set(program['arguments']) != {'operationId'}):
        raise ValueError('V2_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
    operation_id = program['arguments']['operationId']
    if not isinstance(operation_id, str) or not 1 <= len(operation_id) <= 200 or '\0' in operation_id:
        raise ValueError('PLATFORM_OPERATION_ID_INVALID')
    return operation_id


def platform_provisioning_contract(function: str) -> dict:
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj
    from .public_program_contracts import provisioning_field_schemas

    if function == FUNCTION:
        identifier, name = provisioning_field_schemas()
        fields = {'workspaceId': identifier, 'name': name}
        arguments = obj(fields)
        result = obj({**fields, 'status': {'const': 'Active'}})
        example = read_example(function, {'workspaceId': 'operating-plans', 'name': 'Operating plans'},
                               name='Create a workspace', binding='Use an unused workspace ID and a new platform request key.')
        rules = ['Creates an empty workspace and its first Administrator grant for the current operator.']
        recovery = ('For an uncertain result, call platform.operation.receipt.read with the original key. '
                    'Any retry must use the exact original program and key under current authority.')
    elif function == OPERATION_RECEIPT_READ:
        operation_id = {'type': 'string', 'minLength': 1, 'maxLength': 200, 'pattern': r'^[^\x00]+(?![\s\S])'}
        arguments = obj({'operationId': operation_id})
        timestamp = {'type': 'string', 'format': 'date-time'}
        result = {**obj({'operationId': operation_id, 'status': {'enum': ['Committed', 'Pending', 'Unavailable']},
                         'function': {'type': ['string', 'null']}, 'committedAt': {'type': ['string', 'null']}}),
                  'oneOf': [
                      {'properties': {'status': {'const': 'Committed'}, 'function': {'type': 'string'}, 'committedAt': timestamp}},
                      {'properties': {'status': {'const': 'Pending'}, 'function': {'type': 'string'}, 'committedAt': {'type': 'null'}}},
                      {'properties': {'status': {'const': 'Unavailable'}, 'function': {'type': 'null'}, 'committedAt': {'type': 'null'}}},
                  ]}
        example = read_example(function, {'operationId': 'example-platform-request'},
                               name='Check the original platform request', binding='Use the original operation key from your own request.')
        rules = ['Pending leaves the outcome unconfirmed. An absent or foreign receipt returns Unavailable.',
                 'The receipt reports original settlement and carries no current workspace or directory state.']
        recovery = 'Keep the original request key. Pending and Unavailable do not authorize a new effect.'
    else:
        raise ValueError('PLATFORM_PROVISIONING_FUNCTION_INVALID')
    contract = read_contract(function, arguments, result, owner='PostgresPlatformProvisioner',
                             examples=[example], semantic_rules=rules, result_scope='result')
    contract['programContract']['recovery'] = recovery
    return contract


class PostgresPlatformProvisioner:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity):
        if not isinstance(dsn,str) or not dsn:
            raise ValueError('A PostgreSQL provisioner DSN is required')
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError('Verified identity is required')
        self.dsn,self.identity=dsn,identity

    @staticmethod
    def catalog() -> dict:
        return {'languageVersion':2,'functions':{FUNCTION:{
            'mode':'atomic_write','permission':'platform_operator',
            'arguments':{'workspaceId':'stable ID','name':'display name'},
            'result':'blank workspace and creator Administrator grant',
            'previewRequired':False,'idempotencyRequired':True,
            'workClass':'short', **platform_provisioning_contract(FUNCTION)}, OPERATION_RECEIPT_READ:{
            'mode':'read','permission':'platform_operator',
            'arguments':{'operationId':'original exact operation key (1–200 characters)'},
            'result':{'operationId':'requested operation key',
                      'status':'Pending | Committed | Unavailable',
                      'function':'original function or null when unavailable',
                      'committedAt':'UTC timestamp for Committed, otherwise null'},
            'previewRequired':False,'idempotencyRequired':False,
            'workClass':'short', **platform_provisioning_contract(OPERATION_RECEIPT_READ)}}}

    @staticmethod
    def _require_operator(db,identity: VerifiedIdentity) -> None:
        level=db.execute('SHOW transaction_isolation').fetchone()
        if level['transaction_isolation'] != 'read committed':
            raise ValueError('Authorization recheck requires READ COMMITTED')
        authority=db.execute('''SELECT
            epm.identity_subject_active(%s,%s) AS subject_active,
            CASE WHEN %s::bigint IS NULL THEN true ELSE
              epm.identity_subject_session_valid(%s,%s,%s) END AS session_valid,
            EXISTS (SELECT 1 FROM epm.platform_operator_grant
                WHERE issuer=%s AND subject_id=%s) AS granted''',
            (identity.issuer,identity.subject_id,identity.issued_at,
             identity.issuer,identity.subject_id,identity.issued_at,
             identity.issuer,identity.subject_id)).fetchone()
        if not authority['subject_active']:
            raise AccessDenied('IDENTITY_INACTIVE')
        if not authority['session_valid']:
            raise AccessDenied('IDENTITY_SESSION_REVOKED')
        if not authority['granted']:
            raise AccessDenied('PLATFORM_OPERATOR_REQUIRED')

    def check(self) -> None:
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                self._require_operator(db,self.identity)

    def read_operation_receipt(self,program: object) -> dict:
        operation_id = compile_operation_receipt_read(program)
        actor_digest=platform_operation_actor_digest(self.identity)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                self._require_operator(db,self.identity)
                receipt=db.execute('''SELECT function_name,status,committed_at
                    FROM epm.platform_operation_receipt
                    WHERE operation_id=%s AND actor_digest=%s''',
                    (operation_id,actor_digest)).fetchone()
                self._require_operator(db,self.identity)
        if receipt is None:
            return {'operationId':operation_id,'status':'Unavailable',
                    'function':None,'committedAt':None}
        committed_at=receipt['committed_at']
        return {'operationId':operation_id,'status':receipt['status'],
                'function':receipt['function_name'],
                'committedAt':committed_at.astimezone(timezone.utc).isoformat()
                if committed_at is not None else None}

    def create(self,program: object,*,idempotency_key: str) -> dict:
        workspace_id,name=compile_create_workspace(program)
        if (not isinstance(idempotency_key,str)
                or not 1 <= len(idempotency_key) <= 200):
            raise ValueError('Idempotency key is required')
        digest=sha256(json.dumps(program,sort_keys=True,
            ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
        actor_digest=platform_operation_actor_digest(self.identity)
        try:
            with connect_postgres(self.dsn,row_factory=dict_row) as db:
                with db.transaction():
                    db.execute('''SELECT set_config('epm.workspace_id',%s,true)''',
                               (workspace_id,))
                    PostgresAccessChecker.lock_directory_membership_for_assignment(db)
                    self._require_operator(db,self.identity)
                    db.execute('''SELECT pg_advisory_xact_lock(
                        hashtextextended('epm.provision:' || %s,0))''',
                        (idempotency_key,))
                    previous=db.execute('''SELECT command_digest,actor_digest,
                        result,status FROM epm.platform_operation_receipt
                        WHERE operation_id=%s''',(idempotency_key,)).fetchone()
                    if previous:
                        if (previous['command_digest'] != digest
                                or previous['actor_digest'] != actor_digest):
                            raise ValueError('IDEMPOTENCY_KEY_REUSED')
                        if previous['status'] != 'Committed':
                            raise ValueError('PLATFORM_OPERATION_INCOMPLETE')
                        return previous['result']
                    db.execute('''INSERT INTO epm.workspace(workspace_id,name)
                        VALUES (%s,%s)''',(workspace_id,name))
                    db.execute('''INSERT INTO epm.workspace_access_grant
                        (issuer,subject_id,workspace_id,role)
                        VALUES (%s,%s,%s,'Administrator')''',
                        (self.identity.issuer,self.identity.subject_id,
                         workspace_id))
                    result={'workspaceId':workspace_id,'name':name,
                            'status':'Active'}
                    db.execute('''INSERT INTO epm.platform_operation_receipt
                        (operation_id,command_digest,actor_digest,function_name,
                         status,result,committed_at)
                        VALUES (%s,%s,%s,%s,'Committed',%s,
                                transaction_timestamp())''',
                        (idempotency_key,digest,actor_digest,FUNCTION,
                         Jsonb(result)))
                    db.execute('''INSERT INTO epm.security_audit
                        (actor_id,action,workspace_id,target_digest,
                         outcome,detail)
                        VALUES (%s,%s,%s,%s,'Accepted',%s)''',
                        (actor_digest,FUNCTION,workspace_id,
                         sha256(workspace_id.encode()).hexdigest(),
                         Jsonb({'kind':'blank'})))
                    return result
        except UniqueViolation as error:
            raise ValueError('WORKSPACE_ID_EXISTS') from error
