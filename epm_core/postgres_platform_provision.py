"""Verified platform-operator provisioning of blank PostgreSQL workspaces."""
from __future__ import annotations

from hashlib import sha256
import json
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .postgres_access import AccessDenied, VerifiedIdentity


FUNCTION = 'platform.workspace.create'


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
            or name != name.strip()):
        raise ValueError('V2_WORKSPACE_CREATE_INVALID')
    return workspace_id,name


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
            'workClass':'short'}}}

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

    def create(self,program: object,*,idempotency_key: str) -> dict:
        workspace_id,name=compile_create_workspace(program)
        if (not isinstance(idempotency_key,str)
                or not 1 <= len(idempotency_key) <= 200):
            raise ValueError('Idempotency key is required')
        digest=sha256(json.dumps(program,sort_keys=True,
            ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
        actor_digest=sha256((self.identity.issuer+'\0'+
                             self.identity.subject_id).encode()).hexdigest()
        try:
            with connect_postgres(self.dsn,row_factory=dict_row) as db:
                with db.transaction():
                    db.execute('''SELECT set_config('epm.workspace_id',%s,true)''',
                               (workspace_id,))
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
