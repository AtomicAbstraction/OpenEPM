"""Persisted application specialization, scoped authorization and signed preview.

Configuration never grants permissions or creates business metadata. A change
advances policy_revision so existing preview/job publication fences reject it.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
import time
from hashlib import sha256

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_capability_contract import KNOWN_CAPABILITIES, validate_enabled_capabilities
from .postgres_numeric_store import PostgresNumericFactStore

READ = 'application.capabilities.read'
STATE_READ = 'application.state.read'
IDENTITY_READ = 'security.identity.current.read'
CONFIGURE = 'application.capabilities.configure'
HISTORY = 'application.capabilities.history.read'
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def parse_program(program, function):
    if (not isinstance(program, dict) or set(program) != {'languageVersion','function','arguments'}
            or type(program['languageVersion']) is not int or program['languageVersion'] != 2
            or program['function'] != function or not isinstance(program['arguments'],dict)):
        raise ValueError('APPLICATION_CAPABILITY_PROGRAM_INVALID')
    args=program['arguments']
    if function in (READ, STATE_READ, IDENTITY_READ) and not args:
        return {}
    if function == HISTORY:
        if (set(args)-{'afterRevision','limit'}
                or type(args.get('afterRevision',0)) is not int or args.get('afterRevision',0)<0
                or type(args.get('limit',50)) is not int or not 1<=args.get('limit',50)<=100):
            raise ValueError('APPLICATION_CAPABILITY_HISTORY_ARGUMENTS_INVALID')
        return {'afterRevision':args.get('afterRevision',0),'limit':args.get('limit',50)}
    if (function != CONFIGURE or set(args) != {'enabledCapabilities','expectedCapabilityRevision','reason'}
            or not isinstance(args['enabledCapabilities'],list)
            or type(args['expectedCapabilityRevision']) is not int or args['expectedCapabilityRevision'] < 0
            or not isinstance(args['reason'],str) or not 1 <= len(args['reason']) <= 500
            or args['reason'] != args['reason'].strip() or '\x00' in args['reason']):
        raise ValueError('APPLICATION_CAPABILITY_ARGUMENTS_INVALID')
    enabled=validate_enabled_capabilities(args['enabledCapabilities'])
    return {**args,'enabledCapabilities':sorted(enabled)}


def _state(db,scope,*,write=False):
    return db.execute('''SELECT s.metadata_revision,s.data_revision,s.policy_revision,s.schema_epoch,
        s.commit_revision,s.capability_revision,s.security_revision,
        s.enabled_capabilities,s.processing_mode,
        a.status AS application_status FROM epm.application_state s
        JOIN epm.application a USING (workspace_id,application_id)
        WHERE s.workspace_id=%s AND s.application_id=%s '''+
        ('FOR UPDATE OF s' if write else ''),
        (scope.workspace_id,scope.application_id)).fetchone()


def _result(state):
    return {'enabledCapabilities':sorted(validate_enabled_capabilities(state['enabled_capabilities'])),
        'knownCapabilities':sorted(KNOWN_CAPABILITIES),
        'metadataRevision':state['metadata_revision'],
        'dataRevision':state['data_revision'],'schemaEpoch':state['schema_epoch'],
        'capabilityRevision':state['capability_revision'],'policyRevision':state['policy_revision'],
        'commitRevision':state['commit_revision']}


def _state_result(state):
    return {'status':state['application_status'],
        'metadataRevision':state['metadata_revision'],
        'dataRevision':state['data_revision'],'schemaEpoch':state['schema_epoch'],
        'capabilityRevision':state['capability_revision'],
        'securityRevision':state['security_revision'],
        'policyRevision':state['policy_revision'],
        'commitRevision':state['commit_revision']}


class PostgresApplicationCapabilities:
    def __init__(self,dsn,*,identity,preview_secret):
        if not isinstance(dsn,str) or not dsn: raise ValueError('Runtime DSN required')
        if not isinstance(identity,VerifiedIdentity): raise ValueError('Verified identity required')
        if not isinstance(preview_secret,bytes) or len(preview_secret)<32: raise ValueError('Preview secret required')
        self.dsn,self.identity,self.secret=dsn,identity,preview_secret

    @staticmethod
    def catalog():
        return {HISTORY:{'mode':'read_only','permission':'read','arguments':{},
                'optionalArguments':{'afterRevision':'exclusive committed-revision cursor, default 0','limit':'1–100, default 50'},
                'result':'immutable configuration receipts including before/after state, actor and reason',
                'previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
            READ:{'mode':'read_only','permission':'read','arguments':{},
                'result':'enabled and known capabilities plus current metadata/data/policy/schema/commit revision pins',
                'previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
            STATE_READ:{'mode':'read_only','permission':'read','arguments':{},
                'result':'application status and current metadata/data/policy/security/capability/schema/commit revision pins; no application mode or domain capability semantics',
                'previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
            IDENTITY_READ:{'mode':'read_only','permission':'read','arguments':{},
                'result':'server-verified current issuer and subject identity for this authorized application scope',
                'previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
            CONFIGURE:{'mode':'atomic_write','permission':'admin','arguments':{
                'enabledCapabilities':'explicit list of known application capabilities; empty means core only',
                'expectedCapabilityRevision':'current nonnegative integer','reason':'explicit 1–500 character reason'},
                'result':'atomic configuration receipt with before/after state; no business metadata created',
                'previewRequired':True,'idempotencyRequired':True,'workClass':'short'}}

    def _open(self,db,scope,permission,*,exclusive=False):
        if not isinstance(scope,ApplicationScope): raise ValueError('Application scope required')
        configure_statement_timeout(db, 10000)
        PostgresNumericFactStore._set_scope(db,scope)
        PostgresAccessChecker.lock_workspace(
            db,scope.workspace_id,exclusive=exclusive)
        PostgresAccessChecker.check_in_transaction(db,self.identity,scope,permission)

    def read(self,scope,program):
        parse_program(program,READ)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                self._open(db,scope,'read')
                state=_state(db,scope)
                if state is None: raise ValueError('APPLICATION_UNAVAILABLE')
                return _result(state)

    def state_read(self,scope,program):
        parse_program(program,STATE_READ)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                self._open(db,scope,'read')
                state=_state(db,scope)
                if state is None: raise ValueError('APPLICATION_UNAVAILABLE')
                return _state_result(state)

    def identity_current(self,scope,program):
        parse_program(program,IDENTITY_READ)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                self._open(db,scope,'read')
                state=_state(db,scope)
                if state is None: raise ValueError('APPLICATION_UNAVAILABLE')
                return {'issuer':self.identity.issuer,
                    'subjectId':self.identity.subject_id,
                    'verifiedByServer':True}

    def history(self,scope,program):
        args=parse_program(program,HISTORY)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                self._open(db,scope,'read')
                state=_state(db,scope)
                if state is None: raise ValueError('APPLICATION_UNAVAILABLE')
                if args['afterRevision']>state['commit_revision']:
                    raise ValueError('APPLICATION_CAPABILITY_HISTORY_CURSOR_AHEAD')
                rows=db.execute("""SELECT result,committed_at FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s AND committed_revision>%s
                    AND result->>'function'='application.capabilities.configure'
                    ORDER BY committed_revision LIMIT %s""",
                    (scope.workspace_id,scope.application_id,args['afterRevision'],args['limit']+1)).fetchall()
                return {'rows':[{**row['result'],'committedAt':row['committed_at'].isoformat()}
                    for row in rows[:args['limit']]],'hasMore':len(rows)>args['limit'],
                    'nextAfterRevision':rows[min(len(rows),args['limit'])-1]['result']['committedRevision']
                        if rows else args['afterRevision'],
                    'commitRevisionAtRead':state['commit_revision']}

    def _binding(self,scope,args):
        return {'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],
            'function':CONFIGURE,'arguments':args}

    def preview(self,scope,program):
        args=parse_program(program,CONFIGURE)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                self._open(db,scope,'admin')
                state=_state(db,scope)
                self._validate_change(state,args)
                before=_result(state)
                payload={**self._binding(scope,args),'before':before,
                    'metadataRevision':state['metadata_revision'],'dataRevision':state['data_revision'],
                    'expiresAt':int(time.time())+300}
                raw=_canonical(payload)
                token=base64.urlsafe_b64encode(raw+hmac.new(self.secret,raw,sha256).digest()).decode('ascii')
                return {'languageVersion':2,'function':CONFIGURE,'before':before,
                    'enabledCapabilities':args['enabledCapabilities'],'previewToken':token,
                    'policyRevisionWillAdvance':True}

    @staticmethod
    def _validate_change(state,args):
        if state is None: raise ValueError('APPLICATION_UNAVAILABLE')
        if state['application_status']!='Active' or state['processing_mode']!='Active':
            raise ValueError('APPLICATION_NOT_WRITABLE')
        if state['capability_revision'] != args['expectedCapabilityRevision']:
            raise ValueError('STALE_APPLICATION_CAPABILITY_REVISION')
        if sorted(state['enabled_capabilities']) == args['enabledCapabilities']:
            raise ValueError('APPLICATION_CAPABILITIES_UNCHANGED')

    def apply(self,scope,program,*,preview_token,idempotency_key):
        args=parse_program(program,CONFIGURE)
        if not isinstance(idempotency_key,str) or not _KEY.fullmatch(idempotency_key):
            raise ValueError('APPLICATION_CAPABILITY_IDEMPOTENCY_KEY_INVALID')
        binding=self._binding(scope,args)
        digest=sha256(_canonical(binding)).hexdigest()
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                self._open(db,scope,'admin',exclusive=True)
                state=_state(db,scope,write=True)
                if state is None: raise ValueError('APPLICATION_UNAVAILABLE')
                old=db.execute('''SELECT command_digest,result FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
                if old:
                    if old['command_digest']!=digest: raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    return old['result']
                self._validate_change(state,args)
                if not isinstance(preview_token,str) or not 1<=len(preview_token)<=8192:
                    raise ValueError('APPLICATION_CAPABILITY_PREVIEW_INVALID')
                try:
                    packed=base64.b64decode(preview_token,altchars=b'-_',validate=True)
                    raw,signature=packed[:-32],packed[-32:]
                    if not hmac.compare_digest(hmac.new(self.secret,raw,sha256).digest(),signature):
                        raise ValueError('signature')
                    payload=json.loads(raw)
                except (ValueError,TypeError,binascii.Error) as error:
                    raise ValueError('APPLICATION_CAPABILITY_PREVIEW_INVALID') from error
                if (not isinstance(payload,dict) or set(payload)!=set(binding)|{'before','metadataRevision','dataRevision','expiresAt'}
                        or any(payload.get(key)!=value for key,value in binding.items())
                        or payload.get('before')!=_result(state)
                        or payload.get('metadataRevision')!=state['metadata_revision']
                        or payload.get('dataRevision')!=state['data_revision']
                        or type(payload.get('expiresAt')) is not int or payload['expiresAt']<time.time()):
                    raise ValueError('STALE_APPLICATION_CAPABILITY_PREVIEW')
                before=_result(state)
                revision=state['commit_revision']+1
                policy=state['policy_revision']+1
                capability=state['capability_revision']+1
                from .postgres_calculation_impact import object_impact
                impact=object_impact(source_kind='lifecycle',
                    operation_id=idempotency_key,causal_revision=revision,
                    domain='application',object_type='enabled-capabilities',
                    object_id='active',change='replace',
                    reason='definition_changed')
                result={'function':CONFIGURE,'operationId':idempotency_key,'before':before,
                    'enabledCapabilities':args['enabledCapabilities'],'capabilityRevision':capability,
                    'policyRevision':policy,'committedRevision':revision,'reason':args['reason'],
                    'actor':{'issuer':self.identity.issuer,'subjectId':self.identity.subject_id},
                    'impactDigest':impact.digest}
                db.execute('''UPDATE epm.application_state SET enabled_capabilities=%s,
                    capability_revision=%s,policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (args['enabledCapabilities'],capability,policy,revision,scope.workspace_id,scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id,scope.application_id,idempotency_key,digest,
                     sha256(_canonical(binding['identity'])).hexdigest(),revision,Jsonb(result)))
                from .postgres_calculation_impact import record_calculation_impact
                record_calculation_impact(db,scope,
                    operation_id=idempotency_key,impact=impact)
                return result
