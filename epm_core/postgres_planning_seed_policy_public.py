"""Public sealed execution of immutable reusable Seed policies."""
from __future__ import annotations

import base64
from hashlib import sha256
import hmac
import json
import re
import time

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .planning_operation_policy import lower_bound_seed_to_legacy_v2
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_planning_copy import PostgresScenarioCopy
from .postgres_planning_policy_resolution import resolve_published_planning_policy
from .postgres_source_batch import PostgresSourceBatch


PREVIEW = 'planning.operation.policy.seed.preview'
RUN = 'planning.operation.policy.seed.run'
LINEAGE_READ = 'planning.operation.policy.seed.lineage.read'
FUNCTIONS = frozenset((PREVIEW, RUN, LINEAGE_READ))
_CORE = {'policyId', 'effectiveOn', 'bindings'}


def catalog():
    arguments = {'policyId': 'currently published reusable Seed policy ID',
        'effectiveOn': 'ISO date within the immutable policy effective range',
        'bindings': 'all and only typed policy parameters'}
    return {
        PREVIEW: {'mode': 'calculation_preview', 'permission': 'write',
            'requiredCapabilities': [], 'arguments': arguments,
            'result': 'sealed source snapshot, target semantics and active policy pin',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'medium'},
        RUN: {'mode': 'durable_write', 'permission': 'write',
            'requiredCapabilities': [],
            'arguments': {**arguments,
                          'previewToken': 'unexpired server-signed exact preview'},
            'result': 'published source-batch receipt with immutable policy pin',
            'previewRequired': True, 'idempotencyRequired': True,
            'workClass': 'medium'},
        LINEAGE_READ: {'mode': 'read', 'permission': 'read',
            'requiredCapabilities': [], 'arguments': {
                'batchId': 'settled caller-owned Seed batch ID',
                'pageSize': 'integer 1..500',
                'cursor': 'optional signed continuation cursor'},
            'result': 'immutable exact source/target fact-version lineage page',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'small'}}


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False, allow_nan=False)
                  .encode()).hexdigest()


class PostgresPublishedPlanningSeed:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 preview_secret: bytes):
        self.dsn, self.identity, self.preview_secret = (
            dsn, identity, preview_secret)
        from .postgres_language_v2 import PostgresLanguageV2
        self.language = PostgresLanguageV2(
            dsn, identity=identity, preview_secret=preview_secret)

    def _resolve(self, scope, args):
        bound, pointer = resolve_published_planning_policy(
            self.dsn, self.identity, scope, args, expected_kind='Seed',
            function=RUN)
        pin = {key: bound[key] for key in ('policyId', 'version',
            'policyDigest', 'metadataRevision', 'policyRevision')}
        pin.update(pointer)
        return bound, pin

    def _inspect(self, scope, bound, pin):
        definition = bound['definition']
        source_scope = {**definition['filterMembers'],
            definition['scenarioDimension']: definition['sourceMember']}
        target_scope = {**definition['filterMembers'],
            definition['scenarioDimension']: definition['targetMember']}
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write', function=RUN)
                state = db.execute('''SELECT s.metadata_revision,
                    s.data_revision,s.policy_revision,s.processing_mode,a.status
                    FROM epm.application_state s JOIN epm.application a
                    USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None or state['status'] != 'Active' or (
                        state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['metadata_revision'] != pin['metadataRevision']
                        or state['policy_revision'] != pin['policyRevision']):
                    raise ValueError('PLANNING_SEED_POLICY_STALE')
                PostgresSourceBatch._check_scope_members(db, scope, source_scope)
                PostgresSourceBatch._check_scope_members(db, scope, target_scope)
                row = db.execute('''WITH source AS (
                    SELECT epm.coordinate_series_key(c.members ||
                        jsonb_build_object(%s::text,%s::text)) AS series_key,
                        CASE WHEN d.coordinate_id IS NULL THEN 'numeric'
                             ELSE 'detail' END::text AS value_kind,
                        n.amount::text AS amount,NULL::text AS text_value,
                        d.items AS detail_items,
                        'scenario-copy:' || c.series_key AS source_ref
                    FROM epm.coordinate c JOIN epm.numeric_cell_current n
                      ON n.workspace_id=c.workspace_id
                     AND n.application_id=c.application_id
                     AND n.coordinate_id=c.coordinate_id AND n.present
                    LEFT JOIN epm.line_detail_current d
                      ON d.workspace_id=c.workspace_id
                     AND d.application_id=c.application_id
                     AND d.coordinate_id=c.coordinate_id
                    WHERE c.workspace_id=%s AND c.application_id=%s
                      AND c.members @> %s::jsonb
                    UNION ALL
                    SELECT epm.coordinate_series_key(c.members ||
                        jsonb_build_object(%s::text,%s::text)),
                        'text',NULL,t.text_value,NULL,
                        'scenario-copy:' || c.series_key
                    FROM epm.coordinate c JOIN epm.text_cell_current t
                      ON t.workspace_id=c.workspace_id
                     AND t.application_id=c.application_id
                     AND t.coordinate_id=c.coordinate_id AND t.present
                    WHERE c.workspace_id=%s AND c.application_id=%s
                      AND c.members @> %s::jsonb)
                    SELECT count(*) AS row_count,
                      encode(sha256(convert_to(COALESCE(string_agg(
                        jsonb_build_array(series_key,value_kind,amount,
                          text_value,detail_items,source_ref)::text,E'\n'
                        ORDER BY series_key),''),'UTF8')),'hex')
                        AS source_digest FROM source''',
                    (definition['scenarioDimension'],
                     definition['targetMember'],
                     scope.workspace_id, scope.application_id,
                     Jsonb(source_scope), definition['scenarioDimension'],
                     definition['targetMember'], scope.workspace_id,
                     scope.application_id, Jsonb(source_scope))).fetchone()
                if row['row_count'] > 100000:
                    raise ValueError('SCENARIO_COPY_ROW_LIMIT')
                revisions = {key: state[key] for key in (
                    'metadata_revision', 'data_revision', 'policy_revision')}
        return {'sourceScope': source_scope, 'targetScope': target_scope,
            'mode': definition['mode'],
            'provenancePolicy': definition['provenancePolicy'],
            'sourceRowCount': row['row_count'],
            'sourceDigest': row['source_digest'], 'revisions': revisions}

    @staticmethod
    def _normalized(args, pin, inspection):
        return {'version': 1, 'function': RUN, 'arguments': args,
            'reusablePolicy': pin,
            **{key: inspection[key] for key in ('sourceScope','targetScope',
                'mode','provenancePolicy','sourceRowCount','sourceDigest')}}

    def preview(self, scope, program):
        if (not isinstance(program, dict)
                or set(program) != {'languageVersion','function','arguments'}
                or program.get('languageVersion') != 2
                or program.get('function') != PREVIEW
                or not isinstance(program.get('arguments'), dict)
                or set(program['arguments']) != _CORE):
            raise ValueError('PLANNING_SEED_POLICY_PREVIEW_INVALID')
        args = program['arguments']
        bound, pin = self._resolve(scope, args)
        inspection = self._inspect(scope, bound, pin)
        normalized = self._normalized(args, pin, inspection)
        token, program_digest = self.language._sign_preview(
            scope, RUN, normalized, inspection['revisions'],
            extra={'requestDigest': _digest(args)})
        return {**inspection, 'reusablePolicy': pin,
            'programDigest': program_digest, 'previewToken': token}

    def _replay(self, scope, args, key, payload):
        if payload.get('requestDigest') != _digest(args):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write', function=RUN,
                    arguments=args)
                row = db.execute('''SELECT b.*,o.normalized_program
                    FROM epm.source_batch b JOIN epm.planning_copy_origin o
                     ON o.workspace_id=b.workspace_id
                    AND o.application_id=b.application_id
                    AND o.batch_id=b.batch_id
                    WHERE b.workspace_id=%s AND b.application_id=%s
                    AND b.issuer=%s AND b.subject_id=%s
                    AND b.idempotency_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     self.identity.issuer, self.identity.subject_id,
                     key)).fetchone()
        if row is None:
            return None
        origin = row['normalized_program']
        if (not isinstance(origin, dict)
                or set(origin) != {'copyProgram','reusablePolicy',
                                   'publicRequestDigest'}
                or origin['publicRequestDigest'] != _digest(args)
                or origin['reusablePolicy'].get('policyId') != args['policyId']):
            raise ValueError('SCENARIO_COPY_IDEMPOTENCY_CONFLICT')
        descriptor = {'scope': [scope.workspace_id, scope.application_id],
            'identity': [self.identity.issuer, self.identity.subject_id],
            'program': origin['copyProgram'],
            'reusablePolicy': origin['reusablePolicy'],
            'publicRequestDigest': origin['publicRequestDigest']}
        copy = origin['copyProgram']
        inspection = {'sourceScope': {**copy['filterMembers'],
                copy['scenarioDimension']: copy['sourceMember']},
            'targetScope': row['scope_members'], 'mode': copy['mode'],
            'provenancePolicy': 'copy_source_lineage',
            'sourceRowCount': row['row_count'],
            'sourceDigest': row['content_digest']}
        normalized = self._normalized(
            args, origin['reusablePolicy'], inspection)
        if (_canonical_digest(descriptor) != row['request_digest']
                or payload.get('programDigest') !=
                    _canonical_digest(normalized)):
            raise ValueError('SCENARIO_COPY_IDEMPOTENCY_CONFLICT')
        return row

    def _authorizer(self, expected_pin):
        def authorize(db, scope):
            row = db.execute('''SELECT p.version,p.canonical_digest,
                s.pointer_version,s.state_revision,a.metadata_revision,
                a.policy_revision FROM epm.planning_operation_policy_state s
                JOIN epm.planning_operation_policy_version p
                  ON p.workspace_id=s.workspace_id
                 AND p.application_id=s.application_id
                 AND p.policy_id=s.policy_id
                 AND p.version=s.active_version
                JOIN epm.application_state a
                  ON a.workspace_id=s.workspace_id
                 AND a.application_id=s.application_id
                WHERE s.workspace_id=%s AND s.application_id=%s
                  AND s.policy_id=%s''',
                (scope.workspace_id, scope.application_id,
                 expected_pin['policyId'])).fetchone()
            return row is not None and all((
                row['version']==expected_pin['version'],
                row['canonical_digest']==expected_pin['policyDigest'],
                row['pointer_version']==expected_pin['pointerVersion'],
                row['state_revision']==expected_pin['stateRevision'],
                row['metadata_revision']==expected_pin['metadataRevision'],
                row['policy_revision']==expected_pin['policyRevision']))
        return authorize

    def run(self, scope, program, *, idempotency_key):
        if (not isinstance(program, dict)
                or set(program) != {'languageVersion','function','arguments'}
                or program.get('languageVersion') != 2
                or program.get('function') != RUN
                or not isinstance(program.get('arguments'), dict)
                or set(program['arguments']) != _CORE | {'previewToken'}):
            raise ValueError('PLANNING_SEED_POLICY_RUN_INVALID')
        args = dict(program['arguments'])
        token = args.pop('previewToken')
        payload = self.language._unpack_preview(scope, RUN, token)
        replay = self._replay(scope, args, idempotency_key, payload)
        if replay is not None:
            source = PostgresSourceBatch(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret,
                publication_authorizer=(None if replay['status']=='published'
                    else self._authorizer(
                        replay['normalized_program']['reusablePolicy'])))
            if replay['status'] == 'published':
                published = source.published_result(scope, replay['batch_id'])
            else:
                review = source.preview(scope, replay['batch_id'])
                published = source.publish(
                    scope, replay['batch_id'],
                    preview_token=review['previewToken'])
            return {'batchId': replay['batch_id'], 'status': 'published',
                'duplicate': True, 'publication': published,
                'reusablePolicy': replay['normalized_program']['reusablePolicy']}
        bound, pin = self._resolve(scope, args)
        inspection = self._inspect(scope, bound, pin)
        normalized = self._normalized(args, pin, inspection)
        if (payload.get('programDigest') != _canonical_digest(normalized)
                or payload.get('requestDigest') != _digest(args)
                or payload.get('revisions') != inspection['revisions']):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        legacy = lower_bound_seed_to_legacy_v2(
            bound, expected_data_revision=
            inspection['revisions']['data_revision'],
            idempotency_key=idempotency_key)
        prepared = PostgresScenarioCopy(
            self.dsn, identity=self.identity).prepare(
                scope, legacy, policy_pin=pin,
                public_request_digest=_digest(args))
        if (prepared['rowCount'] != inspection['sourceRowCount']
                or prepared['contentDigest'] != inspection['sourceDigest']):
            raise ValueError('SCENARIO_COPY_SOURCE_CHANGED')
        source = PostgresSourceBatch(
            self.dsn, identity=self.identity,
            preview_secret=self.preview_secret,
            publication_authorizer=self._authorizer(pin))
        review = source.preview(scope, prepared['batchId'])
        published = source.publish(
            scope, prepared['batchId'], preview_token=review['previewToken'])
        return {'batchId': prepared['batchId'], 'status': 'published',
            'duplicate': False, 'publication': published,
            'reusablePolicy': pin}

    def _lineage_cursor(self, payload):
        raw = json.dumps(payload,sort_keys=True,separators=(',', ':'),
                         ensure_ascii=True).encode('ascii')
        return base64.urlsafe_b64encode(
            raw+hmac.new(self.preview_secret,raw,sha256).digest()).decode('ascii')

    def _read_lineage_cursor(self, token, scope, batch_id):
        if token is None:
            return 0
        if not isinstance(token,str) or len(token)>4096:
            raise ValueError('PLANNING_SEED_LINEAGE_CURSOR_INVALID')
        try:
            packed=base64.urlsafe_b64decode(token.encode('ascii'))
            raw,signature=packed[:-32],packed[-32:]
            if not hmac.compare_digest(
                    signature,hmac.new(self.preview_secret,raw,sha256).digest()):
                raise ValueError
            payload=json.loads(raw)
        except Exception as error:
            raise ValueError('PLANNING_SEED_LINEAGE_CURSOR_INVALID') from error
        expected={'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],
            'batchId':batch_id}
        if (not isinstance(payload,dict)
                or set(payload)!={'scope','identity','batchId','after','expiresAt'}
                or any(payload.get(key)!=value for key,value in expected.items())
                or type(payload.get('after')) is not int or payload['after']<0
                or type(payload.get('expiresAt')) is not int
                or payload['expiresAt']<int(time.time())):
            raise ValueError('PLANNING_SEED_LINEAGE_CURSOR_INVALID')
        return payload['after']

    def read_lineage(self, scope, program):
        if (not isinstance(program,dict)
                or set(program)!={'languageVersion','function','arguments'}
                or program.get('languageVersion')!=2
                or program.get('function')!=LINEAGE_READ
                or not isinstance(program.get('arguments'),dict)
                or not {'batchId','pageSize'} <= set(program['arguments'])
                or set(program['arguments'])-{'batchId','pageSize','cursor'}):
            raise ValueError('PLANNING_SEED_LINEAGE_READ_INVALID')
        args=program['arguments']; batch_id=args['batchId']; size=args['pageSize']
        if (not isinstance(batch_id,str) or not re.fullmatch(r'[0-9a-f]{32}',batch_id)
                or type(size) is not int or not 1<=size<=500):
            raise ValueError('PLANNING_SEED_LINEAGE_READ_INVALID')
        after=self._read_lineage_cursor(args.get('cursor'),scope,batch_id)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'read',function=LINEAGE_READ,
                    arguments=args)
                batch=db.execute('''SELECT status,issuer,subject_id FROM
                    epm.source_batch WHERE workspace_id=%s AND application_id=%s
                    AND batch_id=%s''',(scope.workspace_id,scope.application_id,
                    batch_id)).fetchone()
                if (batch is None or batch['status']!='published'
                        or batch['issuer']!=self.identity.issuer
                        or batch['subject_id']!=self.identity.subject_id):
                    raise ValueError('PLANNING_SEED_LINEAGE_NOT_FOUND')
                rows=db.execute('''SELECT * FROM epm.planning_seed_lineage
                    WHERE workspace_id=%s AND application_id=%s AND batch_id=%s
                    AND action_ordinal>%s ORDER BY action_ordinal LIMIT %s''',
                    (scope.workspace_id,scope.application_id,batch_id,after,
                     size+1)).fetchall()
        more=len(rows)>size; rows=rows[:size]
        items=[{'ordinal':row['action_ordinal'],'action':row['action'],
            'family':row['value_family'],
            'target':{'seriesKey':row['target_series_key'],
                'coordinateId':row['target_coordinate_id'],
                'changeId':row['target_change_id'],
                'detailChangeId':row['target_detail_change_id'],
                'committedRevision':row['target_committed_revision']},
            'source':(None if row['source_series_key'] is None else {
                'seriesKey':row['source_series_key'],
                'coordinateId':row['source_coordinate_id'],
                'changeId':row['source_change_id'],
                'detailChangeId':row['source_detail_change_id'],
                'committedRevision':row['source_committed_revision']}),
            'policy':{'policyId':row['policy_id'],
                'version':row['policy_version'],'digest':row['policy_digest']},
            'contentDigest':row['content_digest']} for row in rows]
        cursor=None
        if more:
            cursor=self._lineage_cursor({'scope':[scope.workspace_id,
                scope.application_id], 'identity':[self.identity.issuer,
                self.identity.subject_id], 'batchId':batch_id,
                'after':rows[-1]['action_ordinal'],
                'expiresAt':int(time.time())+900})
        return {'batchId':batch_id,'items':items,'nextCursor':cursor}
