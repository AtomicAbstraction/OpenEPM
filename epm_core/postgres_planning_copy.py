"""Set-based numeric/text/detail scenario copy on the generic EPM cube.

This creates a durable, provenance-linked source batch in one transaction.
The existing source preview/publish path remains the only fact writer.
"""
from __future__ import annotations

import re
import uuid
from hashlib import sha256

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security import CUBE_READ_AUTHORIZATION_STALE
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .slice_copy_contract import (FUNCTION as PUBLIC_FUNCTION, FIELDS as PUBLIC_FIELDS,
    OPERATION_KEY_PATTERN, STATUS_READ, STATUS_UNAVAILABLE)
from .postgres_access import AccessDecision,PostgresAccessChecker,VerifiedIdentity
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_source_batch import (PostgresSourceBatch,
    authorize_staged_copy_sources, enforce_source_batch_dimensional_security,
    enforce_source_batch_policy, require_current_copy_groups)


FUNCTION='facts.planning.scenario.copy.prepare'
_KEY=re.compile(OPERATION_KEY_PATTERN)
_EMPTY_DIGEST=sha256(b'').hexdigest()


def compile_copy_program(program: object) -> dict:
    if (not isinstance(program,dict)
            or set(program)!={'languageVersion','function','arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion']!=2
            or program['function'] not in (FUNCTION, PUBLIC_FUNCTION)
            or not isinstance(program['arguments'],dict)):
        raise ValueError('V2_SCENARIO_COPY_FUNCTION_INVALID')
    args=program['arguments']
    if program['function'] == PUBLIC_FUNCTION:
        if set(args) != PUBLIC_FIELDS:
            raise ValueError('V2_SLICE_COPY_ARGUMENTS_INVALID')
        args={**args, 'scenarioDimension':args['dimensionId'],
              'sourceMember':args['sourceMemberId'], 'targetMember':args['targetMemberId']}
        for key in ('dimensionId', 'sourceMemberId', 'targetMemberId'): del args[key]
    if set(args)!={'scenarioDimension','sourceMember','targetMember',
                  'filterMembers','mode','expectedMetadataRevision',
                  'expectedDataRevision','idempotencyKey'}:
        raise ValueError('V2_SCENARIO_COPY_ARGUMENTS_INVALID')
    dimension=args['scenarioDimension']
    source=args['sourceMember']
    target=args['targetMember']
    filters=args['filterMembers']
    if (any(not isinstance(value,str) or not 1<=len(value)<=200
            for value in (dimension,source,target))
            or source==target
            or not isinstance(filters,dict) or len(filters)>31
            or dimension in filters
            or any(not isinstance(axis,str) or not 1<=len(axis)<=200
                   or not isinstance(member,str) or not 1<=len(member)<=200
                   for axis,member in filters.items())
            or args['mode'] not in ('merge','replace')
            or type(args['expectedMetadataRevision']) is not int
            or args['expectedMetadataRevision']<0
            or type(args['expectedDataRevision']) is not int
            or args['expectedDataRevision']<0
            or not isinstance(args['idempotencyKey'],str)
            or not _KEY.fullmatch(args['idempotencyKey'])):
        raise ValueError('V2_SCENARIO_COPY_ARGUMENTS_INVALID')
    return {'function':program['function'],'scenarioDimension':dimension,
            'sourceMember':source,'targetMember':target,
            'filterMembers':dict(sorted(filters.items())),
            'mode':args['mode'],
            'expectedMetadataRevision':args['expectedMetadataRevision'],
            'expectedDataRevision':args['expectedDataRevision'],
            'idempotencyKey':args['idempotencyKey']}


class PostgresScenarioCopy:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity):
        if not isinstance(dsn,str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn=dsn
        self.identity=identity

    def _authorize_sources(self, db, scope, source_scope, *, expected_access: AccessDecision):
        """Bounded exact READ coverage; hidden input never becomes a partial copy."""
        after=''; seen=0
        while True:
            rows=db.execute('''SELECT c.series_key,c.members FROM epm.coordinate c
                WHERE c.workspace_id=%s AND c.application_id=%s
                  AND c.members @> %s::jsonb AND c.series_key>%s
                  AND (EXISTS (SELECT 1 FROM epm.numeric_cell_current n
                    WHERE n.workspace_id=c.workspace_id AND n.application_id=c.application_id
                      AND n.coordinate_id=c.coordinate_id AND n.present)
                   OR EXISTS (SELECT 1 FROM epm.text_cell_current t
                    WHERE t.workspace_id=c.workspace_id AND t.application_id=c.application_id
                      AND t.coordinate_id=c.coordinate_id AND t.present))
                ORDER BY c.series_key LIMIT 1000''',
                (scope.workspace_id,scope.application_id,Jsonb(source_scope),after)).fetchall()
            if not rows:return
            authorize_coordinates(db,self.identity,scope,
                (Coordinate.from_mapping(row['members']) for row in rows),
                kind=AccessKind.READ,expected_access=expected_access)
            seen+=len(rows)
            if seen>100000:raise ValueError('SCENARIO_COPY_ROW_LIMIT')
            after=rows[-1]['series_key']

    def read_status(self, scope: ApplicationScope, program: dict) -> dict:
        if (type(program) is not dict
                or set(program) != {'languageVersion','function','arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2 or program['function'] != STATUS_READ
                or type(program['arguments']) is not dict
                or set(program['arguments']) != {'operationId'}):
            raise ValueError('SCENARIO_COPY_STATUS_PROGRAM_INVALID')
        operation_id = program['arguments']['operationId']
        if type(operation_id) is not str or _KEY.fullmatch(operation_id) is None:
            raise ValueError('SCENARIO_COPY_STATUS_OPERATION_ID_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=STATUS_READ)
                # Only direct slice copy writes can own this status. Source
                # imports and reusable planning policies have separate owners.
                batch = db.execute('''SELECT b.batch_id,b.status,b.row_count,b.content_digest,
                    o.normalized_program FROM epm.source_batch b
                    JOIN epm.planning_copy_origin o USING (workspace_id,application_id,batch_id)
                    WHERE b.workspace_id=%s AND b.application_id=%s AND b.issuer=%s
                      AND b.subject_id=%s AND b.idempotency_key=%s
                      AND o.normalized_program->>'function' IN (%s,%s)''',
                    (scope.workspace_id, scope.application_id, self.identity.issuer,
                     self.identity.subject_id, operation_id, PUBLIC_FUNCTION, FUNCTION)).fetchone()
                if batch is None:
                    raise ValueError(STATUS_UNAVAILABLE)
                authorize_staged_copy_sources(db, self.identity, scope, batch,
                    batch['normalized_program'], expected_access=access,
                    include_targets=True)
                current = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=STATUS_READ)
                if current != access:
                    raise ValueError(CUBE_READ_AUTHORIZATION_STALE)
                return {'batchId':batch['batch_id'], 'status':batch['status'],
                    'rowCount':batch['row_count'], 'contentDigest':batch['content_digest']}

    def prepare(self,scope: ApplicationScope,program: dict, *,
                policy_pin: dict | None = None,
                public_request_digest: str | None = None,
                replay_only: bool = False) -> dict | None:
        normalized=compile_copy_program(program)
        if ((policy_pin is None) != (public_request_digest is None)
                or (policy_pin is not None and (
                    not isinstance(policy_pin,dict)
                    or set(policy_pin)!={'policyId','policyDigest',
                        'metadataRevision','policyRevision',
                        'authoredMetadataRevision','authoredPolicyRevision',
                        'stateToken'}
                    or not isinstance(public_request_digest,str)
                    or not re.fullmatch(r'[0-9a-f]{64}',public_request_digest)))):
            raise ValueError('SCENARIO_COPY_POLICY_PIN_INVALID')
        source_scope={**normalized['filterMembers'],
                      normalized['scenarioDimension']:
                          normalized['sourceMember']}
        target_scope={**normalized['filterMembers'],
                      normalized['scenarioDimension']:
                          normalized['targetMember']}
        digest=_canonical_digest({
            'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],
            'program':normalized,
            **({'reusablePolicy':policy_pin,
                'publicRequestDigest':public_request_digest}
               if policy_pin is not None else {})})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                if replay_only:db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db,scope)
                initial_access = PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')
                state=db.execute('''SELECT s.metadata_revision,
                    s.data_revision,s.commit_revision,s.processing_mode,a.status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    ''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                db.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',
                    ('|'.join(('copy',scope.workspace_id,scope.application_id,
                        self.identity.issuer,self.identity.subject_id,normalized['idempotencyKey'])),))
                previous=db.execute('''SELECT * FROM epm.source_batch
                    WHERE workspace_id=%s AND application_id=%s
                    AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     self.identity.issuer,self.identity.subject_id,
                     normalized['idempotencyKey'])).fetchone()
                if previous:
                    if previous['request_digest']!=digest:
                        raise ValueError('SCENARIO_COPY_IDEMPOTENCY_CONFLICT')
                    groups = authorize_staged_copy_sources(db, self.identity, scope, previous,
                        normalized, expected_access=initial_access)
                    enforce_source_batch_dimensional_security(db,self.identity,scope,previous,
                        expected_access=initial_access)
                    require_current_copy_groups(db, self.identity, groups)
                    return {'batchId':previous['batch_id'],
                            'status':previous['status'],
                            'rowCount':previous['row_count'],
                            'contentDigest':previous['content_digest'],
                            'duplicate':True}
                if replay_only:return None
                if (state['status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['metadata_revision']!=
                        normalized['expectedMetadataRevision']
                        or state['data_revision']!=
                        normalized['expectedDataRevision']):
                    raise ValueError('STALE_SCENARIO_COPY_REVISION')
                PostgresSourceBatch._check_scope_members(db,scope,source_scope)
                PostgresSourceBatch._check_scope_members(db,scope,target_scope)
                self._authorize_sources(db,scope,source_scope,expected_access=initial_access)
                detail=db.execute('''SELECT 1 FROM epm.coordinate c
                    JOIN epm.line_detail_current d
                      ON d.workspace_id=c.workspace_id
                      AND d.application_id=c.application_id
                      AND d.coordinate_id=c.coordinate_id
                    LEFT JOIN epm.numeric_cell_current n
                      ON n.workspace_id=d.workspace_id
                      AND n.application_id=d.application_id
                      AND n.coordinate_id=d.coordinate_id
                    WHERE c.workspace_id=%s AND c.application_id=%s
                    AND c.members @> %s::jsonb
                    AND (n.coordinate_id IS NULL OR NOT n.present
                         OR n.amount<>d.total)
                    LIMIT 1''',
                    (scope.workspace_id,scope.application_id,
                     Jsonb(source_scope))).fetchone()
                if detail:
                    raise ValueError('SCENARIO_COPY_SOURCE_DETAIL_INCONSISTENT')
                count=db.execute('''SELECT
                    (SELECT count(*) FROM epm.coordinate c
                     JOIN epm.numeric_cell_current n
                     ON n.workspace_id=c.workspace_id
                     AND n.application_id=c.application_id
                     AND n.coordinate_id=c.coordinate_id AND n.present
                     WHERE c.workspace_id=%s AND c.application_id=%s
                     AND c.members @> %s::jsonb)
                    + (SELECT count(*) FROM epm.coordinate c
                     JOIN epm.text_cell_current t
                     ON t.workspace_id=c.workspace_id
                     AND t.application_id=c.application_id
                     AND t.coordinate_id=c.coordinate_id AND t.present
                     WHERE c.workspace_id=%s AND c.application_id=%s
                     AND c.members @> %s::jsonb) AS total''',
                    (scope.workspace_id,scope.application_id,
                     Jsonb(source_scope),scope.workspace_id,
                     scope.application_id,Jsonb(source_scope))).fetchone()['total']
                if count>100000:
                    raise ValueError('SCENARIO_COPY_ROW_LIMIT')
                batch_id=uuid.uuid4().hex
                db.execute('''CREATE TEMP TABLE scenario_copy_stage
                    ON COMMIT DROP AS SELECT
                        row_number() OVER (ORDER BY source.series_key)
                            AS row_ordinal,
                        epm.coordinate_series_key(
                            source.members || jsonb_build_object(
                                %s::text,%s::text)) AS series_key,
                        source.members || jsonb_build_object(
                            %s::text,%s::text) AS members,
                        source.amount,source.value_kind,source.text_value,
                        source.detail_items,
                        'scenario-copy:' || source.series_key AS source_ref
                    FROM (
                        SELECT c.series_key,c.members,n.amount,
                            CASE WHEN d.coordinate_id IS NULL THEN 'numeric'
                                 ELSE 'detail' END::text AS value_kind,
                            NULL::text AS text_value,d.items AS detail_items
                        FROM epm.coordinate c
                        JOIN epm.numeric_cell_current n
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
                        SELECT c.series_key,c.members,NULL::numeric,
                            'text'::text,t.text_value,NULL::jsonb
                        FROM epm.coordinate c
                        JOIN epm.text_cell_current t
                        ON t.workspace_id=c.workspace_id
                        AND t.application_id=c.application_id
                        AND t.coordinate_id=c.coordinate_id AND t.present
                        WHERE c.workspace_id=%s AND c.application_id=%s
                        AND c.members @> %s::jsonb
                    ) source''',
                    (normalized['scenarioDimension'],
                     normalized['targetMember'],
                     normalized['scenarioDimension'],
                     normalized['targetMember'],
                     scope.workspace_id,scope.application_id,
                     Jsonb(source_scope),scope.workspace_id,
                     scope.application_id,Jsonb(source_scope)))
                inserted=db.execute('''SELECT count(*) AS total
                    FROM scenario_copy_stage''').fetchone()['total']
                if inserted!=count:
                    raise ValueError('SCENARIO_COPY_SOURCE_CHANGED')
                content=db.execute('''SELECT encode(sha256(convert_to(
                    COALESCE(string_agg(jsonb_build_array(series_key,
                        value_kind,amount::text,text_value,detail_items,
                        source_ref)::text,
                        E'\\n' ORDER BY series_key),''),
                    'UTF8')),'hex') AS digest
                    FROM scenario_copy_stage''').fetchone()['digest']
                # Source discovery and relational staging are read/prepare
                # work.  Keep the application publication row free while they
                # run, then fence the exact revision and current authority
                # before the staged batch becomes Ready.  Any intervening
                # business or metadata effect rolls this entire transaction
                # back; concurrent preparations at the same unchanged source
                # revision may both complete.
                final_state=db.execute('''SELECT s.metadata_revision,
                    s.data_revision,s.processing_mode,a.status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if final_state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')
                if access != initial_access:
                    raise ValueError(CUBE_READ_AUTHORIZATION_STALE)
                if (final_state['status']!='Active'
                        or final_state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (final_state['metadata_revision']!=
                        normalized['expectedMetadataRevision']
                        or final_state['data_revision']!=
                        normalized['expectedDataRevision']):
                    raise ValueError('STALE_SCENARIO_COPY_REVISION')
                db.execute('''INSERT INTO epm.source_batch
                    (workspace_id,application_id,batch_id,issuer,subject_id,
                     idempotency_key,request_digest,mode,scope_members,
                     scope_all,expected_metadata_revision,
                     expected_data_revision,expected_commit_revision,
                     status,content_digest)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,false,%s,%s,%s,
                            'staging',%s)''',
                    (scope.workspace_id,scope.application_id,batch_id,
                     self.identity.issuer,self.identity.subject_id,
                     normalized['idempotencyKey'],digest,
                     normalized['mode'],Jsonb(target_scope),
                     normalized['expectedMetadataRevision'],
                     normalized['expectedDataRevision'],
                     state['commit_revision'],_EMPTY_DIGEST))
                durable_rows=db.execute('''INSERT INTO epm.source_batch_row
                    (workspace_id,application_id,batch_id,row_ordinal,
                     series_key,members,amount,value_kind,text_value,
                     detail_items,source_ref)
                    SELECT %s,%s,%s,row_ordinal,series_key,members,amount,
                        value_kind,text_value,detail_items,source_ref
                    FROM scenario_copy_stage ORDER BY row_ordinal''',
                    (scope.workspace_id,scope.application_id,
                     batch_id)).rowcount
                if durable_rows!=count:
                    raise ValueError('SCENARIO_COPY_SOURCE_CHANGED')
                db.execute('''UPDATE epm.source_batch SET status='ready',
                    row_count=%s,content_digest=%s,
                    updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                    AND batch_id=%s''',
                    (count,content,scope.workspace_id,
                     scope.application_id,batch_id))
                batch=db.execute('''SELECT * FROM epm.source_batch
                    WHERE workspace_id=%s AND application_id=%s
                    AND batch_id=%s''',
                    (scope.workspace_id,scope.application_id,
                     batch_id)).fetchone()
                PostgresSourceBatch._check_locks(db,scope,batch)
                enforce_source_batch_dimensional_security(db,self.identity,scope,batch,
                    expected_access=initial_access)
                enforce_source_batch_policy(db,scope,batch,access.role)
                db.execute('''INSERT INTO epm.planning_copy_origin
                    (workspace_id,application_id,batch_id,
                     normalized_program,source_data_revision,
                     source_row_count)
                    VALUES (%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id,scope.application_id,batch_id,
                    Jsonb({'copyProgram':normalized,
                           'reusablePolicy':policy_pin,
                           'publicRequestDigest':public_request_digest}
                          if policy_pin is not None else normalized),
                    state['data_revision'],count))
                if policy_pin is not None:
                    lineage_count = db.execute('''INSERT INTO epm.planning_seed_lineage
                        (workspace_id,application_id,batch_id,action_ordinal,
                         action,value_family,target_series_key,
                         source_series_key,source_coordinate_id,source_change_id,
                         source_detail_change_id,source_committed_revision,
                         policy_id,policy_state_token,policy_digest,content_digest)
                        SELECT r.workspace_id,r.application_id,r.batch_id,
                          r.row_ordinal,'Set',
                          CASE r.value_kind WHEN 'numeric' THEN 'Numeric'
                            WHEN 'text' THEN 'Text' ELSE 'Detail' END,
                          r.series_key,substring(r.source_ref from 15),c.coordinate_id,
                          CASE WHEN r.value_kind='text' THEN t.change_id
                               ELSE n.change_id END,
                          CASE WHEN r.value_kind='detail' THEN d.change_id END,
                          CASE WHEN r.value_kind='text' THEN t.last_revision
                               ELSE n.last_revision END,
                          %s,%s,%s,%s
                        FROM epm.source_batch_row r
                        JOIN epm.coordinate c ON c.workspace_id=r.workspace_id
                         AND c.application_id=r.application_id
                         AND c.series_key=substring(r.source_ref from 15)
                        LEFT JOIN epm.numeric_cell_current n
                         ON n.workspace_id=c.workspace_id
                         AND n.application_id=c.application_id
                         AND n.coordinate_id=c.coordinate_id AND n.present
                        LEFT JOIN epm.text_cell_current t
                         ON t.workspace_id=c.workspace_id
                         AND t.application_id=c.application_id
                         AND t.coordinate_id=c.coordinate_id AND t.present
                        LEFT JOIN epm.line_detail_current d
                         ON d.workspace_id=c.workspace_id
                         AND d.application_id=c.application_id
                         AND d.coordinate_id=c.coordinate_id
                        WHERE r.workspace_id=%s AND r.application_id=%s
                         AND r.batch_id=%s''',
                        (policy_pin['policyId'],policy_pin['stateToken'],
                         policy_pin['policyDigest'],content,
                         scope.workspace_id,scope.application_id,batch_id)).rowcount
                    if lineage_count != count:
                        raise ValueError('SCENARIO_COPY_SOURCE_LINEAGE_CHANGED')
                require_current_copy_groups(db, self.identity, initial_access.groups)
                return {'batchId':batch_id,'status':'ready',
                        'rowCount':count,'contentDigest':content,
                        'duplicate':False,
                        **({'reusablePolicy':policy_pin}
                           if policy_pin is not None else {})}
