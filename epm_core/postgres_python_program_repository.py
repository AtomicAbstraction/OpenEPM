"""PostgreSQL adapter for isolated Python build control.

User admission/cancellation uses the scoped runtime role plus a verified
identity.  Claims and sealing use the separate NOLOGIN coordinator role.  The
adapter stores only source references, parameters and bounded JSON artifacts;
it never imports or executes authored Python.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import (AccessDenied, PostgresAccessChecker,
                              VerifiedExecutionIdentity, VerifiedIdentity,
                              assert_nonowner_role,durable_authority_fields,
                              durable_execution_identity)
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .python_program_execution import (BuildRecord, BuildStatus, SealedPlan,
                                       MAX_BUILD_LOG_BYTES, MAX_OPERATIONS,
                                       MAX_PLAN_BYTES, MAX_SOURCE_MAP_BYTES,
                                       validate_build_artifacts,
                                       verify_plan_identity)


_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_AUTHORITY_ID = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
_KEY = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_ENTRY_POINT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,99}$")

SAVE = "python.program.save"
READ = "python.program.read"
LIST = "python.program.list"
PUBLISH = "python.program.publish"
DEACTIVATE = "python.program.deactivate"


def python_build_id(scope: ApplicationScope, identity: VerifiedIdentity,
                    idempotency_key: str) -> str:
    """Derive the stable owner-bound identity for one build request."""
    raw = json.dumps({'domain': 'openepm-python-build-v1',
        'scope': [scope.workspace_id, scope.application_id],
        'identity': [identity.issuer, identity.subject_id],
        'idempotencyKey': idempotency_key}, sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode('ascii')
    return sha256(raw).hexdigest()[:32]


def _canonical(value: object, code: str) -> bytes:
    def reject(item: object) -> None:
        if isinstance(item, float):
            raise ValueError(code)
        if isinstance(item, dict):
            if any(type(key) is not str for key in item):
                raise ValueError(code)
            for child in item.values(): reject(child)
        elif isinstance(item, (list, tuple)):
            for child in item: reject(child)
        elif item is not None and type(item) not in (str, int, bool):
            raise ValueError(code)
    reject(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError(code) from error


def _assert_coordinator_role(dsn: str) -> None:
    if type(dsn) is not str or not dsn:
        raise ValueError("PYTHON_COORDINATOR_DSN_REQUIRED")
    with connect_postgres(dsn, row_factory=dict_row) as db:
        row = db.execute('''SELECT r.rolsuper,r.rolbypassrls,r.rolcreaterole,
            r.rolcreatedb,r.rolreplication,
            pg_has_role(current_user,'epm_python_coordinator','member') AS coordinator,
            pg_has_role(current_user,'epm_runtime','member') AS runtime,
            pg_has_role(current_user,'epm_worker','member') AS worker,
            has_schema_privilege(current_user,'epm','CREATE') AS schema_create
            FROM pg_roles r WHERE r.rolname=current_user''').fetchone()
    if (not row or not row['coordinator'] or row['runtime'] or row['worker']
            or any(row[key] for key in ('rolsuper','rolbypassrls','rolcreaterole',
                                        'rolcreatedb','rolreplication','schema_create'))):
        raise ValueError("POSTGRES_PYTHON_COORDINATOR_ROLE_TOO_BROAD")


def _epoch(value: datetime | None) -> int | None:
    return None if value is None else int(value.timestamp())


def _record(row) -> BuildRecord | None:
    if row is None:
        return None
    return BuildRecord(ApplicationScope(row['workspace_id'], row['application_id']),
        row['build_id'], row['request_digest'], BuildStatus(row['status']),
        row['claim_generation'], row['claimant'], _epoch(row['lease_until']),
        row['attempts'], row.get('plan_digest'), row['error_code'])


def _program(raw: object, function: str) -> dict:
    if (type(raw) is not dict
            or set(raw) != {'languageVersion', 'function', 'arguments'}
            or raw.get('languageVersion') != 2
            or raw.get('function') != function
            or type(raw.get('arguments')) is not dict):
        raise ValueError('V2_PYTHON_PROGRAM_FUNCTION_INVALID')
    args = raw['arguments']
    if function == LIST:
        if (set(args) - {'limit', 'afterProgramId'}
                or type(args.get('limit', 100)) is not int
                or not 1 <= args.get('limit', 100) <= 100
                or ('afterProgramId' in args
                    and (type(args['afterProgramId']) is not str
                         or _ID.fullmatch(args['afterProgramId']) is None))):
            raise ValueError('V2_PYTHON_PROGRAM_ARGUMENTS_INVALID')
        return args
    if type(args.get('programId')) is not str or _ID.fullmatch(args['programId']) is None:
        raise ValueError('V2_PYTHON_PROGRAM_ARGUMENTS_INVALID')
    if function == READ:
        if (set(args) not in ({'programId'}, {'programId', 'version'})
                or ('version' in args
                    and (type(args['version']) is not int or args['version'] < 1))):
            raise ValueError('V2_PYTHON_PROGRAM_ARGUMENTS_INVALID')
        return args
    pins = {'expectedMetadataRevision', 'expectedPolicyRevision',
            'expectedSchemaEpoch'}
    if function == SAVE:
        required = {'programId', 'version', 'sourceText', 'entryPoint',
                    'parameterSchema', 'environmentId', 'environmentVersion'} | pins
        if (set(args) != required
                or type(args['version']) is not int or args['version'] < 1
                or type(args['environmentVersion']) is not int
                or args['environmentVersion'] < 1
                or type(args['environmentId']) is not str
                or _ID.fullmatch(args['environmentId']) is None
                or type(args['entryPoint']) is not str
                or _ENTRY_POINT.fullmatch(args['entryPoint']) is None
                or type(args['sourceText']) is not str
                or not 1 <= len(args['sourceText'].encode('utf-8')) <= 1048576
                or '\x00' in args['sourceText']
                or type(args['parameterSchema']) is not dict
                or len(_canonical(args['parameterSchema'],
                                  'PYTHON_PARAMETER_SCHEMA_INVALID')) > 262144):
            raise ValueError('V2_PYTHON_PROGRAM_ARGUMENTS_INVALID')
    else:
        required = {'programId', 'version'} | pins
        if (set(args) != required or type(args['version']) is not int
                or args['version'] < 1):
            raise ValueError('V2_PYTHON_PROGRAM_ARGUMENTS_INVALID')
    if any(type(args[name]) is not int or args[name] < 0 for name in pins):
        raise ValueError('V2_PYTHON_PROGRAM_ARGUMENTS_INVALID')
    return args


class PostgresPythonPrograms:
    """Immutable authored source registry; never imports or executes source."""

    SAVE, READ, LIST, PUBLISH, DEACTIVATE = SAVE, READ, LIST, PUBLISH, DEACTIVATE

    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('Verified identity is required')
        assert_nonowner_role(dsn, 'epm_runtime',
            ('python_program_version', 'python_program_publication'))
        self.dsn, self.identity = dsn, identity

    def execute(self, scope: ApplicationScope, raw: dict, *,
                idempotency_key: str) -> dict:
        function = raw.get('function') if type(raw) is dict else None
        if function not in (SAVE, PUBLISH, DEACTIVATE):
            raise ValueError('V2_PYTHON_PROGRAM_FUNCTION_INVALID')
        args = _program(raw, function)
        if type(idempotency_key) is not str or _KEY.fullmatch(idempotency_key) is None:
            raise ValueError('PYTHON_PROGRAM_IDEMPOTENCY_KEY_INVALID')
        digest = sha256(_canonical({'scope': [scope.workspace_id,
            scope.application_id], 'identity': [self.identity.issuer,
            self.identity.subject_id], 'program': raw},
            'PYTHON_PROGRAM_REQUEST_INVALID')).hexdigest()
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                state = db.execute('''SELECT s.metadata_revision,s.policy_revision,
                    s.schema_epoch,s.commit_revision,s.processing_mode,
                    a.status AS application_status FROM epm.application_state s
                    JOIN epm.application a USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                PostgresAccessChecker.check_in_transaction(db, self.identity,
                    scope, 'rule_design' if function == SAVE else 'rule_publish')
                prior = db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     idempotency_key)).fetchone()
                if prior is not None:
                    if (prior['command_digest'] != digest
                            or prior['actor_id'] != self.identity.subject_id):
                        raise ValueError('PYTHON_PROGRAM_IDEMPOTENCY_CONFLICT')
                    return prior['result']
                if (state['application_status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                for field, argument in (('metadata_revision','expectedMetadataRevision'),
                        ('policy_revision','expectedPolicyRevision'),
                        ('schema_epoch','expectedSchemaEpoch')):
                    if state[field] != args[argument]:
                        raise ValueError('PYTHON_PROGRAM_STALE_CONTEXT')
                revision = state['commit_revision'] + 1
                if function == SAVE:
                    latest = db.execute('''SELECT max(version) AS version
                        FROM epm.python_program_version WHERE workspace_id=%s
                        AND application_id=%s AND program_id=%s''',
                        (scope.workspace_id, scope.application_id,
                         args['programId'])).fetchone()['version']
                    if args['version'] != (latest or 0) + 1:
                        raise ValueError('PYTHON_PROGRAM_VERSION_NOT_NEXT')
                    environment = db.execute('''SELECT 1 FROM
                        epm.python_environment_current WHERE workspace_id=%s
                        AND application_id=%s AND environment_id=%s
                        AND version=%s AND status='Active' ''',
                        (scope.workspace_id, scope.application_id,
                         args['environmentId'],
                         args['environmentVersion'])).fetchone()
                    if environment is None:
                        raise ValueError('PYTHON_ENVIRONMENT_NOT_ACTIVE')
                    source_digest = sha256(args['sourceText'].encode('utf-8')).hexdigest()
                    status, policy_revision = 'Saved', state['policy_revision']
                else:
                    version = db.execute('''SELECT source_digest,environment_id,
                        environment_version FROM epm.python_program_version
                        WHERE workspace_id=%s AND application_id=%s
                        AND program_id=%s AND version=%s''',
                        (scope.workspace_id, scope.application_id,
                         args['programId'], args['version'])).fetchone()
                    if version is None:
                        raise ValueError('PYTHON_PROGRAM_VERSION_UNAVAILABLE')
                    if function == PUBLISH:
                        environment = db.execute('''SELECT 1 FROM
                            epm.python_environment_current WHERE workspace_id=%s
                            AND application_id=%s AND environment_id=%s
                            AND version=%s AND status='Active' ''',
                            (scope.workspace_id, scope.application_id,
                             version['environment_id'],
                             version['environment_version'])).fetchone()
                        if environment is None:
                            raise ValueError('PYTHON_ENVIRONMENT_NOT_ACTIVE')
                        status = 'Published'
                    else:
                        pointer = db.execute('''SELECT version,status FROM
                            epm.python_program_publication WHERE workspace_id=%s
                            AND application_id=%s AND program_id=%s''',
                            (scope.workspace_id, scope.application_id,
                             args['programId'])).fetchone()
                        if (pointer is None or pointer['version'] != args['version']
                                or pointer['status'] != 'Published'):
                            raise ValueError('PYTHON_PROGRAM_PUBLICATION_MISMATCH')
                        status = 'Deactivated'
                    source_digest = version['source_digest']
                    policy_revision = state['policy_revision'] + 1
                result = {'operationId': idempotency_key,
                    'programId': args['programId'], 'version': args['version'],
                    'status': status, 'sourceDigest': source_digest,
                    'metadataRevision': state['metadata_revision'],
                    'policyRevision': policy_revision,
                    'schemaEpoch': state['schema_epoch'],
                    'committedRevision': revision}
                db.execute('''UPDATE epm.application_state SET
                    policy_revision=%s,commit_revision=%s WHERE workspace_id=%s
                    AND application_id=%s''', (policy_revision, revision,
                    scope.workspace_id, scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt(workspace_id,
                    application_id,operation_id,command_digest,actor_id,
                    committed_revision,result) VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id, scope.application_id, idempotency_key,
                     digest, self.identity.subject_id, revision, Jsonb(result)))
                if function == SAVE:
                    db.execute('''INSERT INTO epm.python_program_version(
                        workspace_id,application_id,program_id,version,
                        source_text,source_digest,entry_point,parameter_schema,
                        environment_id,environment_version,created_operation_id,
                        created_revision,created_issuer,created_subject_id)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                        (scope.workspace_id, scope.application_id,
                         args['programId'], args['version'], args['sourceText'],
                         source_digest, args['entryPoint'],
                         Jsonb(json.loads(_canonical(args['parameterSchema'],
                            'PYTHON_PARAMETER_SCHEMA_INVALID'))),
                         args['environmentId'], args['environmentVersion'],
                         idempotency_key, revision, self.identity.issuer,
                         self.identity.subject_id))
                else:
                    db.execute('''INSERT INTO epm.python_program_publication(
                        workspace_id,application_id,program_id,version,status,
                        operation_id,revision) VALUES (%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (workspace_id,application_id,program_id)
                        DO UPDATE SET version=EXCLUDED.version,
                            status=EXCLUDED.status,
                            operation_id=EXCLUDED.operation_id,
                            revision=EXCLUDED.revision,
                            updated_at=transaction_timestamp()''',
                        (scope.workspace_id, scope.application_id,
                         args['programId'], args['version'], status,
                         idempotency_key, revision))
                return result

    def read(self, scope: ApplicationScope, raw: dict) -> dict:
        args = _program(raw, READ)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                pointer = db.execute('''SELECT version,status,revision FROM
                    epm.python_program_publication WHERE workspace_id=%s
                    AND application_id=%s AND program_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     args['programId'])).fetchone()
                version = args.get('version') or (
                    pointer['version'] if pointer else None)
                row = (db.execute('''SELECT version,source_text,source_digest,
                    entry_point,parameter_schema,environment_id,
                    environment_version,created_revision,created_at FROM
                    epm.python_program_version WHERE workspace_id=%s
                    AND application_id=%s AND program_id=%s AND version=%s''',
                    (scope.workspace_id, scope.application_id,
                     args['programId'], version)).fetchone()
                    if version is not None else None)
                return {'programId': args['programId'], 'defined': row is not None,
                    'version': row['version'] if row else version,
                    'status': (pointer['status'] if row and pointer
                        and pointer['version'] == row['version'] else
                        'Saved' if row else None),
                    'sourceText': row['source_text'] if row else None,
                    'sourceDigest': row['source_digest'] if row else None,
                    'entryPoint': row['entry_point'] if row else None,
                    'parameterSchema': row['parameter_schema'] if row else None,
                    'environmentId': row['environment_id'] if row else None,
                    'environmentVersion': row['environment_version'] if row else None,
                    'createdRevision': row['created_revision'] if row else None,
                    'createdAt': row['created_at'].isoformat() if row else None,
                    'publicationRevision': (pointer['revision'] if row and pointer
                        and pointer['version'] == row['version'] else None)}

    def list_published(self, scope: ApplicationScope, raw: dict) -> dict:
        args = _program(raw, LIST)
        limit, after = args.get('limit', 100), args.get('afterProgramId')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                rows = db.execute('''SELECT p.program_id,p.version,p.status,
                    p.revision,v.source_digest,v.entry_point,v.parameter_schema,
                    v.environment_id,v.environment_version
                    FROM epm.python_program_publication p JOIN
                    epm.python_program_version v USING(workspace_id,
                    application_id,program_id,version) WHERE p.workspace_id=%s
                    AND p.application_id=%s AND (%s::text IS NULL
                    OR p.program_id>%s) ORDER BY p.program_id LIMIT %s''',
                    (scope.workspace_id, scope.application_id, after, after,
                     limit + 1)).fetchall()
                return {'programs': [{
                    'programId': row['program_id'],
                    'version': row['version'],
                    'status': row['status'],
                    'publicationRevision': row['revision'],
                    'sourceDigest': row['source_digest'],
                    'entryPoint': row['entry_point'],
                    'parameterSchema': row['parameter_schema'],
                    'environmentId': row['environment_id'],
                    'environmentVersion': row['environment_version']}
                    for row in rows[:limit]],
                    'nextAfterProgramId': (rows[limit-1]['program_id']
                        if len(rows) > limit else None)}


class PostgresPythonProgramRepository:
    def __init__(self, runtime_dsn: str, coordinator_dsn: str | None, *,
                 identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("Verified identity is required")
        assert_nonowner_role(runtime_dsn, 'epm_runtime',
            ('python_program_build','python_plan_artifact','python_program_version'))
        if coordinator_dsn is not None:
            _assert_coordinator_role(coordinator_dsn)
        self.runtime_dsn = runtime_dsn
        self.coordinator_dsn = coordinator_dsn
        self.identity = identity

    def _coordinator(self) -> str:
        if not self.coordinator_dsn:
            raise ValueError("PYTHON_COORDINATOR_DSN_REQUIRED")
        return self.coordinator_dsn

    @staticmethod
    def _scope(db, scope: ApplicationScope) -> None:
        if not isinstance(scope, ApplicationScope):
            raise ValueError("PYTHON_BUILD_SCOPE_INVALID")
        PostgresNumericFactStore._set_scope(db, scope)

    @staticmethod
    def _authorize(db, identity, scope, permission='rule_run') -> None:
        PostgresAccessChecker.check_in_transaction(db, identity, scope, permission)

    def _assert_current_authorization_scope(self, db, scope, row) -> None:
        """Reject status or artifact disclosure after dimensional-scope drift."""
        if (not isinstance(row, dict)
                or row.get('authorization_scope_digest') is None):
            raise AccessDenied('PYTHON_BUILD_AUTHORIZATION_SCOPE_CHANGED')
        current = resolve_effective_dimensional_scope(
            db, self.identity, scope, function='python.program.build').scope_digest
        if row['authorization_scope_digest'] != current:
            raise AccessDenied('PYTHON_BUILD_AUTHORIZATION_SCOPE_CHANGED')

    def accept(self, scope: ApplicationScope, *, build_id: str, program_id: str,
               program_version: int, parameter_values: dict,
               idempotency_key: str, expected_metadata_revision: int,
               expected_policy_revision: int, expected_schema_epoch: int,
               delegation_id: str, delegation_version: int,
               schedule_id: str | None, schedule_version: int | None,
               rerun_of_build_id: str | None = None) -> BuildRecord:
        if (type(build_id) is not str or _HEX32.fullmatch(build_id) is None
                or type(program_id) is not str or _ID.fullmatch(program_id) is None
                or type(program_version) is not int or program_version < 1
                or type(idempotency_key) is not str
                or _KEY.fullmatch(idempotency_key) is None
                or type(parameter_values) is not dict
                or type(delegation_id) is not str
                or _AUTHORITY_ID.fullmatch(delegation_id) is None
                or type(delegation_version) is not int or delegation_version < 1
                or ((schedule_id is None) != (schedule_version is None))
                or (schedule_id is not None and (type(schedule_id) is not str
                    or _AUTHORITY_ID.fullmatch(schedule_id) is None))
                or (schedule_version is not None and
                    (type(schedule_version) is not int or schedule_version < 1))
                or (rerun_of_build_id is not None and
                    (type(rerun_of_build_id) is not str
                     or _HEX32.fullmatch(rerun_of_build_id) is None))):
            raise ValueError("PYTHON_BUILD_ARGUMENTS_INVALID")
        pins = (expected_metadata_revision, expected_policy_revision,
                expected_schema_epoch)
        if any(type(value) is not int or value < 0 for value in pins):
            raise ValueError("PYTHON_BUILD_PINS_INVALID")
        parameters = json.loads(_canonical(parameter_values,
                                            "PYTHON_BUILD_PARAMETERS_INVALID"))
        request = {'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],
            'program':[program_id,program_version], 'parameters':parameters,
            'delegation':[delegation_id,delegation_version],
            'schedule':[schedule_id,schedule_version],
            'pins':list(pins), 'idempotencyKey':idempotency_key}
        # Preserve the pre-0192 digest byte-for-byte for ordinary builds so a
        # historical accepted request remains replayable after the upgrade.
        if rerun_of_build_id is not None:
            request['rerunOfBuildId'] = rerun_of_build_id
        digest = sha256(_canonical(request,"PYTHON_BUILD_REQUEST_INVALID")).hexdigest()
        with connect_postgres(self.runtime_dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                self._scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'rule_run')
                authorization_scope_digest=resolve_effective_dimensional_scope(
                    db,self.identity,scope,access=access).scope_digest
                prior = db.execute('''SELECT b.*,a.plan_digest
                    FROM epm.python_program_build b LEFT JOIN epm.python_plan_artifact a
                    USING(workspace_id,application_id,build_id)
                    WHERE b.workspace_id=%s AND b.application_id=%s
                      AND b.issuer=%s AND b.subject_id=%s AND b.idempotency_key=%s''',
                    (scope.workspace_id,scope.application_id,self.identity.issuer,
                     self.identity.subject_id,idempotency_key)).fetchone()
                if prior is not None:
                    if prior['request_digest'] != digest:
                        raise ValueError("PYTHON_BUILD_IDEMPOTENCY_CONFLICT")
                    if (prior.get('authorization_scope_digest') is None
                            or prior['authorization_scope_digest'] !=
                               authorization_scope_digest):
                        raise AccessDenied(
                            'PYTHON_BUILD_AUTHORIZATION_SCOPE_CHANGED')
                    return _record(prior)
                allowed=db.execute('''SELECT epm.execution_delegation_is_current(
                    %s,%s,%s,%s,%s,%s,%s,%s,%s) AS allowed''',(
                    scope.workspace_id,scope.application_id,delegation_id,
                    delegation_version,self.identity.issuer,
                    self.identity.subject_id,'python.program.build',schedule_id,
                    schedule_version)).fetchone()
                if not allowed or allowed['allowed'] is not True:
                    raise ValueError('PYTHON_EXECUTION_DELEGATION_INVALID')
                state = db.execute('''SELECT metadata_revision,policy_revision,schema_epoch
                    FROM epm.application_state WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                if tuple(state[key] for key in ('metadata_revision','policy_revision','schema_epoch')) != pins:
                    raise ValueError("PYTHON_BUILD_STALE_CONTEXT")
                published = db.execute('''SELECT p.version
                    FROM epm.python_program_publication p
                    JOIN epm.python_program_version v USING
                      (workspace_id,application_id,program_id,version)
                    JOIN epm.python_environment_current e ON
                      e.workspace_id=v.workspace_id AND e.application_id=v.application_id
                      AND e.environment_id=v.environment_id
                      AND e.version=v.environment_version AND e.status='Active'
                    WHERE p.workspace_id=%s AND p.application_id=%s
                      AND p.program_id=%s AND p.version=%s AND p.status='Published' ''',
                    (scope.workspace_id,scope.application_id,program_id,
                     program_version)).fetchone()
                if published is None:
                    raise ValueError("PYTHON_PROGRAM_NOT_PUBLISHED")
                token_issued_at,authority_kind=durable_authority_fields(
                    self.identity)
                inserted = db.execute('''INSERT INTO epm.python_program_build(
                    workspace_id,application_id,build_id,issuer,subject_id,
                    idempotency_key,program_id,program_version,parameter_values,
                    request_digest,expected_metadata_revision,expected_policy_revision,
                    expected_schema_epoch,delegation_id,delegation_version,
                    schedule_id,schedule_version,rerun_of_build_id,
                    verified_groups,authorization_scope_digest,token_issued_at,
                    authority_kind,status) VALUES
                    (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'accepted')
                    ON CONFLICT DO NOTHING RETURNING *,NULL::text AS plan_digest''',
                    (scope.workspace_id,scope.application_id,build_id,
                     self.identity.issuer,self.identity.subject_id,idempotency_key,
                     program_id,program_version,Jsonb(parameters),digest,*pins,
                     delegation_id,delegation_version,schedule_id,
                     schedule_version,rerun_of_build_id,list(access.groups),
                     authorization_scope_digest,token_issued_at,
                     authority_kind)).fetchone()
                if inserted is not None:
                    return _record(inserted)
                prior=db.execute('''SELECT b.*,a.plan_digest
                    FROM epm.python_program_build b LEFT JOIN epm.python_plan_artifact a
                    USING(workspace_id,application_id,build_id)
                    WHERE b.workspace_id=%s AND b.application_id=%s
                      AND b.issuer=%s AND b.subject_id=%s AND b.idempotency_key=%s''',
                    (scope.workspace_id,scope.application_id,self.identity.issuer,
                     self.identity.subject_id,idempotency_key)).fetchone()
                if prior is None or prior['request_digest'] != digest:
                    raise ValueError("PYTHON_BUILD_IDEMPOTENCY_CONFLICT")
                if (prior.get('authorization_scope_digest') is None
                        or prior['authorization_scope_digest'] !=
                           authorization_scope_digest):
                    raise AccessDenied(
                        'PYTHON_BUILD_AUTHORIZATION_SCOPE_CHANGED')
                return _record(prior)

    def read(self, scope: ApplicationScope, build_id: str) -> BuildRecord:
        if type(build_id) is not str or _HEX32.fullmatch(build_id) is None:
            raise ValueError("PYTHON_BUILD_ID_INVALID")
        with connect_postgres(self.runtime_dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db,5000); self._scope(db,scope)
                self._authorize(db,self.identity,scope,'read')
                row=db.execute('''SELECT b.*,a.plan_digest
                    FROM epm.python_program_build b LEFT JOIN epm.python_plan_artifact a
                    USING(workspace_id,application_id,build_id)
                    WHERE b.workspace_id=%s AND b.application_id=%s AND b.build_id=%s
                      AND b.issuer=%s AND b.subject_id=%s''',
                    (scope.workspace_id,scope.application_id,build_id,
                     self.identity.issuer,self.identity.subject_id)).fetchone()
                if row is None: raise ValueError("PYTHON_BUILD_UNAVAILABLE")
                self._assert_current_authorization_scope(db,scope,row)
                return _record(row)

    def read_sealed_artifact(self, scope: ApplicationScope,
                             build_id: str) -> dict:
        """Return one caller-owned sealed artifact after fresh authorization.

        This is a technical inspection path only.  It neither rebuilds the
        authored source nor admits or publishes the sealed plan.
        """
        if type(build_id) is not str or _HEX32.fullmatch(build_id) is None:
            raise ValueError("PYTHON_BUILD_ID_INVALID")
        with connect_postgres(self.runtime_dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                self._scope(db, scope)
                self._authorize(db, self.identity, scope, 'read')
                row = db.execute('''SELECT b.status,b.authorization_scope_digest,
                    a.format,a.canonical_plan,
                    a.plan_digest,a.source_map,a.build_log,a.compiler_version,
                    v.source_digest,e.manifest,e.manifest_digest
                    FROM epm.python_program_build b
                    JOIN epm.python_plan_artifact a USING
                      (workspace_id,application_id,build_id)
                    JOIN epm.python_program_version v ON
                      v.workspace_id=b.workspace_id
                      AND v.application_id=b.application_id
                      AND v.program_id=b.program_id
                      AND v.version=b.program_version
                    JOIN epm.python_environment_version e ON
                      e.workspace_id=v.workspace_id
                      AND e.application_id=v.application_id
                      AND e.environment_id=v.environment_id
                      AND e.version=v.environment_version
                    WHERE b.workspace_id=%s AND b.application_id=%s
                      AND b.build_id=%s AND b.issuer=%s AND b.subject_id=%s
                      AND b.status='sealed' ''',
                    (scope.workspace_id, scope.application_id, build_id,
                     self.identity.issuer,
                     self.identity.subject_id)).fetchone()
                if row is None:
                    raise ValueError("PYTHON_BUILD_ARTIFACT_UNAVAILABLE")
                self._assert_current_authorization_scope(db,scope,row)
                if (row['format'] != 'openepm-python-plan-v1'
                        or type(row['canonical_plan']) is not dict
                        or set(row['canonical_plan']) != {'format', 'units'}
                        or row['canonical_plan'].get('format') !=
                            'openepm-python-plan-v1'
                        or type(row['canonical_plan'].get('units')) is not list
                        or not row['canonical_plan']['units']
                        or type(row['source_map']) is not dict
                        or type(row['build_log']) is not str
                        or _ID.fullmatch(row['compiler_version'] or '') is None
                        or type(row['manifest']) is not dict
                        or type(row['source_digest']) is not str
                        or not re.fullmatch(r'[0-9a-f]{64}',
                                            row['source_digest'])):
                    raise ValueError("PYTHON_BUILD_ARTIFACT_INVALID")
                manifest_compiler = row['manifest'].get('compilerVersion')
                manifest_compilers = row['manifest'].get('compilerVersions')
                try:
                    manifest_raw = json.dumps(row['manifest'], sort_keys=True,
                        separators=(',', ':'), ensure_ascii=False,
                        allow_nan=False).encode('utf-8')
                except (TypeError, ValueError, UnicodeError) as error:
                    raise ValueError(
                        "PYTHON_BUILD_ARTIFACT_COMPILER_INVALID") from error
                if ((manifest_compiler is None) ==
                        (manifest_compilers is None)
                        or sha256(manifest_raw).hexdigest() !=
                            row['manifest_digest']):
                    raise ValueError("PYTHON_BUILD_ARTIFACT_COMPILER_INVALID")
                if manifest_compiler is not None:
                    approved = [manifest_compiler]
                else:
                    approved = manifest_compilers
                if (type(approved) is not list or not approved
                        or len(approved) > 32
                        or len(set(approved)) != len(approved)
                        or any(type(item) is not str
                               or _ID.fullmatch(item) is None
                               for item in approved)
                        or row['compiler_version'] not in approved):
                    raise ValueError("PYTHON_BUILD_ARTIFACT_COMPILER_INVALID")
                operations = 0
                for unit in row['canonical_plan']['units']:
                    if (type(unit) is not dict
                            or set(unit) != {'name', 'operations'}
                            or _ID.fullmatch(unit.get('name') or '') is None
                            or type(unit.get('operations')) is not list
                            or not unit['operations']):
                        raise ValueError("PYTHON_BUILD_ARTIFACT_INVALID")
                    for operation in unit['operations']:
                        operations += 1
                        if (operations > MAX_OPERATIONS
                                or type(operation) is not dict
                                or set(operation) != {'languageVersion',
                                                      'function', 'arguments'}
                                or operation['languageVersion'] != 2
                                or _ID.fullmatch(
                                    operation.get('function') or '') is None
                                or type(operation['arguments']) is not dict):
                            raise ValueError("PYTHON_BUILD_ARTIFACT_INVALID")
                try:
                    plan = _canonical(row['canonical_plan'],
                                      "PYTHON_BUILD_ARTIFACT_INVALID")
                    source_map = _canonical(row['source_map'],
                                            "PYTHON_BUILD_ARTIFACT_INVALID")
                    build_log = row['build_log'].encode('utf-8')
                except (UnicodeEncodeError, ValueError) as error:
                    raise ValueError("PYTHON_BUILD_ARTIFACT_INVALID") from error
                if (sha256(plan).hexdigest() != row['plan_digest']
                        or len(plan) > MAX_PLAN_BYTES
                        or len(source_map) > MAX_SOURCE_MAP_BYTES
                        or len(build_log) > MAX_BUILD_LOG_BYTES
                        or b'\x00' in build_log):
                    raise ValueError("PYTHON_BUILD_ARTIFACT_INVALID")
                return {'buildId': build_id,
                        'planDigest': row['plan_digest'],
                        'sourceDigest': row['source_digest'],
                        'compilerVersion': row['compiler_version'],
                        'unitCount': len(row['canonical_plan']['units']),
                        'sections': {'Plan': plan, 'SourceMap': source_map,
                                     'BuildLog': build_log}}

    def read_build_log(self, scope: ApplicationScope, build_id: str, *,
                       after_character: int = 0,
                       character_limit: int = 16_384) -> dict:
        """Page one caller-owned sealed build log without loading its plan.

        The artifact table already caps the complete UTF-8 log at one MiB.
        This narrower inspection path additionally bounds every response and
        retains the native build repository's owner/current-read authority.
        Character cursors avoid returning malformed partial UTF-8 sequences.
        """
        if type(build_id) is not str or _HEX32.fullmatch(build_id) is None:
            raise ValueError("PYTHON_BUILD_ID_INVALID")
        if (type(after_character) is not int or after_character < 0
                or type(character_limit) is not int
                or not 1 <= character_limit <= 16_384):
            raise ValueError("PYTHON_BUILD_LOG_CURSOR_INVALID")
        with connect_postgres(self.runtime_dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                self._scope(db, scope)
                self._authorize(db, self.identity, scope, 'read')
                row = db.execute('''SELECT b.authorization_scope_digest,
                        substring(a.build_log
                        FROM %s FOR %s) AS page,
                        char_length(a.build_log) AS total_characters,
                        octet_length(a.build_log) AS total_bytes
                    FROM epm.python_program_build b
                    JOIN epm.python_plan_artifact a USING
                      (workspace_id,application_id,build_id)
                    WHERE b.workspace_id=%s AND b.application_id=%s
                      AND b.build_id=%s AND b.issuer=%s AND b.subject_id=%s
                      AND b.status='sealed' ''',
                    (after_character + 1, character_limit,
                     scope.workspace_id, scope.application_id, build_id,
                     self.identity.issuer,
                     self.identity.subject_id)).fetchone()
                if row is None:
                    raise ValueError("PYTHON_BUILD_ARTIFACT_UNAVAILABLE")
                self._assert_current_authorization_scope(db,scope,row)
                page = row['page']
                if (type(page) is not str
                        or type(row['total_characters']) is not int
                        or type(row['total_bytes']) is not int
                        or row['total_bytes'] > MAX_BUILD_LOG_BYTES
                        or b'\x00' in page.encode('utf-8')):
                    raise ValueError("PYTHON_BUILD_ARTIFACT_INVALID")
                next_character = after_character + len(page)
                return {'text': page,
                        'nextCharacter': next_character,
                        'hasMore': next_character < row['total_characters'],
                        'totalCharacters': row['total_characters'],
                        'totalBytes': row['total_bytes']}

    def request_cancel(self, scope: ApplicationScope, build_id: str) -> BuildRecord:
        return self.request_cancel_as_task_controller(
            scope, build_id, allow_application_admin=False)

    def rerun_as_task_controller(self, scope: ApplicationScope,
                                 build_id: str, *,
                                 idempotency_key: str) -> BuildRecord:
        """Create one new owner build from an eligible terminal source build.

        This is deliberately owner-only.  Application administrators may
        inspect or interrupt visible technical work, but cannot reuse another
        subject's delegated Python authority.  The existing admission path
        rechecks the current delegation, published immutable program,
        environment, application revisions and rule-run permission.
        """
        if (type(build_id) is not str or _HEX32.fullmatch(build_id) is None
                or type(idempotency_key) is not str
                or _KEY.fullmatch(idempotency_key) is None):
            raise ValueError("PYTHON_BUILD_RERUN_ARGUMENTS_INVALID")
        new_build_id = python_build_id(scope, self.identity, idempotency_key)
        with connect_postgres(self.runtime_dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                self._scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                self._authorize(db, self.identity, scope, 'rule_run')
                replay = db.execute('''SELECT b.*,a.plan_digest
                    FROM epm.python_program_build b
                    LEFT JOIN epm.python_plan_artifact a USING
                      (workspace_id,application_id,build_id)
                    WHERE b.workspace_id=%s AND b.application_id=%s
                      AND b.build_id=%s AND b.issuer=%s AND b.subject_id=%s
                      AND b.idempotency_key=%s''',
                    (scope.workspace_id, scope.application_id, new_build_id,
                     self.identity.issuer, self.identity.subject_id,
                     idempotency_key)).fetchone()
                if replay is not None:
                    if replay['rerun_of_build_id'] != build_id:
                        raise ValueError("PYTHON_BUILD_IDEMPOTENCY_CONFLICT")
                    return _record(replay)
                source = db.execute('''SELECT program_id,program_version,
                    parameter_values,delegation_id,delegation_version,
                    schedule_id,schedule_version,status
                    FROM epm.python_program_build
                    WHERE workspace_id=%s AND application_id=%s
                      AND build_id=%s AND issuer=%s AND subject_id=%s''',
                    (scope.workspace_id, scope.application_id, build_id,
                     self.identity.issuer,
                     self.identity.subject_id)).fetchone()
                if source is None or source['status'] not in ('failed','cancelled'):
                    raise ValueError("PYTHON_BUILD_RERUN_NOT_SUPPORTED")
                if (source['delegation_id'] is None
                        or source['delegation_version'] is None):
                    raise ValueError("PYTHON_BUILD_RERUN_NOT_SUPPORTED")
                state = db.execute('''SELECT metadata_revision,policy_revision,
                    schema_epoch FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id,
                     scope.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                source_values = dict(source)
                current_pins = tuple(state[key] for key in
                    ('metadata_revision','policy_revision','schema_epoch'))
        return self.accept(scope, build_id=new_build_id,
            program_id=source_values['program_id'],
            program_version=source_values['program_version'],
            parameter_values=source_values['parameter_values'],
            idempotency_key=idempotency_key,
            expected_metadata_revision=current_pins[0],
            expected_policy_revision=current_pins[1],
            expected_schema_epoch=current_pins[2],
            delegation_id=source_values['delegation_id'],
            delegation_version=source_values['delegation_version'],
            schedule_id=source_values['schedule_id'],
            schedule_version=source_values['schedule_version'],
            rerun_of_build_id=build_id)

    def request_cancel_as_task_controller(self, scope: ApplicationScope,
                                          build_id: str, *,
                                          allow_application_admin=False
                                          ) -> BuildRecord:
        """Interrupt one build through its authoritative fenced lifecycle.

        The ordinary public build endpoint remains owner-only.  The universal
        task controller may additionally let a current application
        administrator interrupt visible work, but neither path can seal or
        publish a plan.
        """
        if type(build_id) is not str or _HEX32.fullmatch(build_id) is None:
            raise ValueError("PYTHON_BUILD_ID_INVALID")
        if type(allow_application_admin) is not bool:
            raise ValueError("PYTHON_BUILD_UNAVAILABLE")
        with connect_postgres(self.runtime_dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000); self._scope(db,scope)
                self._authorize(db,self.identity,scope,'rule_run')
                row=db.execute('''SELECT b.*,a.plan_digest
                    FROM epm.python_program_build b LEFT JOIN epm.python_plan_artifact a
                    USING(workspace_id,application_id,build_id)
                    WHERE b.workspace_id=%s AND b.application_id=%s AND b.build_id=%s
                    FOR UPDATE OF b''',
                    (scope.workspace_id,scope.application_id,build_id)).fetchone()
                if row is None: raise ValueError("PYTHON_BUILD_UNAVAILABLE")
                owner = ((row['issuer'], row['subject_id']) ==
                         (self.identity.issuer, self.identity.subject_id))
                if not owner:
                    if not allow_application_admin:
                        raise ValueError("PYTHON_BUILD_UNAVAILABLE")
                    try:
                        self._authorize(db,self.identity,scope,'admin')
                    except AccessDenied as error:
                        raise ValueError("PYTHON_BUILD_UNAVAILABLE") from error
                current=_record(row); updated=current.request_cancel()
                if updated is current: return current
                changed=db.execute('''UPDATE epm.python_program_build SET status=%s,
                    updated_at=transaction_timestamp() WHERE workspace_id=%s
                    AND application_id=%s AND build_id=%s AND status=%s''',
                    (updated.status.value,scope.workspace_id,scope.application_id,
                     build_id,current.status.value)).rowcount
                if changed != 1: raise ValueError("PYTHON_BUILD_STALE_CONTROL_STATE")
                return updated

    def compare_and_set(self, current: BuildRecord, updated: BuildRecord) -> bool:
        if (not isinstance(current,BuildRecord) or not isinstance(updated,BuildRecord)
                or current.scope != updated.scope or current.build_id != updated.build_id
                or current.request_digest != updated.request_digest):
            raise ValueError("PYTHON_BUILD_RECORD_MISMATCH")
        allowed = {
            BuildStatus.ACCEPTED: {BuildStatus.READY,BuildStatus.CANCELLED},
            BuildStatus.READY: {BuildStatus.RUNNING,BuildStatus.CANCELLED},
            BuildStatus.RUNNING: {BuildStatus.RUNNING,BuildStatus.CANCEL_REQUESTED,
                                  BuildStatus.FAILED},
            BuildStatus.CANCEL_REQUESTED: {BuildStatus.CANCELLED,BuildStatus.FAILED},
        }
        if updated.status not in allowed.get(current.status,set()):
            raise ValueError("PYTHON_BUILD_TRANSITION_INVALID")
        if updated.status == BuildStatus.RUNNING and updated.lease_until is None:
            raise ValueError("PYTHON_BUILD_LEASE_INVALID")
        with connect_postgres(self._coordinator(),row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000); self._scope(db,current.scope)
                result=db.execute('''UPDATE epm.python_program_build SET status=%s,
                    claim_generation=%s,claimant=%s,
                    lease_until=CASE WHEN %s::bigint IS NULL THEN NULL
                        ELSE to_timestamp(%s::double precision) END,
                    attempts=%s,error_code=%s,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND build_id=%s
                      AND request_digest=%s AND status=%s AND claim_generation=%s
                      AND claimant IS NOT DISTINCT FROM %s
                      AND (%s NOT IN ('running','cancel_requested')
                           OR lease_until>clock_timestamp())
                      AND (%s NOT IN ('running','cancel_requested')
                           OR to_timestamp(%s::double precision)>clock_timestamp())''',
                    (updated.status.value,updated.claim_generation,updated.claimant,
                     updated.lease_until,updated.lease_until,updated.attempts,
                     updated.error_code,current.scope.workspace_id,
                     current.scope.application_id,current.build_id,
                     current.request_digest,current.status.value,
                     current.claim_generation,current.claimant,current.status.value,
                     updated.status.value,updated.lease_until))
                return result.rowcount == 1

    def store_sealed(self, current: BuildRecord, updated: BuildRecord,
                     plan: SealedPlan, *, source_map, build_log) -> bool:
        if (not isinstance(current,BuildRecord) or not isinstance(updated,BuildRecord)
                or current.scope != updated.scope or current.build_id != updated.build_id
                or updated.status != BuildStatus.SEALED
                or updated.plan_digest != plan.digest):
            raise ValueError("PYTHON_BUILD_RECORD_MISMATCH")
        verify_plan_identity(plan,updated.plan_digest)
        validate_build_artifacts(plan,source_map=source_map,build_log=build_log)
        with connect_postgres(self._coordinator(),row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000); self._scope(db,current.scope)
                inserted=db.execute('''INSERT INTO epm.python_plan_artifact(
                    workspace_id,application_id,build_id,format,canonical_plan,
                    plan_digest,source_map,build_log,compiler_version)
                    SELECT %s,%s,%s,'openepm-python-plan-v1',%s,%s,%s,%s,%s
                    WHERE EXISTS (SELECT 1 FROM epm.python_program_build
                      WHERE workspace_id=%s AND application_id=%s AND build_id=%s
                        AND status='running' AND claim_generation=%s AND claimant=%s
                        AND lease_until>clock_timestamp())
                    ON CONFLICT DO NOTHING RETURNING build_id''',
                    (current.scope.workspace_id,current.scope.application_id,
                     current.build_id,Jsonb(plan.canonical_plan),plan.digest,
                     Jsonb(source_map),build_log,plan.compiler_version,
                     current.scope.workspace_id,current.scope.application_id,
                     current.build_id,current.claim_generation,current.claimant)).fetchone()
                if inserted is None: return False
                changed=db.execute('''UPDATE epm.python_program_build SET status='sealed',
                    claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND build_id=%s
                      AND status='running' AND claim_generation=%s AND claimant=%s
                      AND lease_until>clock_timestamp()''',
                    (current.scope.workspace_id,current.scope.application_id,
                     current.build_id,current.claim_generation,current.claimant)).rowcount
                if changed != 1:
                    raise ValueError("PYTHON_BUILD_STALE_CONTROL_STATE")
                return True

    def worker_context(self, scope: ApplicationScope, build_id: str) -> dict:
        """Read one already-addressed build through the coordinator role.

        This is deliberately not a global queue scan.  A future reviewed
        worker dispatcher must supply the scoped identifier without granting
        the coordinator a cross-application RLS bypass.
        """
        if type(build_id) is not str or _HEX32.fullmatch(build_id) is None:
            raise ValueError("PYTHON_BUILD_ID_INVALID")
        with connect_postgres(self._coordinator(), row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000); self._scope(db, scope)
                row = db.execute('''SELECT b.*,a.plan_digest,v.environment_id,
                    v.environment_version FROM epm.python_program_build b
                    JOIN epm.python_program_version v ON
                      v.workspace_id=b.workspace_id
                      AND v.application_id=b.application_id
                      AND v.program_id=b.program_id
                      AND v.version=b.program_version
                    JOIN epm.python_program_publication p ON
                      p.workspace_id=b.workspace_id
                      AND p.application_id=b.application_id
                      AND p.program_id=b.program_id
                      AND p.version=b.program_version
                      AND p.status='Published'
                    JOIN epm.python_environment_current e ON
                      e.workspace_id=v.workspace_id
                      AND e.application_id=v.application_id
                      AND e.environment_id=v.environment_id
                      AND e.version=v.environment_version
                      AND e.status='Active'
                    LEFT JOIN epm.python_plan_artifact a ON
                      a.workspace_id=b.workspace_id
                      AND a.application_id=b.application_id
                      AND a.build_id=b.build_id
                    WHERE b.workspace_id=%s AND b.application_id=%s
                      AND b.build_id=%s''', (scope.workspace_id,
                    scope.application_id, build_id)).fetchone()
                if row is None:
                    raise ValueError("PYTHON_BUILD_UNAVAILABLE")
                return {'record': _record(row), 'issuer': row['issuer'],
                    'subjectId': row['subject_id'],
                    'verifiedGroups': list(row['verified_groups']),
                    'authorizationScopeDigest':
                        row['authorization_scope_digest'],
                    'tokenIssuedAt':row['token_issued_at'],
                    'authorityKind':row['authority_kind'],
                    'programId': row['program_id'],
                    'programVersion': row['program_version'],
                    'environmentId': row['environment_id'],
                    'environmentVersion': row['environment_version'],
                    'metadataRevision': row['expected_metadata_revision'],
                    'policyRevision': row['expected_policy_revision'],
                    'schemaEpoch': row['expected_schema_epoch']}

    def broker_context(self, scope: ApplicationScope, build_id: str) -> dict:
        """Return bounded builder inputs after a fresh grant and claim check.

        The runtime transaction retains the workspace authorization fence while
        the coordinator role reads source.  This prevents grant revocation or
        application deletion from racing between authorization and disclosure.
        """
        if type(build_id) is not str or _HEX32.fullmatch(build_id) is None:
            raise ValueError("PYTHON_BUILD_ID_INVALID")
        initial = self.worker_context(scope, build_id)
        identity = durable_execution_identity(initial,issuer='issuer',
            subject='subjectId',groups='verifiedGroups',
            scope_digest='authorizationScopeDigest',
            token_issued_at='tokenIssuedAt',authority_kind='authorityKind')
        with connect_postgres(self.runtime_dsn, row_factory=dict_row) as auth:
            with auth.transaction():
                configure_statement_timeout(auth, 5000)
                self._scope(auth, scope)
                access=PostgresAccessChecker.check_in_transaction(
                    auth,identity,scope,'rule_run')
                current_scope=resolve_effective_dimensional_scope(
                    auth,identity,scope,access=access).scope_digest
                if (initial.get('authorizationScopeDigest') is None
                        or initial['authorizationScopeDigest']!=current_scope):
                    raise AccessDenied('PYTHON_BUILD_AUTHORIZATION_REVOKED')
                bound=auth.execute('''SELECT delegation_id,delegation_version,
                    schedule_id,schedule_version FROM epm.python_program_build
                    WHERE workspace_id=%s AND application_id=%s AND build_id=%s
                      AND issuer=%s AND subject_id=%s''',(scope.workspace_id,
                    scope.application_id,build_id,identity.issuer,
                    identity.subject_id)).fetchone()
                if bound is None or bound['delegation_id'] is None:
                    raise ValueError('PYTHON_EXECUTION_DELEGATION_INVALID')
                allowed=auth.execute('''SELECT epm.execution_delegation_is_current(
                    %s,%s,%s,%s,%s,%s,%s,%s,%s) AS allowed''',(
                    scope.workspace_id,scope.application_id,bound['delegation_id'],
                    bound['delegation_version'],identity.issuer,
                    identity.subject_id,'python.program.build',bound['schedule_id'],
                    bound['schedule_version'])).fetchone()
                if not allowed or allowed['allowed'] is not True:
                    raise ValueError('PYTHON_EXECUTION_DELEGATION_INVALID')
                state=auth.execute('''SELECT metadata_revision,policy_revision,
                    schema_epoch FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',(scope.workspace_id,
                    scope.application_id)).fetchone()
                if (state is None or tuple(state[key] for key in
                        ('metadata_revision','policy_revision','schema_epoch')) !=
                        (initial['metadataRevision'],initial['policyRevision'],
                         initial['schemaEpoch'])):
                    raise ValueError('PYTHON_BUILD_STALE_CONTEXT')
                with connect_postgres(self._coordinator(),
                                      row_factory=dict_row) as db:
                    with db.transaction():
                        db.execute('SET TRANSACTION READ ONLY')
                        configure_statement_timeout(db, 5000)
                        self._scope(db, scope)
                        row = db.execute('''SELECT b.issuer,b.subject_id,
                            b.verified_groups,b.authorization_scope_digest,
                            b.token_issued_at,b.authority_kind,
                            b.program_id,b.program_version,b.parameter_values,
                            b.expected_metadata_revision,b.expected_policy_revision,
                            b.expected_schema_epoch,b.claim_generation,b.status,
                            b.lease_until,v.source_text,v.entry_point,
                            v.environment_id,v.environment_version
                            FROM epm.python_program_build b
                            JOIN epm.python_program_version v USING
                              (workspace_id,application_id,program_id)
                            JOIN epm.python_program_publication p ON
                              p.workspace_id=b.workspace_id
                              AND p.application_id=b.application_id
                              AND p.program_id=b.program_id
                              AND p.version=b.program_version
                              AND p.status='Published'
                            JOIN epm.python_environment_current e ON
                              e.workspace_id=v.workspace_id
                              AND e.application_id=v.application_id
                              AND e.environment_id=v.environment_id
                              AND e.version=v.environment_version
                              AND e.status='Active'
                            WHERE b.workspace_id=%s AND b.application_id=%s
                              AND b.build_id=%s AND v.version=b.program_version
                              AND b.status='running'
                              AND b.lease_until>clock_timestamp()''',
                            (scope.workspace_id, scope.application_id,
                             build_id)).fetchone()
                if row is None:
                    raise ValueError("PYTHON_BUILD_UNAVAILABLE")
                if (row['issuer'] != identity.issuer
                        or row['subject_id'] != identity.subject_id
                        or tuple(row['verified_groups']) != identity.groups
                        or row['authorization_scope_digest'] != current_scope):
                    raise ValueError("PYTHON_BUILD_IDENTITY_CHANGED")
                return {'identity': identity,
                    'claimGeneration': row['claim_generation'],
                    'programId': row['program_id'],
                    'programVersion': row['program_version'],
                    'environmentId': row['environment_id'],
                    'environmentVersion': row['environment_version'],
                    'sourceText': row['source_text'],
                    'entryPoint': row['entry_point'],
                    'parameterValues': row['parameter_values'],
                    'buildContext': {
                        'workspaceId': scope.workspace_id,
                        'applicationId': scope.application_id,
                        'metadataRevision': row['expected_metadata_revision'],
                        'policyRevision': row['expected_policy_revision'],
                        'schemaEpoch': row['expected_schema_epoch'],
                        'references': {}}}

    def recover_expired(self, scope: ApplicationScope, build_id: str,
                        *, maximum_attempts: int = 3) -> BuildRecord:
        """Fence one known expired claim and return its durable outcome."""
        if (type(maximum_attempts) is not int
                or not 1 <= maximum_attempts <= 10):
            raise ValueError("PYTHON_BUILD_RECOVERY_LIMIT_INVALID")
        context = self.worker_context(scope, build_id)
        current = context['record']
        if current.status not in (BuildStatus.RUNNING,
                                  BuildStatus.CANCEL_REQUESTED):
            return current
        with connect_postgres(self._coordinator(), row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000); self._scope(db, scope)
                if current.status is BuildStatus.CANCEL_REQUESTED:
                    target, error = 'cancelled', None
                elif current.attempts >= maximum_attempts:
                    target, error = 'failed', 'PYTHON_BUILD_ATTEMPTS_EXHAUSTED'
                else:
                    target, error = 'ready', None
                row = db.execute('''UPDATE epm.python_program_build SET
                    status=%s,claim_generation=claim_generation+1,
                    claimant=NULL,lease_until=NULL,error_code=%s,
                    updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND build_id=%s
                      AND status=%s AND claim_generation=%s AND claimant=%s
                      AND lease_until<=clock_timestamp()
                    RETURNING *,NULL::text AS plan_digest''',
                    (target, error, scope.workspace_id, scope.application_id,
                     build_id, current.status.value, current.claim_generation,
                     current.claimant)).fetchone()
                return _record(row) if row is not None else self.worker_context(
                    scope, build_id)['record']
