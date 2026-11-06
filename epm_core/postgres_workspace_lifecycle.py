"""Fixed-core, workspace-scoped blank application creation for V2 MCP."""
from __future__ import annotations

from hashlib import sha256
import json
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .postgres_access import AccessDenied, PostgresAccessChecker, VerifiedIdentity
from .postgres_capability_contract import validate_enabled_capabilities
from .multidimensional_roles import REQUIRED_PROGRAMMABLE_ROLES


FUNCTION = 'workspace.application.create'
PROGRAMMABLE_APPLICATION_KIND = 'multidimensional'
PROGRAMMABLE_BLUEPRINT_VERSION = 1


def programmable_dimension_blueprint() -> tuple[dict[str, str], ...]:
    """Return the stable, domain-neutral axes for a fresh application."""
    ordered_roles = ('Account', 'Entity', 'Year', 'Period', 'View', 'Value')
    if frozenset(ordered_roles) != REQUIRED_PROGRAMMABLE_ROLES:
        raise RuntimeError('PROGRAMMABLE_BLUEPRINT_ROLE_CONTRACT_DRIFT')
    return tuple({
        'dimensionId': role,
        'name': role,
        'modelRole': role,
        'semanticRole': 'Core entity' if role == 'Entity' else 'Context',
        'density': 'Sparse',
    } for role in ordered_roles)


def compile_create_application(program: object) -> tuple[str, str]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) not in ({'applicationId', 'name', 'kind'},
                {'applicationId', 'name', 'kind', 'enabledCapabilities'})):
        raise ValueError('V2_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
    args = program['arguments']
    if 'enabledCapabilities' in args:
        if not isinstance(args['enabledCapabilities'],list):
            raise ValueError('APPLICATION_CAPABILITIES_INVALID')
        validate_enabled_capabilities(args['enabledCapabilities'])
    app_id, name = args['applicationId'], args['name']
    if (not isinstance(app_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}', app_id)
            or not isinstance(name, str) or not 1 <= len(name) <= 200
            or name != name.strip()
            or args['kind'] not in ('blank', PROGRAMMABLE_APPLICATION_KIND)):
        raise ValueError('V2_APPLICATION_CREATE_INVALID')
    if (args['kind'] == PROGRAMMABLE_APPLICATION_KIND
            and args.get('enabledCapabilities', [])):
        raise ValueError('PROGRAMMABLE_APPLICATION_CAPABILITIES_UNSUPPORTED')
    return app_id, name


class PostgresWorkspaceLifecycle:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL lifecycle DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('Verified identity is required')
        self.dsn, self.identity = dsn, identity

    @staticmethod
    def catalog() -> dict:
        return {'languageVersion': 2, 'functions': {FUNCTION: {
            'mode': 'atomic_write', 'permission': 'workspace_admin',
            'arguments': {'applicationId': 'stable ID', 'name': 'display name',
                          'kind': 'multidimensional (blank retained for compatibility)'},
            'optionalArguments': {'enabledCapabilities': 'explicit initial known capabilities; default empty, no finance metadata seeded'},
            'result': 'created application and administrator grant; multidimensional kind includes the six-axis programmable blueprint',
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace lifecycle-operation namespace; use a distinct key for each intended application creation',
            'nameUniqueness': 'application display names are unique within their workspace',
            'workClass': 'short'}}}

    @staticmethod
    def _set_workspace(db, workspace_id: str, application_id: str = '') -> None:
        db.execute('''SELECT set_config('epm.workspace_id',%s,true),
            set_config('epm.application_id',%s,true)''',
            (workspace_id, application_id))

    @staticmethod
    def _require_administrator(db, workspace_id: str,
                               identity: VerifiedIdentity) -> None:
        level = db.execute('SHOW transaction_isolation').fetchone()
        if level['transaction_isolation'] != 'read committed':
            raise ValueError('Authorization recheck requires READ COMMITTED')
        PostgresAccessChecker.lock_workspace(db, workspace_id)
        workspace = db.execute('''SELECT status FROM epm.workspace
            WHERE workspace_id=%s''', (workspace_id,)).fetchone()
        if not workspace or workspace['status'] != 'Active':
            raise AccessDenied('WORKSPACE_UNAVAILABLE')
        groups = PostgresAccessChecker.current_groups_in_transaction(
            db, identity)
        grant = db.execute('''SELECT
            EXISTS (SELECT 1 FROM epm.workspace_access_grant
                WHERE workspace_id=%s AND issuer=%s AND subject_id=%s
                AND role='Administrator')
            OR EXISTS (SELECT 1 FROM epm.workspace_group_access_grant
                WHERE workspace_id=%s AND issuer=%s
                AND group_id=ANY(%s::text[])
                AND role='Administrator') AS allowed''',
            (workspace_id, identity.issuer, identity.subject_id,
             workspace_id, identity.issuer, list(groups))
            ).fetchone()['allowed']
        if not grant:
            raise AccessDenied('WORKSPACE_ADMIN_REQUIRED')

    def check(self, workspace_id: str) -> None:
        if not isinstance(workspace_id, str) or not 1 <= len(workspace_id) <= 200:
            raise ValueError('Workspace ID is required')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                self._set_workspace(db, workspace_id)
                self._require_administrator(db, workspace_id, self.identity)

    def create(self, workspace_id: str, program: object, *,
               idempotency_key: str) -> dict:
        if not isinstance(workspace_id, str) or not 1 <= len(workspace_id) <= 200:
            raise ValueError('Workspace ID is required')
        app_id, name = compile_create_application(program)
        kind = program['arguments']['kind']
        if (not isinstance(idempotency_key, str)
                or not 1 <= len(idempotency_key) <= 200):
            raise ValueError('Idempotency key is required')
        digest = sha256(json.dumps({
            'workspaceId': workspace_id, 'program': program,
        }, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
        actor_digest = sha256((self.identity.issuer + '\0' +
                               self.identity.subject_id).encode()).hexdigest()
        try:
            with connect_postgres(self.dsn, row_factory=dict_row) as db:
                with db.transaction():
                    self._set_workspace(db, workspace_id, app_id)
                    self._require_administrator(db, workspace_id, self.identity)
                    # Serializes retries of the same key without widening the
                    # workspace grant fence or relying on a preexisting row.
                    db.execute('''SELECT pg_advisory_xact_lock(
                        hashtextextended('epm.lifecycle:' || %s || ':' || %s,0))''',
                        (workspace_id, idempotency_key))
                    receipt = db.execute('''SELECT command_digest,actor_digest,result
                        FROM epm.workspace_lifecycle_receipt
                        WHERE workspace_id=%s AND operation_id=%s''',
                        (workspace_id, idempotency_key)).fetchone()
                    if receipt:
                        if receipt['command_digest'] != digest or receipt['actor_digest'] != actor_digest:
                            raise ValueError('IDEMPOTENCY_KEY_REUSED')
                        return receipt['result']
                    db.execute('''INSERT INTO epm.application
                        (workspace_id,application_id,name,kind)
                        VALUES (%s,%s,%s,%s)''',
                        (workspace_id, app_id, name, kind))
                    db.execute('''INSERT INTO epm.application_state
                        (workspace_id,application_id,enabled_capabilities)
                        VALUES (%s,%s,%s)''',
                        (workspace_id, app_id,
                         sorted(program['arguments'].get('enabledCapabilities',[]))))
                    dimensions = (programmable_dimension_blueprint()
                                  if kind == PROGRAMMABLE_APPLICATION_KIND else ())
                    if dimensions:
                        db.execute('''SELECT
                            epm.initialize_programmable_application_blueprint(
                                %s,%s)''',(workspace_id,app_id))
                    initial_revision = (1 if dimensions else 0)
                    db.execute('''INSERT INTO epm.application_access_grant
                        (issuer,subject_id,workspace_id,application_id,role)
                        VALUES (%s,%s,%s,%s,'Administrator')''',
                        (self.identity.issuer, self.identity.subject_id,
                         workspace_id, app_id))
                    result = {'workspaceId': workspace_id,
                              'applicationId': app_id, 'name': name,
                              'kind': kind, 'status': 'Active',
                              'enabledCapabilities': sorted(program['arguments'].get('enabledCapabilities',[])),
                              'capabilityRevision': 0,
                              **({'blueprintVersion': PROGRAMMABLE_BLUEPRINT_VERSION,
                                  'metadataRevision': initial_revision,
                                  'dimensions': [dimension['dimensionId']
                                                 for dimension in dimensions]}
                                 if dimensions else {})}
                    db.execute('''INSERT INTO epm.workspace_lifecycle_receipt
                        (workspace_id,operation_id,command_digest,actor_digest,result)
                        VALUES (%s,%s,%s,%s,%s)''',
                        (workspace_id, idempotency_key, digest, actor_digest,
                         Jsonb(result)))
                    db.execute('''INSERT INTO epm.security_audit
                        (actor_id,action,workspace_id,application_id,
                         target_digest,outcome,detail)
                        VALUES (%s,%s,%s,%s,%s,'Accepted',%s)''',
                        (actor_digest, FUNCTION, workspace_id, app_id,
                         sha256(app_id.encode()).hexdigest(),
                         Jsonb({'kind': kind,
                                'enabledCapabilities': result['enabledCapabilities'],
                                **({'blueprintVersion': PROGRAMMABLE_BLUEPRINT_VERSION,
                                    'dimensions': result['dimensions']}
                                   if dimensions else {})})))
                    return result
        except UniqueViolation as error:
            raise ValueError('APPLICATION_ID_OR_NAME_EXISTS') from error
