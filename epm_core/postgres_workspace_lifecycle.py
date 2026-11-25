"""Fixed-core, workspace-scoped eight-axis application creation for V2 MCP."""
from __future__ import annotations

from hashlib import sha256
import json
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .application_authorization_actions import ACTION_SCOPE_KINDS
from .current_object_contract import new_state_token
from .dimensional_security_policy import dimensional_security_policy_digest
from .postgres_dimensional_security_policies import assignment_policy_values, policy_from_values
from .postgres_grants import _validate_group_id
from .postgres_capability_contract import validate_enabled_capabilities
from .multidimensional_roles import (
    PROGRAMMABLE_BLUEPRINT_VERSION, programmable_application_blueprint,
    programmable_dimension_blueprint,
)


FUNCTION = 'workspace.application.create'
PROGRAMMABLE_APPLICATION_KIND = 'multidimensional'


def compile_create_application(program: object) -> tuple[str, str]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != FUNCTION
            or not isinstance(program['arguments'], dict)
            or not {'applicationId','name','kind'} <= set(program['arguments'])
            or set(program['arguments']) - {'applicationId','name','kind',
                                             'enabledCapabilities','administratorGroupId'}):
        raise ValueError('V2_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
    args = program['arguments']
    if 'administratorGroupId' in args:
        _validate_group_id(args['administratorGroupId'])
    if 'enabledCapabilities' in args:
        if not isinstance(args['enabledCapabilities'],list):
            raise ValueError('APPLICATION_CAPABILITIES_INVALID')
        validate_enabled_capabilities(args['enabledCapabilities'])
    app_id, name = args['applicationId'], args['name']
    if (not isinstance(app_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}', app_id)
            or not isinstance(name, str) or not 1 <= len(name) <= 200
            or name != name.strip() or '\0' in name
            or args['kind'] != PROGRAMMABLE_APPLICATION_KIND):
        raise ValueError('V2_APPLICATION_CREATE_INVALID')
    if (args['kind'] == PROGRAMMABLE_APPLICATION_KIND
            and args.get('enabledCapabilities', [])):
        raise ValueError('PROGRAMMABLE_APPLICATION_CAPABILITIES_UNSUPPORTED')
    return app_id, name


def application_creation_contract() -> dict:
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj
    from .public_program_contracts import provisioning_field_schemas

    identifier, name = provisioning_field_schemas()
    capabilities = {'type': 'array', 'items': {'type': 'string'}}
    kind = {'const': PROGRAMMABLE_APPLICATION_KIND}
    arguments = obj({'applicationId': identifier, 'name': name, 'kind': kind,
                     'administratorGroupId': {'type':'string','minLength':1,'maxLength':300},
                     'enabledCapabilities': {**capabilities, 'maxItems': 0}},
                    ['applicationId', 'name', 'kind'])
    dimension = obj({field: {'type': 'string'} for field in programmable_dimension_blueprint()[0]})
    result = obj({'workspaceId': {'type': 'string'}, 'applicationId': identifier, 'name': name,
                  'kind': kind, 'status': {'const': 'Active'}, 'enabledCapabilities': capabilities,
                  'capabilityRevision': {'type': 'integer', 'minimum': 0},
                  'metadataRevision': {'type': 'integer', 'minimum': 1},
                  'blueprintVersion': {'type': 'integer', 'minimum': 1},
                  'dimensions': {'type': 'array', 'items': {'type': 'string'}, 'minItems': 1},
                  'dimensionBlueprint': {'type': 'array', 'items': dimension, 'minItems': 1}})
    result['properties'].update({
        'authorizationModel': {'const':'group_assignments'},
        'administratorGroupId': {'type':'string','minLength':1,'maxLength':300},
    })
    contract = read_contract(FUNCTION, arguments, result, owner='PostgresWorkspaceLifecycle',
        examples=[read_example(FUNCTION, {'applicationId': 'operating-cube', 'name': 'Operating cube',
                                         'kind': PROGRAMMABLE_APPLICATION_KIND},
                               name='Create a multidimensional application',
                               binding='Use the listener for the intended workspace, an unused application ID and a new request key.')],
        semantic_rules=['Creates the eight programmable axes without business members or domain capability bundles.',
                        'Omit enabledCapabilities or supply an empty list.',
                        'Select an active administratorGroupId to create a group-assigned application. The group receives access administration but no business fact permission. Omission retains the legacy creator-grant contract.',
                        'The response describes the created foundation. Replay returns the originally recorded foundation.'],
        result_scope='result')
    contract['programContract']['recovery'] = (
        'After an uncertain outcome, verify current workspace authority and retry the exact original program and key. '
        'For a confirmed ID or name conflict, choose an unused value and review a new request.')
    return contract


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
                          'kind': 'multidimensional; eight mandatory axes, no seeded business members'},
            'optionalArguments': {'enabledCapabilities': 'omit or supply an empty list',
                                  'administratorGroupId': 'verified group for a group-assigned application'},
            'result': 'created application and administrator grant with the eight-axis programmable blueprint and editable semantic descriptions',
            'applicationBlueprint': programmable_application_blueprint(),
            'previewRequired': False, 'idempotencyRequired': True,
            'idempotencyScope': 'workspace lifecycle-operation namespace; use a distinct key for each intended application creation',
            'nameUniqueness': 'application display names are unique within their workspace',
            'workClass': 'short', **application_creation_contract()}}}

    @staticmethod
    def _set_workspace(db, workspace_id: str, application_id: str = '') -> None:
        db.execute('''SELECT set_config('epm.workspace_id',%s,true),
            set_config('epm.application_id',%s,true)''',
            (workspace_id, application_id))

    @staticmethod
    def _require_administrator(db, workspace_id: str,
                               identity: VerifiedIdentity) -> None:
        PostgresAccessChecker.check_workspace_administrator_in_transaction(
            db, identity, workspace_id)

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
        initial_group = program['arguments'].get('administratorGroupId')
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
                    if initial_group is not None:
                        PostgresAccessChecker.lock_directory_membership_for_assignment(db)
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
                    dimensions = programmable_dimension_blueprint()
                    if dimensions:
                        descriptor = db.execute('''SELECT
                            epm.programmable_application_blueprint() AS blueprint''').fetchone()
                        if (descriptor is None or descriptor['blueprint'] !=
                                programmable_application_blueprint()):
                            raise ValueError('PROGRAMMABLE_BLUEPRINT_SCHEMA_MISMATCH')
                    db.execute('''INSERT INTO epm.application
                        (workspace_id,application_id,name,kind)
                        VALUES (%s,%s,%s,%s)''',
                        (workspace_id, app_id, name, kind))
                    db.execute('''INSERT INTO epm.application_state
                        (workspace_id,application_id,enabled_capabilities,schema_epoch)
                        VALUES (%s,%s,%s,epm.next_application_schema_epoch(%s,%s))''',
                        (workspace_id, app_id,
                         sorted(program['arguments'].get('enabledCapabilities',[])),
                         workspace_id,app_id))
                    if dimensions:
                        db.execute('''SELECT
                            epm.initialize_programmable_application_blueprint(
                                %s,%s)''',(workspace_id,app_id))
                    initial_revision = (1 if dimensions else 0)
                    if initial_group is None:
                        db.execute('''INSERT INTO epm.application_access_grant
                            (issuer,subject_id,workspace_id,application_id,role)
                            VALUES (%s,%s,%s,%s,'Administrator')''',
                            (self.identity.issuer, self.identity.subject_id,
                             workspace_id, app_id))
                    else:
                        policy_values = assignment_policy_values()
                        initial_policy = policy_from_values(policy_values)
                        actions = sorted({'application.enter','access.manage','access.review','roles.manage'} |
                                         {action for action in ACTION_SCOPE_KINDS if action.startswith('delegate.')})
                        db.execute('''SELECT epm.initialize_application_group_access(
                            %s,%s,%s,%s,%s,%s::text[],%s,%s,%s,%s,%s,%s)''',
                            (workspace_id,app_id,self.identity.issuer,initial_group,self.identity.subject_id,
                             list(self.identity.groups),idempotency_key,actor_digest,new_state_token(),
                             dimensional_security_policy_digest(workspace_id,app_id,initial_policy),actions,
                             Jsonb(policy_values)))
                    result = {'workspaceId': workspace_id,
                              'applicationId': app_id, 'name': name,
                              'kind': kind, 'status': 'Active',
                              'enabledCapabilities': sorted(program['arguments'].get('enabledCapabilities',[])),
                              'capabilityRevision': 0,
                              **({'authorizationModel':'group_assignments','administratorGroupId':initial_group}
                                 if initial_group is not None else {}),
                              **({'blueprintVersion': PROGRAMMABLE_BLUEPRINT_VERSION,
                                  'metadataRevision': initial_revision,
                                  'dimensions': [dimension['dimensionId']
                                                 for dimension in dimensions],
                                  'dimensionBlueprint': list(dimensions)}
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
        except psycopg.Error as error:
            if error.diag.message_primary in (
                    'APPLICATION_GROUP_BOOTSTRAP_UNAVAILABLE','LAST_REACHABLE_APPLICATION_ADMINISTRATOR'):
                raise ValueError(error.diag.message_primary) from error
            raise
