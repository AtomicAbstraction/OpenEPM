"""PostgreSQL adapter for isolated Python build control.

User admission/cancellation uses the scoped runtime role plus a verified
identity.  Claims and sealing use the separate NOLOGIN coordinator role.  The
adapter stores only source references, parameters and bounded JSON artifacts;
it never imports or executes authored Python.
"""
from __future__ import annotations

from datetime import datetime
from contextlib import contextmanager, nullcontext
from hashlib import sha256
import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .current_object_contract import is_state_token,new_state_token
from .python_execution_contract import (
    canonical_json as _canonical, validate_build_inputs,
    ID_PATTERN, HEX32_PATTERN, KEY_PATTERN)
from .current_python_contract import (
    PROGRAM_ACTIVATE,PROGRAM_DEACTIVATE,PROGRAM_DELETE,PROGRAM_LIST,
    PROGRAM_READ,PROGRAM_SAVE,parse_program_mutation)
from .persistence_contract import ApplicationScope
from .postgres_access import (AccessDenied, PostgresAccessChecker,
                              VerifiedIdentity,
                              assert_nonowner_role,durable_authority_fields,
                              durable_execution_identity)
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_group_rule_source import (RULE_OWNER as _CURRENT_RULE_OWNER, designer_validation_statuses,
    require_automatic_rule_validation, require_build_source, require_design_target, require_impact_source,
    require_numeric_rule_declaration)
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .python_source_validation import validate_python_source
from openepm.diagnostics import validate_diagnostic_payload
from .python_program_execution import (BuildRecord, BuildStatus, SealedPlan,
                                       MAX_BUILD_LOG_BYTES, MAX_OPERATIONS,
                                       MAX_PLAN_BYTES, MAX_SOURCE_MAP_BYTES,
                                       validate_build_artifacts,
                                       verify_plan_identity)


_HEX32 = re.compile(HEX32_PATTERN)
_ID = re.compile(ID_PATTERN)
_KEY = re.compile(KEY_PATTERN)
_ENTRY_POINT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,99}$")

SAVE,READ,LIST = PROGRAM_SAVE,PROGRAM_READ,PROGRAM_LIST
ACTIVATE,DEACTIVATE,DELETE = (
    PROGRAM_ACTIVATE,PROGRAM_DEACTIVATE,PROGRAM_DELETE)


def build_request_digest(scope, identity, *, program_id, program_source_token,
        parameters, delegation_id, delegation_state_token, schedule_id,
        schedule_state_token, pins, idempotency_key, purpose='Plan',
        definition_parameters=None, rerun_of_build_id=None):
    """The original native admission digest, also used by historical reads."""
    request = {'scope': [scope.workspace_id, scope.application_id],
        'identity': [identity.issuer, identity.subject_id],
        'program': [program_id, program_source_token], 'parameters': parameters,
        'delegation': [delegation_id, delegation_state_token],
        'schedule': [schedule_id, schedule_state_token],
        'pins': list(pins), 'idempotencyKey': idempotency_key}
    if rerun_of_build_id is not None:
        request['rerunOfBuildId'] = rerun_of_build_id
    if purpose != 'Plan':
        request['purpose'] = purpose
    if definition_parameters:
        request['definitionParameters'] = definition_parameters
    return sha256(_canonical(request, 'PYTHON_BUILD_REQUEST_INVALID')).hexdigest()


def python_build_id(scope: ApplicationScope, identity: VerifiedIdentity,
                    idempotency_key: str, *, schema_epoch: int = 0) -> str:
    """Derive an owner- and application-incarnation-bound build identity."""
    if type(schema_epoch) is not int or schema_epoch < 0:
        raise ValueError('PYTHON_BUILD_SCHEMA_EPOCH_INVALID')
    raw = json.dumps({'domain': 'openepm-python-build-v2',
        'schemaEpoch': schema_epoch,
        'scope': [scope.workspace_id, scope.application_id],
        'identity': [identity.issuer, identity.subject_id],
        'idempotencyKey': idempotency_key}, sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode('ascii')
    return sha256(raw).hexdigest()[:32]


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
        row['attempts'], row.get('plan_digest'), row['error_code'], row.get('diagnostics'),
        row.get('purpose', 'Plan'))


_BUILD_PERMISSION = {'Plan': 'rule_run', 'Validation': 'rule_validate', 'ImpactTest': 'rule_design'}


def _validation_statuses(db, scope, sources, identity, authority_digest):
    """Read status and bounded declarations from the exact sealed artifact.

    Samples are validation inputs, not declaration metadata. Project them out
    in PostgreSQL so source listings cannot copy large MemberList samples.
    No compiled definition exists until explicit source activation.
    """
    if not sources:
        return {}
    from .postgres_python_definitions import KINDS
    rows = db.execute('''WITH actor AS (
        SELECT %s::text AS issuer,%s::text AS subject_id,%s::text AS authority_digest
        )
        SELECT requested.program_id,requested.source_token,b.build_id,b.status,
        b.error_code,b.diagnostics,b.owned_by_caller,
        a.canonical_plan#>>'{units,0,operations,0,function}' AS definition_function,
        COALESCE(a.canonical_plan#>>'{units,0,operations,0,arguments,ruleId}',
          a.canonical_plan#>>'{units,0,operations,0,arguments,definition,listId}',
          a.canonical_plan#>>'{units,0,operations,0,arguments,definition,definitionId}') AS definition_id,
        COALESCE((SELECT jsonb_agg(parameter.value - 'sample' ORDER BY parameter.ordinal)
          FROM jsonb_array_elements(COALESCE(
            a.canonical_plan#>'{units,0,operations,0,arguments,definition,parameters}',
            '[]'::jsonb)) WITH ORDINALITY AS parameter(value,ordinal)),
          '[]'::jsonb) AS definition_parameters,
        (b.expected_metadata_revision=s.metadata_revision
          AND b.expected_policy_revision=s.policy_revision
          AND b.expected_schema_epoch=s.schema_epoch
          AND (b.status<>'sealed' OR coalesce(
            a.sealed_at>clock_timestamp()-interval '24 hours',false))) AS current
        FROM jsonb_to_recordset(%s::jsonb) requested(program_id text,source_token text)
        JOIN epm.application_state s ON s.workspace_id=%s AND s.application_id=%s
        CROSS JOIN actor
        JOIN LATERAL (SELECT build_id,status,error_code,diagnostics,
            expected_metadata_revision,expected_policy_revision,expected_schema_epoch,
            coalesce(issuer=actor.issuer AND subject_id=actor.subject_id
                AND authorization_scope_digest=actor.authority_digest,false) AS owned_by_caller
            FROM epm.python_program_build WHERE workspace_id=s.workspace_id
              AND application_id=s.application_id AND program_id=requested.program_id
              AND program_source_token=requested.source_token AND purpose='Validation'
              AND (idempotency_key ~ '^validate-[a-f0-9]{64}$'
                OR (issuer=actor.issuer AND subject_id=actor.subject_id
                    AND authorization_scope_digest=actor.authority_digest))
            ORDER BY owned_by_caller DESC,created_at DESC,build_id DESC LIMIT 1) b ON true
        LEFT JOIN epm.python_plan_artifact a ON a.workspace_id=s.workspace_id
          AND a.application_id=s.application_id AND a.build_id=b.build_id''',
        (identity.issuer, identity.subject_id, authority_digest,
         Jsonb([{'program_id': program_id, 'source_token': source_token}
                for program_id, source_token in sources]),
         scope.workspace_id, scope.application_id)).fetchall()
    return {(row['program_id'], row['source_token']): {
        'buildId': row['build_id'], 'taskId': 'p:' + row['build_id'],
        'purpose': 'Validation', 'status': row['status'], 'current': row['current'],
        'ownedByCaller': row['owned_by_caller'],
        **({'definition': {'kind': KINDS[row['definition_function']],
            'definitionId': row['definition_id'],
            'parameters': row['definition_parameters']}}
            if row['definition_function'] in KINDS else {}),
        **({'errorCode': row['error_code']} if row['error_code'] else {}),
        **({'diagnostics': row['diagnostics']} if row['diagnostics'] is not None else {})}
        for row in rows}


def _impact_statuses(db, scope, sources, identity, authority_digest, *, group_test=False):
    """Caller-owned Test summaries, filtered by current disclosure authority."""
    if not sources:
        return {}
    from .postgres_python_definitions import KINDS
    rows = db.execute('''SELECT requested.program_id,requested.source_token,b.build_id,b.status,
        b.error_code,b.diagnostics,
        a.canonical_plan#>>'{units,0,operations,0,function}' AS definition_function,
        COALESCE(a.canonical_plan#>>'{units,0,operations,0,arguments,ruleId}',
          a.canonical_plan#>>'{units,0,operations,0,arguments,definition,listId}',
          a.canonical_plan#>>'{units,0,operations,0,arguments,definition,definitionId}') AS definition_id,
        COALESCE((SELECT jsonb_agg(parameter.value - 'sample' ORDER BY parameter.ordinal)
          FROM jsonb_array_elements(COALESCE(
            a.canonical_plan#>'{units,0,operations,0,arguments,definition,parameters}',
            '[]'::jsonb)) WITH ORDINALITY AS parameter(value,ordinal)),
          '[]'::jsonb) AS definition_parameters,
        (b.expected_metadata_revision=s.metadata_revision
          AND b.expected_policy_revision=s.policy_revision
          AND b.expected_schema_epoch=s.schema_epoch AND (NOT %s OR b.status<>'sealed' OR
              (a.impact#>>'{baseline,data_revision}'=s.data_revision::text AND a.sealed_at>clock_timestamp()-interval '24 hours'))) AS current
        FROM jsonb_to_recordset(%s::jsonb) requested(program_id text,source_token text)
        JOIN epm.application_state s ON s.workspace_id=%s AND s.application_id=%s
        JOIN LATERAL (SELECT build_id,status,error_code,diagnostics,
            expected_metadata_revision,expected_policy_revision,expected_schema_epoch
            FROM epm.python_program_build WHERE workspace_id=s.workspace_id
              AND application_id=s.application_id AND program_id=requested.program_id
              AND program_source_token=requested.source_token AND purpose='ImpactTest'
              AND issuer=%s AND subject_id=%s AND authorization_scope_digest=%s
            ORDER BY created_at DESC,build_id DESC LIMIT 1) b ON true
        LEFT JOIN epm.python_plan_artifact a ON a.workspace_id=s.workspace_id
          AND a.application_id=s.application_id AND a.build_id=b.build_id''',
        (group_test, Jsonb([{'program_id': program_id, 'source_token': source_token}
                for program_id, source_token in sources]),
         scope.workspace_id, scope.application_id, identity.issuer, identity.subject_id,
         authority_digest)).fetchall()
    return {(row['program_id'], row['source_token']): {
        'buildId': row['build_id'], 'taskId': 'p:' + row['build_id'],
        'purpose': 'ImpactTest', 'status': row['status'], 'current': row['current'],
        **({'definition': {'kind': KINDS[row['definition_function']],
            'definitionId': row['definition_id'],
            'parameters': row['definition_parameters']}}
            if row['definition_function'] in KINDS else {}),
        **({'errorCode': row['error_code']} if row['error_code'] else {}),
        **({'diagnostics': row['diagnostics']} if row['diagnostics'] is not None else {})}
        for row in rows}


def _current_program_read(raw: object, function: str) -> dict:
    if (type(raw) is not dict
            or set(raw) != {"languageVersion", "function", "arguments"}
            or raw.get("languageVersion") != 2
            or raw.get("function") != function
            or type(raw.get("arguments")) is not dict):
        raise ValueError("CURRENT_PYTHON_PROGRAM_INVALID")
    args = raw["arguments"]
    if function == READ:
        if (set(args) != {"programId"} or type(args["programId"]) is not str
                or _ID.fullmatch(args["programId"]) is None):
            raise ValueError("CURRENT_PYTHON_PROGRAM_ARGUMENTS_INVALID")
    elif function == LIST:
        if (set(args) - {"limit", "afterProgramId"}
                or type(args.get("limit", 100)) is not int
                or not 1 <= args.get("limit", 100) <= 100
                or ("afterProgramId" in args
                    and (type(args["afterProgramId"]) is not str
                         or _ID.fullmatch(args["afterProgramId"]) is None))):
            raise ValueError("CURRENT_PYTHON_PROGRAM_ARGUMENTS_INVALID")
    else:
        raise ValueError("CURRENT_PYTHON_PROGRAM_INVALID")
    return args


class PostgresPythonPrograms:
    """One current Python source per stable program identity."""

    SAVE,READ,LIST,ACTIVATE,DEACTIVATE,DELETE=(
        SAVE,READ,LIST,ACTIVATE,DEACTIVATE,DELETE)

    def __init__(self,dsn: str,*,identity: VerifiedIdentity):
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError('Verified identity is required')
        assert_nonowner_role(dsn,'epm_runtime',('python_program_definition',))
        self.dsn,self.identity=dsn,identity

    def execute(self,scope: ApplicationScope,raw: dict,*,idempotency_key: str)->dict:
        function=raw.get('function') if type(raw) is dict else None
        if function not in (SAVE,ACTIVATE,DEACTIVATE,DELETE):
            raise ValueError('CURRENT_PYTHON_PROGRAM_INVALID')
        args=parse_program_mutation(raw,function)
        if type(idempotency_key) is not str or _KEY.fullmatch(idempotency_key) is None:
            raise ValueError('PYTHON_PROGRAM_IDEMPOTENCY_KEY_INVALID')
        digest=sha256(_canonical({'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],'program':raw},
            'PYTHON_PROGRAM_REQUEST_INVALID')).hexdigest()
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            configure_statement_timeout(db,5000);PostgresNumericFactStore._set_scope(db,scope)
            PostgresAccessChecker.lock_directory_membership_for_assignment(db)
            PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            state=db.execute('''SELECT s.metadata_revision,s.policy_revision,s.schema_epoch,s.data_revision,
              s.commit_revision,s.processing_mode,a.status application_status
              FROM epm.application_state s JOIN epm.application a USING(workspace_id,application_id)
              WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s''',
              (scope.workspace_id,scope.application_id)).fetchone()
            if state is None:raise ValueError('APPLICATION_UNAVAILABLE')
            access = PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'write',function=function)
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,
                'rule_design' if function==SAVE else 'rule_publish',function=function)
            program_id=(args['definition']['programId'] if function==SAVE else args['programId'])
            current=db.execute('''SELECT * FROM epm.python_program_definition WHERE
              workspace_id=%s AND application_id=%s AND program_id=%s FOR UPDATE''',
              (scope.workspace_id,scope.application_id,program_id)).fetchone()
            group_design = access.authorization_model == 'group_assignments'
            if group_design:
                if function==SAVE and args.get('expectedOwnerStateToken') is None:
                    require_design_target(db,scope,args['definition'],current)
                elif function!=ACTIVATE or current is None:
                    raise AccessDenied('RULE_SOURCE_DESIGN_TARGET_UNAVAILABLE')
            prior=db.execute('''SELECT command_digest,actor_id,result FROM epm.operation_receipt
              WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',
              (scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
            if prior is not None:
                if prior['command_digest']!=digest or prior['actor_id']!=self.identity.subject_id:
                    raise ValueError('PYTHON_PROGRAM_IDEMPOTENCY_CONFLICT')
                if group_design and function==ACTIVATE:
                    result = prior['result']
                    if current['state_token']!=result['stateToken'] or current['source_token']!=result['sourceToken']:
                        raise AccessDenied('RULE_IMPACT_SOURCE_UNAVAILABLE')
                    require_impact_source(db,scope,(program_id,current['source_token']),published=True)
                    current_scope = resolve_effective_dimensional_scope(db,self.identity,scope,access=access).scope_digest
                    if not db.execute('''SELECT 1 FROM epm.python_program_build WHERE workspace_id=%s AND application_id=%s
                        AND build_id=%s AND purpose='ImpactTest' AND issuer=%s AND subject_id=%s
                        AND authorization_scope_digest=%s''',
                        (scope.workspace_id,scope.application_id,args['validationBuildId'],self.identity.issuer,
                         self.identity.subject_id,current_scope)).fetchone():
                        raise AccessDenied('PYTHON_BUILD_AUTHORIZATION_SCOPE_CHANGED')
                if group_design and function==SAVE:
                    result = prior['result']
                    source = (program_id,result['sourceToken'])
                    build = result['validation']['buildId']
                    require_automatic_rule_validation(db,scope,self.identity,source,build)
                    digest_now = resolve_effective_dimensional_scope(db,self.identity,scope,access=access).scope_digest
                    if not db.execute("""SELECT 1 FROM epm.python_program_build WHERE workspace_id=%s AND application_id=%s
                        AND build_id=%s AND authorization_scope_digest=%s""",
                        (scope.workspace_id,scope.application_id,build,digest_now)).fetchone():
                        raise AccessDenied('PYTHON_BUILD_AUTHORIZATION_SCOPE_CHANGED')
                return prior['result']
            if state['application_status']!='Active' or state['processing_mode']!='Active':
                raise ValueError('APPLICATION_NOT_WRITABLE')
            for field,name in (('metadata_revision','expectedMetadataRevision'),
                    ('policy_revision','expectedPolicyRevision'),('schema_epoch','expectedSchemaEpoch')):
                if state[field]!=args[name]:raise ValueError('PYTHON_PROGRAM_STALE_CONTEXT')
            expected=args.get('expectedStateToken')
            if function==SAVE:
                if ((current is None)!=(expected is None)
                        or current is not None and current['state_token']!=expected):
                    raise ValueError('PYTHON_PROGRAM_STATE_CONFLICT')
                definition=args['definition']
                environment=db.execute('''SELECT 1 FROM epm.python_environment_definition
                  WHERE workspace_id=%s AND application_id=%s AND environment_id=%s
                  AND state_token=%s AND status='Active' ''',(scope.workspace_id,
                  scope.application_id,definition['environmentId'],
                  definition['environmentStateToken'])).fetchone()
                if environment is None:raise ValueError('PYTHON_ENVIRONMENT_NOT_ACTIVE')
                state_token,source_token=new_state_token(),new_state_token()
                status='Inactive';source_digest=definition['sourceDigest']
                policy_revision=state['policy_revision']+int('declaredOutput' in definition);compiled_definition=None
            else:
                if current is None:raise ValueError('PYTHON_PROGRAM_UNAVAILABLE')
                if current['state_token']!=expected:raise ValueError('PYTHON_PROGRAM_STATE_CONFLICT')
                source_digest=current['source_digest'];source_token=current['source_token']
                compiled_definition=None
                if function==ACTIVATE:
                    if group_design:
                        from .postgres_planning_write_guard import WORKFLOW_ROLE_UNBOUND
                        from .postgres_planning_duty_availability import group_workflow_role_unbound
                        if group_workflow_role_unbound(db,scope,self.identity,access):
                            raise AccessDenied(WORKFLOW_ROLE_UNBOUND)
                        require_impact_source(db,scope,(program_id,source_token))
                    environment=db.execute('''SELECT 1 FROM epm.python_environment_definition
                      WHERE workspace_id=%s AND application_id=%s AND environment_id=%s
                      AND state_token=%s AND status='Active' ''',(scope.workspace_id,
                      scope.application_id,current['environment_id'],
                      current['environment_state_token'])).fetchone()
                    if environment is None:raise ValueError('PYTHON_ENVIRONMENT_NOT_ACTIVE')
                    activation_scope=resolve_effective_dimensional_scope(
                        db,self.identity,scope).scope_digest
                    validated=db.execute('''SELECT b.build_id,b.purpose,b.authorization_scope_digest,a.canonical_plan,a.plan_digest,
                        a.impact->>'planDigest' AS impact_plan_digest,a.impact->>'sourceDigest' AS impact_source_digest,
                        a.impact->>'authorizationScopeDigest' AS impact_authority_digest,
                        a.impact#>>'{baseline,data_revision}' AS impact_data_revision
                      FROM epm.python_program_build b JOIN epm.python_plan_artifact a
                      USING(workspace_id,application_id,build_id)
                      WHERE b.workspace_id=%s AND b.application_id=%s AND b.program_id=%s
                      AND b.program_source_token=%s AND b.purpose IN('Validation','ImpactTest')
                      AND b.status='sealed' AND b.expected_metadata_revision=%s
                      AND b.expected_policy_revision=%s AND b.expected_schema_epoch=%s
                      AND a.source_map->>'sourceDigest'=%s
                      AND a.sealed_at>clock_timestamp()-interval '24 hours'
                      AND(b.purpose='Validation' OR a.impact->>'status'='complete')
                      AND(%s::text IS NULL OR(b.build_id=%s AND b.issuer=%s
                       AND b.subject_id=%s AND b.authorization_scope_digest=%s))
                      ORDER BY b.created_at DESC,b.build_id DESC LIMIT 1''',(
                      scope.workspace_id,scope.application_id,program_id,source_token,
                      state['metadata_revision'],state['policy_revision'],state['schema_epoch'],
                      source_digest,args.get('validationBuildId'),args.get('validationBuildId'),
                      self.identity.issuer,self.identity.subject_id,activation_scope)).fetchone()
                    if group_design and (validated is None or validated['purpose']!='ImpactTest'
                            or validated['impact_plan_digest']!=validated['plan_digest']
                            or validated['impact_source_digest']!=source_digest
                            or validated['impact_authority_digest']!=activation_scope
                            or validated['impact_data_revision']!=str(state['data_revision'])):
                        raise ValueError('RULE_CURRENT_PRIVATE_IMPACT_REQUIRED')
                    if validated is None:raise ValueError('PYTHON_PROGRAM_VALIDATION_REQUIRED')
                    if sha256(_canonical(validated['canonical_plan'],
                        'PYTHON_BUILD_ARTIFACT_INVALID')).hexdigest()!=validated['plan_digest']:
                        raise ValueError('PYTHON_BUILD_ARTIFACT_INVALID')
                    from .postgres_capability_contract import assert_source_plan_purpose
                    assert_source_plan_purpose(validated['canonical_plan'])
                    from .postgres_python_definitions import activate_definition,descriptor
                    if group_design:
                        target=descriptor(validated['canonical_plan'])
                        if target!=current['declared_output']:
                            raise AccessDenied('RULE_IMPACT_SOURCE_UNAVAILABLE')
                        op=validated['canonical_plan']['units'][0]['operations'][0]
                        require_numeric_rule_declaration(target['definitionId'],op['function'],op['arguments'],impact=True)
                    if descriptor(validated['canonical_plan']) is not None \
                            and 'validationBuildId' not in args:
                        raise ValueError('PYTHON_DEFINITION_VALIDATION_BUILD_REQUIRED')
                    compiled_definition=activate_definition(db,scope,dsn=self.dsn,
                        identity=self.identity,plan=validated['canonical_plan'],
                        build_id=validated['build_id'],operation_id=idempotency_key)
                    if compiled_definition is not None:
                        state.update(db.execute('''SELECT policy_revision,commit_revision
                          FROM epm.application_state WHERE workspace_id=%s AND application_id=%s''',
                          (scope.workspace_id,scope.application_id)).fetchone())
                    status='Active'
                elif function==DEACTIVATE:
                    if current['status']!='Active':raise ValueError('PYTHON_PROGRAM_NOT_ACTIVE')
                    status='Inactive'
                else:
                    if current['status']=='Active':raise ValueError('PYTHON_PROGRAM_ACTIVE')
                    status='Deleted'
                state_token=(compiled_definition['stateToken'] if compiled_definition else new_state_token());policy_revision=state['policy_revision']+1
            revision=state['commit_revision']+1
            result={'operationId':idempotency_key,'programId':program_id,
              'stateToken':state_token,'sourceToken':source_token,'status':status,
              'sourceDigest':source_digest,'metadataRevision':state['metadata_revision'],
              'policyRevision':policy_revision,'schemaEpoch':state['schema_epoch']}
            if compiled_definition is not None:result['definition']=compiled_definition
            validation_id=None
            if function==SAVE:
                validation_key='validate-'+sha256(idempotency_key.encode()).hexdigest()
                validation_id=python_build_id(scope,self.identity,validation_key,
                    schema_epoch=state['schema_epoch'])
                result['validation']={'buildId':validation_id,'taskId':'p:'+validation_id,
                    'purpose':'Validation','status':'accepted'}
            db.execute('''UPDATE epm.application_state SET policy_revision=%s,commit_revision=%s
              WHERE workspace_id=%s AND application_id=%s''',(policy_revision,revision,
              scope.workspace_id,scope.application_id))
            db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,
              operation_id,command_digest,actor_id,committed_revision,result)
              VALUES(%s,%s,%s,%s,%s,%s,%s)''',(scope.workspace_id,
              scope.application_id,idempotency_key,digest,self.identity.subject_id,
              revision,Jsonb(result)))
            if function==SAVE:
                from .postgres_definition_lifecycle import DefinitionReferenceBlocked, save_source_owner
                try:
                    save_source_owner(db,scope,definition=definition,current_source=current,
                        state_token=state_token,source_token=source_token,operation_id=idempotency_key,
                        revision=revision,identity=self.identity,metadata_revision=state['metadata_revision'],
                        expected_owner_token=args.get('expectedOwnerStateToken'))
                except DefinitionReferenceBlocked:
                    if group_design:
                        raise AccessDenied('RULE_SOURCE_DESIGN_TARGET_UNAVAILABLE') from None
                    raise
                db.execute('''INSERT INTO epm.python_program_definition(workspace_id,
                  application_id,program_id,state_token,source_token,status,source_text,
                  source_digest,entry_point,parameter_schema,environment_id,
                  environment_state_token,updated_operation_id,
                  updated_issuer,updated_subject_id,declared_output)
                  VALUES(%s,%s,%s,%s,%s,'Inactive',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                  ON CONFLICT(workspace_id,application_id,program_id) DO UPDATE SET
                  state_token=excluded.state_token,source_token=excluded.source_token,
                  status='Inactive',source_text=excluded.source_text,
                  source_digest=excluded.source_digest,entry_point=excluded.entry_point,
                  parameter_schema=excluded.parameter_schema,environment_id=excluded.environment_id,
                  environment_state_token=excluded.environment_state_token,
                  updated_operation_id=excluded.updated_operation_id,
                  updated_issuer=excluded.updated_issuer,
                  updated_subject_id=excluded.updated_subject_id,declared_output=excluded.declared_output,
                  updated_at=transaction_timestamp()''',(scope.workspace_id,
                  scope.application_id,program_id,state_token,source_token,
                  definition['sourceText'],source_digest,definition['entryPoint'],
                  Jsonb(definition['parameterSchema']),definition['environmentId'],
                  definition['environmentStateToken'],idempotency_key,
                  self.identity.issuer,self.identity.subject_id,
                  Jsonb(definition['declaredOutput']) if 'declaredOutput' in definition else None))
                PostgresPythonProgramRepository(self.dsn,None,identity=self.identity).accept(
                  scope,build_id=validation_id,program_id=program_id,
                  program_source_token=source_token,
                  parameter_values=args.get('validationParameters',{}),
                  idempotency_key=validation_key,
                  expected_metadata_revision=state['metadata_revision'],
                  expected_policy_revision=policy_revision,
                  expected_schema_epoch=state['schema_epoch'],delegation_id=None,
                  delegation_state_token=None,schedule_id=None,schedule_state_token=None,
                  purpose='Validation',_connection=db)
            elif function==DELETE:
                from .postgres_definition_lifecycle import transition_source_owner
                transition_source_owner(db,scope,source=current,delete=True,state_token=state_token,
                    operation_id=idempotency_key,revision=revision)
                db.execute('''DELETE FROM epm.python_program_definition WHERE workspace_id=%s
                  AND application_id=%s AND program_id=%s AND state_token=%s''',
                  (scope.workspace_id,scope.application_id,program_id,expected))
            else:
                if function==DEACTIVATE:
                    from .postgres_definition_lifecycle import transition_source_owner
                    transition_source_owner(db,scope,source=current,delete=False,state_token=state_token,
                        operation_id=idempotency_key,revision=revision)
                db.execute('''UPDATE epm.python_program_definition SET state_token=%s,status=%s,
                  updated_operation_id=%s,updated_issuer=%s,
                  updated_subject_id=%s,updated_at=transaction_timestamp()
                  WHERE workspace_id=%s AND application_id=%s AND program_id=%s''',(
                  state_token,status,idempotency_key,self.identity.issuer,
                  self.identity.subject_id,scope.workspace_id,
                  scope.application_id,program_id))
            return result

    @contextmanager
    def _read_cut(self, scope: ApplicationScope, function: str):
        """Resolve source, validation and owner state at one authorized database cut."""
        with connect_postgres(self.dsn, row_factory=dict_row) as authority, authority.transaction():
            authority.execute('SET TRANSACTION READ ONLY')
            configure_statement_timeout(authority, 5000)
            PostgresNumericFactStore._set_scope(authority, scope)
            initial = resolve_effective_dimensional_scope(authority, self.identity, scope, function=function)
            typed_rules = initial.access.authorization_model == 'group_assignments'
            def policy_revision():
                return authority.execute("""SELECT policy_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s""",
                    (scope.workspace_id,scope.application_id)).fetchone()['policy_revision']
            source_revision = policy_revision() if typed_rules else None
            with connect_postgres(self.dsn, row_factory=dict_row) as db, db.transaction():
                db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                yield db, initial.scope_digest, initial.access
            current = resolve_effective_dimensional_scope(authority, self.identity, scope, function=function)
            if (current.access != initial.access or current.scope_digest != initial.scope_digest
                    or typed_rules and policy_revision() != source_revision):
                raise ValueError('PYTHON_PROGRAM_READ_AUTHORIZATION_STALE')

    def _summaries(self, db, scope, rows, authority_digest, *, access):
        from .postgres_definition_lifecycle import source_owner_states

        sources = [(row['program_id'], row['source_token']) for row in rows]
        # A rule inspector receives the authored source. Neither another
        # person's automatic validation nor an impact result is a source field.
        typed_rules = access.authorization_model == 'group_assignments'
        if typed_rules:
            validations = (designer_validation_statuses(db,scope,sources,self.identity,authority_digest)
                           if 'rules.design' in access.actions else {})
        else:
            validations = _validation_statuses(db,scope,sources,self.identity,authority_digest)
        impacts = ({} if typed_rules and 'rules.test' not in access.actions else
                   _impact_statuses(db, scope, sources, self.identity, authority_digest,group_test=typed_rules))
        if typed_rules:
            for impact in impacts.values():
                impact.pop('diagnostics',None)
        owner_states = {} if typed_rules else source_owner_states(db, scope, rows)
        return [{'programId': row['program_id'], 'stateToken': row['state_token'],
                 'sourceToken': row['source_token'], 'status': row['status'],
                 'validation': validations.get((row['program_id'], row['source_token'])),
                 'latestImpactTest': impacts.get((row['program_id'], row['source_token'])),
                 'sourceDigest': row['source_digest'], 'declaredOutput': row['declared_output'],
                 'entryPoint': row['entry_point'], 'parameterSchema': row['parameter_schema'],
                 'environmentId': row['environment_id'], 'environmentStateToken': row['environment_state_token'],
                 **owner_states.get(row['program_id'], {})} for row in rows]

    def read(self,scope: ApplicationScope,raw: dict)->dict:
        args=_current_program_read(raw,READ)
        with self._read_cut(scope, READ) as (db, authority_digest, access):
            typed_rules = access.authorization_model == 'group_assignments'
            row=db.execute('''SELECT d.* FROM epm.python_program_definition d WHERE
              d.workspace_id=%s AND d.application_id=%s AND d.program_id=%s''' + (_CURRENT_RULE_OWNER if typed_rules else ''),(
              scope.workspace_id,scope.application_id,args['programId'])).fetchone()
            if row is None:
                return {'programId': args['programId'], 'defined': False}
            summary, = self._summaries(db, scope, [row], authority_digest, access=access)
            return {**summary, 'defined': True, 'sourceText': row['source_text'],
                    'updatedAt': row['updated_at'].isoformat()}

    def list(self,scope: ApplicationScope,raw: dict)->dict:
        args=_current_program_read(raw,LIST);limit=args.get('limit',100);after=args.get('afterProgramId')
        with self._read_cut(scope, LIST) as (db, authority_digest, access):
            typed_rules = access.authorization_model == 'group_assignments'
            rows=db.execute('''SELECT program_id,state_token,source_token,status,source_digest,
              declared_output,entry_point,parameter_schema,environment_id,environment_state_token
              FROM epm.python_program_definition d WHERE
              workspace_id=%s AND application_id=%s AND(%s::text IS NULL OR program_id>%s)
              ''' + (_CURRENT_RULE_OWNER if typed_rules else '') + ' ORDER BY program_id LIMIT %s',(scope.workspace_id,scope.application_id,
              after,after,limit+1)).fetchall()
            return {'programs':self._summaries(db, scope, rows[:limit], authority_digest, access=access),
              'nextAfterProgramId':rows[limit-1]['program_id'] if len(rows)>limit else None}


class PostgresPythonProgramRepository:
    def __init__(self, runtime_dsn: str, coordinator_dsn: str | None, *,
                 identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("Verified identity is required")
        assert_nonowner_role(runtime_dsn, 'epm_runtime',
            ('python_program_build','python_plan_artifact','python_program_definition'))
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

    def _assert_current_authorization_scope(self, db, scope, row, *, access=None) -> None:
        """Reject status or artifact disclosure after dimensional-scope drift."""
        if (not isinstance(row, dict)
                or row.get('authorization_scope_digest') is None):
            raise AccessDenied('PYTHON_BUILD_AUTHORIZATION_SCOPE_CHANGED')
        current = resolve_effective_dimensional_scope(
            db, self.identity, scope, access=access, function='python.program.build' if access is None else None).scope_digest
        if row['authorization_scope_digest'] != current:
            raise AccessDenied('PYTHON_BUILD_AUTHORIZATION_SCOPE_CHANGED')

    def accept(self, scope: ApplicationScope, *, build_id: str, program_id: str,
               program_source_token: str, parameter_values: dict,
               idempotency_key: str, expected_metadata_revision: int,
               expected_policy_revision: int, expected_schema_epoch: int,
               delegation_id: str | None, delegation_state_token: str | None,
               schedule_id: str | None, schedule_state_token: str | None,
               rerun_of_build_id: str | None = None, purpose: str = 'Plan',
               definition_parameters: dict | None = None, _connection=None,
               replay_only: bool = False, _occurrence_admission=None) -> BuildRecord | None:
        parameters, definition_parameters = validate_build_inputs(
            build_id=build_id, program_id=program_id,
            program_source_token=program_source_token, parameter_values=parameter_values,
            idempotency_key=idempotency_key,
            expected_metadata_revision=expected_metadata_revision,
            expected_policy_revision=expected_policy_revision,
            expected_schema_epoch=expected_schema_epoch, delegation_id=delegation_id,
            delegation_state_token=delegation_state_token, schedule_id=schedule_id,
            schedule_state_token=schedule_state_token, rerun_of_build_id=rerun_of_build_id,
            purpose=purpose, definition_parameters=definition_parameters)
        pins = (expected_metadata_revision, expected_policy_revision, expected_schema_epoch)
        # Preserve the pre-0192 digest byte-for-byte for ordinary builds so a
        # historical accepted request remains replayable after the upgrade.
        digest = build_request_digest(scope, self.identity, program_id=program_id,
            program_source_token=program_source_token, parameters=parameters,
            delegation_id=delegation_id, delegation_state_token=delegation_state_token,
            schedule_id=schedule_id, schedule_state_token=schedule_state_token,
            pins=pins, idempotency_key=idempotency_key, purpose=purpose,
            definition_parameters=definition_parameters, rerun_of_build_id=rerun_of_build_id)
        connection = (nullcontext(_connection) if _connection is not None
                      else connect_postgres(self.runtime_dsn, row_factory=dict_row))
        with connection as db:
            with db.transaction():
                if replay_only:
                    db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                self._scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                if _occurrence_admission is not None:
                    from .postgres_python_occurrence_control import lock_state
                    if replay_only or purpose != 'Plan':
                        raise ValueError('PYTHON_SCHEDULE_ADMISSION_INVALID')
                    lock_state(db,scope)
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,_BUILD_PERMISSION[purpose],
                    action=('rules.design' if purpose=='Validation' and _connection is not None else
                            'rules.test' if purpose=='ImpactTest' else None))
                if access.authorization_model=='group_assignments':
                    require_build_source(db,scope,self.identity,(program_id,program_source_token),build_id,purpose)
                    if purpose=='ImpactTest':
                        from .postgres_planning_write_guard import WORKFLOW_ROLE_UNBOUND
                        from .postgres_planning_duty_availability import group_workflow_role_unbound
                        if group_workflow_role_unbound(db,scope,self.identity,access):
                            raise AccessDenied(WORKFLOW_ROLE_UNBOUND)
                        PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'rule_design',function='python.program.test')
                authorization_scope_digest=resolve_effective_dimensional_scope(
                    db,self.identity,scope,access=access).scope_digest
                occurrence = None
                if _occurrence_admission is not None:
                    from .postgres_python_occurrence_control import prepare_admission,link_admission
                    occurrence=prepare_admission(db,scope,self.identity,_occurrence_admission,
                        build_id=build_id,build_arguments={
                            'programId':program_id,'programSourceToken':program_source_token,
                            'parameters':parameters,'delegationId':delegation_id,
                            'delegationStateToken':delegation_state_token,
                            'scheduleId':schedule_id,'scheduleStateToken':schedule_state_token,
                            'expectedMetadataRevision':pins[0],
                            'expectedPolicyRevision':pins[1],'expectedSchemaEpoch':pins[2]})
                    if idempotency_key != 'py-schedule-build-'+_occurrence_admission.occurrence_id:
                        raise ValueError('PYTHON_SCHEDULE_ADMISSION_INVALID')
                prior = db.execute('''SELECT b.*,a.plan_digest
                    FROM epm.python_program_build b LEFT JOIN epm.python_plan_artifact a
                    USING(workspace_id,application_id,build_id)
                    WHERE b.workspace_id=%s AND b.application_id=%s
                      AND b.issuer=%s AND b.subject_id=%s AND b.idempotency_key=%s''',
                    (scope.workspace_id,scope.application_id,self.identity.issuer,
                     self.identity.subject_id,idempotency_key)).fetchone()
                if prior is not None:
                    if occurrence is not None and occurrence['build_id'] != prior['build_id']:
                        raise ValueError('PYTHON_SCHEDULE_ADMISSION_INVALID')
                    if prior['request_digest'] != digest:
                        raise ValueError("PYTHON_BUILD_IDEMPOTENCY_CONFLICT")
                    if (prior.get('authorization_scope_digest') is None
                            or prior['authorization_scope_digest'] !=
                               authorization_scope_digest):
                        raise AccessDenied(
                            'PYTHON_BUILD_AUTHORIZATION_SCOPE_CHANGED')
                    if access.authorization_model=='group_assignments':
                        prior['diagnostics']=None
                    return _record(prior)
                if replay_only:
                    return None
                if purpose == 'Plan':
                    allowed=db.execute('''SELECT epm.execution_delegation_is_current(
                        %s,%s,%s,%s,%s,%s,%s,%s) AS allowed''',(
                        scope.workspace_id,scope.application_id,delegation_id,
                        delegation_state_token,self.identity.issuer,
                        self.identity.subject_id,'python.program.build',schedule_id)).fetchone()
                    if not allowed or allowed['allowed'] is not True:
                        raise ValueError('PYTHON_EXECUTION_DELEGATION_INVALID')
                state = db.execute('''SELECT metadata_revision,policy_revision,schema_epoch
                    FROM epm.application_state WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                if tuple(state[key] for key in ('metadata_revision','policy_revision','schema_epoch')) != pins:
                    raise ValueError("PYTHON_BUILD_STALE_CONTEXT")
                available = db.execute('''SELECT d.source_token
                    FROM epm.python_program_definition d
                    JOIN epm.python_environment_definition e ON
                      e.workspace_id=d.workspace_id AND e.application_id=d.application_id
                      AND e.environment_id=d.environment_id
                      AND e.state_token=d.environment_state_token AND e.status='Active'
                    WHERE d.workspace_id=%s AND d.application_id=%s
                      AND d.program_id=%s AND d.source_token=%s''',
                    (scope.workspace_id,scope.application_id,program_id,
                     program_source_token)).fetchone()
                if available is None:
                    raise ValueError("PYTHON_PROGRAM_BUILD_SOURCE_UNAVAILABLE")
                token_issued_at,authority_kind=durable_authority_fields(
                    self.identity)
                inserted = db.execute('''INSERT INTO epm.python_program_build(
                    workspace_id,application_id,build_id,issuer,subject_id,
                    idempotency_key,program_id,program_source_token,parameter_values,
                    request_digest,expected_metadata_revision,expected_policy_revision,
                    expected_schema_epoch,delegation_id,delegation_state_token,
                    schedule_id,schedule_state_token,rerun_of_build_id,
                    verified_groups,authorization_scope_digest,token_issued_at,
                    authority_kind,purpose,definition_parameters,status) VALUES
                    (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'accepted')
                    ON CONFLICT DO NOTHING RETURNING *,NULL::text AS plan_digest''',
                    (scope.workspace_id,scope.application_id,build_id,
                     self.identity.issuer,self.identity.subject_id,idempotency_key,
                     program_id,program_source_token,Jsonb(parameters),digest,*pins,
                     delegation_id,delegation_state_token,schedule_id,
                     schedule_state_token,rerun_of_build_id,list(access.groups),
                     authorization_scope_digest,token_issued_at,
                     authority_kind,purpose,Jsonb(definition_parameters))).fetchone()
                if inserted is not None:
                    if occurrence is not None:
                        link_admission(db,scope,_occurrence_admission,inserted['build_id'])
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
                if occurrence is not None and occurrence['build_id'] != prior['build_id']:
                    raise ValueError('PYTHON_SCHEDULE_ADMISSION_INVALID')
                if (prior.get('authorization_scope_digest') is None
                        or prior['authorization_scope_digest'] !=
                           authorization_scope_digest):
                    raise AccessDenied(
                        'PYTHON_BUILD_AUTHORIZATION_SCOPE_CHANGED')
                if access.authorization_model=='group_assignments':
                    prior['diagnostics']=None
                return _record(prior)

    def read(self, scope: ApplicationScope, build_id: str, *,
             expected_request_digest: str | None = None) -> BuildRecord:
        if type(build_id) is not str or _HEX32.fullmatch(build_id) is None:
            raise ValueError("PYTHON_BUILD_ID_INVALID")
        with connect_postgres(self.runtime_dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db,5000); self._scope(db,scope)
                PostgresAccessChecker.lock_directory_membership_for_assignment(db)
                access = PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read',action='rules.test')
                row=db.execute('''SELECT b.*,a.plan_digest
                    FROM epm.python_program_build b LEFT JOIN epm.python_plan_artifact a
                    USING(workspace_id,application_id,build_id)
                    WHERE b.workspace_id=%s AND b.application_id=%s AND b.build_id=%s
                      AND b.issuer=%s AND b.subject_id=%s''',
                    (scope.workspace_id,scope.application_id,build_id,
                     self.identity.issuer,self.identity.subject_id)).fetchone()
                if row is None: raise ValueError("PYTHON_BUILD_UNAVAILABLE")
                if access.authorization_model=='group_assignments':
                    if row['purpose']!='ImpactTest':
                        raise AccessDenied('RULE_IMPACT_SOURCE_UNAVAILABLE')
                    require_impact_source(db,scope,(row['program_id'],row['program_source_token']))
                    row['diagnostics']=None
                self._assert_current_authorization_scope(db,scope,row,
                    access=access if access.authorization_model=='group_assignments' else None)
                if (expected_request_digest is not None
                        and row['request_digest'] != expected_request_digest):
                    raise ValueError('PYTHON_BUILD_IDEMPOTENCY_CONFLICT')
                return _record(row)

    def read_occurrence_control(self, scope, control, *, _connection=None):
        """Read one proven linked build for current-admin cancellation only."""
        from .postgres_python_occurrence_control import authorize_control,verify_child_link
        connection=(nullcontext(_connection) if _connection is not None
                    else connect_postgres(self.runtime_dsn,row_factory=dict_row))
        with connection as db:
            with db.transaction():
                configure_statement_timeout(db,5000);self._scope(db,scope)
                occurrence,controller=authorize_control(db,scope,control)
                if (controller.issuer,controller.subject_id)!=(self.identity.issuer,self.identity.subject_id):
                    raise ValueError('PYTHON_SCHEDULE_STALE_CONTROL')
                row=db.execute('''SELECT b.*,a.plan_digest FROM epm.python_program_build b
                    LEFT JOIN epm.python_plan_artifact a USING(workspace_id,application_id,build_id)
                    WHERE b.workspace_id=%s AND b.application_id=%s AND b.build_id=%s FOR UPDATE OF b''',
                    (scope.workspace_id,scope.application_id,occurrence['build_id'])).fetchone()
                verify_child_link(occurrence,row,family='build')
                # Historical identity is a digest input, never current control authority.
                original=durable_execution_identity(row)
                expected=build_request_digest(scope,original,program_id=row['program_id'],
                    program_source_token=row['program_source_token'],parameters=row['parameter_values'],
                    delegation_id=row['delegation_id'],delegation_state_token=row['delegation_state_token'],
                    schedule_id=row['schedule_id'],schedule_state_token=row['schedule_state_token'],
                    pins=(row['expected_metadata_revision'],row['expected_policy_revision'],row['expected_schema_epoch']),
                    idempotency_key=row['idempotency_key'],purpose=row['purpose'],
                    definition_parameters=row['definition_parameters'],rerun_of_build_id=row['rerun_of_build_id'])
                if row['purpose']!='Plan' or expected!=row['request_digest']:
                    raise ValueError('PYTHON_SCHEDULE_ADMISSION_UNRESOLVED')
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
                PostgresAccessChecker.lock_directory_membership_for_assignment(db)
                access = PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read',action='rules.test')
                row = db.execute('''SELECT b.program_id,b.program_source_token,b.status,b.purpose,b.parameter_values,b.definition_parameters,b.authorization_scope_digest,
                    a.format,a.canonical_plan,a.impact,
                    (b.purpose='ImpactTest' AND a.sealed_at<=clock_timestamp()-interval '24 hours') AS impact_expired,
                    a.plan_digest,a.source_map,a.build_log,a.compiler_version,
                    d.source_digest,e.manifest,e.manifest_digest
                    FROM epm.python_program_build b
                    JOIN epm.python_plan_artifact a USING
                      (workspace_id,application_id,build_id)
                    JOIN epm.python_program_definition d ON
                      d.workspace_id=b.workspace_id
                      AND d.application_id=b.application_id
                      AND d.program_id=b.program_id
                      AND d.source_token=b.program_source_token
                    JOIN epm.python_environment_definition e ON
                      e.workspace_id=d.workspace_id
                      AND e.application_id=d.application_id
                      AND e.environment_id=d.environment_id
                      AND e.state_token=d.environment_state_token
                    WHERE b.workspace_id=%s AND b.application_id=%s
                      AND b.build_id=%s AND b.issuer=%s AND b.subject_id=%s
                      AND b.status='sealed' ''',
                    (scope.workspace_id, scope.application_id, build_id,
                     self.identity.issuer,
                     self.identity.subject_id)).fetchone()
                if row is None:
                    raise ValueError("PYTHON_BUILD_ARTIFACT_UNAVAILABLE")
                group_test = access.authorization_model=='group_assignments'
                if group_test:
                    if row['purpose']!='ImpactTest':
                        raise AccessDenied('RULE_IMPACT_SOURCE_UNAVAILABLE')
                    require_impact_source(db,scope,(row['program_id'],row['program_source_token']))
                self._assert_current_authorization_scope(db,scope,row,
                    access=access if access.authorization_model=='group_assignments' else None)
                if row.get('impact_expired'):
                    raise ValueError('PYTHON_IMPACT_RESULT_EXPIRED')
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
                sections = {'Plan': plan, 'SourceMap': source_map, 'BuildLog': build_log}
                if row.get('purpose') == 'Validation':
                    from .python_plan_summary import static_plan_summary
                    summary = static_plan_summary(
                        row['canonical_plan'], row['source_map'],
                        plan_digest=row['plan_digest'],
                        source_digest=row['source_digest'])
                    sections['PlanSummary'] = _canonical(
                        summary, 'PYTHON_PLAN_SUMMARY_INVALID')
                if row.get('impact') is not None:
                    from .postgres_python_impact import validate_impact_size
                    impact = row['impact']
                    validate_impact_size(impact)
                    if (row.get('purpose') != 'ImpactTest' or type(impact) is not dict
                            or impact.get('sourceDigest') != row['source_digest']
                            or impact.get('planDigest') != row['plan_digest']
                            or impact.get('status') != 'complete'):
                        raise ValueError('PYTHON_IMPACT_ARTIFACT_INVALID')
                    if impact.get('parameters') != row['parameter_values']:
                        raise ValueError('PYTHON_IMPACT_PARAMETERS_MISMATCH')
                    if impact.get('definitionParameters', {}) != row['definition_parameters']:
                        raise ValueError('PYTHON_IMPACT_DEFINITION_PARAMETERS_MISMATCH')
                    sections['Impact'] = _canonical(impact, 'PYTHON_IMPACT_ARTIFACT_INVALID')
                    if group_test:
                        sections={'Impact':sections['Impact']}
                elif row.get('purpose') == 'ImpactTest':
                    raise ValueError('PYTHON_IMPACT_ARTIFACT_UNAVAILABLE')
                return {'buildId': build_id,
                        'planDigest': row['plan_digest'],
                        'sourceDigest': row['source_digest'],
                        'compilerVersion': row['compiler_version'],
                        'unitCount': len(row['canonical_plan']['units']),
                        'sections': sections}

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
        with connect_postgres(self.runtime_dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                self._scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                self._authorize(db, self.identity, scope, 'read')
                state = db.execute('''SELECT metadata_revision,policy_revision,
                    schema_epoch FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                new_build_id = python_build_id(scope,self.identity,idempotency_key,
                    schema_epoch=state['schema_epoch'])
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
                    self._authorize(db, self.identity, scope,
                        _BUILD_PERMISSION[replay['purpose']])
                    self._assert_current_authorization_scope(db,scope,replay)
                    return _record(replay)
                source = db.execute('''SELECT program_id,program_source_token,
                    parameter_values,definition_parameters,delegation_id,delegation_state_token,
                    schedule_id,schedule_state_token,status,purpose
                    FROM epm.python_program_build
                    WHERE workspace_id=%s AND application_id=%s
                      AND build_id=%s AND issuer=%s AND subject_id=%s''',
                    (scope.workspace_id, scope.application_id, build_id,
                     self.identity.issuer,
                     self.identity.subject_id)).fetchone()
                if source is None or source['status'] not in ('failed','cancelled'):
                    raise ValueError("PYTHON_BUILD_RERUN_NOT_SUPPORTED")
                self._authorize(db, self.identity, scope,
                    _BUILD_PERMISSION[source['purpose']])
                if (source['purpose']=='Plan' and (source['delegation_id'] is None
                        or source['delegation_state_token'] is None)):
                    raise ValueError("PYTHON_BUILD_RERUN_NOT_SUPPORTED")
                source_values = dict(source)
                current_pins = tuple(state[key] for key in
                    ('metadata_revision','policy_revision','schema_epoch'))
        return self.accept(scope, build_id=new_build_id,
            program_id=source_values['program_id'],
            program_source_token=source_values['program_source_token'],
            parameter_values=source_values['parameter_values'],
            idempotency_key=idempotency_key,
            expected_metadata_revision=current_pins[0],
            expected_policy_revision=current_pins[1],
            expected_schema_epoch=current_pins[2],
            delegation_id=source_values['delegation_id'],
            delegation_state_token=source_values['delegation_state_token'],
            schedule_id=source_values['schedule_id'],
            schedule_state_token=source_values['schedule_state_token'],
            rerun_of_build_id=build_id, purpose=source_values['purpose'],
            definition_parameters=source_values['definition_parameters'])

    def request_cancel_as_task_controller(self, scope: ApplicationScope,
                                          build_id: str, *,
                                          allow_application_admin=False,
                                          _connection=None) -> BuildRecord:
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
        connection=(nullcontext(_connection) if _connection is not None
                    else connect_postgres(self.runtime_dsn,row_factory=dict_row))
        with connection as db:
            with db.transaction():
                configure_statement_timeout(db,5000); self._scope(db,scope)
                self._authorize(db,self.identity,scope,'read')
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
                self._authorize(db,self.identity,scope,
                    _BUILD_PERMISSION[row['purpose']])
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
                or current.request_digest != updated.request_digest
                or current.purpose != updated.purpose):
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
        diagnostics = (validate_diagnostic_payload(updated.diagnostics)
                       if updated.diagnostics is not None else None)
        with connect_postgres(self._coordinator(),row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000); self._scope(db,current.scope)
                result=db.execute('''UPDATE epm.python_program_build SET status=%s,
                    claim_generation=%s,claimant=%s,
                    lease_until=CASE WHEN %s::bigint IS NULL THEN NULL
                        ELSE to_timestamp(%s::double precision) END,
                    attempts=%s,error_code=%s,diagnostics=%s,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND build_id=%s
                      AND request_digest=%s AND status=%s AND claim_generation=%s
                      AND claimant IS NOT DISTINCT FROM %s
                      AND (%s NOT IN ('running','cancel_requested')
                           OR lease_until>clock_timestamp())
                      AND (%s NOT IN ('running','cancel_requested')
                           OR to_timestamp(%s::double precision)>clock_timestamp())''',
                    (updated.status.value,updated.claim_generation,updated.claimant,
                     updated.lease_until,updated.lease_until,updated.attempts,
                     updated.error_code,Jsonb(diagnostics) if diagnostics is not None else None,
                     current.scope.workspace_id,
                     current.scope.application_id,current.build_id,
                     current.request_digest,current.status.value,
                     current.claim_generation,current.claimant,current.status.value,
                     updated.status.value,updated.lease_until))
                return result.rowcount == 1

    @contextmanager
    def _seal_authority(self, current: BuildRecord, source_map):
        """Retain current runtime authorization through the short coordinator seal.

        Source execution and private evaluation have already finished. This
        READ COMMITTED transaction takes the established workspace-then-state
        fence; the coordinator retains only its narrow technical write grants.
        No build-row lock is taken here because the coordinator updates it on
        its own connection under the exact request/claim/lease predicate.
        """
        scope = current.scope
        with connect_postgres(self.runtime_dsn, row_factory=dict_row) as auth:
            with auth.transaction():
                configure_statement_timeout(auth, 5000)
                self._scope(auth, scope)
                PostgresAccessChecker.lock_directory_membership_for_assignment(auth)
                PostgresAccessChecker.lock_workspace(auth, scope.workspace_id)
                row = auth.execute('''SELECT b.*,d.source_digest
                    FROM epm.python_program_build b
                    JOIN epm.python_program_definition d ON
                      d.workspace_id=b.workspace_id AND d.application_id=b.application_id
                      AND d.program_id=b.program_id AND d.source_token=b.program_source_token
                    JOIN epm.python_environment_definition e ON
                      e.workspace_id=d.workspace_id AND e.application_id=d.application_id
                      AND e.environment_id=d.environment_id
                      AND e.state_token=d.environment_state_token
                      AND e.status='Active'
                    WHERE b.workspace_id=%s AND b.application_id=%s AND b.build_id=%s
                      AND b.request_digest=%s AND b.status='running'
                      AND b.claim_generation=%s AND b.claimant=%s
                      AND b.lease_until>clock_timestamp()''',
                    (scope.workspace_id, scope.application_id, current.build_id,
                     current.request_digest, current.claim_generation, current.claimant)).fetchone()
                if row is None:
                    yield False
                    return
                if (row['purpose'] != current.purpose
                        or source_map.get('sourceDigest') != row['source_digest']):
                    raise ValueError('PYTHON_BUILD_SOURCE_OR_PURPOSE_MISMATCH')
                identity = durable_execution_identity(row)
                access = PostgresAccessChecker.check_in_transaction(auth, identity, scope,
                    _BUILD_PERMISSION[row['purpose']],action={'Validation':'rules.design','ImpactTest':'rules.test'}.get(row['purpose']))
                if access.authorization_model=='group_assignments':
                    row['inspected_rule'] = require_build_source(auth,scope,identity,
                        (row['program_id'],row['program_source_token']),row['build_id'],row['purpose'])
                state = auth.execute('''SELECT metadata_revision,policy_revision,schema_epoch
                    FROM epm.application_state WHERE workspace_id=%s AND application_id=%s
                    FOR SHARE''', (scope.workspace_id, scope.application_id)).fetchone()
                if (state is None or any(state[field] != row['expected_' + field]
                        for field in ('metadata_revision', 'policy_revision', 'schema_epoch'))):
                    raise ValueError('PYTHON_BUILD_STALE_CONTEXT')
                if row['purpose'] == 'Plan':
                    allowed = auth.execute('''SELECT epm.execution_delegation_is_current(
                        %s,%s,%s,%s,%s,%s,%s,%s) AS allowed''',
                        (scope.workspace_id, scope.application_id, row['delegation_id'],
                         row['delegation_state_token'], identity.issuer, identity.subject_id,
                         'python.program.build', row['schedule_id'])).fetchone()
                    if not allowed or allowed['allowed'] is not True:
                        raise ValueError('PYTHON_EXECUTION_DELEGATION_INVALID')
                yield row

    def store_sealed(self, current: BuildRecord, updated: BuildRecord,
                     plan: SealedPlan, *, source_map, build_log, impact=None) -> bool:
        if (not isinstance(current,BuildRecord) or not isinstance(updated,BuildRecord)
                or current.scope != updated.scope or current.build_id != updated.build_id
                or current.request_digest != updated.request_digest
                or current.purpose != updated.purpose
                or updated.status != BuildStatus.SEALED
                or updated.plan_digest != plan.digest):
            raise ValueError("PYTHON_BUILD_RECORD_MISMATCH")
        verify_plan_identity(plan,updated.plan_digest)
        validate_build_artifacts(plan,source_map=source_map,build_log=build_log)
        if (current.purpose == 'ImpactTest') != (impact is not None):
            raise ValueError('PYTHON_IMPACT_ARTIFACT_PURPOSE_MISMATCH')
        if impact is not None:
            from .postgres_python_impact import validate_impact_size
            validate_impact_size(impact)
            if (type(impact) is not dict or impact.get('planDigest') != plan.digest
                    or impact.get('sourceDigest') != source_map.get('sourceDigest')
                    or impact.get('status') != 'complete'):
                raise ValueError('PYTHON_IMPACT_ARTIFACT_INVALID')
        with self._seal_authority(current, source_map) as authorized:
            if not authorized:
                return False
            if 'inspected_rule' in authorized:
                from .postgres_python_definitions import descriptor
                if descriptor(plan.canonical_plan) != {'kind':'ApplicationRule','definitionId':authorized['inspected_rule']}:
                    raise AccessDenied('RULE_SOURCE_VALIDATION_UNAVAILABLE')
                operation = plan.canonical_plan['units'][0]['operations'][0]
                require_numeric_rule_declaration(authorized['inspected_rule'],operation['function'],operation['arguments'],
                    impact=current.purpose=='ImpactTest')
            if impact is not None:
                impact = {**impact, 'parameters': authorized['parameter_values'],
                    'definitionParameters': authorized['definition_parameters']}
                validate_impact_size(impact)
            return self._store_sealed_authorized(current, plan, source_map=source_map,
                build_log=build_log, impact=impact)

    def _store_sealed_authorized(self, current, plan, *, source_map, build_log, impact):
        with connect_postgres(self._coordinator(),row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000); self._scope(db,current.scope)
                inserted=db.execute('''INSERT INTO epm.python_plan_artifact(
                    workspace_id,application_id,build_id,format,canonical_plan,
                    plan_digest,source_map,build_log,compiler_version,impact)
                    SELECT %s,%s,%s,'openepm-python-plan-v1',%s,%s,%s,%s,%s,%s
                    WHERE EXISTS (SELECT 1 FROM epm.python_program_build
                      WHERE workspace_id=%s AND application_id=%s AND build_id=%s
                        AND request_digest=%s AND status='running' AND claim_generation=%s AND claimant=%s
                        AND lease_until>clock_timestamp())
                    ON CONFLICT DO NOTHING RETURNING build_id''',
                    (current.scope.workspace_id,current.scope.application_id,
                     current.build_id,Jsonb(plan.canonical_plan),plan.digest,
                     Jsonb(source_map),build_log,plan.compiler_version,
                     Jsonb(impact) if impact is not None else None,
                     current.scope.workspace_id,current.scope.application_id,
                     current.build_id,current.request_digest,current.claim_generation,current.claimant)).fetchone()
                if inserted is None: return False
                changed=db.execute('''UPDATE epm.python_program_build SET status='sealed',
                    claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND build_id=%s
                      AND request_digest=%s AND status='running' AND claim_generation=%s AND claimant=%s
                      AND lease_until>clock_timestamp()''',
                    (current.scope.workspace_id,current.scope.application_id,
                     current.build_id,current.request_digest,current.claim_generation,current.claimant)).rowcount
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
                row = db.execute('''SELECT b.*,a.plan_digest,d.environment_id,
                    d.environment_state_token,
                    (e.manifest->>'environmentVersion')::integer environment_profile_version
                    FROM epm.python_program_build b
                    JOIN epm.python_program_definition d ON
                      d.workspace_id=b.workspace_id
                      AND d.application_id=b.application_id
                      AND d.program_id=b.program_id
                      AND d.source_token=b.program_source_token
                    JOIN epm.python_environment_definition e ON
                      e.workspace_id=d.workspace_id
                      AND e.application_id=d.application_id
                      AND e.environment_id=d.environment_id
                      AND e.state_token=d.environment_state_token
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
                return {'record': _record(row), 'purpose': row['purpose'], 'issuer': row['issuer'],
                    'subjectId': row['subject_id'],
                    'verifiedGroups': list(row['verified_groups']),
                    'authorizationScopeDigest':
                        row['authorization_scope_digest'],
                    'tokenIssuedAt':row['token_issued_at'],
                    'authorityKind':row['authority_kind'],
                    'programId': row['program_id'],
                    'programSourceToken': row['program_source_token'],
                    'definitionParameters': row['definition_parameters'],
                    'environmentId': row['environment_id'],
                    'environmentStateToken': row['environment_state_token'],
                    'environmentProfileVersion': row['environment_profile_version'],
                    'metadataRevision': row['expected_metadata_revision'],
                    'policyRevision': row['expected_policy_revision'],
                    'schemaEpoch': row['expected_schema_epoch']}

    def broker_context(self, scope: ApplicationScope, build_id: str, *, action: str) -> dict:
        """Return bounded builder inputs after a fresh grant and claim check.

        The runtime transaction retains the workspace authorization fence while
        the coordinator role reads source.  This prevents grant revocation or
        application deletion from racing between authorization and disclosure.
        """
        from .python_build_capability import BUILDER_ACTIONS, SOURCE_READ, CONTEXT_READ
        if action not in BUILDER_ACTIONS:
            raise ValueError("PYTHON_BUILD_CAPABILITY_DENIED")
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
                PostgresAccessChecker.lock_directory_membership_for_assignment(auth)
                access=PostgresAccessChecker.check_in_transaction(
                    auth,identity,scope,_BUILD_PERMISSION[initial['purpose']],
                    action={'Validation':'rules.design','ImpactTest':'rules.test'}.get(initial['purpose']))
                if access.authorization_model=='group_assignments':
                    require_build_source(auth,scope,identity,
                        (initial['programId'],initial['programSourceToken']),build_id,initial['purpose'])
                current_scope=resolve_effective_dimensional_scope(
                    auth,identity,scope,access=access).scope_digest
                if (initial.get('authorizationScopeDigest') is None
                        or initial['authorizationScopeDigest']!=current_scope):
                    raise AccessDenied('PYTHON_BUILD_AUTHORIZATION_REVOKED')
                bound=auth.execute('''SELECT purpose,delegation_id,delegation_state_token,
                    schedule_id,schedule_state_token FROM epm.python_program_build
                    WHERE workspace_id=%s AND application_id=%s AND build_id=%s
                      AND issuer=%s AND subject_id=%s''',(scope.workspace_id,
                    scope.application_id,build_id,identity.issuer,
                    identity.subject_id)).fetchone()
                if bound is None or bound['purpose'] != initial['purpose']:
                    raise ValueError('PYTHON_BUILD_PURPOSE_INVALID')
                if bound['purpose'] == 'Plan':
                    if bound is None or bound['delegation_id'] is None:
                        raise ValueError('PYTHON_EXECUTION_DELEGATION_INVALID')
                    allowed=auth.execute('''SELECT epm.execution_delegation_is_current(
                        %s,%s,%s,%s,%s,%s,%s,%s) AS allowed''',(
                        scope.workspace_id,scope.application_id,bound['delegation_id'],
                        bound['delegation_state_token'],identity.issuer,
                        identity.subject_id,'python.program.build',bound['schedule_id'])).fetchone()
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
                        row = db.execute('''SELECT b.purpose,b.issuer,b.subject_id,
                            b.verified_groups,b.authorization_scope_digest,
                            b.token_issued_at,b.authority_kind,
                            b.program_id,b.program_source_token,b.parameter_values,
                            b.expected_metadata_revision,b.expected_policy_revision,
                            b.expected_schema_epoch,b.claim_generation,b.status,
                            b.lease_until,d.source_text,d.entry_point,
                            d.environment_id,d.environment_state_token,
                            (e.manifest->>'environmentVersion')::integer environment_profile_version
                            FROM epm.python_program_build b
                            JOIN epm.python_program_definition d ON
                              d.workspace_id=b.workspace_id
                              AND d.application_id=b.application_id
                              AND d.program_id=b.program_id
                              AND d.source_token=b.program_source_token
                            JOIN epm.python_environment_definition e ON
                              e.workspace_id=d.workspace_id
                              AND e.application_id=d.application_id
                              AND e.environment_id=d.environment_id
                              AND e.state_token=d.environment_state_token
                              AND e.status='Active'
                            WHERE b.workspace_id=%s AND b.application_id=%s
                              AND b.build_id=%s
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
                result = {'identity': identity, 'purpose': row['purpose'],
                    'claimGeneration': row['claim_generation'],
                    'programId': row['program_id'],
                    'programSourceToken': row['program_source_token'],
                    'environmentId': row['environment_id'],
                    'environmentStateToken': row['environment_state_token'],
                    'environmentProfileVersion': row['environment_profile_version']}
                if action == SOURCE_READ:
                    return {**result, 'sourceText': row['source_text'],
                            'entryPoint': row['entry_point']}
                if action != CONTEXT_READ:
                    return result
                from .postgres_authoring_context import bootstrap_context
                metadata = bootstrap_context(auth, scope, identity,
                    expected_metadata_revision=initial['metadataRevision'])
                return {**result, 'parameterValues': row['parameter_values'],
                    'buildContext': {
                        'workspaceId': scope.workspace_id,
                        'applicationId': scope.application_id,
                        'metadataRevision': row['expected_metadata_revision'],
                        'policyRevision': row['expected_policy_revision'],
                        'schemaEpoch': row['expected_schema_epoch'],
                        'references': {'metadata': metadata}}}

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
