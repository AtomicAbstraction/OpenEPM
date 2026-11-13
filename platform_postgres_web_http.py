"""Small authenticated browser inspector over the PostgreSQL V2 fixed core.

The browser can read bounded cube pages, job status/events and request
cancellation of its own jobs. Business data changes still use typed MCP
programs. No database credential or SQL reaches the browser.
"""
from __future__ import annotations

import json
import mimetypes
import logging
import os
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit

import psycopg
from psycopg.rows import dict_row

from epm_core.postgres_auth import AuthError, access_token, mode
from epm_core.deployment_secrets import configured_hex_bytes, configured_text
from epm_core.postgres_mcp_execution import (authenticate_http, execute_web_request,
    check_startup, verified_mcp_request, WEB_MODULE)
from epm_core.postgres_verified_principal import principal_claims
from epm_core.postgres_http_budget import bounded_request
from epm_core.postgres_execution_policy import HTTP_POST_SECONDS, TIMEOUT_RESPONSE_SECONDS
from mcp.server.mcpserver.exceptions import ToolError
from openepm.diagnostics import SourceValidationError, validate_diagnostic_payload
from epm_core.persistence_contract import ApplicationScope
from epm_core.operation_admission_contract import (
    is_signed_operation_id, issue_operation_admission,
    validate_operation_admission)
from epm_core.postgres_access import (AccessDenied, PostgresAccessChecker,
                                      VerifiedIdentity, assert_lifecycle_role)
from epm_core.postgres_application_capabilities import _state as capability_state
from epm_core.postgres_capability_contract import (FUNCTION_REGISTRY_FORMAT,
    assert_public_program_admitted, filter_catalog, function_registry_digest)
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_jobs import PostgresJobQueue, _canonical_digest
from epm_core.postgres_language_v2 import PostgresLanguageV2
from epm_core.postgres_mcp_router import PostgresMCPRouter
from epm_core.postgres_python_environments import ApprovedPythonEnvironment
from epm_core.postgres_python_environment_startup import load_python_environment_profiles
from epm_core.postgres_numeric_store import PostgresNumericFactStore
from epm_core.postgres_capacity_metrics import PostgresCapacityMetrics
from epm_core.personal_mcp_endpoint import personal_endpoint, endpoint_secret
from epm_core.postgres_processing_limits import policy as processing_policy
from epm_core.processing_operation_registry import (
    PROCESSING_REGISTRY_FORMAT,admit_operation,operation_contracts)
from epm_core.observability import observe_request
from epm_core.postgres_security_language import (PostgresSecurityLanguage,
    FUNCTION as _SECURITY_ACCESS_SET, LIST_FUNCTION as _SECURITY_ACCESS_LIST,
    SUBJECT_LIST_FUNCTION as _SECURITY_SUBJECT_LIST,
    AUDIT_LIST_FUNCTION as _SECURITY_AUDIT_LIST,
    RECEIPT_READ_FUNCTION as _SECURITY_RECEIPT_READ,
    DIMENSION_FUNCTION as _SECURITY_DIMENSION_SET,
    DIMENSION_READ_FUNCTION as _SECURITY_DIMENSION_READ,
    DIMENSION_TAGS_FUNCTION as _SECURITY_DIMENSION_TAGS,
    MEMBER_TAGS_READ_FUNCTION as _SECURITY_MEMBER_TAGS,
    DIMENSION_METADATA_TAGS_READ_FUNCTION as _SECURITY_DIMENSION_METADATA_TAGS,
    RELATIONSHIP_TAGS_READ_FUNCTION as _SECURITY_RELATIONSHIP_TAGS,
    DIMENSION_POLICY_SAVE_FUNCTION as _SECURITY_POLICY_SAVE,
    DIMENSION_POLICY_READ_FUNCTION as _SECURITY_POLICY_READ,
    DIMENSION_POLICY_ACTIVATE_FUNCTION as _SECURITY_POLICY_ACTIVATE,
    DIMENSION_POLICY_DEACTIVATE_FUNCTION as _SECURITY_POLICY_DEACTIVATE,
    RULE_FUNCTION as _SECURITY_RULE_SET)
from epm_core.postgres_tasks import PostgresTaskService
from epm_core.postgres_workspace_lifecycle import (
    FUNCTION as _WORKSPACE_APPLICATION_CREATE,
    PostgresWorkspaceLifecycle,
)


LOG = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parent


def _ui_root() -> Path:
    """Resolve the compiled presentation without making Node a runtime dependency."""
    packaged=ROOT/'web'/'app'
    return packaged if packaged.is_dir() else ROOT/'web-ui'/'dist'


MAX_BODY = 16_384
MAX_SOURCE_LOAD_BODY = 10_000_000
_HEX40 = re.compile(r'^[0-9a-f]{40}$')
_IMAGE_DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
_ERROR_CODE = re.compile(r'^[A-Z][A-Z0-9_]{2,127}$')


def _error_payload(scope: dict, status: int, code: object,
                   *, details: dict | None = None) -> dict:
    """Return the one safe browser failure envelope.

    ``error`` remains as a compatibility alias while clients migrate to the
    explicit code.  Free-form exception text and business values never enter
    this boundary.
    """
    stable = code if isinstance(code, str) and _ERROR_CODE.fullmatch(code) \
        else 'WEB_OPERATION_FAILED'
    correlation = scope.get('openepm.correlation_id')
    if not isinstance(correlation, str) or not re.fullmatch(
            r'[0-9a-f]{32}', correlation):
        correlation = '0' * 32
    return {
        'error': stable,
        'code': stable,
        'message': stable.replace('_', ' ').capitalize(),
        'details': details or {},
        'correlationId': correlation,
        'retryable': status in (429, 502, 503, 504),
    }


def _value_error_response(error: ValueError)->tuple[int,str]:
    """Map fixed-core stable codes to transport semantics without disclosure."""
    raw=str(error)
    candidate=raw.split(':',1)[0]
    code=candidate if _ERROR_CODE.fullmatch(candidate) else 'WEB_OPERATION_FAILED'
    if (code in ('REQUEST_TOO_LARGE','SOURCE_RECORD_TOO_LARGE')
            or code.endswith(('_PAYLOAD_TOO_LARGE','_BODY_TOO_LARGE'))):
        return 413,code
    if (code=='IDEMPOTENCY_KEY_REUSED'
            or code.endswith(('_STALE','_CONFLICT','_REVISION_MISMATCH',
                              '_ALREADY_EXISTS'))):
        return 409,code
    if (code.endswith(('_BUSY','_CAPACITY_EXCEEDED','_QUEUE_FULL'))
            or code in ('CAPACITY_EXCEEDED','ADMISSION_CAPACITY_EXCEEDED')):
        return 429,code
    if (code.endswith('_SERVICE_UNAVAILABLE')
            or code in ('POSTGRES_SECURITY_SERVICE_NOT_CONFIGURED',
                        'POSTGRES_LIFECYCLE_SERVICE_NOT_CONFIGURED')):
        return 503,code
    # Keep malformed transport/query/program shapes as 400.  Only codes that
    # explicitly describe a well-formed request failing semantic validation
    # receive 422; a blanket ``*_INVALID`` mapping changes established request
    # syntax contracts and makes clients misclassify errors they must repair.
    if (code in ('SEMANTIC_VALIDATION_FAILED','VALIDATION_FAILED')
            or code.endswith(('_SEMANTIC_INVALID','_SEMANTIC_UNSUPPORTED'))):
        return 422,code
    return 400,code


def _runtime_build_identity() -> dict:
    """Return only deployment-owned, validated, non-secret build identity."""
    value = {}
    image = os.environ.get('EPM_RUNTIME_APPLICATION_IMAGE', '')
    commit = os.environ.get('EPM_SOURCE_COMMIT', '')
    tree = os.environ.get('EPM_SOURCE_TREE', '')
    if _IMAGE_DIGEST.fullmatch(image):
        value['applicationImage'] = image
    if _HEX40.fullmatch(commit):
        value['sourceCommit'] = commit
    if _HEX40.fullmatch(tree):
        value['sourceTree'] = tree
    migrations = []
    for path in (ROOT / 'schema' / 'postgres').glob('[0-9][0-9][0-9][0-9]_*.sql'):
        try:
            migrations.append(int(path.name[:4]))
        except ValueError:
            continue
    if migrations:
        value['packagedSchema'] = max(migrations)
    return value


def _public_application_mcp_endpoint(issuer: str, subject: str) -> str | None:
    """Return the authenticated user's opaque personal application MCP URL."""
    value = os.environ.get('EPM_PUBLIC_MCP_ORIGIN')
    if value is None:
        return None
    try:
        return personal_endpoint(value, endpoint_secret(os.environ), issuer, subject)
    except ValueError:
        return None
_PLANNING_ACTIONS=frozenset((
    'cube.write.scope.lock','cube.write.scope.submit',
    'cube.write.scope.approve','cube.write.scope.reopen'))
_PLANNING_POLICY_ACTIONS=frozenset((
    'cube.write.policy.save','cube.write.policy.activate',
    'cube.write.policy.deactivate'))
_APPLICATION_WORKFLOW_OCCURRENCE_ACTIONS=frozenset((
    'application.workflow.occurrence.start',
    'application.workflow.activity.complete',
    'application.workflow.activity.return',
    'application.workflow.occurrence.cancel'))
_METADATA_ACTIONS=frozenset((
    'metadata.dimension.create','metadata.member.create',
    'metadata.security-tag.create','metadata.security-tag.update',
    'metadata.security-tag.status.set',
    'metadata.dimension.rename','metadata.member.rename',
    'metadata.relationship.rename','metadata.dimension.describe',
    'metadata.member.describe','metadata.relationship.describe',
    'metadata.dimension.status.set','metadata.member.status.set',
    'metadata.member.security-tags.set',
    'metadata.member.security-string.set',
    'metadata.relationship.create',
    'metadata.relationship.aggregation-operator.set',
    'metadata.relationship.status.set','metadata.hierarchy.build',
    'metadata.attribute-definition.create',
    'metadata.attribute-value.set',
    'metadata.semantic_column.create','metadata.semantic_column.update',
    'metadata.member.attribute.set',
    'metadata.relationship.semantic_column.create',
    'metadata.relationship.semantic_column.update',
    'metadata.relationship.attribute.set',
    'metadata.member_list.save','metadata.member_list.activate',
    'metadata.member_list.deactivate',
    'metadata.member_list.delete',
    'grid.definition.save','grid.definition.delete'))
_RULE_ACTIONS=frozenset((
    'rules.expression.save',
    'rules.expression.activate',
    'application.rule.save',
    'application.rule.activate',
    'application.rule.run',
    'application.rule.run.cancel',
    'application.rule.run.reconcile',
    'calculated.member.save',
    'calculated.member.activate'))
_OWNERSHIP_ACTIONS=frozenset((
    'consolidation.ownership.value.set',))
_SOURCE_ACTIONS=frozenset((
    'facts.planning.scenario.copy.prepare',
    'facts.source.preview','facts.source.publish'))
_SOURCE_LOAD_SOURCE_READS=frozenset((
    'facts.source.preview','facts.transfer.import.read'))
_SOURCE_LOAD_ARTIFACT_READS=frozenset((
    'facts.transfer.import.diagnostics.read',
    'facts.transfer.import.diagnostics.list'))
_SOURCE_LOAD_WRITES=frozenset((
    'facts.source.begin','facts.source.csv.append','facts.source.seal',
    'facts.source.manifest.attach',
    'facts.transfer.import.request','facts.transfer.import.cancel'))
_EXPORT_ORCHESTRATION_READS=frozenset((
    'facts.transfer.export.read',))
_EXPORT_ARTIFACT_READS=frozenset((
    'facts.transfer.export.manifest.read',
    'facts.transfer.export.manifest.list',
    'facts.transfer.export.payload.page'))
_EXPORT_WRITES=frozenset((
    'facts.transfer.export.request','facts.transfer.export.cancel'))
_AGGREGATE_READS=frozenset((
    'facts.cube.aggregate.read',))

_PROGRAM_OPERATION_KEY_FIELDS={
    'facts.planning.scenario.copy.prepare':'idempotencyKey',
    'facts.source.begin':'idempotencyKey',
    'facts.source.manifest.attach':'requestKey',
    'facts.transfer.import.request':'idempotencyKey',
    'facts.transfer.export.request':'idempotencyKey',
}

def _admitted_browser_program(language: PostgresLanguageV2,
        scope: ApplicationScope, program: dict, operation_id: object) -> dict:
    if not is_signed_operation_id(operation_id):
        raise ValueError('OPERATION_ADMISSION_REQUIRED')
    language._validate_signed_operation_id(scope,program,operation_id)
    field=_PROGRAM_OPERATION_KEY_FIELDS.get(program.get('function'))
    if field is None:
        return program
    arguments=program.get('arguments')
    if not isinstance(arguments,dict) or field not in arguments:
        raise ValueError('OPERATION_ADMISSION_PROGRAM_INVALID')
    return {**program,'arguments':{**arguments,field:operation_id}}

def _validate_browser_operation(secret: bytes, scope: ApplicationScope,
        identity: VerifiedIdentity, program: dict, operation_id: object) -> None:
    if not is_signed_operation_id(operation_id):
        raise ValueError('OPERATION_ADMISSION_REQUIRED')
    validate_operation_admission(
        secret,scope,identity,operation_id=operation_id,
        function=program.get('function') if isinstance(program,dict) else '',
        intent_digest=_canonical_digest(program))

_OBSERVABLE_ROUTES=frozenset(('/', '/ui/*', '/api/applications',
    '/api/runtime', '/api/session-identity', '/api/catalog',
    '/api/operation-admission',
    '/api/capacity-metrics', '/api/read', '/api/preview', '/api/submit', '/api/events',
    '/api/job', '/api/cancel', '/api/metadata-action', '/api/rule-action',
    '/api/ownership-action', '/api/planning-action', '/api/planning-policy',
    '/api/source-action', '/api/source-load', '/api/export', '/api/aggregate',
    '/api/python-program', '/api/python-environment', '/api/python-schedule',
    '/api/execution-delegation', '/api/python-build', '/api/python-run',
    '/api/security', '/api/application-schedule', '/api/application-assignment',
    '/api/application-workflow', '/api/application-decision',
    '/api/application-workflow-occurrence', '/api/tasks', '/api/task',
    '/api/task-logs',
    '/api/workspace-application','/api/application-purge'))
# Every browser POST requires same-origin protection.  Function descriptors,
# not route names, classify reads, technical controls and business mutations;
# for example /api/read can admit a Reader-authorized durable technical query.
# Protecting the complete POST surface prevents a caller from influencing CSRF
# policy by substituting a function name in the body.  The exact set is shared
# by the public ASGI boundary and the isolated child boundary.
_BROWSER_POST_ROUTES=frozenset((
    '/api/catalog','/api/operation-admission','/api/capacity-metrics','/api/read','/api/preview','/api/events',
    '/api/job','/api/tasks','/api/task','/api/task-logs',
    '/api/submit','/api/cancel','/api/metadata-action','/api/rule-action',
    '/api/ownership-action','/api/planning-action','/api/planning-policy',
    '/api/source-action','/api/source-load','/api/export','/api/aggregate',
    '/api/python-program','/api/python-environment','/api/python-schedule',
    '/api/execution-delegation','/api/python-build','/api/python-run',
    '/api/security','/api/application-schedule','/api/application-assignment',
    '/api/application-workflow','/api/application-decision',
    '/api/application-workflow-occurrence',
    '/api/workspace-application','/api/application-purge'))
_AGGREGATE_CONTROLS=frozenset((
    'facts.cube.aggregate.request','facts.cube.aggregate.cancel'))
_PYTHON_PROGRAM_READS=frozenset((
    'python.program.read','python.program.list'))
_PYTHON_PROGRAM_WRITES=frozenset((
    'python.program.save','python.program.activate','python.program.deactivate',
    'python.program.delete'))
_PYTHON_ENVIRONMENT_READS=frozenset((
    'python.environment.read','python.environment.list',
    'python.environment.profile.list'))
_PYTHON_ENVIRONMENT_WRITES=frozenset(('python.environment.register',))
_PYTHON_SCHEDULE_READS=frozenset((
    'python.schedule.read','python.schedule.list',
    'python.schedule.occurrence.read'))
_PYTHON_SCHEDULE_WRITES=frozenset((
    'python.schedule.save','python.schedule.activate',
    'python.schedule.deactivate','python.schedule.run',
    'python.schedule.occurrence.cancel'))
_SECURITY_READS=frozenset((
    _SECURITY_ACCESS_LIST,_SECURITY_SUBJECT_LIST,
    _SECURITY_AUDIT_LIST,_SECURITY_RECEIPT_READ,
    _SECURITY_DIMENSION_READ,_SECURITY_DIMENSION_TAGS,
    _SECURITY_MEMBER_TAGS,_SECURITY_POLICY_READ,
    _SECURITY_DIMENSION_METADATA_TAGS,_SECURITY_RELATIONSHIP_TAGS,
    ))
_SECURITY_WRITES=frozenset((
    _SECURITY_ACCESS_SET,_SECURITY_DIMENSION_SET,_SECURITY_RULE_SET,
    _SECURITY_POLICY_SAVE,_SECURITY_POLICY_ACTIVATE,
    _SECURITY_POLICY_DEACTIVATE))
_EXECUTION_DELEGATION_READS=frozenset((
    'execution.delegation.read','execution.delegation.list'))
_EXECUTION_DELEGATION_WRITES=frozenset((
    'execution.delegation.create','execution.delegation.revoke'))
_APPLICATION_SCHEDULE_READS=frozenset((
    'schedule.read','schedule.list'))
_APPLICATION_SCHEDULE_WRITES=frozenset((
    'schedule.save','schedule.activate','schedule.deactivate'))
_APPLICATION_ASSIGNMENT_READS=frozenset((
    'application.assignment.read','application.assignment.list'))
_APPLICATION_ASSIGNMENT_WRITES=frozenset((
    'application.assignment.save','application.assignment.activate',
    'application.assignment.deactivate'))
_APPLICATION_WORKFLOW_READS=frozenset((
    'application.workflow.read','application.workflow.list'))
_APPLICATION_WORKFLOW_WRITES=frozenset((
    'application.workflow.save','application.workflow.activate',
    'application.workflow.deactivate'))


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if (not parsed.scheme or not parsed.netloc or parsed.path
            or parsed.query or parsed.fragment or parsed.username
            or parsed.password or parsed.scheme not in ('http','https')
            or (parsed.scheme == 'http' and parsed.hostname not in
                ('127.0.0.1','localhost','::1'))):
        raise ValueError('EPM_PUBLIC_WEB_ORIGIN must be an HTTPS origin or loopback HTTP')
    return value.rstrip('/')


def _scope(value: object) -> ApplicationScope:
    if (not isinstance(value,dict)
            or not isinstance(value.get('workspaceId'),str)
            or not 1<=len(value['workspaceId'])<=200
            or not isinstance(value.get('applicationId'),str)
            or not 1<=len(value['applicationId'])<=200):
        raise ValueError('WORKSPACE_AND_APPLICATION_REQUIRED')
    return ApplicationScope(value['workspaceId'],value['applicationId'])


class PostgresWebApp:
    def __init__(self,router: PostgresMCPRouter,*,public_origin: str,
                 lifecycle_dsn: str | None = None):
        self.router=router
        self.public_origin=_origin(public_origin)
        self.lifecycle_dsn=lifecycle_dsn or None

    def _assert_current_browser_session(self, principal) -> None:
        """Fence cached gateway tokens against the current native directory."""
        identity = VerifiedIdentity(
            principal.issuer, principal.subject, principal.groups,
            issued_at=principal.issued_at)
        with connect_postgres(self.router.access_dsn,
                              row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                PostgresAccessChecker.current_groups_in_transaction(db, identity)

    @staticmethod
    async def _send(send,status: int,payload: bytes,content_type: bytes,
                    *,html: bool=False,
                    cache_control: bytes=b'no-store') -> None:
        headers=[(b'content-type',content_type),
                 (b'cache-control',cache_control),
                 (b'x-content-type-options',b'nosniff'),
                 (b'referrer-policy',b'no-referrer'),
                 (b'cross-origin-resource-policy',b'same-origin'),
                 (b'permissions-policy',
                  b'camera=(), microphone=(), geolocation=(), payment=(), usb=()')]
        if status==503:
            headers.append((b'retry-after',b'1'))
        if html:
            headers.append((b'content-security-policy',
                b"default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                b"connect-src 'self'; worker-src 'self'; font-src 'self'; "
                b"img-src 'self' data:; "
                b"frame-src 'self'; frame-ancestors 'self'; "
                b"base-uri 'none'; form-action 'self'"))
        await send({'type':'http.response.start','status':status,
                    'headers':headers})
        await send({'type':'http.response.body','body':payload})

    @classmethod
    async def _json(cls,send,status: int,value: object) -> None:
        await cls._send(send,status,json.dumps(value,ensure_ascii=False,
            separators=(',',':'),allow_nan=False).encode(),
            b'application/json; charset=utf-8')

    @staticmethod
    async def _body(receive,max_bytes: int=MAX_BODY) -> dict:
        data=bytearray()
        while True:
            message=await receive()
            if message['type']!='http.request':
                raise ValueError('REQUEST_INTERRUPTED')
            data.extend(message.get('body',b''))
            if len(data)>max_bytes:
                raise ValueError('REQUEST_TOO_LARGE')
            if not message.get('more_body',False):
                break
        try:
            result=json.loads(data)
        except (UnicodeError,json.JSONDecodeError) as error:
            raise ValueError('JSON_BODY_REQUIRED') from error
        if not isinstance(result,dict):
            raise ValueError('JSON_OBJECT_REQUIRED')
        return result

    def _dispatch(self,path: str,query: bytes,body: dict | None,
                  identity: VerifiedIdentity) -> object:
        if path=='/api/applications':
            try:
                params=parse_qs(query.decode('ascii'),strict_parsing=True)
            except (UnicodeDecodeError,ValueError) as error:
                raise ValueError('APPLICATION_LIST_ARGUMENTS_INVALID') from error
            if set(params)-{'afterWorkspaceId','afterApplicationId','limit'}:
                raise ValueError('APPLICATION_LIST_ARGUMENTS_INVALID')
            if any(len(values)!=1 for values in params.values()):
                raise ValueError('APPLICATION_LIST_ARGUMENTS_INVALID')
            after=None
            if 'afterWorkspaceId' in params or 'afterApplicationId' in params:
                if not {'afterWorkspaceId','afterApplicationId'}<=set(params):
                    raise ValueError('APPLICATION_LIST_CURSOR_INVALID')
                after={'workspaceId':params['afterWorkspaceId'][0],
                       'applicationId':params['afterApplicationId'][0]}
            try:
                limit=int(params.get('limit',['100'])[0])
            except ValueError as error:
                raise ValueError('APPLICATION_LIST_LIMIT_INVALID') from error
            return self.router.list_applications_for_identity(
                identity,after=after,limit=limit)
        if body is None:
            raise ValueError('JSON_BODY_REQUIRED')
        program=body.get('program')
        if isinstance(program,dict) and isinstance(program.get('function'),str):
            function=program.get('function')
            try:
                contract=admit_operation(program,
                    scope=('workspace' if path in ('/api/workspace-application','/api/application-purge')
                           else 'application'))
            except ValueError as error:
                # Route-specific confirmation/allow-list errors remain the
                # stable response for retired or invented functions. Every
                # function an active route can accept is separately proved to
                # be registered, so an unregistered value cannot dispatch.
                if not str(error).startswith(
                        'PROCESSING_OPERATION_NOT_REGISTERED:'):
                    raise
            else:
                expected_boundary=(
                    'workspace_lifecycle_adapter'
                    if path in ('/api/workspace-application','/api/application-purge') else
                    'application_security_adapter'
                    if (path=='/api/security' or path=='/api/operation-admission'
                        and function in PostgresSecurityLanguage.catalog()['functions']) else
                    'fixed_python_application_language')
                if contract['handlerBoundary']!=expected_boundary:
                    raise ValueError('PROCESSING_OPERATION_HANDLER_MISMATCH:'+
                                     function)
        if path=='/api/application-purge':
            from epm_core.postgres_application_purge import PostgresApplicationPurge
            if set(body)!={'workspaceId','program','idempotencyKey'}:
                raise ValueError('APPLICATION_PURGE_REQUEST_INVALID')
            if not self.lifecycle_dsn:
                raise ValueError('POSTGRES_LIFECYCLE_SERVICE_NOT_CONFIGURED')
            return PostgresApplicationPurge(self.lifecycle_dsn,identity=identity).execute(
                body['workspaceId'],body['program'],idempotency_key=body['idempotencyKey'])
        if path=='/api/workspace-application':
            if (set(body)!={'workspaceId','program','idempotencyKey','confirmed'}
                    or body.get('confirmed') is not True):
                raise ValueError('CONFIRMATION_REQUIRED')
            if not self.lifecycle_dsn:
                raise ValueError('POSTGRES_LIFECYCLE_SERVICE_NOT_CONFIGURED')
            program=body.get('program')
            if (not isinstance(program,dict)
                    or program.get('languageVersion')!=2
                    or program.get('function')!=_WORKSPACE_APPLICATION_CREATE):
                raise ValueError('WORKSPACE_APPLICATION_FUNCTION_NOT_ALLOWED')
            return PostgresWorkspaceLifecycle(
                self.lifecycle_dsn,identity=identity).create(
                    body.get('workspaceId'),program,
                    idempotency_key=body.get('idempotencyKey'))
        scope=_scope(body)
        if path=='/api/operation-admission':
            if set(body)!={'workspaceId','applicationId','program'}:
                raise ValueError('OPERATION_ADMISSION_REQUEST_INVALID')
            assert_public_program_admitted(body['program'])
            function=body['program']['function']
            specification=PostgresLanguageV2.catalog()['functions'].get(function)
            if specification is None:
                specification=(PostgresSecurityLanguage.catalog()
                               ['functions'].get(function))
            if (not isinstance(specification,dict)
                    or specification.get('idempotencyRequired') is not True):
                raise ValueError('OPERATION_ADMISSION_PROGRAM_INVALID')
            with connect_postgres(self.router.runtime_dsn,row_factory=dict_row) as db:
                with db.transaction():
                    PostgresNumericFactStore._set_scope(db,scope)
                    PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                    PostgresAccessChecker.check_in_transaction(
                        db,identity,scope,specification['permission'],
                        function=function,arguments=body['program']['arguments'])
            admission=issue_operation_admission(
                self.router.preview_secret,scope,identity,function=function,
                intent_digest=_canonical_digest(body['program']))
            return {'operationId':admission.operation_id,
                    'expiresAt':admission.expires_at,
                    'intentDigest':admission.intent_digest}
        if path=='/api/catalog':
            if set(body)!={'workspaceId','applicationId'}:
                raise ValueError('CATALOG_ARGUMENTS_INVALID')
            with connect_postgres(self.router.runtime_dsn,row_factory=dict_row) as db:
                with db.transaction():
                    PostgresNumericFactStore._set_scope(db,scope)
                    checker=PostgresAccessChecker.check_in_transaction
                    checker(db,identity,scope,'read')
                    allowed={'read'}
                    for permission in ('write','admin','workspace_admin',
                                       'rule_design','rule_publish','rule_run'):
                        if permission.startswith('rule_') and 'write' not in allowed:
                            continue
                        try:
                            checker(db,identity,scope,permission)
                            allowed.add(permission)
                        except AccessDenied:
                            pass
                    state=capability_state(db,scope)
                    if state is None:
                        raise AccessDenied('APPLICATION_UNAVAILABLE')
                    enabled=state['enabled_capabilities']
                    revision=state['capability_revision']
            catalog=filter_catalog(PostgresLanguageV2.catalog(),enabled)
            if self.router.security_dsn:
                catalog['functions'].update(
                    PostgresSecurityLanguage.catalog()['functions'])
            functions={name:spec for name,spec in catalog['functions'].items()
                       if spec['permission'] in allowed}
            contracts=operation_contracts(functions,scope='application')
            return {'languageVersion':2,
                    'registryFormat':FUNCTION_REGISTRY_FORMAT,
                    'registryDigest':function_registry_digest(functions),
                    'processingRegistryFormat':PROCESSING_REGISTRY_FORMAT,
                    'operationContracts':contracts,
                    'processingPolicy':processing_policy(),
                    'listener':{'scope':'application',
                                'workspaceId':scope.workspace_id,
                                'applicationId':scope.application_id},
                    'enabledCapabilities':sorted(enabled),
                    'capabilityRevision':revision,
                    'applicationAccess':{
                        'role':('Administrator' if 'admin' in allowed else
                                'Editor' if 'write' in allowed else 'Reader'),
                        'workspaceAdministrator':'workspace_admin' in allowed,
                        'issuer':identity.issuer,
                        'subjectId':identity.subject_id},
                    'revisions':{
                        'metadata':state['metadata_revision'],
                        'data':state['data_revision'],
                        'policy':state['policy_revision'],
                        'commit':state['commit_revision'],
                        'capability':state['capability_revision'],
                        'security':state['security_revision'],
                        'schemaEpoch':state['schema_epoch']},
                    'functions':functions}
        if path=='/api/capacity-metrics':
            if set(body)!={'workspaceId','applicationId'}:
                raise ValueError('CAPACITY_METRICS_ARGUMENTS_INVALID')
            return PostgresCapacityMetrics(self.router.runtime_dsn).read(
                identity,scope)
        if path=='/api/read':
            if set(body)!={'workspaceId','applicationId','program'}:
                raise ValueError('READ_ARGUMENTS_INVALID')
            assert_public_program_admitted(body['program'])
            return PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,
                preview_secret=self.router.preview_secret).execute_read(
                    scope,body['program'])
        if path=='/api/preview':
            if set(body)!={'workspaceId','applicationId','program'}:
                raise ValueError('PREVIEW_ARGUMENTS_INVALID')
            assert_public_program_admitted(body['program'])
            specification=PostgresLanguageV2.catalog()['functions'].get(
                body['program']['function'])
            if specification is None or specification['previewRequired'] is not True:
                raise ValueError('PREVIEW_NOT_REQUIRED')
            return PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,
                preview_secret=self.router.preview_secret).preview(
                    scope,body['program'])
        if path=='/api/submit':
            expected={'workspaceId','applicationId','program','idempotencyKey',
                      'dependsOnJobIds','previewToken','confirmed'}
            if (set(body)!=expected or body['confirmed'] is not True
                    or not isinstance(body['program'],dict)
                    or not isinstance(body['idempotencyKey'],str)
                    or not isinstance(body['previewToken'],str)
                    or not body['previewToken']
                    or not isinstance(body['dependsOnJobIds'],list)
                    or any(not isinstance(value,str)
                           for value in body['dependsOnJobIds'])):
                raise ValueError('JOB_SUBMISSION_CONFIRMATION_REQUIRED')
            assert_public_program_admitted(body['program'])
            if not is_signed_operation_id(body['idempotencyKey']):
                raise ValueError('OPERATION_ADMISSION_REQUIRED')
            language=PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,preview_secret=self.router.preview_secret)
            language._validate_signed_operation_id(
                scope,body['program'],body['idempotencyKey'])
            replay=language.replay_batch(scope,body['program'],
                idempotency_key=body['idempotencyKey'],
                depends_on_job_ids=tuple(body['dependsOnJobIds']))
            if (replay is None and body['program'].get('function') in
                    ('facts.planning.spread.equal',
                     'facts.planning.spread.calendar')):
                replay=language.replay_spread(scope,body['program'],
                    idempotency_key=body['idempotencyKey'],
                    depends_on_job_ids=tuple(body['dependsOnJobIds']))
            if replay is not None:
                return replay
            return language.submit(scope,body['program'],
                preview_token=body['previewToken'],
                idempotency_key=body['idempotencyKey'],
                depends_on_job_ids=tuple(body['dependsOnJobIds']))
        if path=='/api/metadata-action':
            expected={'workspaceId','applicationId','program',
                      'idempotencyKey','confirmed'}
            if (set(body)!=expected or body['confirmed'] is not True
                    or not isinstance(body['program'],dict)
                    or body['program'].get('function') not in _METADATA_ACTIONS
                    or not isinstance(body['idempotencyKey'],str)):
                raise ValueError('METADATA_ACTION_CONFIRMATION_REQUIRED')
            if not is_signed_operation_id(body['idempotencyKey']):
                raise ValueError('OPERATION_ADMISSION_REQUIRED')
            language=PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,
                preview_secret=self.router.preview_secret)
            language._validate_signed_operation_id(
                scope,body['program'],body['idempotencyKey'])
            return language.execute_metadata(scope,body['program'],
                idempotency_key=body['idempotencyKey'])
        if path=='/api/application-decision':
            from epm_core.postgres_application_decisions import WRITES
            if (set(body)!={'workspaceId','applicationId','program','idempotencyKey'}
                    or not isinstance(body['program'],dict)
                    or body['program'].get('function') not in WRITES
                    or not isinstance(body['idempotencyKey'],str)):
                raise ValueError('APPLICATION_DECISION_REQUEST_INVALID')
            if not is_signed_operation_id(body['idempotencyKey']):
                raise ValueError('OPERATION_ADMISSION_REQUIRED')
            language=PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,
                preview_secret=self.router.preview_secret)
            language._validate_signed_operation_id(
                scope,body['program'],body['idempotencyKey'])
            return language.execute_application_decision(
                scope,body['program'],idempotency_key=body['idempotencyKey'])
        if path=='/api/rule-action':
            expected={'workspaceId','applicationId','program',
                      'idempotencyKey','confirmed'}
            if (set(body)!=expected or body['confirmed'] is not True
                    or not isinstance(body['program'],dict)
                    or body['program'].get('function') not in _RULE_ACTIONS
                    or not isinstance(body['idempotencyKey'],str)):
                raise ValueError('RULE_ACTION_CONFIRMATION_REQUIRED')
            if not is_signed_operation_id(body['idempotencyKey']):
                raise ValueError('OPERATION_ADMISSION_REQUIRED')
            language=PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,
                preview_secret=self.router.preview_secret)
            language._validate_signed_operation_id(
                scope,body['program'],body['idempotencyKey'])
            return language.execute_expression_rule(scope,body['program'],
                idempotency_key=body['idempotencyKey'])
        if path=='/api/ownership-action':
            expected={'workspaceId','applicationId','program',
                      'idempotencyKey','confirmed'}
            if (set(body)!=expected or body['confirmed'] is not True
                    or not isinstance(body['program'],dict)
                    or body['program'].get('function') not in _OWNERSHIP_ACTIONS
                    or not isinstance(body['idempotencyKey'],str)):
                raise ValueError('OWNERSHIP_ACTION_CONFIRMATION_REQUIRED')
            if not is_signed_operation_id(body['idempotencyKey']):
                raise ValueError('OPERATION_ADMISSION_REQUIRED')
            language=PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,
                preview_secret=self.router.preview_secret)
            language._validate_signed_operation_id(
                scope,body['program'],body['idempotencyKey'])
            return language.execute_ownership(scope,body['program'],
                idempotency_key=body['idempotencyKey'])
        if path=='/api/planning-action':
            if (set(body)!={'workspaceId','applicationId','program',
                            'previewToken','idempotencyKey','confirmed'}
                    or body['confirmed'] is not True
                    or not isinstance(body['program'],dict)
                    or not isinstance(body['previewToken'],str)
                    or not body['previewToken']
                    or not isinstance(body['idempotencyKey'],str)
                    or body['program'].get('function') not in _PLANNING_ACTIONS):
                raise ValueError('PLANNING_ACTION_CONFIRMATION_REQUIRED')
            language=PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,preview_secret=self.router.preview_secret)
            assert_public_program_admitted(body['program'])
            if not is_signed_operation_id(body['idempotencyKey']):
                raise ValueError('OPERATION_ADMISSION_REQUIRED')
            language._validate_signed_operation_id(
                scope,body['program'],body['idempotencyKey'])
            replay=language.replay_planning_lock(
                scope,body['program'],idempotency_key=body['idempotencyKey'])
            if replay is not None:
                return replay
            return language.apply_planning_lock(
                scope,body['program'],preview_token=body['previewToken'],
                idempotency_key=body['idempotencyKey'])
        if path=='/api/planning-policy':
            if (set(body)!={'workspaceId','applicationId','program',
                            'idempotencyKey','confirmed'}
                    or body['confirmed'] is not True
                    or not isinstance(body['program'],dict)
                    or body['program'].get('function') not in
                    _PLANNING_POLICY_ACTIONS):
                raise ValueError('PLANNING_POLICY_CONFIRMATION_REQUIRED')
            function=body['program']['function'];key=body['idempotencyKey']
            if not isinstance(key,str) or not key:
                raise ValueError('PLANNING_POLICY_CONFIRMATION_REQUIRED')
            if not is_signed_operation_id(key):
                raise ValueError('OPERATION_ADMISSION_REQUIRED')
            language=PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,
                preview_secret=self.router.preview_secret)
            language._validate_signed_operation_id(scope,body['program'],key)
            return language.execute_planning_workflow_policy(
                scope,body['program'],idempotency_key=key)
        if path=='/api/source-action':
            if (not isinstance(body.get('program'),dict)
                    or body['program'].get('function') not in _SOURCE_ACTIONS):
                raise ValueError('SOURCE_ACTION_CONFIRMATION_REQUIRED')
            function=body['program']['function']
            expected={'workspaceId','applicationId','program','confirmed'}
            if function!='facts.source.preview':
                expected.add('idempotencyKey')
            if (set(body)!=expected or body['confirmed'] is not True
                    or not isinstance(body['program'],dict)
                    or body['program'].get('function') not in _SOURCE_ACTIONS):
                raise ValueError('SOURCE_ACTION_CONFIRMATION_REQUIRED')
            language=PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,
                preview_secret=self.router.preview_secret)
            program=body['program']
            if function!='facts.source.preview':
                program=_admitted_browser_program(
                    language,scope,program,body['idempotencyKey'])
            return language.execute_source(scope,program)
        if path=='/api/source-load':
            if not isinstance(body.get('program'),dict):
                raise ValueError('SOURCE_LOAD_ACTION_INVALID')
            function=body['program'].get('function')
            if function in (_SOURCE_LOAD_SOURCE_READS|
                            _SOURCE_LOAD_ARTIFACT_READS):
                if set(body)!={'workspaceId','applicationId','program'}:
                    raise ValueError('SOURCE_LOAD_ACTION_INVALID')
            elif function in _SOURCE_LOAD_WRITES:
                if (set(body)!={'workspaceId','applicationId','program','confirmed',
                                'idempotencyKey'}
                        or body['confirmed'] is not True):
                    raise ValueError('SOURCE_LOAD_CONFIRMATION_REQUIRED')
            else:
                raise ValueError('SOURCE_LOAD_ACTION_INVALID')
            language=PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,preview_secret=self.router.preview_secret)
            program=body['program']
            if function in _SOURCE_LOAD_WRITES:
                program=_admitted_browser_program(
                    language,scope,program,body['idempotencyKey'])
            return (language.execute_read(scope,body['program'])
                    if function in _SOURCE_LOAD_ARTIFACT_READS else
                    language.execute_source(scope,program))
        if path=='/api/export':
            if not isinstance(body.get('program'),dict):
                raise ValueError('EXPORT_ACTION_INVALID')
            function=body['program'].get('function')
            if function in (_EXPORT_ORCHESTRATION_READS|
                            _EXPORT_ARTIFACT_READS):
                if set(body)!={'workspaceId','applicationId','program'}:
                    raise ValueError('EXPORT_ACTION_INVALID')
                execute=('read' if function in _EXPORT_ARTIFACT_READS
                         else 'source')
            elif function in _EXPORT_WRITES:
                if (set(body)!={'workspaceId','applicationId','program','confirmed',
                                'idempotencyKey'}
                        or body['confirmed'] is not True):
                    raise ValueError('EXPORT_CONFIRMATION_REQUIRED')
                execute='source'
            else:
                raise ValueError('EXPORT_ACTION_INVALID')
            language=PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,preview_secret=self.router.preview_secret)
            program=body['program']
            if function in _EXPORT_WRITES:
                program=_admitted_browser_program(
                    language,scope,program,body['idempotencyKey'])
            return (language.execute_read(scope,body['program'])
                    if execute=='read' else
                    language.execute_source(scope,program))
        if path=='/api/aggregate':
            if not isinstance(body.get('program'),dict):
                raise ValueError('AGGREGATE_ACTION_INVALID')
            function=body['program'].get('function')
            if function in _AGGREGATE_READS:
                if set(body)!={'workspaceId','applicationId','program'}:
                    raise ValueError('AGGREGATE_ACTION_INVALID')
            elif function in _AGGREGATE_CONTROLS:
                if (set(body)!={'workspaceId','applicationId','program','confirmed'}
                        or body['confirmed'] is not True):
                    raise ValueError('AGGREGATE_CONFIRMATION_REQUIRED')
            else:
                raise ValueError('AGGREGATE_ACTION_INVALID')
            return PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,
                preview_secret=self.router.preview_secret).execute_read(
                    scope,body['program'])
        if path=='/api/python-program':
            if not isinstance(body.get('program'),dict):
                raise ValueError('PYTHON_PROGRAM_ACTION_INVALID')
            function=body['program'].get('function')
            language=PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,preview_secret=self.router.preview_secret)
            if function in _PYTHON_PROGRAM_READS:
                if set(body)!={'workspaceId','applicationId','program'}:
                    raise ValueError('PYTHON_PROGRAM_ACTION_INVALID')
                return language.execute_read(scope,body['program'])
            if function in _PYTHON_PROGRAM_WRITES:
                if (set(body)!={'workspaceId','applicationId','program',
                                'idempotencyKey','confirmed'}
                        or body['confirmed'] is not True
                        or not isinstance(body['idempotencyKey'],str)
                        or not body['idempotencyKey']):
                    raise ValueError('PYTHON_PROGRAM_CONFIRMATION_REQUIRED')
                if not is_signed_operation_id(body['idempotencyKey']):
                    raise ValueError('OPERATION_ADMISSION_REQUIRED')
                language._validate_signed_operation_id(
                    scope,body['program'],body['idempotencyKey'])
                return language.execute_python_program(scope,body['program'],
                    idempotency_key=body['idempotencyKey'])
            raise ValueError('PYTHON_PROGRAM_ACTION_INVALID')
        if path=='/api/security':
            if not self.router.security_dsn:
                raise ValueError('POSTGRES_SECURITY_SERVICE_NOT_CONFIGURED')
            if not isinstance(body.get('program'),dict):
                raise ValueError('SECURITY_ACTION_INVALID')
            function=body['program'].get('function')
            security=PostgresSecurityLanguage(
                self.router.security_dsn,identity=identity)
            if function in _SECURITY_READS:
                if set(body)!={'workspaceId','applicationId','program'}:
                    raise ValueError('SECURITY_ACTION_INVALID')
                if function==_SECURITY_ACCESS_LIST:
                    return security.list_application_access(scope,body['program'])
                if function==_SECURITY_SUBJECT_LIST:
                    return security.list_application_subjects(
                        scope,body['program'])
                if function==_SECURITY_AUDIT_LIST:
                    return security.list_application_audit(scope,body['program'])
                if function==_SECURITY_RECEIPT_READ:
                    return security.read_application_receipt(
                        scope,body['program'])
                if function==_SECURITY_DIMENSION_TAGS:
                    return security.read_dimension_tags(scope,body['program'])
                if function==_SECURITY_MEMBER_TAGS:
                    return security.read_member_tags(scope,body['program'])
                if function==_SECURITY_DIMENSION_METADATA_TAGS:
                    return security.read_dimension_metadata_tags(
                        scope,body['program'])
                if function==_SECURITY_RELATIONSHIP_TAGS:
                    return security.read_relationship_tags(
                        scope,body['program'])
                if function == _SECURITY_POLICY_READ:
                    return security.read_dimension_policy(
                        scope,body['program'])
                return security.read_dimension_access(scope,body['program'])
            if function in _SECURITY_WRITES:
                if (set(body)!={'workspaceId','applicationId','program',
                                'idempotencyKey','confirmed'}
                        or body['confirmed'] is not True
                        or not isinstance(body['idempotencyKey'],str)
                        or not body['idempotencyKey']):
                    raise ValueError('SECURITY_CONFIRMATION_REQUIRED')
                _validate_browser_operation(
                    self.router.preview_secret,scope,identity,
                    body['program'],body['idempotencyKey'])
                if function==_SECURITY_RULE_SET:
                    return security.execute_rule(scope,body['program'],
                        idempotency_key=body['idempotencyKey'])
                return security.execute(scope,body['program'],
                    idempotency_key=body['idempotencyKey'])
            raise ValueError('SECURITY_ACTION_INVALID')
        if path=='/api/python-environment':
            if not isinstance(body.get('program'),dict):
                raise ValueError('PYTHON_ENVIRONMENT_ACTION_INVALID')
            function=body['program'].get('function')
            language=PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,preview_secret=self.router.preview_secret,
                approved_python_profiles=self.router.approved_python_profiles)
            if function in _PYTHON_ENVIRONMENT_READS:
                if set(body)!={'workspaceId','applicationId','program'}:
                    raise ValueError('PYTHON_ENVIRONMENT_ACTION_INVALID')
                return language.execute_read(scope,body['program'])
            if function in _PYTHON_ENVIRONMENT_WRITES:
                if (set(body)!={'workspaceId','applicationId','program',
                                'idempotencyKey','confirmed'}
                        or body['confirmed'] is not True
                        or not isinstance(body['idempotencyKey'],str)
                        or not body['idempotencyKey']):
                    raise ValueError('PYTHON_ENVIRONMENT_CONFIRMATION_REQUIRED')
                if not is_signed_operation_id(body['idempotencyKey']):
                    raise ValueError('OPERATION_ADMISSION_REQUIRED')
                language._validate_signed_operation_id(
                    scope,body['program'],body['idempotencyKey'])
                return language.execute_python_program(scope,body['program'],
                    idempotency_key=body['idempotencyKey'])
            raise ValueError('PYTHON_ENVIRONMENT_ACTION_INVALID')
        if path=='/api/python-schedule':
            if not isinstance(body.get('program'),dict):
                raise ValueError('PYTHON_SCHEDULE_ACTION_INVALID')
            function=body['program'].get('function')
            language=PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,preview_secret=self.router.preview_secret)
            if function in _PYTHON_SCHEDULE_READS:
                if set(body)!={'workspaceId','applicationId','program'}:
                    raise ValueError('PYTHON_SCHEDULE_ACTION_INVALID')
                return language.execute_read(scope,body['program'])
            if function in _PYTHON_SCHEDULE_WRITES:
                if (set(body)!={'workspaceId','applicationId','program',
                                'idempotencyKey','confirmed'}
                        or body['confirmed'] is not True
                        or not isinstance(body['idempotencyKey'],str)
                        or not body['idempotencyKey']):
                    raise ValueError('PYTHON_SCHEDULE_CONFIRMATION_REQUIRED')
                if not is_signed_operation_id(body['idempotencyKey']):
                    raise ValueError('OPERATION_ADMISSION_REQUIRED')
                language._validate_signed_operation_id(
                    scope,body['program'],body['idempotencyKey'])
                return language.execute_python_program(scope,body['program'],
                    idempotency_key=body['idempotencyKey'])
            raise ValueError('PYTHON_SCHEDULE_ACTION_INVALID')
        if path=='/api/execution-delegation':
            if not isinstance(body.get('program'),dict):
                raise ValueError('EXECUTION_DELEGATION_ACTION_INVALID')
            function=body['program'].get('function')
            language=PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,preview_secret=self.router.preview_secret)
            if function in _EXECUTION_DELEGATION_READS:
                if set(body)!={'workspaceId','applicationId','program'}:
                    raise ValueError('EXECUTION_DELEGATION_ACTION_INVALID')
                return language.execute_read(scope,body['program'])
            if function in _EXECUTION_DELEGATION_WRITES:
                if (set(body)!={'workspaceId','applicationId','program',
                                'idempotencyKey','confirmed'}
                        or body['confirmed'] is not True
                        or not isinstance(body['idempotencyKey'],str)
                        or not body['idempotencyKey']):
                    raise ValueError('EXECUTION_DELEGATION_CONFIRMATION_REQUIRED')
                if not is_signed_operation_id(body['idempotencyKey']):
                    raise ValueError('OPERATION_ADMISSION_REQUIRED')
                language._validate_signed_operation_id(
                    scope,body['program'],body['idempotencyKey'])
                return language.execute_execution_delegation(
                    scope,body['program'],idempotency_key=body['idempotencyKey'])
            raise ValueError('EXECUTION_DELEGATION_ACTION_INVALID')
        if path=='/api/python-build':
            language=PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,preview_secret=self.router.preview_secret)
            action=body.get('action')
            if action=='request':
                if (set(body)!={'workspaceId','applicationId','action','program',
                                'idempotencyKey','confirmed'}
                        or body['confirmed'] is not True
                        or not isinstance(body['program'],dict)
                        or body['program'].get('function') not in ('python.program.build','python.program.test')
                        or not isinstance(body['idempotencyKey'],str)
                        or not body['idempotencyKey']):
                    raise ValueError('PYTHON_BUILD_CONFIRMATION_REQUIRED')
                if not is_signed_operation_id(body['idempotencyKey']):
                    raise ValueError('OPERATION_ADMISSION_REQUIRED')
                language._validate_signed_operation_id(
                    scope,body['program'],body['idempotencyKey'])
                return language.execute_python_build(scope,body['program'],
                    idempotency_key=body['idempotencyKey'])
            if action=='read':
                if set(body)!={'workspaceId','applicationId','action','buildId'}:
                    raise ValueError('PYTHON_BUILD_ACTION_INVALID')
                return {'result':language.read_python_build(scope,body['buildId'])}
            if action=='artifact':
                if set(body)!={'workspaceId','applicationId','action','buildId',
                               'section','cursor'}:
                    raise ValueError('PYTHON_BUILD_ACTION_INVALID')
                return {'result':language.read_python_build_artifact(scope,
                    build_id=body['buildId'],section=body['section'],
                    cursor=body['cursor'])}
            if action=='cancel':
                if (set(body)!={'workspaceId','applicationId','action','buildId',
                                'confirmed'} or body['confirmed'] is not True):
                    raise ValueError('PYTHON_BUILD_CONFIRMATION_REQUIRED')
                return {'result':language.cancel_python_build(
                    scope,body['buildId'])}
            raise ValueError('PYTHON_BUILD_ACTION_INVALID')
        if path=='/api/python-run':
            language=PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,preview_secret=self.router.preview_secret)
            action=body.get('action')
            if action=='request':
                if (set(body)!={'workspaceId','applicationId','action','program',
                                'idempotencyKey','confirmed'}
                        or body['confirmed'] is not True
                        or not isinstance(body['program'],dict)
                        or body['program'].get('function')!='python.program.run'
                        or not isinstance(body['idempotencyKey'],str)
                        or not body['idempotencyKey']):
                    raise ValueError('PYTHON_RUN_CONFIRMATION_REQUIRED')
                if not is_signed_operation_id(body['idempotencyKey']):
                    raise ValueError('OPERATION_ADMISSION_REQUIRED')
                language._validate_signed_operation_id(
                    scope,body['program'],body['idempotencyKey'])
                return language.execute_python_run(scope,body['program'],
                    idempotency_key=body['idempotencyKey'])
            if action=='read':
                if set(body)!={'workspaceId','applicationId','action','workflowId'}:
                    raise ValueError('PYTHON_RUN_ACTION_INVALID')
                return {'result':language.read_python_workflow(
                    scope,body['workflowId'])}
            if action=='cancel':
                if (set(body)!={'workspaceId','applicationId','action','workflowId',
                                'confirmed'} or body['confirmed'] is not True):
                    raise ValueError('PYTHON_RUN_CONFIRMATION_REQUIRED')
                return {'result':language.cancel_python_workflow(
                    scope,body['workflowId'])}
            raise ValueError('PYTHON_RUN_ACTION_INVALID')
        if path=='/api/application-schedule':
            if not isinstance(body.get('program'),dict):
                raise ValueError('APPLICATION_SCHEDULE_ACTION_INVALID')
            function=body['program'].get('function')
            if function in _APPLICATION_SCHEDULE_READS:
                if set(body)!={'workspaceId','applicationId','program'}:
                    raise ValueError('APPLICATION_SCHEDULE_ACTION_INVALID')
                key=None
            elif function in _APPLICATION_SCHEDULE_WRITES:
                if (set(body)!={'workspaceId','applicationId','program',
                                'idempotencyKey','confirmed'}
                        or body['confirmed'] is not True
                        or not isinstance(body['idempotencyKey'],str)
                        or not body['idempotencyKey']):
                    raise ValueError(
                        'APPLICATION_SCHEDULE_CONFIRMATION_REQUIRED')
                key=body['idempotencyKey']
            else:
                raise ValueError('APPLICATION_SCHEDULE_ACTION_INVALID')
            if key is not None and not is_signed_operation_id(key):
                raise ValueError('OPERATION_ADMISSION_REQUIRED')
            language=PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,
                preview_secret=self.router.preview_secret)
            if key is not None:
                language._validate_signed_operation_id(
                    scope,body['program'],key)
            return language.execute_application_schedule(
                scope,body['program'],idempotency_key=key)
        if path in ('/api/application-assignment','/api/application-workflow'):
            if not isinstance(body.get('program'),dict):
                raise ValueError('APPLICATION_GOVERNANCE_ACTION_INVALID')
            function=body['program'].get('function')
            reads=(_APPLICATION_ASSIGNMENT_READS if
                path=='/api/application-assignment' else
                _APPLICATION_WORKFLOW_READS)
            writes=(_APPLICATION_ASSIGNMENT_WRITES if
                path=='/api/application-assignment' else
                _APPLICATION_WORKFLOW_WRITES)
            if function in reads:
                if set(body)!={'workspaceId','applicationId','program'}:
                    raise ValueError('APPLICATION_GOVERNANCE_ACTION_INVALID')
                key=None
            elif function in writes:
                if (set(body)!={'workspaceId','applicationId','program',
                                'idempotencyKey','confirmed'}
                        or body['confirmed'] is not True
                        or not isinstance(body['idempotencyKey'],str)
                        or not body['idempotencyKey']):
                    raise ValueError(
                        'APPLICATION_GOVERNANCE_CONFIRMATION_REQUIRED')
                key=body['idempotencyKey']
            else:
                raise ValueError('APPLICATION_GOVERNANCE_ACTION_INVALID')
            language=PostgresLanguageV2(self.router.runtime_dsn,
                identity=identity,preview_secret=self.router.preview_secret)
            if key is not None:
                if not is_signed_operation_id(key):
                    raise ValueError('OPERATION_ADMISSION_REQUIRED')
                language._validate_signed_operation_id(
                    scope,body['program'],key)
            if path=='/api/application-assignment':
                return language.execute_application_assignment(
                    scope,body['program'],idempotency_key=key)
            return language.execute_application_workflow(
                scope,body['program'],idempotency_key=key)
        if path=='/api/application-workflow-occurrence':
            expected={'workspaceId','applicationId','program',
                      'idempotencyKey','confirmed'}
            if (set(body)!=expected or body['confirmed'] is not True
                    or not isinstance(body['program'],dict)
                    or body['program'].get('function') not in
                    _APPLICATION_WORKFLOW_OCCURRENCE_ACTIONS
                    or not isinstance(body['idempotencyKey'],str)
                    or not body['idempotencyKey']):
                raise ValueError(
                    'APPLICATION_WORKFLOW_CONFIRMATION_REQUIRED')
            if not is_signed_operation_id(body['idempotencyKey']):
                raise ValueError('OPERATION_ADMISSION_REQUIRED')
            language=PostgresLanguageV2(
                self.router.runtime_dsn,identity=identity,
                preview_secret=self.router.preview_secret)
            language._validate_signed_operation_id(
                scope,body['program'],body['idempotencyKey'])
            return language.execute_application_workflow_occurrence(
                scope,body['program'],
                idempotency_key=body['idempotencyKey'])
        tasks=PostgresTaskService(self.router.runtime_dsn,identity=identity)
        if path=='/api/tasks':
            if set(body)-{'workspaceId','applicationId','afterSequence','limit',
                          'attentionOnly'}:
                raise ValueError('TASK_LIST_ARGUMENTS_INVALID')
            return tasks.list(scope,
                after_sequence=body.get('afterSequence',0),
                limit=body.get('limit',100),
                attention_only=body.get('attentionOnly',False))
        if path=='/api/task':
            if set(body)-{'workspaceId','applicationId','taskId','afterEvent',
                          'eventLimit'} or 'taskId' not in body:
                raise ValueError('TASK_READ_ARGUMENTS_INVALID')
            return tasks.read(scope,body['taskId'],
                after_event=body.get('afterEvent',0),
                event_limit=body.get('eventLimit',100))
        if path=='/api/task-logs':
            if set(body)-{'workspaceId','applicationId','taskId','afterEvent',
                          'eventLimit','afterCharacter','characterLimit'} \
                    or 'taskId' not in body:
                raise ValueError('TASK_LOG_ARGUMENTS_INVALID')
            return tasks.logs(scope,body['taskId'],
                after_event=body.get('afterEvent',0),
                event_limit=body.get('eventLimit',100),
                after_character=body.get('afterCharacter',0),
                character_limit=body.get('characterLimit',16_384))
        queue=PostgresJobQueue(self.router.runtime_dsn,identity=identity)
        if path=='/api/events':
            if set(body)-{'workspaceId','applicationId','afterSequence','limit'}:
                raise ValueError('EVENT_ARGUMENTS_INVALID')
            return queue.events(scope,after_sequence=body.get('afterSequence',0),
                                limit=body.get('limit',100))
        if path in ('/api/job','/api/cancel'):
            expected={'workspaceId','applicationId','jobId'}
            if (set(body)!=(expected if path=='/api/job'
                            else expected|{'confirmed'})
                    or path=='/api/cancel'
                    and body.get('confirmed') is not True):
                raise ValueError('JOB_ARGUMENTS_INVALID')
            if path=='/api/job':
                return queue.read(scope,body['jobId'])
            return queue.request_cancel(scope,body['jobId'])
        raise ValueError('UNKNOWN_ROUTE')

    async def __call__(self,scope,receive,send):
        if scope['type']!='http':return
        headers={}
        for key,value in scope.get('headers',[]):
            headers.setdefault(key.decode('latin-1').lower(),[]).append(
                value.decode('latin-1'))
        path=scope.get('path','')
        observed_path='/ui/*' if isinstance(path,str) and path.startswith('/ui/') else path
        with observe_request(headers=headers,method=scope.get('method',''),
                path=observed_path,allowed_routes=_OBSERVABLE_ROUTES,
                logger=LOG,service='openepm-web') as observation:
            async def observed_send(message):
                if message.get('type')=='http.response.start':
                    observation.status=int(message.get('status',500))
                    message={**message,'headers':[
                        *message.get('headers',[]),
                        (b'x-correlation-id',
                         observation.correlation_id.encode('ascii'))]}
                await send(message)
            observed_scope={**scope,
                'openepm.correlation_id':observation.correlation_id}
            return await bounded_request(self._handle,observed_scope,receive,
                observed_send,seconds=HTTP_POST_SECONDS,
                response_seconds=TIMEOUT_RESPONSE_SECONDS)

    async def _handle(self,scope,receive,send):
        path=scope.get('path','')
        method=scope.get('method','')
        # The gateway owns interactive authentication.  Always deliver the
        # inert application shell and immutable presentation assets so an
        # expired/invalid upstream session can render the recovery journey.
        # Every data/API route below still requires a freshly verified token.
        if method=='GET' and path=='/':
            payload=(_ui_root()/'index.html').read_bytes()
            await self._send(send,200,payload,
                b'text/html; charset=utf-8',html=True)
            return
        if method=='GET' and path.startswith('/ui/'):
            relative=path[len('/ui/'):]
            app_root=_ui_root().resolve()
            candidate=(app_root/relative).resolve()
            if (not relative or not candidate.is_relative_to(app_root)
                    or not candidate.is_file()):
                await self._json(send,404,_error_payload(
                    scope,404,'UNKNOWN_ROUTE'))
                return
            content_type=(mimetypes.guess_type(candidate.name)[0]
                          or 'application/octet-stream')
            fingerprinted=bool(re.fullmatch(
                r'.+-[A-Za-z0-9_-]{8,}\.[A-Za-z0-9]+',candidate.name))
            await self._send(send,200,candidate.read_bytes(),
                f'{content_type}; charset=utf-8'.encode(),
                cache_control=(b'public, max-age=31536000, immutable'
                    if fingerprinted else b'no-store'))
            return
        headers={}
        for key,value in scope.get('headers',[]):
            headers.setdefault(key.decode('latin-1').lower(),[]).append(
                value.decode('latin-1'))
        header_name='authorization'
        tokens=headers.get(header_name,[])
        if len(tokens)!=1:
            await self._json(send,401,_error_payload(
                scope,401,'WEB_ACCESS_ASSERTION_REQUIRED'))
            return
        try:
            principal=await authenticate_http(WEB_MODULE,{header_name:tokens[0]})
        except AuthError as error:
            LOG.warning('Browser authentication rejected: code=%s correlationId=%s',
                        error.code,scope.get('openepm.correlation_id','0'*32))
            await self._json(send,error.status,_error_payload(
                scope,error.status,error.code))
            return
        if method=='GET' and path=='/api/runtime':
            await self._json(send,200,{'readOnlyReview':
                os.environ.get('EPM_UI_READ_ONLY_REVIEW')=='1',
                'build':_runtime_build_identity()})
            return
        if method=='GET' and path=='/api/session-identity':
            if scope.get('query_string',b''):
                await self._json(send,400,_error_payload(
                    scope,400,'SESSION_IDENTITY_ARGUMENTS_INVALID'))
                return
            try:
                self._assert_current_browser_session(principal)
            except AccessDenied as error:
                await self._json(send,401,_error_payload(
                    scope,401,str(error)))
                return
            await self._json(send,200,{
                'issuer':principal.issuer,
                'subject':principal.subject,
                'displayIdentity':principal.login_id,
                'loginIdSha256':principal.login_id_sha256,
                'audience':principal.audience,
                'applicationMcpEndpoint':_public_application_mcp_endpoint(
                    principal.issuer,principal.subject)})
            return
        if ((method=='GET' and path not in
                ('/api/applications','/api/runtime','/api/session-identity'))
                or (method=='POST' and path not in _BROWSER_POST_ROUTES)
                or method not in ('GET','POST')):
            await self._json(send,404,_error_payload(
                scope,404,'UNKNOWN_ROUTE'))
            return
        if method=='POST':
            if (headers.get('content-type',[''])[0].split(';')[0].strip()
                    != 'application/json'):
                await self._json(send,415,_error_payload(
                    scope,415,'JSON_CONTENT_TYPE_REQUIRED'))
                return
            if (path in _BROWSER_POST_ROUTES
                    and headers.get('origin',[])!=[self.public_origin]):
                await self._json(send,403,_error_payload(
                    scope,403,'WEB_ORIGIN_REQUIRED'))
                return
        try:
            body=(await self._body(receive,
                    MAX_SOURCE_LOAD_BODY if path=='/api/source-load' else
                    72*1024 if path=='/api/application-decision' else MAX_BODY)
                  if method=='POST' else None)
            configuration={'accessDsn':self.router.access_dsn,'runtimeDsn':self.router.runtime_dsn,
                'secretHex':self.router.preview_secret.hex(),'publicOrigin':self.public_origin,
                'securityDsn':self.router.security_dsn,
                'lifecycleDsn':self.lifecycle_dsn,
                'pythonProfiles':[{'profileId':item.profile_id,
                    'imageDigest':item.image_digest,'manifest':item.manifest}
                    for item in self.router.approved_python_profiles]}
            with verified_mcp_request(principal):
                result=await execute_web_request({'configuration':configuration,'path':path,
                    'query':scope.get('query_string',b'').decode('latin-1'),'body':body},
                    {name:values[0] for name,values in headers.items()
                     if name in ('authorization','origin') and len(values)==1})
            payload=result['payload']
            if (result['status'] >= 400 and isinstance(payload,dict)
                    and 'error' in payload):
                details = (validate_diagnostic_payload(payload['details'])
                    if payload['error'] == SourceValidationError.code
                    and 'details' in payload else None)
                payload=_error_payload(scope,result['status'],payload['error'],
                                       details=details)
            await self._json(send,result['status'],payload)
        except ToolError as error:
            LOG.warning('Fixed web child operation unavailable: %s',error)
            await self._json(send,503,_error_payload(
                scope,503,'WEB_OPERATION_OUTCOME_UNKNOWN'))
        except AccessDenied as error:
            await self._json(send,403,_error_payload(scope,403,str(error)))
        except ValueError as error:
            status,code=_value_error_response(error)
            await self._json(send,status,_error_payload(scope,status,code,
                details=error.diagnostics if isinstance(error,SourceValidationError) else None))
        except psycopg.Error:
            LOG.exception('PostgreSQL web operation failed')
            await self._json(send,503,_error_payload(
                scope,503,'POSTGRES_OPERATION_FAILED'))


def _optional_secret(direct_name: str, file_name: str) -> str | None:
    if os.environ.get(direct_name) or os.environ.get(file_name):
        return configured_text(os.environ, direct_name, file_name)
    return None


def build_app() -> PostgresWebApp:
    if mode() != 'oidc':
        raise RuntimeError('PostgreSQL web inspector requires verified JWTs')
    check_startup(WEB_MODULE)
    return PostgresWebApp(_configured_router(),
        public_origin=os.environ.get('EPM_PUBLIC_WEB_ORIGIN',''),
        lifecycle_dsn=_optional_secret('EPM_PG_LIFECYCLE_DSN',
                                       'EPM_PG_LIFECYCLE_DSN_FILE'))


def _configured_router():
    secret=configured_hex_bytes(os.environ,
        'EPM_PG_PREVIEW_SECRET_HEX','EPM_PG_PREVIEW_SECRET_FILE')
    return PostgresMCPRouter(
        configured_text(os.environ,'EPM_PG_ACCESS_DSN',
                        'EPM_PG_ACCESS_DSN_FILE'),
        configured_text(os.environ,'EPM_PG_RUNTIME_DSN',
                        'EPM_PG_RUNTIME_DSN_FILE'),
        preview_secret=secret,
        security_dsn=_optional_secret('EPM_PG_SECURITY_DSN',
                                      'EPM_PG_SECURITY_DSN_FILE'),
        approved_python_profiles=load_python_environment_profiles(os.environ))


def _startup_role_check():
    _configured_router().assert_runtime_roles()
    lifecycle_dsn=_optional_secret('EPM_PG_LIFECYCLE_DSN',
                                   'EPM_PG_LIFECYCLE_DSN_FILE')
    if lifecycle_dsn:
        assert_lifecycle_role(lifecycle_dsn)


def _web_request(arguments,headers):
    identity=None
    app=None
    body=arguments.get('body') if isinstance(arguments,dict) else None
    try:
        if set(arguments)!={'configuration','path','query','body'}:
            raise ValueError('WEB_OPERATION_INVALID')
        config=arguments['configuration']
        if set(config)!={'accessDsn','runtimeDsn','secretHex','publicOrigin',
                         'securityDsn','lifecycleDsn','pythonProfiles'}:
            raise ValueError('WEB_CONFIGURATION_INVALID')
        if (config['securityDsn'] is not None and
                not isinstance(config['securityDsn'],str)):
            raise ValueError('WEB_CONFIGURATION_INVALID')
        if (config['lifecycleDsn'] is not None and
                not isinstance(config['lifecycleDsn'],str)):
            raise ValueError('WEB_CONFIGURATION_INVALID')
        profiles=config['pythonProfiles']
        if type(profiles) is not list:
            raise ValueError('WEB_CONFIGURATION_INVALID')
        approved_profiles=tuple(ApprovedPythonEnvironment(
            item['profileId'],item['imageDigest'],item['manifest'])
            for item in profiles if type(item) is dict and
            set(item)=={'profileId','imageDigest','manifest'})
        if len(approved_profiles)!=len(profiles):
            raise ValueError('WEB_CONFIGURATION_INVALID')
        principal=principal_claims(access_token(headers),'web')
        identity=VerifiedIdentity(principal['issuer'],principal['subject'],
                                  principal.get('groups',()), issued_at=principal['issuedAt'])
        app=PostgresWebApp(PostgresMCPRouter(config['accessDsn'],config['runtimeDsn'],
            preview_secret=bytes.fromhex(config['secretHex']),
            security_dsn=config['securityDsn'],
            approved_python_profiles=approved_profiles),
            public_origin=config['publicOrigin'],
            lifecycle_dsn=config['lifecycleDsn'])
        if (arguments['path'] in _BROWSER_POST_ROUTES
                and headers.get('origin')!=app.public_origin):
            return {'status':403,'payload':{'error':'WEB_ORIGIN_REQUIRED'}}
        value=app._dispatch(arguments['path'],arguments['query'].encode('latin-1'),arguments['body'],identity)
        return {'status':200,'payload':value}
    except AuthError as error:return {'status':error.status,'payload':{'error':error.code}}
    except AccessDenied as error:
        program=body.get('program') if isinstance(body,dict) else None
        function=program.get('function') if isinstance(program,dict) else None
        specification=(
            PostgresSecurityLanguage.catalog()['functions'].get(function)
            or PostgresLanguageV2.catalog()['functions'].get(function)
            if isinstance(function,str) else None)
        workspace=body.get('workspaceId') if isinstance(body,dict) else None
        application=body.get('applicationId') if isinstance(body,dict) else None
        if (app is not None and identity is not None
                and app.router.security_dsn and specification is not None
                and specification['permission'] in ('admin','workspace_admin')
                and isinstance(workspace,str) and workspace
                and isinstance(application,str) and application):
            try:
                PostgresSecurityLanguage(
                    app.router.security_dsn,identity=identity
                ).record_privileged_denial(
                    ApplicationScope(workspace,application),program,str(error))
            except Exception:
                LOG.exception('Privileged browser denial audit failed')
        return {'status':403,'payload':{'error':str(error)}}
    except ValueError as error:
        status,code=_value_error_response(error)
        payload={'error':code}
        if isinstance(error,SourceValidationError):
            payload['details']=error.diagnostics
        return {'status':status,'payload':payload}
    except psycopg.Error:
        LOG.exception('PostgreSQL web operation failed')
        return {'status':503,'payload':{'error':'POSTGRES_OPERATION_FAILED'}}


if __name__=='__main__':
    import uvicorn
    # Uvicorn configures its own named loggers, not this application logger.
    # Attach one bounded stderr handler so request/auth correlation events are
    # actually observable in the packaged container.
    if not LOG.handlers:
        handler=logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(levelname)s %(name)s %(message)s'))
        LOG.addHandler(handler)
    LOG.setLevel(logging.INFO)
    LOG.propagate=False
    raw=os.environ.get('EPM_PG_WEB_PORT','5195')
    if not raw.isdecimal() or not 1024<=int(raw)<=65535:
        raise ValueError('EPM_PG_WEB_PORT must be 1024–65535')
    host=os.environ.get('EPM_PG_BIND_HOST','127.0.0.1')
    if host not in ('127.0.0.1','0.0.0.0'):
        raise ValueError('Invalid web bind host')
    uvicorn.run(build_app(),host=host,port=int(raw),log_level='info')
