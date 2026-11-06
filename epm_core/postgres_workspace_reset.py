"""Owner-checked V2 reset inventory and reversible maintenance transitions.

This service never deletes a workspace. A signed inventory binds quiesce to
the exact observed state; apply runs only in a separate owner-credential
listener after deployment readiness and endpoint retirement.
"""
from __future__ import annotations

from hashlib import sha256
import hmac
import json
import re
import time

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .postgres_access import AccessDenied, PostgresAccessChecker, VerifiedIdentity
from .postgres_endpoint_inventory import parse_endpoint_inventory
from .postgres_reset_schema import inspect_reset_schema
from .postgres_workspace_lifecycle import PostgresWorkspaceLifecycle


FUNCTION = 'workspace.reset.prepare'
QUIESCE_FUNCTION = 'workspace.reset.quiesce'
RESUME_FUNCTION = 'workspace.reset.resume'
SETTLE_FUNCTION = 'workspace.reset.settle'
_ACTIVE_JOB_STATUSES = frozenset((
    'accepted', 'ready', 'running', 'staged', 'cancel_requested',
    'needs_inspection'))
_UNPUBLISHED_BATCH_STATUSES = frozenset(('staging', 'ready'))
_ACTIVE_SEQUENCE_STATUSES = frozenset((
    'accepted', 'running', 'cancel_requested'))
_ACTIVE_PYTHON_BUILD_STATUSES = frozenset((
    'accepted', 'ready', 'running', 'cancel_requested'))
_ACTIVE_CUBE_QUERY_STATUSES = frozenset((
    'accepted', 'ready', 'running', 'computed', 'cancel_requested'))
_ACTIVE_PYTHON_WORKFLOW_STATUSES = frozenset((
    'accepted', 'running', 'cancel_requested', 'needs_inspection'))
_ACTIVE_EXPORT_PRODUCER_STATUSES = frozenset((
    'Accepted', 'Reading', 'Prepared'))
_ACTIVE_TRANSFER_CLEANUP_STATUSES = frozenset(('Accepted', 'Running'))
_ACTIVE_IMPORT_EXECUTION_STATUSES = frozenset(('Accepted','Claimed','Publishing'))
_ACTIVE_LAYOUT_REPLACEMENT_STATUSES = frozenset((
    'Accepted', 'Staging', 'Staged'))
_ACTIVE_LAYOUT_ACTIVATION_STATUSES = frozenset(('Requested', 'Activating'))
_ACTIVE_APPLICATION_SCHEDULE_STATUSES = frozenset((
    'ready', 'running', 'submitted', 'cancel_requested',
    'needs_inspection'))
_MAX_VISIBLE_ACTIVE = 1000


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':')).encode('utf-8')


def reset_active_work_blockers(manifest: dict) -> tuple[str, ...]:
    """Return exact active-work gates shared by preview and destructive apply."""
    mapping=(('jobs','UNSETTLED_OR_INSPECTION_JOBS'),
      ('expressionRuleSequences','UNSETTLED_RULE_SEQUENCES'),
      ('fullAggregateSequences','UNSETTLED_FULL_SEQUENCES'),
      ('sourceBatches','UNPUBLISHED_SOURCE_BATCHES'),
      ('pythonBuilds','UNSETTLED_PYTHON_BUILDS'),
      ('cubeAggregateQueries','UNSETTLED_CUBE_AGGREGATE_QUERIES'),
      ('pythonWorkflows','UNSETTLED_PYTHON_WORKFLOWS'))
    mapping += (('transferExportProducers','UNSETTLED_EXPORT_PRODUCER'),
                ('transferCleanupRequests','UNSETTLED_TRANSFER_CLEANUP'),
                ('importExecutions','UNSETTLED_IMPORT_EXECUTIONS'))
    mapping += (('layoutReplacementRequests',
                 'UNSETTLED_LAYOUT_REPLACEMENT'),
                ('layoutReplacementActivations',
                 'UNSETTLED_LAYOUT_ACTIVATION'),
                ('applicationSchedules',
                 'UNSETTLED_APPLICATION_SCHEDULE_WORK'))
    if type(manifest) is not dict or any(type(manifest.get(name)) is not dict
            or type(manifest[name].get('active')) is not list
            for name,_ in mapping):
        raise ValueError('RESET_ACTIVE_WORK_INVENTORY_INVALID')
    return tuple(code for name,code in mapping if manifest[name]['active'])


def compile_reset_prepare(program: object) -> None:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != FUNCTION
            or program['arguments'] != {'scope': 'workspace'}):
        raise ValueError('V2_RESET_PREPARE_ARGUMENTS_INVALID')


def compile_reset_transition(program: object) -> tuple[str, dict]:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] not in (QUIESCE_FUNCTION, RESUME_FUNCTION,
                                           SETTLE_FUNCTION)
            or not isinstance(program['arguments'], dict)):
        raise ValueError('V2_RESET_TRANSITION_ARGUMENTS_INVALID')
    name, args = program['function'], program['arguments']
    if name in (QUIESCE_FUNCTION, SETTLE_FUNCTION):
        if (set(args) != {'manifestDigest', 'expiresAt', 'signature'}
                or not isinstance(args['manifestDigest'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', args['manifestDigest'])
                or type(args['expiresAt']) is not int
                or not isinstance(args['signature'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', args['signature'])):
            raise ValueError('V2_RESET_TRANSITION_ARGUMENTS_INVALID')
    elif (set(args) != {'reason'} or not isinstance(args['reason'], str)
          or not 1 <= len(args['reason']) <= 200
          or args['reason'] != args['reason'].strip()):
        raise ValueError('V2_RESET_TRANSITION_ARGUMENTS_INVALID')
    return name, args


class PostgresWorkspaceResetPreview:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 secret: bytes, endpoint_inventory_json: str | None = None):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL lifecycle DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('Verified identity is required')
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError('A server-owned reset secret of 32+ bytes is required')
        self.dsn, self.identity, self.secret = dsn, identity, secret
        self.endpoint_inventory_json = endpoint_inventory_json

    @staticmethod
    def catalog() -> dict:
        return {'languageVersion': 2, 'functions': {FUNCTION: {
            'mode': 'read_only',
            'permission': 'platform_operator_and_workspace_admin',
            'arguments': {'scope': 'workspace'},
            'result': 'signed PostgreSQL target inventory; no deletion',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'medium'}, QUIESCE_FUNCTION: {
            'mode': 'atomic_write',
            'permission': 'platform_operator_and_workspace_admin',
            'arguments': {'manifestDigest': 'sha256 from prepare',
                          'expiresAt': 'epoch seconds from prepare',
                          'signature': 'signature from prepare'},
            'result': 'workspace Maintenance; no deletion',
            'previewRequired': True, 'idempotencyRequired': True,
            'workClass': 'short'}, RESUME_FUNCTION: {
            'mode': 'atomic_write',
            'permission': 'platform_operator_and_workspace_admin',
            'arguments': {'reason': 'explicit reason, 1–200 characters'},
            'result': 'workspace Active; no deletion',
            'previewRequired': False, 'idempotencyRequired': True,
            'workClass': 'short'}, SETTLE_FUNCTION: {
            'mode': 'atomic_write',
            'permission': 'platform_operator_and_workspace_admin',
            'arguments': {'manifestDigest': 'sha256 from Maintenance prepare',
                          'expiresAt': 'epoch seconds from Maintenance prepare',
                          'signature': 'signature from Maintenance prepare'},
            'result': 'fenced job and staged-source settlement counts',
            'previewRequired': True, 'idempotencyRequired': True,
            'workClass': 'short'}}}

    def is_operator(self) -> bool:
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            return db.execute('''SELECT
                epm.identity_subject_active(%s,%s)
                AND (CASE WHEN %s::bigint IS NULL THEN true ELSE
                  epm.identity_subject_session_valid(%s,%s,%s) END)
                AND EXISTS (
                    SELECT 1 FROM epm.platform_operator_grant
                    WHERE issuer=%s AND subject_id=%s) AS allowed''',
                (self.identity.issuer,self.identity.subject_id,
                 self.identity.issued_at,self.identity.issuer,
                 self.identity.subject_id,self.identity.issued_at,
                 self.identity.issuer,
                 self.identity.subject_id)).fetchone()['allowed']

    @staticmethod
    def _require_owner(db, workspace_id: str,
                       identity: VerifiedIdentity) -> str:
        isolation = db.execute('SHOW transaction_isolation').fetchone()
        if isolation['transaction_isolation'] != 'read committed':
            raise ValueError('Authorization recheck requires READ COMMITTED')
        workspace = db.execute('''SELECT status FROM epm.workspace
            WHERE workspace_id=%s''', (workspace_id,)).fetchone()
        if not workspace or workspace['status'] not in ('Active','Maintenance'):
            raise AccessDenied('WORKSPACE_UNAVAILABLE')
        active=db.execute('''SELECT epm.identity_subject_active(%s,%s)
            AS active, CASE WHEN %s::bigint IS NULL THEN true ELSE
              epm.identity_subject_session_valid(%s,%s,%s) END AS session_valid''',
            (identity.issuer,identity.subject_id,identity.issued_at,
             identity.issuer,identity.subject_id,identity.issued_at)).fetchone()
        if not active['active']:
            raise AccessDenied('IDENTITY_INACTIVE')
        if not active['session_valid']:
            raise AccessDenied('IDENTITY_SESSION_REVOKED')
        grant = db.execute('''SELECT 1 FROM epm.workspace_access_grant
            WHERE workspace_id=%s AND issuer=%s AND subject_id=%s
            AND role='Administrator' ''',
            (workspace_id, identity.issuer,
             identity.subject_id)).fetchone()
        if not grant:
            raise AccessDenied('WORKSPACE_ADMIN_REQUIRED')
        operator = db.execute('''SELECT 1 FROM epm.platform_operator_grant
            WHERE issuer=%s AND subject_id=%s''',
            (identity.issuer, identity.subject_id)).fetchone()
        if not operator:
            raise AccessDenied('PLATFORM_OPERATOR_REQUIRED')
        return workspace['status']

    def check_owner(self, workspace_id: str) -> str:
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresWorkspaceLifecycle._set_workspace(db, workspace_id)
                PostgresAccessChecker.lock_workspace(db, workspace_id)
                return self._require_owner(db, workspace_id, self.identity)

    @staticmethod
    def _fingerprint(db, name: str, query: str, workspace_id: str,
                     *, active_statuses: frozenset[str] = frozenset()) -> dict:
        digest = sha256()
        count = 0
        by_status: dict[str, int] = {}
        active: list[dict] = []
        with db.cursor(name='reset_manifest_' + name) as cursor:
            cursor.execute(query, (workspace_id,))
            for row in cursor:
                item = dict(row)
                for key, value in item.items():
                    if hasattr(value, 'isoformat'):
                        item[key] = value.isoformat()
                digest.update(_canonical(item) + b'\n')
                count += 1
                status = item.get('status') or item.get('role')
                if status:
                    by_status[status] = by_status.get(status, 0) + 1
                if status in active_statuses:
                    if len(active) >= _MAX_VISIBLE_ACTIVE:
                        raise ValueError('RESET_ACTIVE_TARGETS_EXCEED_LIMIT')
                    active.append(item)
        return {'count': count, 'sha256': digest.hexdigest(),
                'byStatus': dict(sorted(by_status.items())),
                'active': active}

    def _manifest(self, db, workspace_id: str) -> dict:
        workspace = db.execute('''SELECT workspace_id,name,status,
            created_at::text AS created_at FROM epm.workspace
            WHERE workspace_id=%s''', (workspace_id,)).fetchone()
        applications = [dict(row) for row in db.execute('''
            SELECT a.application_id,a.name,a.kind,a.status,
                a.created_at::text AS created_at,
                s.schema_epoch,s.metadata_revision,s.data_revision,
                s.policy_revision,s.commit_revision,s.processing_mode,
                s.active_projection_generation,
                s.currency_settings
            FROM epm.application a LEFT JOIN epm.application_state s
              ON s.workspace_id=a.workspace_id
             AND s.application_id=a.application_id
            WHERE a.workspace_id=%s ORDER BY a.application_id''',
            (workspace_id,)).fetchall()]
        grants = {
            'workspace': self._fingerprint(db, 'workspace_grants',
                '''SELECT issuer,subject_id,role,granted_at FROM
                epm.workspace_access_grant WHERE workspace_id=%s
                ORDER BY issuer,subject_id''', workspace_id),
            'application': self._fingerprint(db, 'application_grants',
                '''SELECT application_id,issuer,subject_id,role,
                granted_at FROM epm.application_access_grant
                WHERE workspace_id=%s
                ORDER BY application_id,issuer,subject_id''',workspace_id),
            'rule': self._fingerprint(db, 'rule_grants',
                '''SELECT application_id,issuer,subject_id,can_design,
                can_publish,can_run,granted_at FROM epm.rule_access_grant
                WHERE workspace_id=%s
                ORDER BY application_id,issuer,subject_id''',workspace_id),
        }
        jobs = self._fingerprint(db, 'jobs',
            '''SELECT application_id,job_id,status,claim_generation,
            program_digest,request_digest,plan_digest,
            issuer,subject_id,token_issued_at,authority_kind,
            receipt_revision,error_code,updated_at FROM epm.job
            WHERE workspace_id=%s ORDER BY application_id,job_id''',
            workspace_id, active_statuses=_ACTIVE_JOB_STATUSES)
        sequences = self._fingerprint(db, 'expression_rule_sequences',
            '''SELECT application_id,sequence_id,issuer,subject_id,
                token_issued_at,authority_kind,request_digest,manifest,status,current_step,job_ids,
                error_code,updated_at FROM epm.expression_rule_sequence
                WHERE workspace_id=%s ORDER BY application_id,sequence_id''',
            workspace_id, active_statuses=_ACTIVE_SEQUENCE_STATUSES)
        full_sequences = self._fingerprint(db, 'full_aggregate_sequences',
            '''SELECT application_id,sequence_id,issuer,subject_id,
                token_issued_at,authority_kind,request_digest,manifest,status,current_step,job_ids,
                error_code,updated_at FROM epm.full_aggregate_sequence
                WHERE workspace_id=%s ORDER BY application_id,sequence_id''',
            workspace_id, active_statuses=_ACTIVE_SEQUENCE_STATUSES)
        python_builds = self._fingerprint(db, 'python_program_builds',
            '''SELECT application_id,build_id,status,claim_generation,
                request_digest,program_id,program_version,error_code,updated_at
                FROM epm.python_program_build WHERE workspace_id=%s
                ORDER BY application_id,build_id''',workspace_id,
            active_statuses=_ACTIVE_PYTHON_BUILD_STATUSES)
        cube_queries = self._fingerprint(db, 'cube_aggregate_queries',
            '''SELECT application_id,query_id,status,claim_generation,
                request_digest,plan_digest,result_digest,result_group_count,
                result_bytes,error_code,next_attempt_at,last_claimant,updated_at
                FROM epm.cube_aggregate_query WHERE workspace_id=%s
                ORDER BY application_id,query_id''',workspace_id,
            active_statuses=_ACTIVE_CUBE_QUERY_STATUSES)
        python_workflows = self._fingerprint(db, 'python_workflows',
            '''SELECT application_id,workflow_id,status,claim_generation,
                claimant,lease_until FROM epm.python_program_workflow
                WHERE workspace_id=%s ORDER BY application_id,workflow_id''',
            workspace_id,active_statuses=_ACTIVE_PYTHON_WORKFLOW_STATUSES)
        transfer_export_producers = self._fingerprint(db, 'transfer_export_producers',
            '''SELECT application_id,request_id,status,claim_generation,
                claimant,lease_until,cancel_requested,artifact_id
                FROM epm.fact_export_producer_request WHERE workspace_id=%s
                ORDER BY application_id,request_id''',workspace_id,
            active_statuses=_ACTIVE_EXPORT_PRODUCER_STATUSES)
        transfer_cleanup_requests = self._fingerprint(db, 'transfer_cleanup_requests',
            '''SELECT application_id,request_id,status,claim_generation,
                claimant,lease_until FROM epm.transfer_cleanup_request
                WHERE workspace_id=%s ORDER BY application_id,request_id''',
            workspace_id,active_statuses=_ACTIVE_TRANSFER_CLEANUP_STATUSES)
        import_executions=self._fingerprint(db,'import_executions',
            '''SELECT application_id,request_id,batch_id,status,claim_generation,
                claimant,lease_until,error_code FROM epm.source_import_execution
                WHERE workspace_id=%s ORDER BY application_id,request_id''',
            workspace_id,active_statuses=_ACTIVE_IMPORT_EXECUTION_STATUSES)
        layout_replacement_requests = self._fingerprint(
            db,'layout_replacement_requests',
            '''SELECT application_id,request_id,target_generation_id,status,
                claim_generation,claimant,lease_until,updated_at
                FROM epm.layout_replacement_request WHERE workspace_id=%s
                ORDER BY application_id,request_id''',workspace_id,
            active_statuses=_ACTIVE_LAYOUT_REPLACEMENT_STATUSES)
        layout_replacement_activations = self._fingerprint(
            db,'layout_replacement_activations',
            '''SELECT application_id,activation_id,request_id,status,
                claim_generation,claimant,lease_until,updated_at
                FROM epm.layout_replacement_activation WHERE workspace_id=%s
                ORDER BY application_id,activation_id''',workspace_id,
            active_statuses=_ACTIVE_LAYOUT_ACTIVATION_STATUSES)
        application_schedules = self._fingerprint(
            db, 'application_schedules',
            '''SELECT o.application_id,o.occurrence_id,o.status,o.claimant,
                o.lease_until,v.execution_issuer,v.execution_subject,
                v.execution_token_issued_at,v.execution_authority_kind
                FROM epm.application_schedule_occurrence o
                JOIN epm.application_schedule_version v ON
                  (v.workspace_id,v.application_id,v.schedule_id,v.version)=
                  (o.workspace_id,o.application_id,o.schedule_id,
                   o.schedule_version)
                WHERE o.workspace_id=%s
                ORDER BY o.application_id,o.occurrence_id''',
            workspace_id,
            active_statuses=_ACTIVE_APPLICATION_SCHEDULE_STATUSES)
        receipts = self._fingerprint(db, 'operation_receipts',
            '''SELECT application_id,operation_id,command_digest,actor_id,
                committed_revision,committed_at FROM epm.operation_receipt
                WHERE workspace_id=%s
                ORDER BY application_id,operation_id''', workspace_id)
        artifacts = self._fingerprint(db, 'batches',
            '''SELECT application_id,batch_id,status,chunk_count,
            row_count,content_digest,updated_at FROM epm.source_batch
            WHERE workspace_id=%s ORDER BY application_id,batch_id''',
            workspace_id, active_statuses=_UNPUBLISHED_BATCH_STATUSES)
        seed_lineage = self._fingerprint(db, 'planning_seed_lineage',
            '''SELECT application_id,batch_id,action_ordinal,action,
                value_family,target_series_key,target_coordinate_id,
                target_change_id,target_detail_change_id,
                target_committed_revision,source_series_key,
                source_coordinate_id,source_change_id,
                source_detail_change_id,source_committed_revision,
                policy_id,policy_version,policy_digest,content_digest
                FROM epm.planning_seed_lineage WHERE workspace_id=%s
                ORDER BY application_id,batch_id,action_ordinal''',workspace_id)
        policy_artifacts = self._fingerprint(db, 'policy_artifacts',
            '''SELECT application_id,artifact_id,source_ref,
            source_version,media_type,content_sha256,content_bytes,
            actor_issuer,actor_subject,policy_revision,
            committed_revision,captured_at
            FROM epm.policy_source_artifact WHERE workspace_id=%s
            ORDER BY application_id,artifact_id''', workspace_id)
        policy_approvals = self._fingerprint(db,'policy_approvals',
            '''SELECT application_id,approval_id,bundle_operation_id,
                review_operation_id,evaluation_digest,approval_digest,
                approver_issuer,approver_subject,policy_revision,
                committed_revision,approved_at
                FROM epm.policy_acquisition_approval WHERE workspace_id=%s
                ORDER BY application_id,approval_id''',workspace_id)
        policy_activation_events=self._fingerprint(db,'policy_activation_events',
            '''SELECT application_id,event_id,variant_key,action,approval_id,
                activation_id,previous_event_id,manifest,actor_issuer,
                actor_subject,policy_revision,committed_revision,recorded_at
                FROM epm.policy_activation_event WHERE workspace_id=%s
                ORDER BY application_id,event_id''',workspace_id)
        policy_activations=self._fingerprint(db,'policy_activations',
            '''SELECT application_id,variant_key,event_id,activation_id,status
                FROM epm.policy_activation_current WHERE workspace_id=%s
                ORDER BY application_id,variant_key''',workspace_id)
        acquisition_journals=self._fingerprint(db,'acquisition_journals',
            '''SELECT application_id,journal_id,acquisition_key,job_id,reversal_of,
                activation_id,currency_dimension_id,currency_member_id,reason,manifest,status,
                issuer,subject_id,metadata_revision,policy_revision,committed_revision,
                posted_at FROM epm.acquisition_journal WHERE workspace_id=%s
                ORDER BY application_id,journal_id''',workspace_id)
        acquisition_lines=self._fingerprint(db,'acquisition_journal_lines',
            '''SELECT application_id,journal_id,line_ordinal,coordinate_id,
                signed_amount::text AS signed_amount,line_role
                FROM epm.acquisition_journal_line WHERE workspace_id=%s
                ORDER BY application_id,journal_id,line_ordinal''',workspace_id)
        projection_recovery = self._fingerprint(db, 'projection_recovery',
            '''SELECT application_id,job_id,target_generation,phase,updated_at
                FROM epm.projection_recovery_manifest WHERE workspace_id=%s
                ORDER BY application_id,job_id''',workspace_id)
        projection_cleanup = self._fingerprint(db, 'projection_cleanup',
            '''SELECT application_id,job_id,rebuild_job_id,generation_kind,
                target_generation,phase,updated_at FROM epm.projection_cleanup_manifest
                WHERE workspace_id=%s ORDER BY application_id,job_id''',workspace_id)
        raw_operations = self._fingerprint(db, 'raw_operation_membership',
            '''SELECT application_id,operation_id FROM epm.raw_operation_membership
                WHERE workspace_id=%s ORDER BY application_id,operation_id''',workspace_id)
        endpoint_inventory = parse_endpoint_inventory(
            self.endpoint_inventory_json, workspace_id)
        known_applications = {row['application_id'] for row in applications}
        if any(item['kind'] == 'application_mcp' and
               item['applicationId'] not in known_applications
               for item in endpoint_inventory['endpoints']):
            raise ValueError('RESET_ENDPOINT_APPLICATION_UNKNOWN')
        return {
            'schemaMigrationVersion': db.execute(
                'SELECT max(version) AS version FROM epm.schema_migration'
            ).fetchone()['version'],
            'schemaCoverage': inspect_reset_schema(db),
            'workspace': dict(workspace), 'applications': applications,
            'grants': grants, 'jobs': jobs,
            'expressionRuleSequences': sequences,
            'fullAggregateSequences': full_sequences,
            'pythonBuilds': python_builds,
            'cubeAggregateQueries': cube_queries,
            'pythonWorkflows': python_workflows,
            'transferExportProducers': transfer_export_producers,
            'transferCleanupRequests': transfer_cleanup_requests,
            'importExecutions':import_executions,
            'layoutReplacementRequests': layout_replacement_requests,
            'layoutReplacementActivations': layout_replacement_activations,
            'applicationSchedules': application_schedules,
            'projectionRecovery': projection_recovery,
            'projectionCleanup': projection_cleanup,
            'rawOperationMembership': raw_operations,
            'operationReceipts': receipts, 'sourceBatches': artifacts,
            'planningSeedLineage': seed_lineage,
            'policySourceArtifacts': policy_artifacts,
            'policyApprovals':policy_approvals,
            'policyActivationEvents':policy_activation_events,
            'policyActivations':policy_activations,
            'acquisitionJournals':acquisition_journals,
            'acquisitionJournalLines':acquisition_lines,
            'storage': {'kind': 'postgresql', 'schema': 'epm',
                        'externalRoots': []},
            'endpointInventory': endpoint_inventory,
        }

    def prepare(self, workspace_id: str, program: object) -> dict:
        compile_reset_prepare(program)
        if not isinstance(workspace_id, str) or not 1 <= len(workspace_id) <= 200:
            raise ValueError('Workspace ID is required')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 30000)
                PostgresWorkspaceLifecycle._set_workspace(db, workspace_id)
                # The exclusive workspace fence prevents grant changes and
                # application effects from passing the owner recheck.
                PostgresAccessChecker.lock_workspace(
                    db, workspace_id, exclusive=True)
                self._require_owner(db, workspace_id, self.identity)
                manifest = self._manifest(db, workspace_id)
        observed = int(time.time())
        expires = observed + 300
        manifest_digest = sha256(_canonical(manifest)).hexdigest()
        signed = {'workspaceId': workspace_id,
                  'issuer': self.identity.issuer,
                  'subjectId': self.identity.subject_id,
                  'manifestDigest': manifest_digest,
                  'expiresAt': expires}
        signature = hmac.new(self.secret,
                             b'workspace-reset-prepare-v2\x00' +
                             _canonical(signed), sha256).hexdigest()
        blockers = ['DEDICATED_RESET_APPLY_LISTENER_REQUIRED',
                    'EXTERNAL_ENDPOINT_INVENTORY_REQUIRED']
        coverage=manifest['schemaCoverage']
        if (not coverage['matchesExpected']
                or coverage['globalToWorkspaceReferences']
                or coverage['externalIncomingReferences']
                or coverage['otherRelations']
                or coverage['cycleTables']):
            blockers.append('RESET_SCHEMA_COVERAGE_DRIFT')
        if any(item['schema_epoch'] is None
               for item in manifest['applications']):
            blockers.append('RESET_APPLICATION_STATE_MISSING')
        blockers.extend(reset_active_work_blockers(manifest))
        return {'languageVersion': 2, 'function': FUNCTION,
                'manifest': manifest,
                'manifestDigest': manifest_digest,
                'observedAt': observed, 'expiresAt': expires,
                'signature': signature,
                'quiesceSupported': True,
                'resumeSupported': True,
                'settleSupported': True,
                'applySupported': False,
                'applyBlockers': blockers}

    def transition(self, workspace_id: str, program: object, *,
                   idempotency_key: str) -> dict:
        name, args = compile_reset_transition(program)
        if not isinstance(workspace_id, str) or not 1 <= len(workspace_id) <= 200:
            raise ValueError('Workspace ID is required')
        if (not isinstance(idempotency_key, str)
                or not 1 <= len(idempotency_key) <= 200):
            raise ValueError('Idempotency key is required')
        digest = sha256(_canonical({'workspaceId': workspace_id,
                                    'program': program})).hexdigest()
        actor = sha256((self.identity.issuer + '\0' +
                        self.identity.subject_id).encode()).hexdigest()
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 30000)
                PostgresWorkspaceLifecycle._set_workspace(db, workspace_id)
                PostgresAccessChecker.lock_workspace(
                    db, workspace_id, exclusive=True)
                status = self._require_owner(db, workspace_id, self.identity)
                receipt = db.execute('''SELECT command_digest,actor_digest,result
                    FROM epm.workspace_lifecycle_receipt
                    WHERE workspace_id=%s AND operation_id=%s''',
                    (workspace_id, idempotency_key)).fetchone()
                if receipt:
                    if (receipt['command_digest'] != digest
                            or receipt['actor_digest'] != actor):
                        raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    return receipt['result']
                if name in (QUIESCE_FUNCTION, SETTLE_FUNCTION):
                    if name == QUIESCE_FUNCTION and status != 'Active':
                        raise ValueError('WORKSPACE_NOT_ACTIVE')
                    if name == SETTLE_FUNCTION and status != 'Maintenance':
                        raise ValueError('WORKSPACE_NOT_IN_MAINTENANCE')
                    signed = {'workspaceId': workspace_id,
                              'issuer': self.identity.issuer,
                              'subjectId': self.identity.subject_id,
                              'manifestDigest': args['manifestDigest'],
                              'expiresAt': args['expiresAt']}
                    expected = hmac.new(self.secret,
                        b'workspace-reset-prepare-v2\x00' + _canonical(signed),
                        sha256).hexdigest()
                    if (args['expiresAt'] < int(time.time())
                            or not hmac.compare_digest(expected,
                                                       args['signature'])):
                        raise ValueError('RESET_MANIFEST_INVALID_OR_EXPIRED')
                    observed = sha256(_canonical(
                        self._manifest(db, workspace_id))).hexdigest()
                    if observed != args['manifestDigest']:
                        raise ValueError('RESET_MANIFEST_STALE')
                    if name == SETTLE_FUNCTION:
                        anomaly = db.execute('''SELECT 1
                            FROM epm.source_batch b
                            JOIN epm.operation_receipt r
                              ON r.workspace_id=b.workspace_id
                             AND r.application_id=b.application_id
                             AND r.operation_id=b.batch_id
                            WHERE b.workspace_id=%s
                              AND b.status IN ('staging','ready')
                            LIMIT 1''', (workspace_id,)).fetchone()
                        if anomaly:
                            raise ValueError(
                                'SOURCE_BATCH_RECEIPT_REQUIRES_INSPECTION')
                        counts = db.execute('''SELECT cancelled_count,
                            inspection_count FROM
                            epm.settle_workspace_reset_jobs(%s)''',
                            (workspace_id,)).fetchone()
                        failed_batches = db.execute('''SELECT
                            epm.settle_workspace_reset_batches(%s)
                            AS failed_batch_count''',
                            (workspace_id,)).fetchone()['failed_batch_count']
                        settled_schedules = db.execute('''SELECT
                            cancelled_occurrences,cleared_dispatch_claims FROM
                            epm.settle_workspace_reset_application_schedules(%s)''',
                            (workspace_id,)).fetchone()
                        settled_python = db.execute('''SELECT
                            cancelled_workflows,partially_published_workflows FROM
                            epm.settle_workspace_reset_python_workflows(%s)''',
                            (workspace_id,)).fetchone()
                        target = 'Maintenance'
                    else:
                        target = 'Maintenance'
                else:
                    if status != 'Maintenance':
                        raise ValueError('WORKSPACE_NOT_IN_MAINTENANCE')
                    target = 'Active'
                if name != SETTLE_FUNCTION:
                    db.execute('''UPDATE epm.workspace SET status=%s
                        WHERE workspace_id=%s''', (target, workspace_id))
                result = {'workspaceId': workspace_id, 'status': target,
                          'function': name, 'idempotencyKey': idempotency_key}
                if name == SETTLE_FUNCTION:
                    result['cancelledCount'] = counts['cancelled_count']
                    result['inspectionCount'] = counts['inspection_count']
                    result['failedBatchCount'] = failed_batches
                    result['cancelledScheduleOccurrenceCount'] = (
                        settled_schedules['cancelled_occurrences'])
                    result['clearedScheduleDispatchClaimCount'] = (
                        settled_schedules['cleared_dispatch_claims'])
                    result['cancelledPythonWorkflowCount'] = (
                        settled_python['cancelled_workflows'])
                    result['partiallyPublishedPythonWorkflowCount'] = (
                        settled_python['partially_published_workflows'])
                db.execute('''INSERT INTO epm.workspace_lifecycle_receipt
                    (workspace_id,operation_id,command_digest,actor_digest,result)
                    VALUES (%s,%s,%s,%s,%s)''',
                    (workspace_id,idempotency_key,digest,actor,Jsonb(result)))
                db.execute('''INSERT INTO epm.security_audit
                    (actor_id,action,workspace_id,target_digest,outcome,detail)
                    VALUES (%s,%s,%s,%s,'Accepted',%s)''',
                    (actor,name,workspace_id,sha256(workspace_id.encode()).hexdigest(),
                     Jsonb({'status': target,
                            'manifestDigest': args.get('manifestDigest')})))
                return result
