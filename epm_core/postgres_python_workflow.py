"""PostgreSQL persistence for execution of sealed Python-generated plans."""
from __future__ import annotations

from hashlib import sha256
import json

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import (AccessDenied, PostgresAccessChecker,
                              VerifiedIdentity,durable_authority_fields)
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .python_program_execution import (UnitCheckpoint, WorkflowRecord,
                                       WorkflowStatus, SealedPlan,
                                       verify_plan_identity)
from .python_plan_runner import (SealedPlanRunner, workflow_request_digest)


def _result(record: WorkflowRecord) -> dict:
    return {'planDigest': record.plan_digest, 'unitCount': record.unit_count,
            'checkpoints': [{'ordinal': item.ordinal, 'jobId': item.job_id,
                'committed': item.committed, 'receiptId': item.receipt_id}
                for item in record.checkpoints]}


def _record(row) -> WorkflowRecord:
    result = row['result'] or {}
    checkpoints = tuple(UnitCheckpoint(item['ordinal'], item['jobId'],
        item['committed'], item.get('receiptId'))
        for item in result.get('checkpoints', []))
    return WorkflowRecord(ApplicationScope(row['workspace_id'],
        row['application_id']), row['workflow_id'], row['build_id'],
        result['planDigest'], result['unitCount'], WorkflowStatus(row['status']),
        checkpoints)


def python_workflow_id(scope: ApplicationScope, identity: VerifiedIdentity,
                       idempotency_key: str) -> str:
    """Return the stable public workflow identity for one owner request."""
    raw = json.dumps({'scope': [scope.workspace_id, scope.application_id],
        'identity': [identity.issuer, identity.subject_id],
        'idempotencyKey': idempotency_key}, sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode('ascii')
    return sha256(raw).hexdigest()[:32]


class PostgresPythonWorkflowStore:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 worker_claim: dict | None = None):
        if type(dsn) is not str or not dsn or not isinstance(identity, VerifiedIdentity):
            raise ValueError('PYTHON_WORKFLOW_STORE_CONFIGURATION_INVALID')
        if worker_claim is not None:
            required={'workflow_id','claim_generation','claimant'}
            if (type(worker_claim) is not dict or not required <= set(worker_claim)
                    or type(worker_claim['claim_generation']) is not int
                    or type(worker_claim['claimant']) is not str):
                raise ValueError('PYTHON_WORKFLOW_WORKER_CLAIM_INVALID')
        self.dsn, self.identity = dsn, identity
        self.worker_claim=worker_claim

    @staticmethod
    def _scope(db, scope: ApplicationScope) -> None:
        PostgresNumericFactStore._set_scope(db, scope)

    def authorize_run(self, scope: ApplicationScope) -> None:
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000); self._scope(db, scope)
                PostgresAccessChecker.check_in_transaction(db, self.identity,
                    scope, 'rule_run', function='python.program.run')

    def _authorize_bound_run(self, db, scope: ApplicationScope,
                             build_id: str):
        access = PostgresAccessChecker.check_in_transaction(db,self.identity,scope,
            'rule_run',function='python.program.run',arguments={'buildId':build_id})
        row=db.execute('''SELECT delegation_id,delegation_version,schedule_id,
            schedule_version,issuer,subject_id FROM epm.python_program_build
            WHERE workspace_id=%s AND application_id=%s AND build_id=%s''',
            (scope.workspace_id,scope.application_id,build_id)).fetchone()
        if (row is None or row['delegation_id'] is None
                or row['issuer'] != self.identity.issuer
                or row['subject_id'] != self.identity.subject_id):
            raise ValueError('PYTHON_EXECUTION_DELEGATION_INVALID')
        allowed=db.execute('''SELECT epm.execution_delegation_is_current(
            %s,%s,%s,%s,%s,%s,%s,%s,%s) AS allowed''',(
            scope.workspace_id,scope.application_id,row['delegation_id'],
            row['delegation_version'],self.identity.issuer,
            self.identity.subject_id,'python.program.run',row['schedule_id'],
            row['schedule_version'])).fetchone()
        if not allowed or allowed['allowed'] is not True:
            raise ValueError('PYTHON_EXECUTION_DELEGATION_INVALID')
        return access

    def _authorization_scope_digest(self, db, scope: ApplicationScope,
                                    *, access=None) -> str:
        return resolve_effective_dimensional_scope(db, self.identity, scope,
            access=access, function='python.program.run').scope_digest

    def _assert_workflow_authorization_scope(self, db,
            scope: ApplicationScope, workflow_id: str, *, access=None) -> str:
        row = db.execute('''SELECT authorization_scope_digest
            FROM epm.python_program_workflow WHERE workspace_id=%s
              AND application_id=%s AND workflow_id=%s''',
            (scope.workspace_id,scope.application_id,workflow_id)).fetchone()
        current = self._authorization_scope_digest(db,scope,access=access)
        if (row is None or row['authorization_scope_digest'] is None
                or row['authorization_scope_digest'] != current):
            raise AccessDenied('PYTHON_WORKFLOW_AUTHORIZATION_SCOPE_CHANGED')
        return current

    def authorize_publication(self, workflow: WorkflowRecord) -> dict:
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db,5000);self._scope(db,workflow.scope)
                access=self._authorize_bound_run(
                    db,workflow.scope,workflow.build_id)
                self._assert_workflow_authorization_scope(db,workflow.scope,
                    workflow.workflow_id,access=access)
                row=db.execute('''SELECT delegation_id,delegation_version,
                    schedule_id,schedule_version FROM epm.python_program_build
                    WHERE workspace_id=%s AND application_id=%s AND build_id=%s''',
                    (workflow.scope.workspace_id,workflow.scope.application_id,
                     workflow.build_id)).fetchone()
                return {'python_workflow_id':workflow.workflow_id,
                    'delegation_id':row['delegation_id'],
                    'delegation_version':row['delegation_version'],
                    'schedule_id':row['schedule_id'],
                    'schedule_version':row['schedule_version']}

    def create_or_read(self, workflow: WorkflowRecord, *, issuer: str,
                       subject_id: str, idempotency_key: str,
                       request_digest: str,
                       rerun_of_workflow_id: str | None = None
                       ) -> WorkflowRecord:
        if issuer != self.identity.issuer or subject_id != self.identity.subject_id:
            raise ValueError('PYTHON_WORKFLOW_IDENTITY_MISMATCH')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                self._scope(db, workflow.scope)
                PostgresAccessChecker.lock_workspace(db, workflow.scope.workspace_id)
                access=self._authorize_bound_run(
                    db,workflow.scope,workflow.build_id)
                authorization_scope_digest=self._authorization_scope_digest(
                    db,workflow.scope,access=access)
                prior = db.execute('''SELECT * FROM epm.python_program_workflow
                    WHERE workspace_id=%s AND application_id=%s AND issuer=%s
                      AND subject_id=%s AND idempotency_key=%s FOR UPDATE''',
                    (workflow.scope.workspace_id, workflow.scope.application_id,
                     issuer, subject_id, idempotency_key)).fetchone()
                if prior is not None:
                    if (prior['request_digest'] != request_digest
                            or prior['build_id'] != workflow.build_id
                            or prior['rerun_of_workflow_id'] !=
                               rerun_of_workflow_id):
                        raise ValueError('PYTHON_WORKFLOW_IDEMPOTENCY_CONFLICT')
                    if (prior['authorization_scope_digest'] is None
                            or prior['authorization_scope_digest'] !=
                               authorization_scope_digest):
                        raise AccessDenied(
                            'PYTHON_WORKFLOW_AUTHORIZATION_SCOPE_CHANGED')
                    return _record(prior)
                sealed = db.execute('''SELECT a.plan_digest,a.canonical_plan,
                    b.expected_metadata_revision,b.expected_policy_revision,
                    b.expected_schema_epoch,s.metadata_revision,s.policy_revision,
                    s.schema_epoch
                    FROM epm.python_program_build b
                    JOIN epm.python_plan_artifact a USING
                      (workspace_id,application_id,build_id)
                    JOIN epm.python_program_publication p ON
                      p.workspace_id=b.workspace_id AND p.application_id=b.application_id
                      AND p.program_id=b.program_id AND p.version=b.program_version
                      AND p.status='Published'
                    JOIN epm.application_state s ON
                      s.workspace_id=b.workspace_id
                      AND s.application_id=b.application_id
                    WHERE b.workspace_id=%s AND b.application_id=%s
                      AND b.build_id=%s AND b.status='sealed'
                      AND b.issuer=%s AND b.subject_id=%s''',
                    (workflow.scope.workspace_id, workflow.scope.application_id,
                     workflow.build_id, issuer, subject_id)).fetchone()
                if sealed is None:
                    raise ValueError('PYTHON_SEALED_BUILD_UNAVAILABLE')
                if sealed['plan_digest'] != workflow.plan_digest:
                    raise ValueError('PYTHON_WORKFLOW_PLAN_MISMATCH')
                units = sealed['canonical_plan'].get('units')
                if type(units) is not list or len(units) != workflow.unit_count:
                    raise ValueError('PYTHON_WORKFLOW_PLAN_MISMATCH')
                expected = (sealed['expected_metadata_revision'],
                            sealed['expected_policy_revision'],
                            sealed['expected_schema_epoch'])
                current = (sealed['metadata_revision'], sealed['policy_revision'],
                           sealed['schema_epoch'])
                if expected != current:
                    raise ValueError('PYTHON_RUN_STALE_CONTEXT')
                token_issued_at,authority_kind=durable_authority_fields(
                    self.identity)
                row = db.execute('''INSERT INTO epm.python_program_workflow(
                    workspace_id,application_id,workflow_id,build_id,issuer,
                    subject_id,idempotency_key,request_digest,status,result,
                    rerun_of_workflow_id,verified_groups,
                    authorization_scope_digest,token_issued_at,authority_kind)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'accepted',%s,%s,%s,%s,%s,%s)
                    RETURNING *''', (workflow.scope.workspace_id,
                    workflow.scope.application_id, workflow.workflow_id,
                    workflow.build_id, issuer, subject_id, idempotency_key,
                    request_digest, Jsonb(_result(workflow)),
                    rerun_of_workflow_id,list(self.identity.groups),
                    authorization_scope_digest,token_issued_at,
                    authority_kind)).fetchone()
                return _record(row)

    def rerun_as_task_controller(self, scope: ApplicationScope,
                                 workflow_id: str, *,
                                 idempotency_key: str) -> WorkflowRecord:
        """Create a new zero-effect workflow attempt from one sealed plan.

        Only the verified owner may rerun a failed/cancelled workflow, and
        only when no unit committed.  The original workflow remains immutable
        history.  Same-key replay returns the previously admitted rerun before
        checking moving application revisions; a new key must pass all native
        sealed-plan, publication, delegation and authorization checks again.
        """
        if (type(workflow_id) is not str or len(workflow_id) != 32
                or any(char not in '0123456789abcdef' for char in workflow_id)
                or type(idempotency_key) is not str
                or not 8 <= len(idempotency_key) <= 128
                or any(char not in
                       'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
                       '0123456789._-' for char in idempotency_key)):
            raise ValueError('PYTHON_WORKFLOW_RERUN_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000); self._scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'rule_run',
                    function='python.program.run')
                source = db.execute('''SELECT *
                    FROM epm.python_program_workflow WHERE workspace_id=%s
                    AND application_id=%s AND workflow_id=%s AND issuer=%s
                    AND subject_id=%s FOR UPDATE''', (scope.workspace_id,
                    scope.application_id, workflow_id, self.identity.issuer,
                    self.identity.subject_id)).fetchone()
                if source is None:
                    raise ValueError('PYTHON_WORKFLOW_UNAVAILABLE')
                original = _record(source)
                if (original.status not in (WorkflowStatus.FAILED,
                                             WorkflowStatus.CANCELLED)
                        or original.committed_units != 0):
                    raise ValueError('PYTHON_WORKFLOW_RERUN_NOT_AVAILABLE')
                prior = db.execute('''SELECT *
                    FROM epm.python_program_workflow WHERE workspace_id=%s
                    AND application_id=%s AND issuer=%s AND subject_id=%s
                    AND idempotency_key=%s FOR UPDATE''', (
                    scope.workspace_id, scope.application_id,
                    self.identity.issuer, self.identity.subject_id,
                    idempotency_key)).fetchone()
                if prior is not None:
                    if (prior['build_id'] != source['build_id']
                            or prior['rerun_of_workflow_id'] != workflow_id):
                        raise ValueError('PYTHON_WORKFLOW_IDEMPOTENCY_CONFLICT')
                    return _record(prior)
                build_id = source['build_id']
        plan = self.sealed_plan(scope, build_id)
        # Validate every sealed unit against the same fixed-core run contract
        # before recording a new durable attempt.  No child is admitted here;
        # the ordinary workflow worker performs that step later.
        SealedPlanRunner._units(plan)
        new_id = python_workflow_id(scope, self.identity, idempotency_key)
        digest = workflow_request_digest(scope, build_id, plan.digest,
            (self.identity.issuer, self.identity.subject_id))
        proposed = WorkflowRecord(scope, new_id, build_id, plan.digest,
                                  plan.unit_count)
        return self.create_or_read(proposed, issuer=self.identity.issuer,
            subject_id=self.identity.subject_id,
            idempotency_key=idempotency_key, request_digest=digest,
            rerun_of_workflow_id=workflow_id)

    def read(self, scope: ApplicationScope, workflow_id: str) -> WorkflowRecord:
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000); self._scope(db, scope)
                PostgresAccessChecker.check_in_transaction(db, self.identity,
                    scope, 'read')
                row = db.execute('''SELECT * FROM epm.python_program_workflow
                    WHERE workspace_id=%s AND application_id=%s AND workflow_id=%s
                      AND issuer=%s AND subject_id=%s''',
                    (scope.workspace_id, scope.application_id, workflow_id,
                     self.identity.issuer, self.identity.subject_id)).fetchone()
                if row is None: raise ValueError('PYTHON_WORKFLOW_UNAVAILABLE')
                self._assert_workflow_authorization_scope(
                    db,scope,workflow_id)
                return _record(row)

    def request_cancel_as_task_controller(self, scope: ApplicationScope,
                                          workflow_id: str, *,
                                          allow_application_admin=False
                                          ) -> WorkflowRecord:
        """Request native workflow cancellation under current authority.

        This controller changes only the workflow state.  The caller reissues
        cancellation for the latest uncommitted child job after commit, making
        a lost acknowledgement safely retryable without undoing committed
        units or rebuilding Python source.
        """
        if (type(workflow_id) is not str or len(workflow_id) != 32
                or any(char not in '0123456789abcdef' for char in workflow_id)
                or type(allow_application_admin) is not bool):
            raise ValueError('PYTHON_WORKFLOW_UNAVAILABLE')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                self._scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'rule_run',
                    function='python.program.run')
                row = db.execute('''SELECT * FROM epm.python_program_workflow
                    WHERE workspace_id=%s AND application_id=%s
                    AND workflow_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id,
                     workflow_id)).fetchone()
                if row is None:
                    raise ValueError('PYTHON_WORKFLOW_UNAVAILABLE')
                owner = ((row['issuer'], row['subject_id']) ==
                         (self.identity.issuer, self.identity.subject_id))
                if not owner:
                    if not allow_application_admin:
                        raise ValueError('PYTHON_WORKFLOW_UNAVAILABLE')
                    try:
                        PostgresAccessChecker.check_in_transaction(
                            db, self.identity, scope, 'admin')
                    except AccessDenied as error:
                        raise ValueError(
                            'PYTHON_WORKFLOW_UNAVAILABLE') from error
                current = _record(row)
                updated = current.request_cancel()
                if updated == current:
                    return current
                changed = db.execute('''UPDATE epm.python_program_workflow
                    SET status=%s,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                    AND workflow_id=%s AND status=%s''',
                    (updated.status.value, scope.workspace_id,
                     scope.application_id, workflow_id,
                     current.status.value)).rowcount
                if changed != 1:
                    raise ValueError('PYTHON_WORKFLOW_STALE_CONTROL_STATE')
                return updated

    def sealed_plan(self, scope: ApplicationScope, build_id: str) -> SealedPlan:
        """Load only the caller's trusted sealed artifact; never rebuild Python."""
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000); self._scope(db, scope)
                self._authorize_bound_run(db,scope,build_id)
                row = db.execute('''SELECT a.canonical_plan,a.plan_digest,
                    a.compiler_version,b.expected_metadata_revision,
                    b.expected_policy_revision,b.expected_schema_epoch,
                    s.metadata_revision,s.policy_revision,s.schema_epoch
                    FROM epm.python_plan_artifact a
                    JOIN epm.python_program_build b USING
                      (workspace_id,application_id,build_id)
                    JOIN epm.python_program_publication p ON
                      p.workspace_id=b.workspace_id
                      AND p.application_id=b.application_id
                      AND p.program_id=b.program_id
                      AND p.version=b.program_version
                      AND p.status='Published'
                    JOIN epm.application_state s ON
                      s.workspace_id=b.workspace_id
                      AND s.application_id=b.application_id
                    WHERE a.workspace_id=%s AND a.application_id=%s
                      AND a.build_id=%s AND b.status='sealed'
                      AND b.issuer=%s AND b.subject_id=%s''',
                    (scope.workspace_id, scope.application_id, build_id,
                     self.identity.issuer, self.identity.subject_id)).fetchone()
                if row is None:
                    raise ValueError('PYTHON_SEALED_BUILD_UNAVAILABLE')
                if ((row['expected_metadata_revision'],
                     row['expected_policy_revision'],row['expected_schema_epoch']) !=
                    (row['metadata_revision'],row['policy_revision'],
                     row['schema_epoch'])):
                    raise ValueError('PYTHON_RUN_STALE_CONTEXT')
        canonical = row['canonical_plan']
        if (type(canonical) is not dict or canonical.get('format') !=
                'openepm-python-plan-v1' or type(canonical.get('units')) is not list):
            raise ValueError('PYTHON_STORED_PLAN_INVALID')
        try:
            raw = json.dumps(canonical, sort_keys=True, separators=(',', ':'),
                ensure_ascii=True, allow_nan=False).encode('ascii')
        except (TypeError, ValueError, UnicodeEncodeError) as error:
            raise ValueError('PYTHON_STORED_PLAN_INVALID') from error
        operations = 0
        for unit in canonical['units']:
            if type(unit) is not dict or type(unit.get('operations')) is not list:
                raise ValueError('PYTHON_STORED_PLAN_INVALID')
            operations += len(unit['operations'])
        plan = SealedPlan(canonical, raw, sha256(raw).hexdigest(),
            len(canonical['units']), operations, row['compiler_version'])
        verify_plan_identity(plan, row['plan_digest'])
        return plan

    def compare_and_set(self, current: WorkflowRecord,
                        updated: WorkflowRecord) -> bool:
        if (current.scope != updated.scope
                or current.workflow_id != updated.workflow_id
                or current.build_id != updated.build_id
                or current.plan_digest != updated.plan_digest
                or current.unit_count != updated.unit_count):
            raise ValueError('PYTHON_WORKFLOW_RECORD_MISMATCH')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000); self._scope(db, current.scope)
                row = db.execute('''SELECT * FROM epm.python_program_workflow
                    WHERE workspace_id=%s AND application_id=%s AND workflow_id=%s
                      AND issuer=%s AND subject_id=%s FOR UPDATE''',
                    (current.scope.workspace_id, current.scope.application_id,
                     current.workflow_id, self.identity.issuer,
                     self.identity.subject_id)).fetchone()
                if row is None or _record(row) != current:
                    return False
                self._assert_workflow_authorization_scope(db,current.scope,
                    current.workflow_id)
                if self.worker_claim is None:
                    if (row.get('claimant') is not None
                            and row.get('lease_until') is not None):
                        return False
                elif (current.workflow_id != self.worker_claim['workflow_id']
                      or row.get('claimant') != self.worker_claim['claimant']
                      or row.get('claim_generation') !=
                         self.worker_claim['claim_generation']
                      or row.get('lease_until') is None
                      or not db.execute('SELECT %s>clock_timestamp() AS live',
                            (row['lease_until'],)).fetchone()['live']):
                    return False
                fence = (''' AND claimant IS NULL''' if self.worker_claim is None
                    else ''' AND claimant=%s AND claim_generation=%s
                              AND lease_until>clock_timestamp()''')
                parameters=[updated.status.value,Jsonb(_result(updated)),
                    current.scope.workspace_id,current.scope.application_id,
                    current.workflow_id,current.status.value]
                if self.worker_claim is not None:
                    parameters.extend((self.worker_claim['claimant'],
                                       self.worker_claim['claim_generation']))
                changed = db.execute('''UPDATE epm.python_program_workflow SET
                    status=%s,result=%s,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND workflow_id=%s
                      AND status=%s''' + fence,parameters).rowcount
                if changed != 1:
                    return False
                if len(updated.checkpoints) > len(current.checkpoints):
                    child = updated.checkpoints[-1]
                    db.execute('''INSERT INTO epm.python_program_workflow_child(
                        workspace_id,application_id,workflow_id,unit_ordinal,job_id)
                        VALUES(%s,%s,%s,%s,%s)''',
                        (current.scope.workspace_id, current.scope.application_id,
                         current.workflow_id, child.ordinal, child.job_id))
                return True

    def recover_child(self, workflow: WorkflowRecord, *, ordinal: int,
                      operation: dict) -> UnitCheckpoint | None:
        """Recover a committed job admission after a lost transport response.

        The child key is server-derived.  Exact stored program/function checks
        prevent a caller-owned job from being attached to another sealed unit.
        """
        if (not isinstance(workflow,WorkflowRecord) or type(ordinal) is not int
                or ordinal != len(workflow.checkpoints)+1
                or type(operation) is not dict
                or set(operation) != {'languageVersion','function','arguments'}):
            raise ValueError('PYTHON_WORKFLOW_CHILD_RECOVERY_INVALID')
        key=f'py-{workflow.workflow_id}-{ordinal}'
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db,5000);self._scope(db,workflow.scope)
                access=self._authorize_bound_run(
                    db,workflow.scope,workflow.build_id)
                self._assert_workflow_authorization_scope(db,workflow.scope,
                    workflow.workflow_id,access=access)
                row=db.execute('''SELECT job_id,function_name,normalized_program
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                      AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',
                    (workflow.scope.workspace_id,workflow.scope.application_id,
                     self.identity.issuer,self.identity.subject_id,key)).fetchone()
        if row is None:return None
        # The job stores the compiler-normalized program while the sealed plan
        # retains the public operation.  They are not valid direct equality
        # operands.  As with application-rule recovery, bind the server-owned
        # key and function here, then let the runner replay the exact public
        # operation through the authoritative compiler and queue.  Queue
        # idempotency proves semantic equality before the checkpoint is kept.
        if row['function_name'] != operation['function']:
            raise ValueError('PYTHON_WORKFLOW_CHILD_CONFLICT')
        return UnitCheckpoint(ordinal,row['job_id'],False)
