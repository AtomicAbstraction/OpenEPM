"""Bounded long-lived process loop for supported PostgreSQL V2 jobs.

The worker credential is separate from the application runtime credential.
Each tick executes at most one fixed, catalogued job quantum. Staged recovery
can durably yield ready and rotate work classes without publishing its stage.
Recovery is periodic; final publication remains a native application transaction.
"""
from __future__ import annotations

import logging
import os
import socket
import threading
import time
import uuid

import psycopg

from .postgres_jobs import PostgresFixedJobRunner,PostgresJobWorker
from .postgres_cube_aggregate_dispatch import PostgresCubeAggregateDispatch
from .postgres_python_build_dispatch import PostgresPythonBuildDispatch
from .postgres_python_workflow_dispatch import PostgresPythonWorkflowDispatch
from .postgres_application_rule_dispatch import PostgresApplicationRuleDispatch
from .postgres_application_rule_workflow import PostgresApplicationRuleRun
from .postgres_application_schedule_worker import PostgresApplicationScheduleWorker
from .postgres_python_run import PostgresPythonRun
from .postgres_python_schedule_worker import PostgresPythonScheduleWorker
from .postgres_language_v2 import PostgresLanguageV2
from .postgres_import_execution import PostgresImportExecutionWorker
from .postgres_transfer_export_dispatch import PostgresTransferExportDispatch
from .postgres_transfer_orchestration import PostgresTransferExportWorker
from .postgres_cube_aggregate_repository import PostgresCubeAggregateRepository
from .cube_aggregate_lifecycle import AggregateCursorCodec,AggregateQueryStatus
from .cube_aggregate_native import NativeCubeAggregateStage
from .cube_aggregate_service import CubeAggregateService
from .resolved_cube_read_technical import ResolvedCubeReadTechnicalService
from .postgres_access import AccessDenied,durable_execution_identity
from .postgres_expression_sequence import PostgresExpressionSequenceCoordinator
from .postgres_full_sequence import PostgresFullAggregateSequenceCoordinator
from .postgres_service_startup import assert_worker_startup, StartupCancelled
from .observability import observe_worker_tick,record_operational_signal
from .persistence_contract import ApplicationScope


LOG=logging.getLogger(__name__)
_PYTHON_SAFE_ERROR_PREFIXES=('PYTHON_SANDBOX_','PYTHON_BUILD_','BUILDER_')
_PYTHON_DISPATCH_SETTLEMENT_CODES=frozenset((
    'PYTHON_BUILD_AUTHORIZATION_REVOKED',
    'PYTHON_BUILD_CAPABILITY_UNAVAILABLE',
    'PYTHON_SANDBOX_RUNTIME_UNAVAILABLE',
    'PYTHON_BUILD_WORKER_FAILED'))


def _python_build_error_code(error: Exception) -> str:
    """Preserve only bounded public sandbox codes across the outer dispatcher."""
    value=str(error)
    if (isinstance(error,ValueError)
            and value.startswith(_PYTHON_SAFE_ERROR_PREFIXES)
            and len(value)<=100
            and value.replace('_','').isalnum()
            and value.upper()==value):
        return value
    return 'PYTHON_BUILD_WORKER_FAILED'


class PostgresWorkerService:
    def __init__(self,*,worker_dsn: str,runtime_dsn: str,
                 preview_secret: bytes,
                 recovery_interval: float=30.0,poll_interval: float=0.5,
                 scope: ApplicationScope | None=None,
                 capacity_limits: tuple[int,int,int]=(32,8,2),
                 python_build_worker=None,heartbeat=None):
        if (not isinstance(worker_dsn,str) or not worker_dsn
                or not isinstance(runtime_dsn,str) or not runtime_dsn
                or not isinstance(preview_secret,bytes)
                or len(preview_secret)<32
                or not 1 <= recovery_interval <= 300
                or not 0.05 <= poll_interval <= 30
                or (scope is not None and not isinstance(scope,ApplicationScope))
                or not isinstance(capacity_limits,tuple)
                or len(capacity_limits)!=3
                or any(type(limit) is not int or not 1 <= limit <= 10000
                       for limit in capacity_limits)
                or not (capacity_limits[0]>=capacity_limits[1]>=
                        capacity_limits[2])):
            raise ValueError('Invalid worker service configuration')
        self.worker_dsn=worker_dsn
        self.runtime_dsn=runtime_dsn
        self.recovery_interval=float(recovery_interval)
        self.poll_interval=float(poll_interval)
        self.scope=scope
        self.capacity_limits=capacity_limits
        self.class_cursor=0
        # Rotate across operation families as well as resource classes.  A
        # permanently non-empty business-job queue must not starve technical
        # queries, Python work or schedules. Each tick still executes at most
        # one family quantum.
        self.family_cursor=0
        self.worker=PostgresJobWorker(worker_dsn)
        self.sequence=PostgresExpressionSequenceCoordinator(
            worker_dsn=worker_dsn,runtime_dsn=runtime_dsn,
            preview_secret=preview_secret)
        self.full_sequence=PostgresFullAggregateSequenceCoordinator(
            worker_dsn=worker_dsn,runtime_dsn=runtime_dsn,
            preview_secret=preview_secret)
        self.runner=PostgresFixedJobRunner(
            worker_dsn=worker_dsn,runtime_dsn=runtime_dsn)
        self.preview_secret=preview_secret
        self.aggregate_dispatch=None
        if (python_build_worker is not None
                and not hasattr(python_build_worker, 'run_claim')):
            raise ValueError('Invalid Python build worker configuration')
        self.python_build_worker=python_build_worker
        if heartbeat is not None and not callable(heartbeat):
            raise ValueError('WORKER_HEARTBEAT_INVALID')
        self.heartbeat=heartbeat
        self.python_build_dispatch=None
        self.python_workflow_dispatch=None
        self.application_rule_dispatch=None
        self.application_schedule_worker=None
        self.python_schedule_worker=None
        self.claimant=(f'{socket.gethostname()}:{os.getpid()}:'+
                       uuid.uuid4().hex)[:200]
        if (self.python_build_worker is not None
                and hasattr(self.python_build_worker,'bind_worker_id')):
            self.python_build_worker.bind_worker_id(self.claimant)
        # Role attestation in run() must happen before any service constructor
        # opens a database connection.
        self.import_execution_worker=None
        self.transfer_export_dispatch=None
        self.next_recovery=0.0

    def assert_roles(self, *, stop=None) -> None:
        assert_worker_startup(self.worker_dsn,self.runtime_dsn,stop=stop)

    def tick(self) -> dict | None:
        now=time.monotonic()
        if now>=self.next_recovery:
            recovered=self._defer_lock_contention(self.worker.recover_expired)
            aggregate_dispatch=self._aggregate_dispatch()
            self._defer_lock_contention(aggregate_dispatch.recover)
            self._defer_lock_contention(aggregate_dispatch.expire)
            if self.python_build_worker is not None:
                self._defer_lock_contention(self._python_dispatch().recover)
            # As with the other global adapters, keep role attestation ahead of
            # first construction. Once the stage has been visited, periodically
            # recover its expired generation-fenced claims.
            if self.python_workflow_dispatch is not None:
                self._defer_lock_contention(self.python_workflow_dispatch.recover)
            if self.application_rule_dispatch is not None:
                self._defer_lock_contention(self.application_rule_dispatch.recover)
            if self.application_schedule_worker is not None:
                self._defer_lock_contention(
                    self.application_schedule_worker.dispatch.recover)
            if recovered is not None:
                self.next_recovery=now+self.recovery_interval
        sequence_result=self._defer_lock_contention(self.sequence.advance_once,scope=self.scope)
        full_sequence_result=self._defer_lock_contention(self.full_sequence.advance_once,scope=self.scope)
        family_result=None
        families=(self._run_business_job_once,self._run_aggregate_once,
                  self._run_python_build_once,self._run_python_workflow_once,
                  self._run_application_rule_once,
                  self._run_application_schedule_once,
                  self._run_import_execution_once,
                  self._run_transfer_export_once,
                  self._run_python_schedule_once)
        for offset in range(len(families)):
            index=(self.family_cursor+offset)%len(families)
            family_result=self._defer_lock_contention(families[index])
            if family_result is not None:
                self.family_cursor=(index+1)%len(families)
                break
        return family_result or sequence_result or full_sequence_result

    def _run_business_job_once(self):
        classes=('short','medium','long')
        job_result=None
        for offset in range(len(classes)):
            index=(self.class_cursor+offset)%len(classes)
            job_result=self._defer_lock_contention(self.runner.run_once,
                self.claimant,scope=self.scope,
                resource_class=classes[index],
                capacity_limits=self.capacity_limits)
            if job_result is not None:
                # A successful staged checkpoint is work too: rotate instead
                # of draining an entire long reconstruction inside one tick.
                self.class_cursor=(index+1)%len(classes)
                break
        return job_result

    def _run_import_execution_once(self):
        if self.import_execution_worker is None:
            self.import_execution_worker=PostgresImportExecutionWorker(
                self.worker_dsn,runtime_dsn=self.runtime_dsn,
                worker_id=self.claimant,preview_secret=self.preview_secret)
        claim=self.import_execution_worker.claim_next(
            capacity_limits=self.capacity_limits)
        return (None if claim is None
                else self.import_execution_worker.run_claim(claim))

    def _run_transfer_export_once(self):
        if self.transfer_export_dispatch is None:
            self.transfer_export_dispatch=PostgresTransferExportDispatch(
                self.worker_dsn)
        claim=self.transfer_export_dispatch.claim(
            self.claimant,capacity_limits=self.capacity_limits)
        if claim is None:return None
        claim={**claim,'claimant':self.claimant}
        try:
            return PostgresTransferExportWorker(
                self.runtime_dsn,
                identity=durable_execution_identity(claim),
                preview_secret=self.preview_secret,
                worker_id=self.claimant).process(
                    ApplicationScope(claim['workspace_id'],
                                     claim['application_id']),
                    claim['request_id'],chunk_budget=1,page_budget=1)
        except AccessDenied:
            code='EXPORT_PRODUCER_AUTHORIZATION_REVOKED'
        except ValueError as error:
            value=str(error)
            code=(value if len(value)<=128 and value.isascii()
                  and value.replace('_','').isalnum()
                  and value.upper()==value
                  else 'EXPORT_PRODUCER_WORKER_FAILED')
        except Exception:
            # Export production is checkpointed and the dispatcher settlement
            # is generation-fenced. Contain an unexpected poisoned request so
            # it cannot repeatedly expire its lease or terminate the shared
            # worker. Exception text may include payload or storage details.
            code='EXPORT_PRODUCER_WORKER_FAILED'
        if not self.transfer_export_dispatch.settle_failed(claim,code):
            raise ValueError('EXPORT_PRODUCER_STALE_WORKER_FENCE')
        return {'requestId':claim['request_id'],'status':'failed',
                'errorCode':code}

    def _run_python_schedule_once(self):
        if self.python_schedule_worker is None:
            self.python_schedule_worker=PostgresPythonScheduleWorker(
                worker_dsn=self.worker_dsn,runtime_dsn=self.runtime_dsn,
                admission_factory=lambda identity:PostgresLanguageV2(
                    self.runtime_dsn,identity=identity,
                    preview_secret=self.preview_secret),worker_id=self.claimant)
        return (self.python_schedule_worker.advance_once()
                or self.python_schedule_worker.materialize_once())

    def _aggregate_dispatch(self):
        if self.aggregate_dispatch is None:
            self.aggregate_dispatch=PostgresCubeAggregateDispatch(self.worker_dsn)
        return self.aggregate_dispatch

    def _python_dispatch(self):
        if self.python_build_dispatch is None:
            self.python_build_dispatch=PostgresPythonBuildDispatch(self.worker_dsn)
        return self.python_build_dispatch

    def _python_workflow_dispatch(self):
        if self.python_workflow_dispatch is None:
            self.python_workflow_dispatch=PostgresPythonWorkflowDispatch(
                self.worker_dsn)
        return self.python_workflow_dispatch

    def _run_python_workflow_once(self):
        dispatch=self._python_workflow_dispatch()
        claim=dispatch.claim(self.claimant,capacity_limits=self.capacity_limits)
        if claim is None:return None
        owned={**claim,'claimant':self.claimant}
        scope=ApplicationScope(claim['workspace_id'],claim['application_id'])
        identity=durable_execution_identity(claim)
        language=PostgresLanguageV2(self.runtime_dsn,identity=identity,
                                    preview_secret=self.preview_secret)
        service=PostgresPythonRun(self.runtime_dsn,identity=identity,
            admission=language,worker_claim=owned)
        settled=False;renew_stop=threading.Event();renew_errors=[]
        def renew_lease():
            while not renew_stop.wait(20):
                try:
                    if not dispatch.renew(owned,lease_seconds=65):
                        renew_errors.append('PYTHON_WORKFLOW_LEASE_LOST');return
                except Exception as error:  # reported after the bounded quantum
                    renew_errors.append(error);return
        renewer=threading.Thread(target=renew_lease,
            name='openepm-python-workflow-lease',daemon=True)
        renewer.start()
        try:
            result=service.advance_existing(scope,claim['workflow_id'])
            if renew_errors:
                raise ConnectionError('PYTHON_WORKFLOW_LEASE_RENEWAL_FAILED')
            return result
        except AccessDenied:
            settled=dispatch.settle_failed(owned,
                'PYTHON_WORKFLOW_AUTHORIZATION_REVOKED')
            return {'workflowId':claim['workflow_id'],
                'status':'failed','errorCode':
                'PYTHON_WORKFLOW_AUTHORIZATION_REVOKED'}
        except ValueError as error:
            value=str(error)
            if value in ('PYTHON_WORKFLOW_CHILD_CONFLICT',
                    'IDEMPOTENCY_KEY_REUSED'):
                code='PYTHON_WORKFLOW_CHILD_CONFLICT'
                outcome=dispatch.settle_unexpected(owned,code)
                if outcome is None:
                    raise ValueError('PYTHON_WORKFLOW_STALE_WORKER_FENCE')
                settled=True
                return {'workflowId':claim['workflow_id'],
                    'status':outcome,'errorCode':code}
            if value in ('PYTHON_RUN_STALE_CONTEXT',
                    'STALE_CELL_CHANGE_ID','STALE_DATA_REVISION',
                    'STALE_METADATA_REVISION','STALE_POLICY_REVISION'):
                settled=dispatch.settle_failed(owned,
                    'PYTHON_WORKFLOW_STALE_CONTEXT')
                return {'workflowId':claim['workflow_id'],
                    'status':'failed','errorCode':'PYTHON_WORKFLOW_STALE_CONTEXT'}
            code='PYTHON_WORKFLOW_WORKER_FAILED'
            outcome=dispatch.settle_unexpected(owned,code)
            if outcome is None:
                raise ValueError('PYTHON_WORKFLOW_STALE_WORKER_FENCE')
            settled=True
            return {'workflowId':claim['workflow_id'],'status':outcome,
                    'errorCode':code}
        except (psycopg.Error,OSError,TimeoutError):
            code='PYTHON_WORKFLOW_INFRASTRUCTURE_FAILURE'
            outcome=dispatch.settle_unexpected(owned,code)
            if outcome is None:
                raise ValueError('PYTHON_WORKFLOW_STALE_WORKER_FENCE')
            settled=True
            return {'workflowId':claim['workflow_id'],'status':outcome,
                    'errorCode':code}
        except Exception:
            code='PYTHON_WORKFLOW_WORKER_FAILED'
            outcome=dispatch.settle_unexpected(owned,code)
            if outcome is None:
                raise ValueError('PYTHON_WORKFLOW_STALE_WORKER_FENCE')
            settled=True
            return {'workflowId':claim['workflow_id'],'status':outcome,
                    'errorCode':code}
        finally:
            renew_stop.set();renewer.join(timeout=2)
            # One quantum per claim keeps scheduling fair. A stale worker cannot
            # clear a successor's claim because release is generation-fenced.
            if not settled:dispatch.release(owned)

    def _application_rule_dispatch(self):
        if self.application_rule_dispatch is None:
            self.application_rule_dispatch=PostgresApplicationRuleDispatch(
                self.worker_dsn)
        return self.application_rule_dispatch

    def _run_application_schedule_once(self):
        if self.application_schedule_worker is None:
            self.application_schedule_worker=PostgresApplicationScheduleWorker(
                worker_dsn=self.worker_dsn,runtime_dsn=self.runtime_dsn,
                preview_secret=self.preview_secret,worker_id=self.claimant,
                capacity_limits=self.capacity_limits)
        # Reconcile already materialized work before admitting another due
        # occurrence. Each call remains one bounded wrapper quantum.
        return (self.application_schedule_worker.advance_once()
                or self.application_schedule_worker.materialize_once())

    def _run_application_rule_once(self):
        dispatch=self._application_rule_dispatch()
        claim=dispatch.claim(self.claimant,capacity_limits=self.capacity_limits)
        if claim is None:return None
        owned={**claim,'claimant':self.claimant}
        scope=ApplicationScope(claim['workspace_id'],claim['application_id'])
        identity=durable_execution_identity(claim)
        language=PostgresLanguageV2(self.runtime_dsn,identity=identity,
                                    preview_secret=self.preview_secret)
        service=PostgresApplicationRuleRun(self.runtime_dsn,identity=identity,
            language=language,worker_claim=owned)
        settled=False;renew_stop=threading.Event();renew_errors=[]
        def renew_lease():
            while not renew_stop.wait(20):
                try:
                    if not dispatch.renew(owned,lease_seconds=65):
                        renew_errors.append('APPLICATION_RULE_LEASE_LOST');return
                except Exception as error:
                    renew_errors.append(error);return
        renewer=threading.Thread(target=renew_lease,
            name='openepm-application-rule-lease',daemon=True)
        renewer.start()
        try:
            result=service.advance_existing(scope,claim['workflow_id'])
            if renew_errors:
                raise ConnectionError('APPLICATION_RULE_LEASE_RENEWAL_FAILED')
            return result
        except AccessDenied:
            settled=dispatch.settle_failed(owned,
                'APPLICATION_RULE_AUTHORIZATION_REVOKED')
            return {'workflowId':claim['workflow_id'],'status':'failed',
                    'errorCode':'APPLICATION_RULE_AUTHORIZATION_REVOKED'}
        except ValueError as error:
            if str(error) not in ('APPLICATION_RULE_WORKFLOW_PUBLICATION_STALE',
                    'APPLICATION_RULE_WORKFLOW_CONTEXT_STALE','STALE_CELL_CHANGE_ID',
                    'STALE_DATA_REVISION','STALE_METADATA_REVISION',
                    'STALE_POLICY_REVISION'):
                code='APPLICATION_RULE_WORKER_FAILED'
                outcome=dispatch.settle_unexpected(owned,code)
                if outcome is None:
                    raise ValueError('APPLICATION_RULE_STALE_WORKER_FENCE')
                settled=True
                return {'workflowId':claim['workflow_id'],'status':outcome,
                        'errorCode':code}
            settled=dispatch.settle_failed(owned,
                'APPLICATION_RULE_STALE_CONTEXT')
            return {'workflowId':claim['workflow_id'],'status':'failed',
                    'errorCode':'APPLICATION_RULE_STALE_CONTEXT'}
        except (psycopg.Error,OSError,TimeoutError):
            code='APPLICATION_RULE_INFRASTRUCTURE_FAILURE'
            outcome=dispatch.settle_unexpected(owned,code)
            if outcome is None:
                raise ValueError('APPLICATION_RULE_STALE_WORKER_FENCE')
            settled=True
            return {'workflowId':claim['workflow_id'],'status':outcome,
                    'errorCode':code}
        except Exception:
            code='APPLICATION_RULE_WORKER_FAILED'
            outcome=dispatch.settle_unexpected(owned,code)
            if outcome is None:
                raise ValueError('APPLICATION_RULE_STALE_WORKER_FENCE')
            settled=True
            return {'workflowId':claim['workflow_id'],'status':outcome,
                    'errorCode':code}
        finally:
            renew_stop.set();renewer.join(timeout=2)
            if not settled:dispatch.release(owned)

    def _run_python_build_once(self):
        if self.python_build_worker is None:return None
        dispatch=self._python_dispatch()
        limits=(min(10,self.capacity_limits[0]),
                min(5,self.capacity_limits[1]),
                min(2,self.capacity_limits[2]))
        claim=dispatch.claim(self.claimant,lease_seconds=90,
                             capacity_limits=limits)
        if claim is None:return None
        scope=ApplicationScope(claim['workspace_id'],claim['application_id'])
        try:
            return self.python_build_worker.run_claim(scope,claim['build_id'],
                claim['claim_generation'])
        except AccessDenied:
            dispatch.settle_failed({**claim,'claimant':self.claimant},
                'PYTHON_BUILD_AUTHORIZATION_REVOKED')
            return {'buildId':claim['build_id'],'status':'failed',
                    'errorCode':'PYTHON_BUILD_AUTHORIZATION_REVOKED'}
        except ValueError as error:
            code=_python_build_error_code(error)
            settlement_code=(code if code in _PYTHON_DISPATCH_SETTLEMENT_CODES
                else 'PYTHON_BUILD_WORKER_FAILED')
            settled=dispatch.settle_failed(
                {**claim,'claimant':self.claimant},settlement_code)
            if settled:
                code=settlement_code
            return {'buildId':claim['build_id'],'status':'failed',
                    'errorCode':code}
        except Exception:
            # The build worker may already have durably failed its repository
            # row before propagating an unexpected launcher/compiler error.
            # Reconcile the generation-fenced dispatch claim as terminal too,
            # so one poisoned build cannot repeatedly expire its lease or
            # terminate the shared multi-family worker loop. Never expose the
            # exception text, which may contain source or sandbox details.
            dispatch.settle_failed({**claim,'claimant':self.claimant},
                                   'PYTHON_BUILD_WORKER_FAILED')
            return {'buildId':claim['build_id'],'status':'failed',
                    'errorCode':'PYTHON_BUILD_WORKER_FAILED'}

    def _run_aggregate_once(self):
        dispatch=self._aggregate_dispatch()
        claim=dispatch.claim(self.claimant,capacity_limits=self.capacity_limits)
        if claim is None:return None
        scope=ApplicationScope(claim['workspace_id'],claim['application_id'])
        identity=durable_execution_identity(claim)
        repository=PostgresCubeAggregateRepository(self.runtime_dsn,identity=identity)
        resolved=claim.get('request_family')=='resolved_read'
        if resolved:
            service=ResolvedCubeReadTechnicalService(self.runtime_dsn,
                identity=identity,cursor_codec=AggregateCursorCodec(
                    self.preview_secret))
            certificate_wire=service._certificate
        else:
            service=CubeAggregateService(repository,
                NativeCubeAggregateStage(self.runtime_dsn,identity=identity),
                AggregateCursorCodec(self.preview_secret),identity=identity)
            certificate_wire=service._certificate_wire
        try:
            record=(repository.get_resolved(scope,claim['query_id'])
                    if resolved else repository.get(scope,claim['query_id']))
            if record is None:raise AccessDenied('APPLICATION_UNAVAILABLE')
            # Computed rows are deliberately short, lease-free sealing work.
            # Another worker may seal the same row after this worker's claim
            # transaction. Treat that observed terminal state as idempotent
            # replay instead of attempting to compute it again.
            if record.status is AggregateQueryStatus.SEALED:
                return {'queryId':record.query_id,'status':'sealed',
                    'technicalCertificate':certificate_wire(
                        record.certificate)}
            if record.status in (AggregateQueryStatus.CANCELLED,
                    AggregateQueryStatus.FAILED,AggregateQueryStatus.EXPIRED):
                result={'queryId':record.query_id,
                        'status':record.status.value}
                if record.error_code is not None:
                    result['errorCode']=record.error_code
                return result
            if record.status is AggregateQueryStatus.COMPUTED:
                sealed=repository.seal(record)
                return {'queryId':sealed.query_id,'status':sealed.status.value,
                    'technicalCertificate':certificate_wire(sealed.certificate)}
            worker_claim={'record':record,
                'normalizedRequest':claim['normalized_request'],
                'claimant':self.claimant,
                'claimGeneration':claim['claim_generation']}
            if record.status is AggregateQueryStatus.CANCEL_REQUESTED:
                if not repository.settle_cancelled_claim(worker_claim):
                    raise ValueError('CUBE_AGGREGATE_STALE_WORKER_FENCE')
                return {'queryId':record.query_id,'status':'cancelled'}
            return service.worker_run_claim(worker_claim)
        except AccessDenied:
            if claim['status']=='running':
                dispatch.settle_failed({**claim,'claimant':self.claimant},
                    'CUBE_AGGREGATE_AUTHORIZATION_REVOKED')
            return {'queryId':claim['query_id'],'status':'failed',
                    'errorCode':'CUBE_AGGREGATE_AUTHORIZATION_REVOKED'}
        except Exception:
            # The private result or final seal may already have committed even
            # though the worker lost its acknowledgement. Reconcile the exact
            # generation and durable last claimant before admitting a retry;
            # never expose exception text or rescan a computed result.
            reconciled=dispatch.reconcile_unexpected(
                {**claim,'claimant':self.claimant})
            status=reconciled['status']
            if status=='stale':
                raise ValueError('CUBE_AGGREGATE_STALE_WORKER_FENCE') from None
            result={'queryId':claim['query_id'],'status':status}
            if status=='ready':
                result['errorCode']='CUBE_AGGREGATE_WORKER_RETRY_SCHEDULED'
            elif reconciled.get('errorCode') is not None:
                result['errorCode']=reconciled['errorCode']
            elif status=='sealed':
                current=(repository.get_resolved(scope,claim['query_id'])
                    if resolved else repository.get(scope,claim['query_id']))
                if current is None or current.certificate is None:
                    raise ValueError(
                        'CUBE_AGGREGATE_RECONCILIATION_INVALID') from None
                result['technicalCertificate']=certificate_wire(
                    current.certificate)
            return result

    @staticmethod
    def _defer_lock_contention(operation,*args,**kwargs):
        try:
            return operation(*args,**kwargs)
        except psycopg.errors.LockNotAvailable:
            record_operational_signal('lock_wait')
            # The callee's transaction has unwound. Do not declare failed
            # business work, hide other database errors, or skip other stages.
            LOG.debug('Processing stage deferred by transient lock contention')
            return None

    def run(self,stop: threading.Event) -> None:
        if not isinstance(stop,threading.Event):
            raise ValueError('A stop event is required')
        try:
            self.assert_roles(stop=stop)
        except StartupCancelled:
            if stop.is_set():return
            raise
        if self.heartbeat is not None:self.heartbeat()
        while not stop.is_set():
            if self.heartbeat is not None:self.heartbeat()
            try:
                with observe_worker_tick(logger=LOG) as observation:
                    result=self.tick()
                    if result is not None:
                        observation['status']=str(result.get('status','completed'))
                        observation['family']=(
                            'aggregate' if result.get('queryId') else
                            'python_build' if result.get('buildId') else
                            'python_workflow' if result.get('workflowId') else
                            'python_schedule' if result.get('occurrenceId') else
                            'sequence' if result.get('sequenceId') else
                            'business')
                if result is not None:
                    if result.get('errorCode','').endswith('RETRY_SCHEDULED'):
                        record_operational_signal('retry',family=observation['family'])
                    if 'STALE_WORKER' in result.get('errorCode',''):
                        record_operational_signal('lease_loss',family=observation['family'])
                    if result.get('checkpoint') is True:
                        LOG.debug('Checkpointed work %s: %s',result.get('jobId'),
                                  result.get('result',{}).get('phase'))
                    else:
                        LOG.info('Processed work %s: %s%s',
                                 result.get('jobId') or result.get('sequenceId'),
                                 result['status'],
                                 (f" ({result['errorCode']})"
                                  if result.get('errorCode') else ''))
                    continue
            except psycopg.Error as error:
                # PostgreSQL diagnostics can echo SQL values. Keep the
                # operational class and SQLSTATE without logging the message.
                LOG.error('Worker database %s failure (%s); retrying after pause',
                          type(error).__name__,error.sqlstate or 'no-sqlstate')
            except Exception as error:
                # Family handlers must durably reconcile claimed work before
                # returning. This outer boundary is a last-resort availability
                # fence: an implementation defect in one tick must not kill the
                # shared worker and starve every other family. Do not include
                # exception text because it may contain payload or secret data.
                LOG.error('Worker unexpected %s failure; continuing after pause',
                          type(error).__name__)
            stop.wait(self.poll_interval)
