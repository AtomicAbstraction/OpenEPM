"""Fixed-core orchestration for replaying an already sealed Python plan.

This module never evaluates Python.  It converts each supported atomic unit
back into the ordinary V2 preview/submit lifecycle and records the resulting
job checkpoint.  A narrowly qualified composite is lowered into one existing
transactional batch publisher; every other multi-operation unit is rejected.
Sequential publication is never mislabeled atomic.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Mapping, Protocol

from .persistence_contract import ApplicationScope
from .python_program_execution import (SealedPlan, UnitCheckpoint,
                                       WorkflowRecord, WorkflowStatus,
                                       verify_plan_identity)


class V2Admission(Protocol):
    def preview(self, scope: ApplicationScope, program: dict) -> dict: ...
    def submit(self, scope: ApplicationScope, program: dict, *,
               preview_token: str, idempotency_key: str,
               depends_on_job_ids: tuple[str, ...] = (),
               _execution_authority: Mapping[str, object] | None = None) -> dict: ...


class WorkflowStore(Protocol):
    def create_or_read(self, workflow: WorkflowRecord, *, issuer: str,
                       subject_id: str, idempotency_key: str,
                       request_digest: str) -> WorkflowRecord: ...
    def compare_and_set(self, current: WorkflowRecord,
                        updated: WorkflowRecord) -> bool: ...
    def recover_child(self, workflow: WorkflowRecord, *, ordinal: int,
                      operation: Mapping[str, object]) -> UnitCheckpoint | None: ...
    def authorize_publication(self, workflow: WorkflowRecord) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class ChildOutcome:
    job_id: str
    status: str
    receipt_id: str | None = None


class JobInspector(Protocol):
    def inspect(self, scope: ApplicationScope, job_id: str) -> ChildOutcome: ...
    def request_cancel(self, scope: ApplicationScope, job_id: str) -> None: ...


def workflow_request_digest(scope: ApplicationScope, build_id: str,
                            plan_digest: str, identity: tuple[str, str]) -> str:
    descriptor = {'scope': [scope.workspace_id, scope.application_id],
                  'buildId': build_id, 'planDigest': plan_digest,
                  'identity': list(identity)}
    raw = json.dumps(descriptor, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=True).encode('ascii')
    return sha256(raw).hexdigest()


class SealedPlanRunner:
    """Admit and reconcile supported units without rebuilding the plan."""

    def __init__(self, admission: V2Admission, store: WorkflowStore,
                 inspector: JobInspector):
        self.admission, self.store, self.inspector = admission, store, inspector

    @staticmethod
    def _units(plan: SealedPlan) -> list[Mapping[str, object]]:
        verify_plan_identity(plan, plan.digest)
        units = plan.canonical_plan.get('units')
        if type(units) is not list or len(units) != plan.unit_count:
            raise ValueError('PYTHON_RUN_PLAN_INVALID')
        if any(type(unit) is not dict
               or type(unit.get('operations')) is not list
               or not unit['operations'] for unit in units):
            raise ValueError('PYTHON_RUN_PLAN_INVALID')
        for unit in units:SealedPlanRunner._atomic_operation(unit)
        return units

    @staticmethod
    def _atomic_operation(unit: Mapping[str, object]) -> dict:
        """Lower only units supported by one transactional publisher.

        Numeric and text batch publishers already commit disjoint mutations
        and one receipt in one PostgreSQL transaction. Other V2 publishers do
        not accept a shared transaction/staging handle, so they remain rejected
        rather than being emulated through sequential child jobs.
        """
        operations=unit['operations']
        if len(operations)==1:return dict(operations[0])
        functions={item.get('function') for item in operations
                   if type(item) is dict}
        composite={'facts.numeric.batch','facts.text.batch',
                   'facts.line-detail.replace'}
        if functions==composite:
            from .postgres_composite_fact_batch import compile_program
            program={'languageVersion':2,'function':'facts.composite.batch',
                     'arguments':{'operations':[dict(item)
                                               for item in operations]}}
            compile_program(program)
            return program
        if len(functions)!=1 or next(iter(functions),None) not in (
                'facts.numeric.batch','facts.text.batch'):
            raise ValueError('PYTHON_RUN_COMPOSITE_PUBLISHER_UNAVAILABLE')
        function=next(iter(functions));mutations=[];coordinates=set()
        for operation in operations:
            if (set(operation)!={'languageVersion','function','arguments'}
                    or operation.get('languageVersion')!=2
                    or type(operation.get('arguments')) is not dict
                    or set(operation['arguments'])!={'mutations'}
                    or type(operation['arguments']['mutations']) is not list):
                raise ValueError('PYTHON_RUN_COMPOSITE_BATCH_INVALID')
            for mutation in operation['arguments']['mutations']:
                if (type(mutation) is not dict
                        or type(mutation.get('coordinate')) is not dict):
                    raise ValueError('PYTHON_RUN_COMPOSITE_BATCH_INVALID')
                try:
                    coordinate=json.dumps(mutation['coordinate'],sort_keys=True,
                        separators=(',',':'),ensure_ascii=True,allow_nan=False)
                except (TypeError,ValueError,UnicodeEncodeError) as error:
                    raise ValueError('PYTHON_RUN_COMPOSITE_BATCH_INVALID') from error
                if coordinate in coordinates:
                    raise ValueError('PYTHON_RUN_COMPOSITE_COORDINATE_OVERLAP')
                coordinates.add(coordinate);mutations.append(dict(mutation))
                if len(mutations)>500:
                    raise ValueError('PYTHON_RUN_COMPOSITE_BATCH_LIMIT')
        if not mutations:raise ValueError('PYTHON_RUN_COMPOSITE_BATCH_INVALID')
        return {'languageVersion':2,'function':function,
                'arguments':{'mutations':mutations}}

    def accept(self, scope: ApplicationScope, *, workflow_id: str,
               build_id: str, plan: SealedPlan, issuer: str, subject_id: str,
               idempotency_key: str) -> WorkflowRecord:
        self._units(plan)
        digest = workflow_request_digest(scope, build_id, plan.digest,
                                         (issuer, subject_id))
        proposed = WorkflowRecord(scope, workflow_id, build_id, plan.digest,
                                  plan.unit_count)
        return self.store.create_or_read(proposed, issuer=issuer,
            subject_id=subject_id, idempotency_key=idempotency_key,
            request_digest=digest)

    def advance(self, workflow: WorkflowRecord,
                plan: SealedPlan) -> WorkflowRecord:
        units = self._units(plan)
        if workflow.plan_digest != plan.digest:
            raise ValueError('PYTHON_WORKFLOW_PLAN_MISMATCH')
        current = workflow
        if current.status == WorkflowStatus.ACCEPTED:
            started = current.start()
            if not self.store.compare_and_set(current, started):
                raise ValueError('PYTHON_WORKFLOW_STALE_CONTROL_STATE')
            current = started
        if current.status not in (WorkflowStatus.RUNNING,
                                  WorkflowStatus.CANCEL_REQUESTED):
            return current
        # Reconcile an admitted child before admitting the next unit.  This
        # gives retries a durable, receipt-based boundary.
        if current.checkpoints and not current.checkpoints[-1].committed:
            last = current.checkpoints[-1]
            outcome = self.inspector.inspect(current.scope, last.job_id)
            if outcome.status in ('accepted', 'ready', 'queued', 'running',
                                  'staged', 'cancel_requested'):
                return current
            if outcome.status == 'published' and outcome.receipt_id:
                checkpoints = current.checkpoints[:-1] + (UnitCheckpoint(
                    last.ordinal, last.job_id, True, outcome.receipt_id),)
                updated = WorkflowRecord(current.scope, current.workflow_id,
                    current.build_id, current.plan_digest, current.unit_count,
                    current.status, checkpoints)
                if not self.store.compare_and_set(current, updated):
                    raise ValueError('PYTHON_WORKFLOW_STALE_CONTROL_STATE')
                current = updated
            else:
                settled=(current.settle_cancel()
                         if current.status==WorkflowStatus.CANCEL_REQUESTED
                         else current.fail())
                if not self.store.compare_and_set(current, settled):
                    raise ValueError('PYTHON_WORKFLOW_STALE_CONTROL_STATE')
                return settled
        if current.status == WorkflowStatus.CANCEL_REQUESTED:
            settled = current.settle_cancel()
            if not self.store.compare_and_set(current, settled):
                raise ValueError('PYTHON_WORKFLOW_STALE_CONTROL_STATE')
            return settled
        if len(current.checkpoints) == current.unit_count:
            finished = current.finish()
            if not self.store.compare_and_set(current, finished):
                raise ValueError('PYTHON_WORKFLOW_STALE_CONTROL_STATE')
            return finished
        ordinal = len(current.checkpoints) + 1
        operation = self._atomic_operation(units[ordinal - 1])
        recovered = self.store.recover_child(current, ordinal=ordinal,
                                             operation=operation)
        if recovered is not None:
            # A key lookup locates a possibly lost response; it does not prove
            # semantic equality because the job stores compiler-normalized
            # payload while the sealed plan stores the public operation. Replay
            # the same admission through the authoritative compiler and queue.
            # Queue idempotency rejects different content under the same key.
            self.store.authorize_publication(current)
            preview=self.admission.preview(current.scope,operation)
            token=preview.get('previewToken') if isinstance(preview,dict) else None
            if type(token) is not str or not token:
                raise ValueError('PYTHON_RUN_PREVIEW_INVALID')
            dependencies=(() if not current.checkpoints else
                          (current.checkpoints[-1].job_id,))
            key_factory=getattr(self.store,'child_idempotency_key',None)
            key=(key_factory(current,ordinal) if callable(key_factory)
                 else f'py-{current.workflow_id}-{ordinal}')
            authority=self.store.authorize_publication(current)
            submission=dict(preview_token=token,idempotency_key=key,
                            depends_on_job_ids=dependencies)
            if authority:submission['_execution_authority']=authority
            admitted=self.admission.submit(current.scope,operation,**submission)
            if (not isinstance(admitted,dict)
                    or admitted.get('jobId')!=recovered.job_id):
                raise ValueError('PYTHON_WORKFLOW_CHILD_CONFLICT')
            updated=current.checkpoint(recovered)
            if not self.store.compare_and_set(current,updated):
                raise ValueError('PYTHON_WORKFLOW_STALE_CONTROL_STATE')
            return updated
        # Recheck persisted authority immediately around child admission.  The
        # store derives it from the sealed build; callers cannot swap it.
        self.store.authorize_publication(current)
        preview = self.admission.preview(current.scope, operation)
        token = preview.get('previewToken') if isinstance(preview, dict) else None
        if type(token) is not str or not token:
            raise ValueError('PYTHON_RUN_PREVIEW_INVALID')
        dependencies = (() if not current.checkpoints else
                        (current.checkpoints[-1].job_id,))
        key_factory=getattr(self.store,'child_idempotency_key',None)
        key=(key_factory(current,ordinal) if callable(key_factory)
             else f'py-{current.workflow_id}-{ordinal}')
        authority=self.store.authorize_publication(current)
        submission = dict(
            preview_token=token, idempotency_key=key,
            depends_on_job_ids=dependencies)
        if authority:
            submission['_execution_authority']=authority
        admitted = self.admission.submit(current.scope, operation, **submission)
        job_id = admitted.get('jobId') if isinstance(admitted, dict) else None
        if type(job_id) is not str or not job_id:
            raise ValueError('PYTHON_RUN_ADMISSION_INVALID')
        updated = current.checkpoint(UnitCheckpoint(ordinal, job_id, False))
        if not self.store.compare_and_set(current, updated):
            # The ordinary job submission is idempotent.  A retry uses the same
            # derived key and reconciles the durable child rather than creating
            # another business effect.
            raise ValueError('PYTHON_WORKFLOW_STALE_CONTROL_STATE')
        return updated

    def request_cancel(self, workflow: WorkflowRecord) -> WorkflowRecord:
        updated = workflow.request_cancel()
        if updated != workflow:
            if not self.store.compare_and_set(workflow, updated):
                raise ValueError('PYTHON_WORKFLOW_STALE_CONTROL_STATE')
        if updated.status == WorkflowStatus.CANCEL_REQUESTED:
            pending = next((item for item in reversed(updated.checkpoints)
                            if not item.committed), None)
            if pending is not None:
                # Reissue on an idempotent cancel replay.  A transport failure
                # after the workflow CAS but before child control must not
                # strand the child in running state.
                self.inspector.request_cancel(updated.scope, pending.job_id)
        return updated
