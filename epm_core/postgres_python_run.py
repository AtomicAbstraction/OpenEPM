"""Public control surface for fixed-core execution of sealed Python plans."""
from __future__ import annotations

import re

from .persistence_contract import ApplicationScope
from .postgres_access import VerifiedIdentity
from .postgres_jobs import PostgresJobQueue
from .postgres_python_workflow import (PostgresPythonWorkflowStore,
                                       python_workflow_id)
from .python_plan_runner import ChildOutcome, SealedPlanRunner
from .python_execution_contract import (
    RUN as RUN, workflow_result as _wire, parse_run_program)


_HEX32 = re.compile(r'^[0-9a-f]{32}$')


class _JobInspector:
    def __init__(self, queue: PostgresJobQueue): self.queue = queue
    def inspect(self, scope, job_id):
        value = self.queue.read(scope, job_id)
        status = value['status']
        receipt = job_id if status == 'published' and value.get(
            'receipt_revision') is not None else None
        return ChildOutcome(job_id, status, receipt)
    def request_cancel(self, scope, job_id):
        self.queue.request_cancel(scope, job_id)


class PostgresPythonRun:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity, admission,
                 worker_claim: dict | None = None, _occurrence_admission=None):
        if (type(dsn) is not str or not dsn
                or not isinstance(identity, VerifiedIdentity)
                or not hasattr(admission, 'preview') or not hasattr(admission, 'submit')):
            raise ValueError('PYTHON_RUN_CONFIGURATION_INVALID')
        self.identity = identity
        self.store = PostgresPythonWorkflowStore(dsn, identity=identity,
                                                  worker_claim=worker_claim,
                                                  _occurrence_admission=_occurrence_admission)
        queue = PostgresJobQueue(dsn, identity=identity)
        self.runner = SealedPlanRunner(admission, self.store,
                                       _JobInspector(queue))

    @staticmethod
    def _workflow_id(scope, identity, idempotency_key,*,build_id):
        return python_workflow_id(scope, identity, idempotency_key,build_id=build_id)

    @staticmethod
    def _build_id(program: object, idempotency_key: str) -> str:
        return parse_run_program(program, idempotency_key)

    def replay(self, scope: ApplicationScope, program: object, *,
               idempotency_key: str) -> dict | None:
        build_id=self._build_id(program,idempotency_key)
        record=self.store.replay(scope,build_id=build_id,idempotency_key=idempotency_key)
        return None if record is None else _wire(record)

    def run(self, scope: ApplicationScope, program: object, *,
            idempotency_key: str) -> dict:
        build_id = self._build_id(program,idempotency_key)
        plan = self.store.sealed_plan(scope, build_id)
        from .postgres_python_definitions import descriptor
        if descriptor(plan.canonical_plan) is not None:
            raise ValueError('PYTHON_DEFINITION_USE_COMPILED_EXECUTION')
        workflow = self.runner.accept(scope,
            workflow_id=self._workflow_id(scope,self.identity,idempotency_key,build_id=build_id),
            build_id=build_id, plan=plan, issuer=self.identity.issuer,
            subject_id=self.identity.subject_id,
            idempotency_key=idempotency_key)
        try:
            advanced=self.runner.advance(workflow, plan)
        except ValueError as error:
            if str(error)!='PYTHON_WORKFLOW_STALE_CONTROL_STATE':
                raise
            # A worker may claim and advance this exact durable workflow after
            # accept/replay but before the caller's optional inline quantum.
            # That is successful concurrent progress, not a request failure.
            # Return the caller-scoped durable state; worker paths retain their
            # strict generation/lease fencing through ``advance_existing``.
            advanced=self.store.read(scope,workflow.workflow_id)
        return _wire(advanced)

    def advance_existing(self, scope: ApplicationScope,
                         workflow_id: str) -> dict:
        """Advance one durable quantum; never executes the Python builder."""
        if type(workflow_id) is not str or _HEX32.fullmatch(workflow_id) is None:
            raise ValueError('PYTHON_WORKFLOW_ID_INVALID')
        workflow=self.store.read(scope,workflow_id)
        plan=self.store.sealed_plan(scope,workflow.build_id,
            _cancellation=workflow) if workflow.status.value=='cancel_requested' else self.store.sealed_plan(scope,workflow.build_id)
        return _wire(self.runner.advance(workflow,plan))

    def read(self, scope: ApplicationScope, workflow_id: str) -> dict:
        if type(workflow_id) is not str or _HEX32.fullmatch(workflow_id) is None:
            raise ValueError('PYTHON_WORKFLOW_ID_INVALID')
        return _wire(self.store.read(scope, workflow_id))

    def read_original(self, scope: ApplicationScope, program: dict, *,
                      idempotency_key: str) -> dict:
        """Historical inspection uses READ, never the execution replay path."""
        build_id = self._build_id(program, idempotency_key)
        workflow_id = self._workflow_id(scope, self.identity, idempotency_key, build_id=build_id)
        return _wire(self.store.read(scope, workflow_id, original_build_id=build_id,
            original_idempotency_key=idempotency_key))

    def cancel(self, scope: ApplicationScope, workflow_id: str) -> dict:
        if type(workflow_id) is not str or _HEX32.fullmatch(workflow_id) is None:
            raise ValueError('PYTHON_WORKFLOW_ID_INVALID')
        self.store.authorize_run(scope)
        # Retain current owner/read scope before the shared control owner;
        # unlike execution CAS, control may interrupt an active worker claim.
        self.store.read(scope, workflow_id)
        current = self.store.request_cancel_as_task_controller(scope, workflow_id)
        return _wire(self.runner.request_cancel(current))
