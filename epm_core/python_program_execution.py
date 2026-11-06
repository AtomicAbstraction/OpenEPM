"""Fixed-core contracts for isolated Python builds and sealed-plan execution.

Trusted services coordinate durable state through these types.  They never
import, evaluate or execute authored Python: an external sandbox launcher
returns JSON, which is canonicalized and validated again before it can be
sealed.  Business effects remain ordinary V2 jobs owned by the existing core.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from hashlib import sha256
import json
import re
from typing import Mapping, Protocol, Sequence

from .persistence_contract import ApplicationScope


MAX_PLAN_BYTES = 4 * 1024 * 1024
MAX_OPERATIONS = 10_000
MAX_SOURCE_MAP_BYTES = 1024 * 1024
MAX_BUILD_LOG_BYTES = 1024 * 1024
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _identifier(value: object, code: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError(code)
    return value


def _digest(value: object, code: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise ValueError(code)
    return value


def _canonical(value: object, code: str) -> bytes:
    def inspect(item: object) -> None:
        if isinstance(item, float):
            raise ValueError(code)
        if isinstance(item, Mapping):
            if any(type(key) is not str for key in item):
                raise ValueError(code)
            for child in item.values():
                inspect(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                inspect(child)
        elif item is not None and type(item) not in (str, int, bool):
            raise ValueError(code)
    inspect(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError(code) from error


class FunctionValidator(Protocol):
    """Authoritative registry/compiler boundary, not a client allow-list."""

    def validate_operation(self, scope: ApplicationScope, function: str,
                           arguments: Mapping[str, object]) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class SealedPlan:
    canonical_plan: Mapping[str, object]
    canonical_bytes: bytes
    digest: str
    unit_count: int
    operation_count: int
    compiler_version: str


def validate_proposed_plan(scope: ApplicationScope, proposed: object, *,
                           registry: FunctionValidator,
                           compiler_version: str) -> SealedPlan:
    """Validate sandbox JSON and return the only replayable execution artifact."""
    if not isinstance(scope, ApplicationScope):
        raise ValueError("PYTHON_PLAN_SCOPE_INVALID")
    _identifier(compiler_version, "PYTHON_PLAN_COMPILER_INVALID")
    if type(proposed) is not dict or set(proposed) != {"format", "units"}:
        raise ValueError("PYTHON_PLAN_INVALID")
    if proposed.get("format") != "openepm-python-plan-v1":
        raise ValueError("PYTHON_PLAN_FORMAT_UNSUPPORTED")
    units = proposed.get("units")
    if type(units) is not list or not units or len(units) > MAX_OPERATIONS:
        raise ValueError("PYTHON_PLAN_UNITS_INVALID")
    normalized_units: list[dict[str, object]] = []
    operations = 0
    for unit in units:
        if type(unit) is not dict or set(unit) != {"name", "operations"}:
            raise ValueError("PYTHON_PLAN_UNIT_INVALID")
        name = _identifier(unit["name"], "PYTHON_PLAN_UNIT_INVALID")
        raw_operations = unit["operations"]
        if type(raw_operations) is not list or not raw_operations:
            raise ValueError("PYTHON_PLAN_UNIT_INVALID")
        normalized_operations = []
        for operation in raw_operations:
            operations += 1
            if operations > MAX_OPERATIONS:
                raise ValueError("PYTHON_PLAN_OPERATION_LIMIT")
            if type(operation) is not dict or set(operation) != {
                    "languageVersion", "function", "arguments"}:
                raise ValueError("PYTHON_PLAN_OPERATION_INVALID")
            if operation["languageVersion"] != 2:
                raise ValueError("PYTHON_PLAN_LANGUAGE_UNSUPPORTED")
            function = _identifier(operation["function"],
                                   "PYTHON_PLAN_FUNCTION_INVALID")
            arguments = operation["arguments"]
            if type(arguments) is not dict:
                raise ValueError("PYTHON_PLAN_ARGUMENTS_INVALID")
            # The server registry normalizes and rejects SQL/code/internal-engine
            # choices for each function.  The sandbox cannot declare a backend.
            normalized = registry.validate_operation(scope, function, arguments)
            if type(normalized) is not dict:
                raise ValueError("PYTHON_PLAN_REGISTRY_RESULT_INVALID")
            normalized_operations.append({"languageVersion": 2,
                "function": function, "arguments": normalized})
        normalized_units.append({"name": name,
                                 "operations": normalized_operations})
    plan = {"format": "openepm-python-plan-v1", "units": normalized_units}
    raw = _canonical(plan, "PYTHON_PLAN_NOT_CANONICAL_JSON")
    if len(raw) > MAX_PLAN_BYTES:
        raise ValueError("PYTHON_PLAN_BYTE_LIMIT")
    return SealedPlan(plan, raw, sha256(raw).hexdigest(), len(units), operations,
                      compiler_version)


class BuildStatus(StrEnum):
    ACCEPTED = "accepted"
    READY = "ready"
    RUNNING = "running"
    SEALED = "sealed"
    FAILED = "failed"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class BuildRecord:
    scope: ApplicationScope
    build_id: str
    request_digest: str
    status: BuildStatus
    claim_generation: int = 0
    claimant: str | None = None
    lease_until: int | None = None
    attempts: int = 0
    plan_digest: str | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        if (not isinstance(self.scope, ApplicationScope)
                or type(self.build_id) is not str
                or _HEX32.fullmatch(self.build_id) is None):
            raise ValueError("PYTHON_BUILD_ID_INVALID")
        _digest(self.request_digest, "PYTHON_BUILD_REQUEST_DIGEST_INVALID")
        if not isinstance(self.status, BuildStatus):
            raise ValueError("PYTHON_BUILD_STATUS_INVALID")
        if type(self.claim_generation) is not int or self.claim_generation < 0:
            raise ValueError("PYTHON_BUILD_CLAIM_INVALID")
        if type(self.attempts) is not int or self.attempts < 0:
            raise ValueError("PYTHON_BUILD_ATTEMPTS_INVALID")
        running = self.status in (BuildStatus.RUNNING, BuildStatus.CANCEL_REQUESTED)
        if running != (self.claimant is not None and self.lease_until is not None):
            raise ValueError("PYTHON_BUILD_LEASE_INVALID")
        if self.claimant is not None:
            _identifier(self.claimant, "PYTHON_BUILD_CLAIM_INVALID")
        if self.lease_until is not None and (type(self.lease_until) is not int
                                             or self.lease_until < 0):
            raise ValueError("PYTHON_BUILD_LEASE_INVALID")
        if self.status == BuildStatus.SEALED:
            _digest(self.plan_digest, "PYTHON_BUILD_PLAN_REQUIRED")
        elif self.plan_digest is not None:
            raise ValueError("PYTHON_BUILD_PLAN_UNEXPECTED")
        if self.status == BuildStatus.FAILED:
            _identifier(self.error_code, "PYTHON_BUILD_ERROR_REQUIRED")
        elif self.error_code is not None:
            raise ValueError("PYTHON_BUILD_ERROR_UNEXPECTED")

    def ready(self) -> BuildRecord:
        if self.status != BuildStatus.ACCEPTED:
            raise ValueError("PYTHON_BUILD_TRANSITION_INVALID")
        return replace(self, status=BuildStatus.READY)

    def claim(self, worker_id: str, *, lease_until: int) -> BuildRecord:
        if self.status != BuildStatus.READY:
            raise ValueError("PYTHON_BUILD_TRANSITION_INVALID")
        _identifier(worker_id, "PYTHON_BUILD_CLAIM_INVALID")
        return replace(self, status=BuildStatus.RUNNING,
                       claim_generation=self.claim_generation + 1,
                       claimant=worker_id, lease_until=lease_until,
                       attempts=self.attempts + 1)

    def renew(self, worker_id: str, generation: int, *, lease_until: int) -> BuildRecord:
        self.assert_claim(worker_id, generation)
        return replace(self, lease_until=lease_until)

    def assert_claim(self, worker_id: str, generation: int) -> None:
        if (self.status not in (BuildStatus.RUNNING, BuildStatus.CANCEL_REQUESTED)
                or self.claimant != worker_id or self.claim_generation != generation):
            raise ValueError("PYTHON_BUILD_STALE_CLAIM")

    def request_cancel(self) -> BuildRecord:
        if self.status in (BuildStatus.ACCEPTED, BuildStatus.READY):
            return replace(self, status=BuildStatus.CANCELLED)
        if self.status == BuildStatus.RUNNING:
            return replace(self, status=BuildStatus.CANCEL_REQUESTED)
        if self.status in (BuildStatus.CANCEL_REQUESTED, BuildStatus.CANCELLED):
            return self
        raise ValueError("PYTHON_BUILD_CANCEL_NOT_AVAILABLE")

    def seal(self, worker_id: str, generation: int, plan: SealedPlan) -> BuildRecord:
        self.assert_claim(worker_id, generation)
        if self.status == BuildStatus.CANCEL_REQUESTED:
            raise ValueError("PYTHON_BUILD_CANCELLED_BEFORE_SEAL")
        if not isinstance(plan, SealedPlan):
            raise ValueError("PYTHON_PLAN_REQUIRED")
        return replace(self, status=BuildStatus.SEALED, claimant=None,
                       lease_until=None, plan_digest=plan.digest)

    def fail(self, worker_id: str, generation: int, error_code: str) -> BuildRecord:
        self.assert_claim(worker_id, generation)
        _identifier(error_code, "PYTHON_BUILD_ERROR_REQUIRED")
        return replace(self, status=BuildStatus.FAILED, claimant=None,
                       lease_until=None, error_code=error_code)

    def cancel_claimed(self, worker_id: str, generation: int) -> BuildRecord:
        self.assert_claim(worker_id, generation)
        if self.status != BuildStatus.CANCEL_REQUESTED:
            raise ValueError("PYTHON_BUILD_CANCEL_NOT_REQUESTED")
        return replace(self, status=BuildStatus.CANCELLED, claimant=None,
                       lease_until=None)


class WorkflowStatus(StrEnum):
    ACCEPTED = "accepted"
    RUNNING = "running"
    PUBLISHED = "published"
    PARTIALLY_PUBLISHED = "partially_published"
    FAILED = "failed"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELLED = "cancelled"
    NEEDS_INSPECTION = "needs_inspection"


@dataclass(frozen=True, slots=True)
class UnitCheckpoint:
    ordinal: int
    job_id: str
    committed: bool
    receipt_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.ordinal) is not int or not 1 <= self.ordinal <= MAX_OPERATIONS:
            raise ValueError("PYTHON_WORKFLOW_UNIT_INVALID")
        _identifier(self.job_id, "PYTHON_WORKFLOW_JOB_INVALID")
        if type(self.committed) is not bool:
            raise ValueError("PYTHON_WORKFLOW_UNIT_INVALID")
        if self.committed:
            _identifier(self.receipt_id, "PYTHON_WORKFLOW_RECEIPT_REQUIRED")
        elif self.receipt_id is not None:
            raise ValueError("PYTHON_WORKFLOW_RECEIPT_UNEXPECTED")


@dataclass(frozen=True, slots=True)
class WorkflowRecord:
    scope: ApplicationScope
    workflow_id: str
    build_id: str
    plan_digest: str
    unit_count: int
    status: WorkflowStatus = WorkflowStatus.ACCEPTED
    checkpoints: tuple[UnitCheckpoint, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.scope, ApplicationScope):
            raise ValueError("PYTHON_WORKFLOW_SCOPE_INVALID")
        for value, code in ((self.workflow_id, "PYTHON_WORKFLOW_ID_INVALID"),
                            (self.build_id, "PYTHON_BUILD_ID_INVALID")):
            if type(value) is not str or _HEX32.fullmatch(value) is None:
                raise ValueError(code)
        _digest(self.plan_digest, "PYTHON_WORKFLOW_PLAN_INVALID")
        if type(self.unit_count) is not int or not 1 <= self.unit_count <= MAX_OPERATIONS:
            raise ValueError("PYTHON_WORKFLOW_UNIT_COUNT_INVALID")
        if not isinstance(self.status, WorkflowStatus):
            raise ValueError("PYTHON_WORKFLOW_STATUS_INVALID")
        ordinals = [item.ordinal for item in self.checkpoints]
        if (any(not isinstance(item, UnitCheckpoint) for item in self.checkpoints)
                or ordinals != list(range(1, len(ordinals) + 1))
                or len(ordinals) > self.unit_count):
            raise ValueError("PYTHON_WORKFLOW_CHECKPOINTS_INVALID")

    @property
    def committed_units(self) -> int:
        return sum(item.committed for item in self.checkpoints)

    def start(self) -> WorkflowRecord:
        if self.status != WorkflowStatus.ACCEPTED:
            raise ValueError("PYTHON_WORKFLOW_TRANSITION_INVALID")
        return replace(self, status=WorkflowStatus.RUNNING)

    def checkpoint(self, item: UnitCheckpoint) -> WorkflowRecord:
        if self.status not in (WorkflowStatus.RUNNING,
                               WorkflowStatus.CANCEL_REQUESTED):
            raise ValueError("PYTHON_WORKFLOW_TRANSITION_INVALID")
        if item.ordinal != len(self.checkpoints) + 1 or item.ordinal > self.unit_count:
            raise ValueError("PYTHON_WORKFLOW_CHECKPOINT_ORDER_INVALID")
        return replace(self, checkpoints=self.checkpoints + (item,))

    def finish(self) -> WorkflowRecord:
        if self.status != WorkflowStatus.RUNNING:
            raise ValueError("PYTHON_WORKFLOW_TRANSITION_INVALID")
        if len(self.checkpoints) != self.unit_count or not all(
                item.committed for item in self.checkpoints):
            raise ValueError("PYTHON_WORKFLOW_INCOMPLETE")
        return replace(self, status=WorkflowStatus.PUBLISHED)

    def fail(self) -> WorkflowRecord:
        if self.status not in (WorkflowStatus.RUNNING,
                               WorkflowStatus.CANCEL_REQUESTED):
            raise ValueError("PYTHON_WORKFLOW_TRANSITION_INVALID")
        status = (WorkflowStatus.PARTIALLY_PUBLISHED if self.committed_units
                  else WorkflowStatus.FAILED)
        return replace(self, status=status)

    def request_cancel(self) -> WorkflowRecord:
        if self.status == WorkflowStatus.ACCEPTED:
            return replace(self, status=WorkflowStatus.CANCELLED)
        if self.status == WorkflowStatus.RUNNING:
            return replace(self, status=WorkflowStatus.CANCEL_REQUESTED)
        if self.status in (WorkflowStatus.CANCEL_REQUESTED,
                           WorkflowStatus.CANCELLED):
            return self
        raise ValueError("PYTHON_WORKFLOW_CANCEL_NOT_AVAILABLE")

    def settle_cancel(self) -> WorkflowRecord:
        if self.status != WorkflowStatus.CANCEL_REQUESTED:
            raise ValueError("PYTHON_WORKFLOW_CANCEL_NOT_REQUESTED")
        status = (WorkflowStatus.PARTIALLY_PUBLISHED if self.committed_units
                  else WorkflowStatus.CANCELLED)
        return replace(self, status=status)


class BuildRepository(Protocol):
    def compare_and_set(self, current: BuildRecord, updated: BuildRecord) -> bool: ...
    def store_sealed(self, current: BuildRecord, updated: BuildRecord,
                     plan: SealedPlan, *, source_map: Mapping[str, object],
                     build_log: str) -> bool: ...


class SandboxLauncher(Protocol):
    """Trusted launcher accepts fixed identifiers/budgets, never Docker args."""

    def start(self, *, build_id: str, environment_id: str,
              environment_version: int, capability_token: str,
              claim_generation: int,
              cpu_limit: int, memory_mib: int, wall_seconds: int) -> None: ...
    def collect(self, *, build_id: str, claim_generation: int,
                wall_seconds: int) -> object: ...
    def terminate(self, *, build_id: str, claim_generation: int) -> None: ...


def validate_build_artifacts(plan: SealedPlan, *, source_map: object,
                             build_log: object) -> tuple[bytes, str]:
    if not isinstance(plan, SealedPlan):
        raise ValueError("PYTHON_PLAN_REQUIRED")
    if not isinstance(source_map, Mapping):
        raise ValueError("PYTHON_SOURCE_MAP_INVALID")
    source = _canonical(source_map, "PYTHON_SOURCE_MAP_INVALID")
    if len(source) > MAX_SOURCE_MAP_BYTES:
        raise ValueError("PYTHON_SOURCE_MAP_LIMIT")
    if (type(build_log) is not str or "\x00" in build_log
            or len(build_log.encode("utf-8")) > MAX_BUILD_LOG_BYTES):
        raise ValueError("PYTHON_BUILD_LOG_INVALID")
    return source, build_log


def verify_plan_identity(plan: SealedPlan, expected_digest: str) -> None:
    if not isinstance(plan, SealedPlan):
        raise ValueError("PYTHON_PLAN_REQUIRED")
    _digest(expected_digest, "PYTHON_PLAN_DIGEST_INVALID")
    _identifier(plan.compiler_version, "PYTHON_PLAN_COMPILER_INVALID")
    canonical = plan.canonical_plan
    if (type(canonical) is not dict
            or set(canonical) != {"format", "units"}
            or canonical.get("format") != "openepm-python-plan-v1"
            or type(canonical.get("units")) is not list
            or not canonical["units"]
            or len(canonical["units"]) > MAX_OPERATIONS):
        raise ValueError("PYTHON_PLAN_INTERNAL_STRUCTURE_MISMATCH")
    operation_count = 0
    for unit in canonical["units"]:
        if (type(unit) is not dict
                or set(unit) != {"name", "operations"}
                or type(unit.get("name")) is not str
                or _ID.fullmatch(unit["name"]) is None
                or type(unit.get("operations")) is not list
                or not unit["operations"]):
            raise ValueError("PYTHON_PLAN_INTERNAL_STRUCTURE_MISMATCH")
        for operation in unit["operations"]:
            operation_count += 1
            if (operation_count > MAX_OPERATIONS
                    or type(operation) is not dict
                    or set(operation) != {
                        "languageVersion", "function", "arguments"}
                    or operation.get("languageVersion") != 2
                    or type(operation.get("function")) is not str
                    or _ID.fullmatch(operation["function"]) is None
                    or type(operation.get("arguments")) is not dict):
                raise ValueError("PYTHON_PLAN_INTERNAL_STRUCTURE_MISMATCH")
    if (plan.unit_count != len(canonical["units"])
            or plan.operation_count != operation_count):
        raise ValueError("PYTHON_PLAN_INTERNAL_COUNT_MISMATCH")
    canonical_bytes = _canonical(
        canonical, "PYTHON_PLAN_INTERNAL_STRUCTURE_MISMATCH")
    if (len(canonical_bytes) > MAX_PLAN_BYTES
            or type(plan.canonical_bytes) is not bytes):
        raise ValueError("PYTHON_PLAN_INTERNAL_CANONICAL_MISMATCH")
    # Preserve the established digest error for byte-level corruption, then
    # prove that the structured value serializes to those exact signed bytes.
    if sha256(plan.canonical_bytes).hexdigest() != plan.digest:
        raise ValueError("PYTHON_PLAN_INTERNAL_DIGEST_MISMATCH")
    if canonical_bytes != plan.canonical_bytes:
        raise ValueError("PYTHON_PLAN_INTERNAL_CANONICAL_MISMATCH")
    if plan.digest != expected_digest:
        raise ValueError("PYTHON_PLAN_DIGEST_MISMATCH")


class PythonBuildCoordinator:
    """Coordinates fixed identifiers; the sandbox alone runs authored source."""

    def __init__(self, repository: BuildRepository, launcher: SandboxLauncher,
                 registry: FunctionValidator, *, compiler_version: str):
        if not (hasattr(repository, "compare_and_set")
                and hasattr(repository, "store_sealed")):
            raise ValueError("PYTHON_BUILD_REPOSITORY_INVALID")
        if not (hasattr(launcher, "start") and hasattr(launcher, "collect")
                and hasattr(launcher, "terminate")):
            raise ValueError("PYTHON_SANDBOX_LAUNCHER_INVALID")
        if not hasattr(registry, "validate_operation"):
            raise ValueError("PYTHON_FUNCTION_REGISTRY_INVALID")
        _identifier(compiler_version, "PYTHON_PLAN_COMPILER_INVALID")
        self.repository = repository
        self.launcher = launcher
        self.registry = registry
        self.compiler_version = compiler_version

    def dispatch(self, current: BuildRecord) -> BuildRecord:
        """Make an accepted build claimable without starting untrusted code."""
        ready = current.ready()
        if not self.repository.compare_and_set(current, ready):
            raise ValueError("PYTHON_BUILD_STALE_CONTROL_STATE")
        return ready

    def claim(self, current: BuildRecord, worker_id: str, *,
              lease_until: int, environment_id: str,
              environment_version: int, capability_token: str) -> BuildRecord:
        if (type(environment_version) is not int or environment_version < 1
                or type(capability_token) is not str or not capability_token):
            raise ValueError("PYTHON_BUILD_ENVIRONMENT_INVALID")
        _identifier(environment_id, "PYTHON_BUILD_ENVIRONMENT_INVALID")
        updated = current.claim(worker_id, lease_until=lease_until)
        if not self.repository.compare_and_set(current, updated):
            raise ValueError("PYTHON_BUILD_STALE_CONTROL_STATE")
        # Launch only after the durable claim exists.  The claim generation is
        # attached to the sandbox so a stale cancellation cannot terminate a
        # replacement worker's process.
        self.launcher.start(build_id=current.build_id,
            environment_id=environment_id, environment_version=environment_version,
            capability_token=capability_token,
            claim_generation=updated.claim_generation,
            cpu_limit=1, memory_mib=512, wall_seconds=60)
        return updated

    def seal(self, current: BuildRecord, worker_id: str, generation: int, *,
             proposed_plan: object, source_map: object,
             build_log: object) -> tuple[BuildRecord, SealedPlan]:
        current.assert_claim(worker_id, generation)
        plan = validate_proposed_plan(current.scope, proposed_plan,
            registry=self.registry, compiler_version=self.compiler_version)
        validate_build_artifacts(plan, source_map=source_map, build_log=build_log)
        updated = current.seal(worker_id, generation, plan)
        if not self.repository.store_sealed(current, updated, plan,
                source_map=source_map, build_log=build_log):
            raise ValueError("PYTHON_BUILD_STALE_CONTROL_STATE")
        return updated, plan

    def collect_and_seal(self, current: BuildRecord, worker_id: str,
                         generation: int) -> tuple[BuildRecord, SealedPlan]:
        """Collect one bounded sandbox result and seal it under the same claim."""
        current.assert_claim(worker_id, generation)
        output = self.launcher.collect(build_id=current.build_id,
            claim_generation=generation, wall_seconds=60)
        if not all(hasattr(output, name) for name in
                   ("proposed_plan", "source_map", "build_log")):
            raise ValueError("PYTHON_SANDBOX_OUTPUT_INVALID")
        return self.seal(current, worker_id, generation,
            proposed_plan=output.proposed_plan, source_map=output.source_map,
            build_log=output.build_log)

    def cancel(self, current: BuildRecord) -> BuildRecord:
        updated = current.request_cancel()
        if updated is current:
            return current
        if not self.repository.compare_and_set(current, updated):
            raise ValueError("PYTHON_BUILD_STALE_CONTROL_STATE")
        if updated.status == BuildStatus.CANCEL_REQUESTED:
            self.launcher.terminate(build_id=current.build_id,
                                    claim_generation=current.claim_generation)
        return updated
