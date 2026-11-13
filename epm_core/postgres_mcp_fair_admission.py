"""Bounded fair admission for verified MCP principals.

This module schedules already-authenticated internal work metadata.  It does not
authenticate callers, classify humans versus agents, dispatch tools, or confer
application authority.  Raw issuer/subject values are deliberately absent from
the metrics surface.
"""
from __future__ import annotations

import asyncio
from collections import Counter, defaultdict, deque
from .observability import record_operational_signal
from dataclasses import dataclass
import time
from typing import Deque, Dict, Hashable


IDENTITY_CAPACITY_CODE = "MCP_IDENTITY_CAPACITY_NOT_DISPATCHED"
APPLICATION_CAPACITY_CODE = "MCP_APPLICATION_CAPACITY_NOT_DISPATCHED"
LISTENER_CAPACITY_CODE = "MCP_LISTENER_CAPACITY_NOT_DISPATCHED"
DEADLINE_CODE = "MCP_FAIR_ADMISSION_DEADLINE_NOT_DISPATCHED"


class AdmissionRejected(RuntimeError):
    """A request was rejected before a worker or business tool was dispatched."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(eq=False)
class _Waiter:
    application: Hashable
    principal: Hashable
    future: asyncio.Future
    queued_at: float
    granted: bool = False


class AdmissionPermit:
    """One granted scheduler slot; release is idempotent."""

    def __init__(self, scheduler: "FairAdmissionScheduler", application: Hashable,
                 principal: Hashable):
        self._scheduler = scheduler
        self._application = application
        self._principal = principal
        self._released = False

    async def release(self) -> None:
        if self._released:
            return
        self._released = True
        await self._scheduler._release(self._application, self._principal)

    async def __aenter__(self) -> "AdmissionPermit":
        return self

    async def __aexit__(self, _type, _value, _traceback) -> None:
        await self.release()


class FairAdmissionScheduler:
    """Round-robin applications, then principals, with fixed queue bounds."""

    _WAIT_BUCKETS = (0.01, 0.1, 1.0, 5.0)

    def __init__(self, *, max_active: int = 8,
                 max_active_per_principal: int = 2,
                 max_outstanding_per_principal: int = 4,
                 max_active_per_application: int = 4,
                 max_outstanding_per_application: int = 12,
                 max_waiting: int = 32):
        values = (max_active, max_active_per_principal,
                  max_outstanding_per_principal, max_active_per_application,
                  max_outstanding_per_application, max_waiting)
        if any(type(value) is not int or value <= 0 for value in values):
            raise ValueError("Fair-admission limits must be positive integers")
        if max_active_per_principal > max_outstanding_per_principal:
            raise ValueError("Principal active limit exceeds outstanding limit")
        if max_active_per_application > max_outstanding_per_application:
            raise ValueError("Application active limit exceeds outstanding limit")
        self.max_active = max_active
        self.max_active_per_principal = max_active_per_principal
        self.max_outstanding_per_principal = max_outstanding_per_principal
        self.max_active_per_application = max_active_per_application
        self.max_outstanding_per_application = max_outstanding_per_application
        self.max_waiting = max_waiting
        self._lock = asyncio.Lock()
        self._queues: Dict[Hashable, Dict[Hashable, Deque[_Waiter]]] = defaultdict(
            lambda: defaultdict(deque))
        self._app_order: Deque[Hashable] = deque()
        self._principal_order: Dict[Hashable, Deque[Hashable]] = defaultdict(deque)
        self._active = 0
        self._active_app = Counter()
        self._active_principal = Counter()
        self._outstanding_app = Counter()
        self._outstanding_principal = Counter()
        self._outstanding_pair = Counter()
        self._waiting = 0
        self._last_app = None
        self._last_principal = {}
        self._rejected = Counter()
        self._wait_buckets = Counter()
        self._generation = 0
        self._started_at = time.monotonic()

    async def acquire(self, application: Hashable, principal: Hashable, *,
                      deadline: float | None = None) -> AdmissionPermit:
        if application is None or principal is None:
            raise ValueError("Verified application and principal keys are required")
        loop = asyncio.get_running_loop()
        waiter = _Waiter(application, principal, loop.create_future(), loop.time())
        async with self._lock:
            self._admit_waiter(waiter)
            self._drain(loop.time())
        try:
            if deadline is None:
                await asyncio.shield(waiter.future)
            else:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise asyncio.TimeoutError
                await asyncio.wait_for(asyncio.shield(waiter.future), remaining)
        except asyncio.TimeoutError:
            await self._withdraw(waiter, deadline=True)
            raise AdmissionRejected(DEADLINE_CODE) from None
        except asyncio.CancelledError:
            await self._withdraw(waiter, deadline=False)
            raise
        return AdmissionPermit(self, application, principal)

    def _admit_waiter(self, waiter: _Waiter) -> None:
        app = waiter.application
        principal = waiter.principal
        if self._outstanding_principal[principal] >= self.max_outstanding_per_principal:
            self._reject(IDENTITY_CAPACITY_CODE)
        if self._outstanding_app[app] >= self.max_outstanding_per_application:
            self._reject(APPLICATION_CAPACITY_CODE)
        if self._waiting >= self.max_waiting:
            self._reject(LISTENER_CAPACITY_CODE)
        queue = self._queues[app][principal]
        if (not queue
                and not any(candidate == principal
                            for candidate in self._principal_order[app])):
            self._principal_order[app].append(principal)
        if not any(candidate == app for candidate in self._app_order):
            self._app_order.append(app)
        queue.append(waiter)
        self._waiting += 1
        self._outstanding_app[app] += 1
        self._outstanding_principal[principal] += 1
        self._outstanding_pair[(app, principal)] += 1
        self._generation += 1

    def _reject(self, code: str) -> None:
        self._rejected[code] += 1
        reason={IDENTITY_CAPACITY_CODE:'identity',APPLICATION_CAPACITY_CODE:'application',
                LISTENER_CAPACITY_CODE:'listener'}.get(code,'unknown')
        record_operational_signal('admission_rejection',reason=reason)
        self._generation += 1
        raise AdmissionRejected(code)

    def _eligible_apps(self) -> list[Hashable]:
        return [app for app in self._app_order
                if self._active_app[app] < self.max_active_per_application
                and self._has_eligible_principal(app)]

    def _has_eligible_principal(self, app: Hashable) -> bool:
        return any(self._queues[app][principal]
                   and self._active_principal[principal] < self.max_active_per_principal
                   for principal in self._principal_order[app])

    @staticmethod
    def _after_last(candidates: list[Hashable], order: Deque[Hashable], last):
        if not candidates:
            return None
        if last not in order or len(candidates) == 1:
            return candidates[0]
        values = list(order)
        start = values.index(last)
        allowed = set(candidates)
        for offset in range(1, len(values) + 1):
            candidate = values[(start + offset) % len(values)]
            if candidate in allowed:
                return candidate
        return candidates[0]

    def _choose_principal(self, app: Hashable):
        order = self._principal_order[app]
        candidates = [principal for principal in order
                      if self._queues[app][principal]
                      and self._active_principal[principal] < self.max_active_per_principal]
        return self._after_last(candidates, order, self._last_principal.get(app))

    def _drain(self, now: float) -> None:
        while self._active < self.max_active:
            apps = self._eligible_apps()
            app = self._after_last(apps, self._app_order, self._last_app)
            if app is None:
                return
            principal = self._choose_principal(app)
            if principal is None:
                return
            queue = self._queues[app][principal]
            waiter = queue.popleft()
            self._waiting -= 1
            self._active += 1
            self._active_app[app] += 1
            self._active_principal[principal] += 1
            waiter.granted = True
            self._last_app = app
            self._last_principal[app] = principal
            self._record_wait(max(0.0, now - waiter.queued_at))
            self._cleanup_orders(app, principal)
            self._generation += 1
            if not waiter.future.done():
                waiter.future.set_result(True)

    def _record_wait(self, seconds: float) -> None:
        for bound in self._WAIT_BUCKETS:
            if seconds <= bound:
                self._wait_buckets[f"le_{bound:g}s"] += 1
                return
        self._wait_buckets["gt_5s"] += 1

    def _cleanup_orders(self, app: Hashable, principal: Hashable) -> None:
        if (not self._queues[app][principal]
                and self._outstanding_pair[(app, principal)] <= 0):
            self._remove_all(self._principal_order[app], principal)
            self._queues[app].pop(principal, None)
        if not self._queues[app] and self._outstanding_app[app] <= 0:
            self._remove_all(self._app_order, app)
            self._principal_order.pop(app, None)
            self._queues.pop(app, None)

    @staticmethod
    def _remove_all(values: Deque, target) -> None:
        retained = [value for value in values if value != target]
        values.clear()
        values.extend(retained)

    async def _withdraw(self, waiter: _Waiter, *, deadline: bool) -> None:
        async with self._lock:
            if waiter.granted:
                self._release_locked(waiter.application, waiter.principal)
            else:
                queue = self._queues.get(waiter.application, {}).get(waiter.principal)
                if queue is not None:
                    try:
                        queue.remove(waiter)
                    except ValueError:
                        pass
                    else:
                        self._waiting -= 1
                        self._outstanding_app[waiter.application] -= 1
                        self._outstanding_principal[waiter.principal] -= 1
                        self._outstanding_pair[(waiter.application, waiter.principal)] -= 1
                        self._cleanup_orders(waiter.application, waiter.principal)
                        self._generation += 1
            if deadline:
                self._rejected[DEADLINE_CODE] += 1
                record_operational_signal('admission_rejection',reason='deadline')
            self._drain(asyncio.get_running_loop().time())

    async def _release(self, application: Hashable, principal: Hashable) -> None:
        async with self._lock:
            self._release_locked(application, principal)
            self._drain(asyncio.get_running_loop().time())

    def _release_locked(self, application: Hashable, principal: Hashable) -> None:
        if self._active_app[application] <= 0 or self._active_principal[principal] <= 0:
            raise RuntimeError("Admission permit state is inconsistent")
        self._active -= 1
        self._active_app[application] -= 1
        self._active_principal[principal] -= 1
        self._outstanding_app[application] -= 1
        self._outstanding_principal[principal] -= 1
        self._outstanding_pair[(application, principal)] -= 1
        self._cleanup_orders(application, principal)
        self._generation += 1

    async def snapshot(self) -> dict:
        """Return fixed-cardinality aggregate metrics without principal identifiers."""
        async with self._lock:
            active_counts = list(self._active_principal.values())
            outstanding_counts = list(self._outstanding_principal.values())
            return {
                "active": self._active,
                "waiting": self._waiting,
                "applicationsActive": sum(1 for count in self._active_app.values() if count),
                "applicationsWaiting": sum(
                    1 for queues in self._queues.values()
                    if any(queue for queue in queues.values())
                ),
                "principalsActive": sum(1 for count in active_counts if count),
                "principalsOutstanding": sum(1 for count in outstanding_counts if count),
                "maxActiveForOnePrincipal": max(active_counts, default=0),
                "maxOutstandingForOnePrincipal": max(outstanding_counts, default=0),
                "rejected": {code: self._rejected[code] for code in (
                    IDENTITY_CAPACITY_CODE, APPLICATION_CAPACITY_CODE,
                    LISTENER_CAPACITY_CODE, DEADLINE_CODE)},
                "waitBuckets": {name: self._wait_buckets[name] for name in (
                    "le_0.01s", "le_0.1s", "le_1s", "le_5s", "gt_5s")},
                "generation": self._generation,
                "uptimeSeconds": max(0.0, time.monotonic() - self._started_at),
            }
