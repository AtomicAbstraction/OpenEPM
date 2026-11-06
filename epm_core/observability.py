"""Bounded OpenTelemetry and structured-event helpers.

Only technical identifiers enter telemetry.  Business payloads, credentials,
principal names and free-form exception text are deliberately excluded.
Export remains deployment-owned: the OpenTelemetry API uses the configured
provider when one is installed and is otherwise a safe no-op provider.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import logging
import re
import secrets
import time
from typing import Iterator

from opentelemetry import metrics, propagate, trace
from opentelemetry.trace import SpanKind, Status, StatusCode
from .telemetry import configure_release_telemetry

configure_release_telemetry()


_TOKEN = re.compile(r"^[A-Za-z0-9._:/*-]{1,128}$")
_METHODS = frozenset(("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"))
_TRACER = trace.get_tracer("openepm.fixed-core")
_METER = metrics.get_meter("openepm.fixed-core")
_REQUESTS = _METER.create_counter(
    "http.server.requests", unit="{request}",
    description="Completed Open EPM HTTP requests")
_REQUEST_ERRORS = _METER.create_counter(
    "http.server.errors", unit="{request}",
    description="Completed Open EPM HTTP requests with server errors")
_AUTHENTICATION_FAILURES = _METER.create_counter(
    "http.server.authentication.failures", unit="{request}",
    description="HTTP requests rejected because authentication is required")
_REQUEST_DURATION = _METER.create_histogram(
    "http.server.request.duration", unit="ms",
    description="Open EPM HTTP request duration")
_WORKER_TICKS = _METER.create_counter(
    "openepm.worker.ticks", unit="{tick}",
    description="Completed Open EPM worker scheduling ticks")
_WORKER_DURATION = _METER.create_histogram(
    "openepm.worker.tick.duration", unit="ms",
    description="Open EPM worker scheduling tick duration")
_ADMISSION_REJECTIONS = _METER.create_counter(
    "openepm.admission.rejections", unit="{rejection}")
_WORK_RETRIES = _METER.create_counter("openepm.work.retries", unit="{retry}")
_LEASE_LOSSES = _METER.create_counter("openepm.worker.lease.losses", unit="{lease}")
_LOCK_WAITS = _METER.create_counter("openepm.database.lock.waits", unit="{wait}")
_MIGRATION_FAILURES = _METER.create_counter("openepm.migration.failure", unit="{failure}")
_RECOVERY_FAILURES = _METER.create_counter("openepm.recovery.failure", unit="{failure}")
_DISK_USED_RATIO = _METER.create_histogram("system.filesystem.used_ratio", unit="1")
_SIGNING_KEY_AVAILABLE = _METER.create_histogram("openepm.signing_key.available", unit="1")
_QUEUE_OLDEST_AGE = _METER.create_histogram("openepm.queue.oldest_age_seconds", unit="s")
_WORKER_STATUSES = frozenset((
    "idle", "completed", "published", "checkpoint", "ready", "failed",
    "cancelled", "needs_inspection", "error"))
_WORKER_FAMILIES = frozenset((
    "none", "aggregate", "python_build", "python_workflow",
    "python_schedule", "sequence", "business"))
_CORRELATION = re.compile(r"^[0-9a-f]{32}$")
_ROUTE = re.compile(r"^/[A-Za-z0-9._:/*-]{1,96}$")
_EVENT_FIELDS = {
    "request.completed": frozenset((
        "service", "correlationId", "method", "route", "status",
        "durationMs")),
    "worker.tick": frozenset(("status", "family", "durationMs")),
}
_ADMISSION_REASONS = frozenset(("identity", "application", "listener", "deadline"))
_RETRY_FAMILIES = _WORKER_FAMILIES - {"none"}


def record_operational_signal(signal: str, value: object = 1, *,
                              family: object = "none",
                              reason: object = "unknown") -> None:
    """Record one fixed-schema operational signal without business labels."""
    if signal == "admission_rejection":
        label = reason if isinstance(reason, str) and reason in _ADMISSION_REASONS else "unknown"
        _ADMISSION_REJECTIONS.add(1, {"reason": label})
    elif signal == "retry":
        label = family if isinstance(family, str) and family in _RETRY_FAMILIES else "unknown"
        _WORK_RETRIES.add(1, {"family": label})
    elif signal == "lease_loss":
        label = family if isinstance(family, str) and family in _RETRY_FAMILIES else "unknown"
        _LEASE_LOSSES.add(1, {"family": label})
    elif signal == "lock_wait":
        _LOCK_WAITS.add(1, {})
    elif signal == "migration_failure":
        _MIGRATION_FAILURES.add(1, {})
    elif signal == "recovery_failure":
        _RECOVERY_FAILURES.add(1, {})
    elif signal == "disk_used_ratio":
        bounded = value if type(value) in (int, float) and 0 <= value <= 1 else 1
        _DISK_USED_RATIO.record(bounded, {})
    elif signal == "signing_key_available":
        _SIGNING_KEY_AVAILABLE.record(1 if value is True else 0, {})
    elif signal == "queue_oldest_age":
        label = family if isinstance(family, str) and family in _WORKER_FAMILIES else "unknown"
        bounded = value if type(value) is int and 0 <= value <= 31_536_000 else 31_536_000
        _QUEUE_OLDEST_AGE.record(bounded, {"family": label})
    else:
        raise ValueError("OPERATIONAL_SIGNAL_INVALID")


def _safe_token(value: object, fallback: str) -> str:
    return value if isinstance(value, str) and _TOKEN.fullmatch(value) else fallback


def normalized_route(path: object, allowed: frozenset[str]) -> str:
    """Return only a declared low-cardinality route label."""
    return path if isinstance(path, str) and path in allowed else "unknown"


def correlation_id() -> str:
    context = trace.get_current_span().get_span_context()
    if context.is_valid:
        return f"{context.trace_id:032x}"
    return secrets.token_hex(16)


def _http_status(value: object) -> int:
    return value if type(value) is int and 100 <= value <= 599 else 500


def _worker_label(value: object, allowed: frozenset[str], fallback: str) -> str:
    return value if isinstance(value, str) and value in allowed else fallback


def extracted_context(headers: dict[str, list[str]]):
    """Extract only W3C trace context; baggage is intentionally ignored."""
    carrier = {}
    values = headers.get("traceparent", [])
    if len(values) == 1:
        carrier["traceparent"] = values[0]
    states = headers.get("tracestate", [])
    if len(states) == 1:
        carrier["tracestate"] = states[0]
    return propagate.get_global_textmap().extract(carrier=carrier)


def structured_event(logger: logging.Logger, level: int, event: str, **fields) -> None:
    """Write one schema-bound canonical event.

    This is deliberately not a general structured logger.  An allow-list per
    event prevents a future caller from accidentally exporting a token-shaped
    username, credential, business value, or other high-cardinality field.
    Invalid values are replaced with bounded technical fallbacks.
    """
    event_name = event if event in _EVENT_FIELDS else "invalid_event"
    value = {"event": event_name}
    if event_name == "invalid_event":
        logger.log(level, json.dumps(value, sort_keys=True, separators=(",", ":")))
        return
    allowed = _EVENT_FIELDS[event_name]
    for name in allowed:
        if name not in fields:
            continue
        item = fields[name]
        if name == "correlationId":
            value[name] = item if isinstance(item, str) and _CORRELATION.fullmatch(item) else "0" * 32
        elif name == "method":
            value[name] = item if item in _METHODS or item == "OTHER" else "OTHER"
        elif name == "route":
            value[name] = item if isinstance(item, str) and _ROUTE.fullmatch(item) else "unknown"
        elif name == "status":
            if event_name == "request.completed":
                value[name] = _http_status(item)
            else:
                value[name] = _worker_label(item, _WORKER_STATUSES, "error")
        elif name == "family":
            value[name] = _worker_label(item, _WORKER_FAMILIES, "unknown")
        elif name == "durationMs":
            value[name] = item if type(item) is int and 0 <= item <= 86_400_000 else 0
        elif name == "service":
            value[name] = _safe_token(item, "openepm")
    logger.log(level, json.dumps(value, sort_keys=True, separators=(",", ":")))


@dataclass
class RequestObservation:
    correlation_id: str
    route: str
    method: str
    started: float
    status: int = 500


@contextmanager
def observe_request(*, headers: dict[str, list[str]], method: object,
                    path: object, allowed_routes: frozenset[str],
                    logger: logging.Logger,
                    service: str) -> Iterator[RequestObservation]:
    route = normalized_route(path, allowed_routes)
    verb = method if isinstance(method, str) and method in _METHODS else "OTHER"
    parent = extracted_context(headers)
    started = time.monotonic()
    with _TRACER.start_as_current_span(
            f"{verb} {route}", context=parent, kind=SpanKind.SERVER,
            attributes={"service.name": _safe_token(service, "openepm"),
                        "http.request.method": verb,
                        "http.route": route}) as span:
        observed = RequestObservation(correlation_id(), route, verb, started)
        try:
            yield observed
        except BaseException:
            observed.status = 500
            span.set_status(Status(StatusCode.ERROR))
            raise
        finally:
            status = _http_status(observed.status)
            observed.status = status
            span.set_attribute("http.response.status_code", status)
            if status >= 500:
                span.set_status(Status(StatusCode.ERROR))
            attributes = {"http.request.method": verb, "http.route": route,
                          "http.response.status_code": status}
            duration_ms = max(0, int((time.monotonic()-started)*1000))
            _REQUESTS.add(1, attributes)
            _REQUEST_DURATION.record(duration_ms, attributes)
            if status >= 500:
                _REQUEST_ERRORS.add(1, attributes)
            if status == 401:
                _AUTHENTICATION_FAILURES.add(1, attributes)
            structured_event(logger, logging.INFO, "request.completed",
                service=service, correlationId=observed.correlation_id,
                method=verb, route=route, status=status,
                durationMs=duration_ms)


@contextmanager
def observe_worker_tick(*, logger: logging.Logger) -> Iterator[object]:
    """Trace a worker scheduling tick without recording business identifiers."""
    started = time.monotonic()
    with _TRACER.start_as_current_span(
            "worker.tick", kind=SpanKind.CONSUMER,
            attributes={"service.name": "openepm-worker"}) as span:
        outcome = {"status": "idle", "family": "none"}
        try:
            yield outcome
        except BaseException:
            outcome["status"] = "error"
            span.set_status(Status(StatusCode.ERROR))
            raise
        finally:
            status = _worker_label(
                outcome.get("status"), _WORKER_STATUSES, "error")
            family = _worker_label(
                outcome.get("family"), _WORKER_FAMILIES, "unknown")
            span.set_attribute("openepm.worker.status", status)
            span.set_attribute("openepm.worker.family", family)
            attributes = {"openepm.worker.status": status,
                          "openepm.worker.family": family}
            duration_ms = max(0, int((time.monotonic()-started)*1000))
            _WORKER_TICKS.add(1, attributes)
            _WORKER_DURATION.record(duration_ms, attributes)
            if status != "idle":
                structured_event(logger, logging.INFO, "worker.tick",
                    status=status, family=family, durationMs=duration_ms)
