"""Release-owned, bounded OpenTelemetry SDK configuration."""
from __future__ import annotations

import os
import re

_SERVICES = frozenset(("openepm-platform", "openepm-router", "openepm-web",
                       "openepm-worker", "openepm-operations"))
_ENDPOINT = re.compile(r"^http://telemetry-collector:4318$")
_configured = False


def configure_release_telemetry() -> bool:
    """Install local OTLP providers only for an explicitly configured service.

    Resource attributes are constructed here rather than accepted through the
    generic OTEL_RESOURCE_ATTRIBUTES environment variable.  This prevents
    deployment or request-controlled tenant/user labels from becoming series.
    """
    global _configured
    if _configured:
        return True
    service = os.environ.get("EPM_TELEMETRY_SERVICE_NAME", "")
    if not service:
        return False
    endpoint = os.environ.get("EPM_TELEMETRY_OTLP_ENDPOINT", "")
    if service not in _SERVICES or _ENDPOINT.fullmatch(endpoint) is None:
        raise RuntimeError("TELEMETRY_CONFIGURATION_INVALID")

    from opentelemetry import metrics, trace
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    resource = Resource.create({"service.name": service,
                                "service.namespace": "openepm"})
    tracer = TracerProvider(resource=resource)
    tracer.add_span_processor(BatchSpanProcessor(
        OTLPSpanExporter(endpoint=endpoint + "/v1/traces", timeout=5),
        max_queue_size=512, max_export_batch_size=128,
        schedule_delay_millis=5000, export_timeout_millis=5000))
    trace.set_tracer_provider(tracer)
    reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(endpoint=endpoint + "/v1/metrics", timeout=5),
        export_interval_millis=15000, export_timeout_millis=5000)
    metrics.set_meter_provider(MeterProvider(resource=resource,
                                              metric_readers=(reader,)))
    _configured = True
    return True
