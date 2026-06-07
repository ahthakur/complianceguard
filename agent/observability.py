"""
=============================================================================
observability.py - OpenTelemetry Setup for ComplianceGuard
=============================================================================

This module configures OpenTelemetry for the agent. It sets up the three
signal providers (traces, metrics, logs) and wires them to CONSOLE exporters,
which means telemetry prints to your terminal when you run the agent.

WHY CONSOLE EXPORTERS?
No infrastructure needed. No Docker, no Collector, no Grafana. You run the
agent, and traces/metrics/logs print to stdout so you can see exactly what
the instrumentation produces. Once you understand the output, switching to
a real backend (Grafana) is a one-line change per exporter.

HOW TO USE:
In main.py, call initialize_observability() once at startup (right after
configure_logging), and call shutdown_observability() once before the agent
exits (to flush any buffered telemetry).

=============================================================================
"""

import logging
import os

# --- Trace imports ---
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter


# --- Metric imports ---
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter

# --- Log imports ---
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import SimpleLogRecordProcessor, ConsoleLogExporter
from opentelemetry._logs import set_logger_provider

# --- Resource (shared identity for all signals) ---
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION


# We hold references to the providers at module level so shutdown_observability()
# can flush them before the process exits. This matters for a CLI tool like
# ComplianceGuard that runs once and exits: without an explicit flush, buffered
# telemetry can be lost when the process terminates.
_tracer_provider: TracerProvider | None = None
_meter_provider: MeterProvider | None = None
_logger_provider: LoggerProvider | None = None
OTLP_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

def _create_resource() -> Resource:
    """
    Create the Resource that identifies this service in all telemetry.

    Every span, metric, and log record carries these attributes. When you
    eventually send this to Grafana, you filter by service.name to find
    ComplianceGuard's telemetry among everything else.
    """
    return Resource.create(
        {
            SERVICE_NAME: os.getenv("OTEL_SERVICE_NAME", "complianceguard"),
            SERVICE_VERSION: os.getenv("OTEL_SERVICE_VERSION", "1.0.0"),
            "deployment.environment": os.getenv("OTEL_ENV", "development"),
        }
    )


def _setup_tracing(resource: Resource) -> None:
    """
    Configure the tracer provider with a console exporter.

    NOTE ON SimpleSpanProcessor vs BatchSpanProcessor:
    We use SimpleSpanProcessor here because it exports each span IMMEDIATELY
    when the span ends. This is ideal for learning and for the console because
    you see spans print in real time as the pipeline runs. In production you
    would use BatchSpanProcessor, which buffers spans and exports them in
    batches for efficiency (fewer network calls), but requires an explicit
    flush on shutdown.
    """
    global _tracer_provider

    _tracer_provider = TracerProvider(resource=resource)

    # CHANGED: BatchSpanProcessor + OTLP exporter instead of Simple + Console
    _tracer_provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=OTLP_ENDPOINT, insecure=True))
    )

    # Register as the global provider so trace.get_tracer() works everywhere
    trace.set_tracer_provider(_tracer_provider)


def _setup_metrics(resource: Resource) -> None:
    """
    Configure the meter provider with a console exporter.

    The PeriodicExportingMetricReader collects metrics and exports them on an
    interval. For a short-lived CLI agent, the interval may not fire before the
    process exits, which is why shutdown_observability() force-flushes metrics
    at the end. The export prints the current value of every counter, histogram,
    and gauge to the console.
    """
    global _meter_provider

    metric_reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(endpoint=OTLP_ENDPOINT, insecure=True),  # CHANGED
        export_interval_millis=10000,
    )

    _meter_provider = MeterProvider(
        resource=resource,
        metric_readers=[metric_reader],
    )

    metrics.set_meter_provider(_meter_provider)


def _setup_logging(resource: Resource) -> None:
    """
    Bridge Python's standard logging to OpenTelemetry.

    ComplianceGuard already uses logging.getLogger(__name__) everywhere with a
    root config in main.py. This function attaches an OTel LoggingHandler to the
    root logger, so EVERY existing log call automatically flows into the
    telemetry pipeline AND gets tagged with the current trace_id and span_id.

    That trace correlation is the magic: a log emitted inside the "classify"
    span carries that span's trace_id, so later you can jump from a log line
    to the exact trace it belongs to.
    """
    global _logger_provider

    _logger_provider = LoggerProvider(resource=resource)
    _logger_provider.add_log_record_processor(
        SimpleLogRecordProcessor(ConsoleLogExporter())
    )
    set_logger_provider(_logger_provider)

    # Attach the OTel handler to the root logger. Because all modules use
    # logging.getLogger(__name__), they inherit the root logger's handlers,
    # so this single attachment captures logs from every module.
    otel_handler = LoggingHandler(
        level=logging.INFO,
        logger_provider=_logger_provider,
    )
    logging.getLogger().addHandler(otel_handler)


def initialize_observability() -> None:
    """
    Set up all three signals. Call this ONCE at agent startup,
    right after configure_logging() in main.py.
    """
    resource = _create_resource()
    _setup_tracing(resource)
    _setup_metrics(resource)
    #_setup_logging(resource)


def shutdown_observability() -> None:
    """
    Flush and shut down all providers. Call this ONCE before the agent exits.

    WHY THIS MATTERS:
    ComplianceGuard runs once and exits (it is a batch CLI tool, not a
    long-running server). The metric reader and any buffered telemetry need to
    be flushed before the process terminates, or you lose the final data.
    Calling shutdown() forces a final export of everything still in memory.
    """
    if _tracer_provider is not None:
        _tracer_provider.shutdown()
    if _meter_provider is not None:
        _meter_provider.shutdown()
    if _logger_provider is not None:
        _logger_provider.shutdown()