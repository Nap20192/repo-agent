from opentelemetry import trace
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from scanner.app import observe


def test_setup_tracing(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    assert observe.setup_tracing() is False
    # the global tracer provider can be set once per process: install our in-memory exporter first
    from google.adk.telemetry.setup import OTelHooks, maybe_set_otel_providers

    mem = InMemorySpanExporter()
    maybe_set_otel_providers(otel_hooks_to_setup=[OTelHooks(span_processors=[SimpleSpanProcessor(mem)])])
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
    assert observe.setup_tracing() is True
    with trace.get_tracer("t").start_as_current_span("probe"):
        pass
    assert "probe" in {s.name for s in mem.get_finished_spans()}
