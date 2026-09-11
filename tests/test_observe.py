from opentelemetry import trace
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from scanner.app import observe


def test_compaction_config(monkeypatch):
    monkeypatch.delenv("COMPACTION_INTERVAL", raising=False)
    assert observe.compaction_config("gemini-flash-lite-latest") is None
    monkeypatch.setenv("COMPACTION_INTERVAL", "3")
    monkeypatch.setenv("COMPACTION_OVERLAP", "1")
    cfg = observe.compaction_config("gemini-flash-lite-latest")
    assert (cfg.compaction_interval, cfg.overlap_size) == (3, 1) and cfg.summarizer is not None


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
