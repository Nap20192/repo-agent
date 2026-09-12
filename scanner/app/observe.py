"""Observability: OTEL tracing (OTLP, like git-agent3's `scan full`) and ADK events compaction."""

from __future__ import annotations

import logging

from google.adk.apps._configs import EventsCompactionConfig
from google.adk.apps.llm_event_summarizer import LlmEventSummarizer
from google.adk.models.registry import LLMRegistry

from scanner.core.settings import Settings

log = logging.getLogger("scanner.observe")


def setup_tracing(settings: Settings | None = None) -> bool:
    """Export ADK spans over OTLP when `otel_endpoint` is set (e.g. Jaeger on :4318); no-op otherwise."""
    s = settings or Settings.from_env()
    if not s.otel_endpoint:
        return False
    from google.adk.telemetry.setup import (
        maybe_set_otel_providers,  # pulls the OTLP exporter only when needed
    )
    from opentelemetry.sdk.resources import Resource

    maybe_set_otel_providers(otel_resource=Resource.create({"service.name": s.otel_service_name}))
    log.info("tracing → %s (service %s)", s.otel_endpoint, s.otel_service_name)
    return True


def compaction_config(model, settings: Settings | None = None) -> EventsCompactionConfig | None:
    """Session events compaction: every `compaction_interval` invocations the older events are summarized by the
    model (`compaction_overlap` kept verbatim). Off when the interval is 0. Our agents run with
    include_contents="none", so this shrinks the stored session (State/UI), not the per-activation prompts."""
    s = settings or Settings.from_env()
    if s.compaction_interval <= 0:
        return None
    llm = model if not isinstance(model, str) else LLMRegistry.new_llm(model)
    return EventsCompactionConfig(
        compaction_interval=s.compaction_interval, overlap_size=s.compaction_overlap,
        summarizer=LlmEventSummarizer(llm=llm),
    )
