"""Observability: OTEL tracing (OTLP from env, like git-agent3's `scan full`) and ADK events compaction."""

from __future__ import annotations

import logging
import os

from google.adk.apps._configs import EventsCompactionConfig
from google.adk.apps.llm_event_summarizer import LlmEventSummarizer
from google.adk.models.registry import LLMRegistry

log = logging.getLogger("scanner.observe")


def setup_tracing() -> bool:
    """Export ADK spans over OTLP when OTEL_EXPORTER_OTLP_ENDPOINT is set (e.g. Jaeger on :4318); no-op otherwise."""
    if not os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        return False
    os.environ.setdefault("OTEL_SERVICE_NAME", "scanner")
    from google.adk.telemetry.setup import (
        maybe_set_otel_providers,  # pulls the OTLP exporter only when needed
    )

    maybe_set_otel_providers()
    log.info("tracing → %s (service %s)", os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"], os.environ["OTEL_SERVICE_NAME"])
    return True


def compaction_config(model) -> EventsCompactionConfig | None:
    """Session events compaction: every COMPACTION_INTERVAL invocations the older events are summarized by the
    model (COMPACTION_OVERLAP kept verbatim). Off when the interval is unset. Our agents run with
    include_contents="none", so this shrinks the stored session (State/UI), not the per-activation prompts."""
    n = int(os.environ.get("COMPACTION_INTERVAL", "0") or 0)
    if n <= 0:
        return None
    llm = model if not isinstance(model, str) else LLMRegistry.new_llm(model)
    return EventsCompactionConfig(
        compaction_interval=n, overlap_size=int(os.environ.get("COMPACTION_OVERLAP", "2") or 0),
        summarizer=LlmEventSummarizer(llm=llm),
    )
