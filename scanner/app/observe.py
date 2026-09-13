"""Observability: OTEL tracing (OTLP, like git-agent3's `scan full`)."""

from __future__ import annotations

import logging

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
