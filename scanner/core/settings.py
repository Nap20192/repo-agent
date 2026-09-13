"""Settings: every runtime knob in one frozen dataclass, parsed once from a Mapping (ADR-0004).

`Settings.from_env()` is the only place that knows environment variable names. Modules receive values
through constructor/function parameters; nothing else reads `os.environ`.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass


def _int(env: Mapping[str, str], key: str, default: int) -> int:
    try:
        return int(env.get(key, "") or default)
    except ValueError:
        return default


def _float(env: Mapping[str, str], key: str, default: float) -> float:
    try:
        return float(env.get(key, "") or default)
    except ValueError:
        return default


def _on(env: Mapping[str, str], key: str) -> bool:
    """A feature switch: on unless the variable is exactly "0"."""
    return env.get(key) != "0"


@dataclass(frozen=True)
class Settings:
    # model
    google_api_key: str = ""
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_model: str = ""
    # graph
    max_rounds: int = 4
    max_hyps: int = 8
    max_parallel: int = 3
    stage_timeout: float = 600.0
    threat_model: bool = True  # the model stage (architecture + threats); off → anchors only
    critic: bool = True  # the critique pass over confirmed findings
    # budgets (model calls per activation)
    model_max_calls: int = 40
    verifier_max_calls: int = 30
    critic_max_calls: int = 20
    # state
    state_path: str = ".state/state.db"
    workspace_root: str = "."  # adk web: a chat message may only name targets under this directory (card 48)
    sessions_path: str = ".state/sessions.db"
    skip_deps: bool = False
    # index
    index_max_files: int = 3000
    index_max_bytes: int = 30 * 1024 * 1024
    # observability
    otel_endpoint: str = ""
    otel_service_name: str = "scanner"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        e = os.environ if env is None else env
        return cls(
            google_api_key=e.get("GOOGLE_API_KEY", ""),
            llm_api_key=e.get("LLM_API_KEY", ""),
            llm_base_url=e.get("LLM_BASE_URL", ""),
            llm_model=e.get("LLM_MODEL", ""),
            max_rounds=_int(e, "BUGFINDER_MAX_ROUNDS", 4),
            max_hyps=_int(e, "BUGFINDER_MAX_HYPS", 8),
            max_parallel=_int(e, "BUGFINDER_MAX_PARALLEL", 3),
            stage_timeout=_float(e, "STAGE_TIMEOUT", 600.0),
            threat_model=_on(e, "THREAT_MODEL"),
            critic=_on(e, "CRITIC"),
            model_max_calls=_int(e, "MODEL_MAX_MODEL_CALLS", 40),
            verifier_max_calls=_int(e, "VERIFIER_MAX_MODEL_CALLS", 30),
            critic_max_calls=_int(e, "CRITIC_MAX_MODEL_CALLS", 20),
            state_path=e.get("STATE_PATH") or ".state/state.db",
            workspace_root=e.get("WORKSPACE_ROOT") or ".",
            sessions_path=e.get("SESSIONS_PATH") or ".state/sessions.db",
            skip_deps=e.get("SKIP_DEPS") == "1",
            index_max_files=_int(e, "INDEX_MAX_FILES", 3000),
            index_max_bytes=_int(e, "INDEX_MAX_BYTES", 30 * 1024 * 1024),
            otel_endpoint=e.get("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
            otel_service_name=e.get("OTEL_SERVICE_NAME") or "scanner",
        )
