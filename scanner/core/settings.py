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
    pipeline: str = "v2"  # "v2" (BaseAgent graph) | "v3" (ADK Workflow graph, card 43)
    max_rounds: int = 4
    max_hyps: int = 8
    max_parallel: int = 3
    json_retry: bool = True
    stage_timeout: float = 600.0
    specialists: bool = True
    threat_model: bool = True
    domain_model: bool = True
    critic: bool = True
    # budgets (model calls)
    verifier_max_calls: int = 30
    critic_max_calls: int = 20
    architect_max_calls: int = 40
    domain_modeler_max_calls: int = 12
    threat_modeler_max_calls: int = 6
    knowledge_max_calls: int = 10
    # state
    state_path: str = ".state/state.db"
    sessions_path: str = ".state/sessions.db"
    skip_deps: bool = False
    # knowledge
    knowledge_cache: str = ".state/knowledge.db"
    knowledge_enrich: bool = True
    ghsa_dir: str = ""
    github_token: str = ""
    nvd_api_key: str = ""
    web_search: str = ""
    tavily_api_key: str = ""
    # index
    index_max_files: int = 3000
    index_max_bytes: int = 30 * 1024 * 1024
    # observability
    otel_endpoint: str = ""
    otel_service_name: str = "scanner"
    compaction_interval: int = 0
    compaction_overlap: int = 2

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        e = os.environ if env is None else env
        return cls(
            google_api_key=e.get("GOOGLE_API_KEY", ""),
            llm_api_key=e.get("LLM_API_KEY", ""),
            llm_base_url=e.get("LLM_BASE_URL", ""),
            llm_model=e.get("LLM_MODEL", ""),
            pipeline=e.get("PIPELINE") or "v2",
            max_rounds=_int(e, "BUGFINDER_MAX_ROUNDS", 4),
            max_hyps=_int(e, "BUGFINDER_MAX_HYPS", 8),
            max_parallel=_int(e, "BUGFINDER_MAX_PARALLEL", 3),
            json_retry=_on(e, "JSON_RETRY"),
            stage_timeout=_float(e, "STAGE_TIMEOUT", 600.0),
            specialists=_on(e, "SPECIALISTS"),
            threat_model=_on(e, "THREAT_MODEL"),
            domain_model=_on(e, "DOMAIN_MODEL"),
            critic=_on(e, "CRITIC"),
            verifier_max_calls=_int(e, "VERIFIER_MAX_MODEL_CALLS", 30),
            critic_max_calls=_int(e, "CRITIC_MAX_MODEL_CALLS", 20),
            architect_max_calls=_int(e, "ARCHITECT_MAX_MODEL_CALLS", 40),
            domain_modeler_max_calls=_int(e, "DOMAIN_MODELER_MAX_MODEL_CALLS", 12),
            threat_modeler_max_calls=_int(e, "THREAT_MODELER_MAX_MODEL_CALLS", 6),
            knowledge_max_calls=_int(e, "KNOWLEDGE_MAX_MODEL_CALLS", 10),
            state_path=e.get("STATE_PATH") or ".state/state.db",
            sessions_path=e.get("SESSIONS_PATH") or ".state/sessions.db",
            skip_deps=e.get("SKIP_DEPS") == "1",
            knowledge_cache=e.get("KNOWLEDGE_CACHE") or ".state/knowledge.db",
            knowledge_enrich=_on(e, "KNOWLEDGE_ENRICH"),
            ghsa_dir=e.get("GHSA_DIR", ""),
            github_token=e.get("GITHUB_TOKEN", ""),
            nvd_api_key=e.get("NVD_API_KEY", ""),
            web_search=e.get("WEB_SEARCH", ""),
            tavily_api_key=e.get("TAVILY_API_KEY", ""),
            index_max_files=_int(e, "INDEX_MAX_FILES", 3000),
            index_max_bytes=_int(e, "INDEX_MAX_BYTES", 30 * 1024 * 1024),
            otel_endpoint=e.get("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
            otel_service_name=e.get("OTEL_SERVICE_NAME") or "scanner",
            compaction_interval=_int(e, "COMPACTION_INTERVAL", 0),
            compaction_overlap=_int(e, "COMPACTION_OVERLAP", 2),
        )
