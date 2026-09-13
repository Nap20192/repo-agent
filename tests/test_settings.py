"""Settings is the only env reader: defaults, overrides, .env precedence, and a grep guard on the owned modules."""

import re
from pathlib import Path

from scanner.app.settings import Settings, apply_dotenv, load_dotenv


def test_defaults_match_the_previous_hardcoded_values():
    s = Settings.from_env({})
    assert (s.max_rounds, s.max_hyps, s.max_parallel) == (4, 8, 3)
    assert (s.verifier_max_calls, s.critic_max_calls, s.model_max_calls) == (30, 20, 40)
    assert s.stage_timeout == 600.0 and s.threat_model and s.critic
    assert s.state_path == ".state/state.db" and s.knowledge_cache == ".state/knowledge.db"
    assert s.index_max_bytes == 30 * 1024 * 1024 and s.otel_service_name == "scanner"


def test_env_overrides_and_switches():
    s = Settings.from_env({"BUGFINDER_MAX_HYPS": "2", "STAGE_TIMEOUT": "1.5", "CRITIC": "0",
                           "VERIFIER_MAX_MODEL_CALLS": "junk", "SKIP_DEPS": "1", "KNOWLEDGE_ENRICH": "0"})
    assert s.max_hyps == 2 and s.stage_timeout == 1.5 and not s.critic
    assert s.verifier_max_calls == 30  # unparsable → default, as before
    assert s.skip_deps and not s.knowledge_enrich


def test_dotenv_process_env_wins(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("# comment\nBUGFINDER_MAX_ROUNDS=9\nLLM_MODEL='m'\nbroken line\n")
    assert load_dotenv(env) == {"BUGFINDER_MAX_ROUNDS": "9", "LLM_MODEL": "m"}
    monkeypatch.setenv("BUGFINDER_MAX_ROUNDS", "1")
    monkeypatch.delenv("LLM_MODEL", raising=False)
    apply_dotenv(env)
    s = Settings.from_env()
    assert s.max_rounds == 1 and s.llm_model == "m"


def test_dotenv_inline_comments_and_utf8(tmp_path):
    env = tmp_path / ".env"
    lines = ["BUGFINDER_TARGET=      # цель по умолчанию для web (adk web)", "LLM_MODEL=m   # модель",
             "URL=http://h/#frag", "Q='a # b'  # c"]
    env.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert load_dotenv(env) == {"BUGFINDER_TARGET": "", "LLM_MODEL": "m", "URL": "http://h/#frag", "Q": "a # b"}


def test_no_env_reads_outside_settings():
    owned = ["scanner/app/runner.py", "scanner/app/graph/helpers.py", "scanner/app/graph/workflow.py", "scanner/app/graph/nodes/critique.py", "scanner/adapter/knowledge.py",
             "scanner/adapter/index/lsp.py", "scanner/app/observe.py"]
    root = Path(__file__).resolve().parent.parent
    offenders = [f for f in owned if re.search(r"os\.(environ|getenv)", (root / f).read_text(encoding="utf-8"))]
    assert offenders == []
