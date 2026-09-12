# repo-agent2 — LLM-verified SAST on Google ADK (Python port of git-agent3)

Read `README.md` for the pipeline, `BOARD.md` for the cards/contract, `docs/rnd/` for ECC R&D reports.

## Layers (keep the dependency rule — guarded by tests/test_layers.py)

```
scanner/core      domain leaf: types (Literal vocabularies), rules, calibrate, settings, ports (Index parts, RunStore, Router)
scanner/adapter   fs, entrypoints, static scanners, SQLite State, OWASP, skills, knowledge, domain, dominance, tools/ (package), index/ (LSP per language + grep)
scanner/app       ADK agents (one `new_agent` factory), specialists registry + router, PipelineV2 graph, reconcile, callbacks, observe, runner (composition root)
scanner/main.py   CLI only            eval/dataset.py  eval logic            web/fullscan/agent.py   adk web entrypoint (lazy)
```
Arrows point inward: `core` imports nothing of ours; `adapter` never imports `app`; only `runner.py` wires adapter
concretes. Env is read once in `core/settings.py` (`Settings.from_env`), never deep in modules. Shared test fakes live
in `tests/fakes.py`; test modules never import each other. Architecture rationale and sources: docs/architecture.md,
decisions: docs/adr/.

## Commands

```
uv run pytest -q                       # default suite (live evals deselected)
uvx ruff check scanner tests web eval scripts
uv run python -m scanner full --target samples/02-vulnshop     # exit 0/1/2
LIVE_EVAL=1 uv run python -m eval.agents --model openai/qwen3:1.7b --k 3   # per-agent pass@k
uv run python scripts/ecc_rnd.py       # ECC catalog diff (see .claude/skills/ecc-rnd)
```

## Rules for agents working here

- Work through ECC: `ecc:orch-add-feature` / `orch-fix-defect` / `orch-refine-code` → `tdd-workflow` →
  `code-reviewer` (+ `security-reviewer` when subprocesses, paths, secrets or the gate change). Honor GATE 1
  (plan) and GATE 2 (commit). Keep BOARD.md cards: owner, state, files, merge gate.
- Tests first; a node or tool without a test is unfinished. Fakes live in `tests/test_graph.py`.
- Never use the user's LLM keys for your own tests: use ollama (`LLM_BASE_URL=http://localhost:11434/v1`).
- Findings exist only through the `report_finding` gate (the one exception is the deterministic direct lane:
  osv/gitleaks/semgrep-error anchors → `store.report` with dedup and enrichment, no model, no gate — card 42); secrets are redacted (`core.redact_secrets`); tool
  outputs are capped; symlinks outside the target are invisible. Do not weaken these.
- Ponytail: stdlib first, no abstraction with one implementation, mark deliberate corners `# ponytail:`.
- `.env`, `.state/`, `.runs/`, `.targets/` are local; never commit them.
