# repo-agent2 — LLM-verified SAST on Google ADK (Python port of git-agent3)

Read `README.md` for the pipeline, `BOARD.md` for the cards/contract, `docs/rnd/` for ECC R&D reports.

## Layers (keep the dependency rule — guarded by tests/test_layers.py)

```
scanner/core      domain leaf: types (Literal vocabularies), rules, settings, ports (Index, RunStore), workflow state keys
scanner/adapter   fs, entrypoints, git, scanners/ (one scanner per file), SQLite State, OWASP, osv.dev, skills,
                  tools/ (one tool per file: make(ctx) + registry), index/ (LSP per language + grep)
scanner/app       agents/ (3: model, verify, critic — one folder each: agent.py SPEC,
                  instruction.py, tools.py; base.py = the one factory; registry.py = AGENTS + the class overlay), graph/
                  (nodes/ one per file — scan, build_skeleton, direct_findings, model, plan, audit, critique, export;
                  workflow.py edges; helpers/planning/reconcile), callbacks, observe, runner (composition root)
scanner/main.py   CLI only            eval/dataset.py  eval logic            web/<agent>/agent.py   adk web entrypoints (lazy)
```
Adding an agent = a folder from the template + one line in `registry.AGENTS` (+ a node file and one edge if it runs in
the graph) — see docs/adr/0009-feature-folders.md; the graph itself: docs/adr/0010-small-graph.md. Adding a tool = `tools/<group>/<tool>.py` with `make(ctx)` + one line in
`registry.TOOLS`.
Arrows point inward: `core` imports nothing of ours; `adapter` never imports `app`; inside `app`, `agents/` never imports
`graph/` or `runner`, `graph/` never imports `runner`; only `runner.py` wires adapter concretes. Env is read once in `core/settings.py` (`Settings.from_env`), never deep in modules. Shared test fakes live
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
- Tests first; a node or tool without a test is unfinished. Fakes live in `tests/fakes.py` (node-shaped doubles, `_workflow`, `_run`).
- Never use the user's LLM keys for your own tests: use ollama (`LLM_BASE_URL=http://localhost:11434/v1`).
- Findings exist only through the `report_finding` gate (the one exception is the deterministic direct lane:
  osv/gitleaks/semgrep-error anchors → `store.report` with dedup and enrichment, no model, no gate — card 42); secrets are redacted (`core.redact_secrets`); tool
  outputs are capped; symlinks outside the target are invisible. Do not weaken these.
- Ponytail: stdlib first, no abstraction with one implementation, mark deliberate corners `# ponytail:`.
- `.env`, `.state/`, `.runs/`, `.targets/` are local; never commit them.
