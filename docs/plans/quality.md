# Plan: quality phase (orch-refine-code, behavior-neutral)

Source: docs/audits/{architecture,types,comments}.md. Tier: large. Baseline: 194 tests green, ruff clean.
Rule per step: tests green after each change, no new behavior, `refactor:` commits.

## Wave 1 (disjoint files, parallel)
- A `ports-and-fakes`: arch 1, 2, 3; types 4, 5 — core/ports.py (RunStore, Router, SymbolLocator/Definitions/CallGraph/Closeable/Degradable, Index = union), adapter/index/__init__.py (FallbackIndex on Degradable), delete tools._GrepIndex/_default_index, `_Graph.store/router` and `PipelineV2.index` typed, tests/fakes.py + tests/conftest.py, all test imports moved. ADR 0002 (ports), 0003 (index split), 0005 (fakes).
- F `docs-architecture`: docs/architecture.md (layer → SOLID → source mapping, cited), ADR 0001..0005 files per ecc:architecture-decision-records, comment fixes not touching code owned by A (pipeline_v2 docstring, graph ParallelAgent note).
- G `cli-eval-web`: arch 11 (eval logic → eval/dataset.py, main.py CLI only), 12 (web lazy prepare, pyproject package config instead of sys.path), delete RoundInput/RoundOutput only if A has not; `ROUTER → route_name` alias kept for compatibility.

## Wave 2 (after A; disjoint)
- B `fs-entrypoints`: arch 6 — adapter/fs.py + adapter/entrypoints.py (per-language detector table), static.py slimmed; update importers.
- C `types-literals`: types 1, 2, 3 — Literal fields, model validators mirroring existing gate messages, wstg_id/asvs_id propagated to Finding (+ Finding.asvs_id).
- D `settings`: arch 9 — app/settings.py built once in runner; env reads removed from graph/pipeline/knowledge/static/lsp; PYTEST_CURRENT_TEST removed (tests inject).
- E `tools-package`: arch 5, 7, 8 — adapter/tools/ package (gates, code, lsp, common, rosters), one `inside`, one `new_agent` factory, single consult_domain impl (map first, grep fallback), consult_knowledge over knowledge.osv_vuln; types 6 (TypedDicts).

## Wave 3
- `ecc:code-simplifier` + `ecc:refactor-cleaner` sweep; `ecc:python-reviewer` + `ecc:code-reviewer`; commit.
