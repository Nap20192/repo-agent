# ADR-0011: fewer entities — no consultants, no enrichment stack, no calibration, one Index port

Status: accepted (2026-09-12). Amends ADR-0010 (five agents → three) and supersedes ADR-0003 (the Index port split).

## Context

After the small graph (ADR-0010) the run still carried entities that cost more than they returned: two consultant
agents (`knowledge`, `domain`) wired as AgentTools of `verify`/`critic`, each with its own budget, prompt, web app
and eval set; a 374-line knowledge adapter (OSV + GHSA + NVD + EPSS + KEV + deps.dev, SQLite cache, enrichment of
osv anchors in the pre-pass, five env knobs); a report-only calibration score with an `intent` (production/sample)
the model had to judge; an adversarial sweep and file baselines in `plan`; an `Index` port split five ways with
one consumer. The owner asked to cut "the complex entities nobody needs".

## Decision

| gone | instead |
|---|---|
| `knowledge` agent, `adapter/knowledge.py`, `tools/knowledge/*`, `KNOWLEDGE_*`, `GHSA_DIR`, `GITHUB_TOKEN`, `NVD_API_KEY` | `adapter/osv.py` (fetch / normalize / vuln / batch, no cache) behind ONE tool `osv_query` on `verify` and `critic`; it answers with `ref: knowledge:<id>` — the gate's evidence requirement is unchanged |
| `domain` agent | `verify` / `critic` read the ownership / role check themselves (grep, lsp) and cite `domain:<entity>`; the gate still requires it for authz classes |
| `AgentSpec.consults`, `build(extra_tools=)`, AgentTool wiring, `per_invocation` budgets, `folder`, `CONSULTANTS` | nothing — an agent is its roster |
| `core/calibrate.py`, `Finding.calibration`, `ThreatModel.intent`, `planning.calibrate_all`, the export calibration step, `Finding.viability` / `repro_status` | severity and confidence as the gate recorded them; the Critic's `review` is the only annotation |
| `adversarial_sweep`, file baselines (`FILE_BASELINE_MAX`, `source_files_fn`) | entry-point baselines only (`coverage`), classes by route words (`hunt_classes`) |
| `SymbolLocator` / `Definitions` / `CallGraph` / `Closeable` / `Degradable` | one `Index` Protocol (+ `close`); an LSP adapter exposes `failed` for the fallback |
| `web/knowledge`, `web/domain` | three web apps: `model`, `verify`, `critic` (+ `fullscan`) |

## Consequences

- Dependency findings from the direct lane cite the advisory ids osv-scanner reported (`knowledge:<id>`) and the
  import count; CVSS/EPSS/KEV facts are no longer attached — the Investigator fetches what it needs with `osv_query`.
- No network in the pre-pass beyond the scanners themselves; `osv_query` is the only outbound call an agent can make,
  capped at 4 MB per answer, errors returned as tool answers.
- `summary.json` loses `intent` and `findings[].calibration`; SARIF `properties` keep `finding_id`, `anchor_id`,
  `confidence`, `source`, `review`.
- Settings: 20 knobs → 13.
