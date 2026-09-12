# Eval corpus

`eval/dataset.json` is the ground truth for `python -m scanner eval`: per case a target directory and the
expected confirmed findings as `(cwe, file, line)` where `line` is the **sink** line. A finding matches when
the CWE is equal and `|line − expected| ≤ tolerance`. Precision/recall/F1 are computed over confirmed findings
only; the run passes when every expected finding is confirmed and nothing else is.

## Rules for a case

- **Safe neighbour per class.** Every vulnerable handler has a sibling that does the same job correctly
  (parameterized query, argv without shell, `realpath` + prefix check, allow-listed host, escaped output).
  Safe neighbours are never listed in `expected`: confirming one is a false positive and lowers precision.
- **`sink` keyword.** Optional but recommended: the text the expected line must contain
  (`db.Query`, `exec(`, `sendFile`, `redirect`, `eval(`…). `tests/test_eval_dataset.py` fails when a sample
  edit moves the line, so ground truth cannot drift silently.
- **Remote targets.** A case may carry `"url"`; `scan eval` clones it shallowly into `target` when the
  directory is missing (`.targets/` is git-ignored, nothing is vendored). `notes` explains each expectation.
- **Design-only defects.** Cases like `nodegoat` CWE-943 have no scanner anchor; they measure the
  ThreatModeler → synthetic anchor path, not the pre-pass.

## Commands

```
uv run python -m scanner eval --dry            # validate the dataset (clones remote targets), no model
uv run python -m scanner eval                  # full run, exit 0 iff no FP and no FN
uv run pytest -q tests/test_eval_dataset.py    # local cases: files, lines and sinks exist
```

## Cases

| case | target | language | classes |
|---|---|---|---|
| hello | samples/01-hello | Go | none (control) |
| vulnshop | samples/02-vulnshop | Go | 89, 78 (+ `/safe`) |
| govulnlab | samples/03-govulnlab | Go | 89, 78, 22, 918, 79 |
| idor-go | samples/08-idor-go | Go | 639 (design-only) |
| flaskshop | samples/10-flaskshop | Python/Flask | 89, 78, 22, 918, 79, each with `_safe` |
| expressshop | samples/11-expressshop | JS/Express | 89, 78, 22, 601, 95, each with `_safe`; inline arrow handlers |
| nodegoat | `.targets/NodeGoat` (clone) | JS/Express | 95, 943, 601, 79, 639 |

## Licenses

Samples 10 and 11 are original. NodeGoat is OWASP's, Apache-2.0 — cloned at eval time, not vendored.

## Live per-agent eval (`eval/agents.py`)

```
uv run python -m eval.agents --model openai/qwen3:1.7b --k 3 --budget 12 --out eval/scorecard.json
uv run python -m eval.agents --only taint,authz_critic --k 1          # a subset
LIVE_EVAL=1 EVAL_ONLY=taint uv run pytest -m live tests/live           # same via pytest
```

One trial per agent, graded by code, reported as pass@k / pass^k with model calls and seconds. Beyond the
four stage agents and the tool window, every specialist of `scanner/app/specialists.py` gets its own fixture,
routed exactly like the graph (`route()` picks it and the language overlay suffix):

| trial | fixture | pass when |
|---|---|---|
| taint | 02-vulnshop CWE-89 anchor, go overlay | confirmed finding quoting `db.Query` |
| authz | 08-idor-go `getOrder`, canned `domain_map` artifact | `consult_domain` called, confirmed with a `domain:` ref |
| dependency | 11-expressshop, osv anchor GHSA-rv95-896h-c2vc | verdict cites `knowledge:`, knowledge consulted, no shell |
| secrets | temp `config.js` with a fake GitHub token | verdict recorded, evidence never contains the raw token, no shell |
| config | temp Express `res.cookie` without flags (CWE-614) | verdict recorded |
| taint_critic | confirmed `/safe` `$1` query + real SQLi | `/safe` disproved after `check_dominance`, real SQLi survives |
| authz_critic | owner check in the `else` branch, admin branch unchecked | finding survives |
| dependency_critic | express 4.17.1 declared, `res.redirect` never called | finding disproved after a reachability tool |

Model: ollama only for our own runs (`LLM_BASE_URL`, key `ollama`); a Gemini spec needs `GOOGLE_API_KEY`.
The dependency trial consults osv.dev over the network; `KNOWLEDGE_ENRICH=0` keeps the pre-pass offline.
