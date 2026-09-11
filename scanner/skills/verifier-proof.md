---
name: verifier-proof
description: What counts as proof for a Verifier verdict and the exact rules of the report_finding gate
---

# Verifier Proof Standard

Your output is a verdict on one Hypothesis, backed by lines you actually read. The
store is the truth: a finding exists only after `report_finding` accepts it. The
Dossier carries the `finding_id`, not the finding.

## What is proof

- **Confirmed**: a source→sink path you traced in code, with the untrusted input named,
  every hop cited `file:line`, and no adequate sanitizer or validator between them.
  On Go, start from `build_paths(anchor_id)`; on other languages follow
  `lsp_references` / `lsp_definition` hop by hop.
- **Rejected**: a counter-fact at a specific line. A parameterized query, an allowlist
  check, an ownership comparison, a `patched_in` version. "Looks safe" is not a
  counter-fact.
- **Uncertain**: you could not finish the trace. Say which hop is missing. This is a
  valid, cheap answer; a padded confirmation is not.

A sanitizer counts only if it dominates the sink on the path you traced. A check on
another branch, a different handler, or after the sink does not count.

## The report_finding gate

Refused, in this order:

1. No `anchor_id`, or an `anchor_id` not in `list_anchors`.
2. `cwe`, `file` or `line` that differ from the anchor. Omit them; the anchor is the
   source of truth.
3. Class needs a consult and the evidence lacks it: osv/CVE/GHSA anchors need
   `knowledge:<id>`, authz CWEs (284/285/639/862/863) need `domain:<entity>`.
   Applies to confirmed and rejected; uncertain is exempt.
4. Confirmed without evidence, or with evidence that is not found in the code around
   the anchor line. Quote lines exactly as read; consult references are skipped by
   this check, so at least one real code line is required.
5. Store validation: title required, status in confirmed|rejected|uncertain,
   confidence in 0..1.

A duplicate of an already accepted finding (same anchor, or same CWE+file+line with
the same status) is not an error: the existing finding is returned. A higher
confidence replaces it.

## OWASP methodology

Before confirming a class you are unsure how to test, call `consult_owasp` with the
CWE (e.g. `{"cwe": "CWE-89"}`). It returns the OWASP WSTG test (id + objectives — what
to check), the Top 10 2021 category, and the prevention cheat sheet — grounded in the
local OWASP corpus, no invention. Follow its objectives when tracing the path, and cite
the result in evidence as `owasp:<source>` (the WSTG or Top10 id, e.g. `owasp:WSTG-INJT-05`).
This is guidance, not a hard gate: a finding is still proven by the code path, but the
OWASP citation makes the verdict traceable to a recognised standard.

## Evidence list, in this order

1. `knowledge:<id>` or `domain:<entity>` when the class requires it.
2. `owasp:<WSTG-or-Top10-id>` when you consulted OWASP for the class.
3. The source line (where untrusted data enters).
4. Each hop that matters, one line each.
5. The sink line, exactly as in the file.

## New hypotheses

You may return up to 3. Each needs an `anchor_id` or a symbol you saw in the index,
and a claim of its own. Do not restate the one you just verified.
