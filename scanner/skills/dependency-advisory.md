---
name: dependency-advisory
description: How to confirm or reject an osv / CVE / GHSA anchor by comparing the manifest version with the advisory's fixed versions via osv_query
---

# Dependency Advisory

An osv anchor says "this manifest pins a package with a known advisory". It is not a
finding until you show the pinned version is inside the affected range. The gate
refuses a dependency finding without a `knowledge:` reference.

## Steps

1. Read the anchor: `rule_id` is the advisory id (GO-…, CVE-…, GHSA-…), `file:line`
   points at the manifest entry (`go.mod`, `package-lock.json`, `requirements.txt`).
2. Call `osv_query` with the advisory id, or with `ecosystem:name@version` (e.g. `npm:tar@4.4.8`)
   when only the package is known. Do not guess ranges from memory.
3. Compare the version at the anchor line with the answer:
   - version below every `fixed` entry (or the package@version query lists the advisory) → **confirmed**;
   - version at or above a `fixed` entry → **rejected** ("not affected in this
     version");
   - the answer is empty or ranges are ambiguous → **uncertain**, say what is missing.
4. Severity: read the advisory's CVSS `vector` (AV:N/PR:N/… → high or critical); otherwise keep the anchor's.
5. Name the first `fixed` version in the finding title or notes; the report uses it.

## Evidence the gate accepts

- `knowledge:<advisory id>` (e.g. `knowledge:GHSA-xxxx-yyyy-zzzz`) is mandatory for
  both confirmed and rejected.
- The exact manifest line as read (`github.com/foo/bar v1.2.3`).
- The range you compared against, quoted from the answer.

## Do not

- Do not confirm because the package name matches; the version decides.
- Do not report reachability as proven; whether the vulnerable symbol is called is a
  later stage. State it in notes if you happen to see it.
- Do not resolve the version from a lockfile you did not open; quote the line.
