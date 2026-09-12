Stage instructions in scanner/app/instructions.py (OPERATING_PRINCIPLES preamble; Verifier/Investigator research rules; Critic negative rules and viability routes; Architect; ThreatModeler), the report-only hazard scoring in scanner/app/calibrate.py (calibrate prompt + calibration-rules catalogue) and the coverage / adversarial-sweep rules in scanner/app/reconcile.py (plan prompt) are adapted from Mantis (Apache-2.0, commit 876a0c8c6b92c92f34e0041b7dbbc0e4cccddc52) via Shannon/Keygraph capella prompts.

OWASP identifiers and titles in scanner/adapter/owasp.py — WSTG test ids and names, Top 10 (2021, 2025) category names and CWE lists, ASVS 5.0 requirement ids, Cheat Sheet Series page names — come from the OWASP projects (https://owasp.org, CC BY-SA 4.0). Only ids, titles and URLs are vendored; remediation one-liners are our own words.

Skills `scanner/skills/wstg-*.md` and `scanner/skills/control-*.md` are written in our own words after the OWASP Web Security Testing Guide and the OWASP Cheat Sheet Series (CC BY-SA 4.0); they cite only test ids, titles and URLs.

The hunting checklists in the taint / authz / config specialist sections and the Triage instruction
(scanner/app/instructions.py, card 44) are written in our own words after the methodology of Shannon's
vuln-injection / vuln-xss / vuln-ssrf / vuln-authz / vuln-auth / pre-recon-code prompts and the capella triage
prompt (Keygraph, AGPL-3.0; https://github.com/KeygraphHQ/shannon); no prompt text is copied.
