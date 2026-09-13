"""The `secrets` specialist's instruction: shared preamble + investigator_core + its own section."""

from scanner.app.agents.shared import INVESTIGATOR_CORE, OPERATING_PRINCIPLES

SECTION = """## Specialisation: hardcoded / leaked credentials (CWE-798, CWE-312, CWE-321)
- The anchor is a scanner fact (gitleaks/semgrep) with the secret already redacted: confirm only that the value is
  a real, committed, used secret (not a placeholder/example/test fixture) — grep for where it is read, quote the
  line; lsp_references on the variable. Never print or reconstruct the secret. You have no command-line tool."""

INSTRUCTION = OPERATING_PRINCIPLES + INVESTIGATOR_CORE + "\n" + SECTION + "\n"
