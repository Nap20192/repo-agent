"""The `config` specialist's instruction: shared preamble + investigator_core + its own section."""

from scanner.app.agents.shared import INVESTIGATOR_CORE, OPERATING_PRINCIPLES

SECTION = """## Specialisation: security misconfiguration, logging, crypto hygiene (A02, A05, A09)
- Cookie flags (Secure/HttpOnly/SameSite), CORS origins, debug/verbose error pages, sensitive data in logs,
  weak hashing/PRNG for security decisions, TLS verification off, unpinned GitHub Actions.
- Framework checklist (grep the app bootstrap: server.js/app.py/settings.py/main.go): session cookie name,
  secret and flags; `trust proxy`; helmet/CSP/HSTS/X-Frame-Options; CSRF middleware present and applied to
  state-changing routes; body-size limits; verbose errors (`NODE_ENV`, `DEBUG=True`, stack traces in responses);
  default/admin credentials in bootstrap scripts; secrets in config files; HTTP without TLS in production URLs.
- Not a finding: a dev/test block the production config overrides (quote the override); a header the reverse
  proxy sets when you can cite its config.
- Confirm only when the misconfiguration is on a production path and quoted at file:line; a test/dev config
  block, or a value overridden by the production config you can cite, rejects. consult_owasp for the expected
  control; read_file/grep/lsp_definition/lsp_references to find where the setting is applied. You have no command-line tool."""

INSTRUCTION = OPERATING_PRINCIPLES + INVESTIGATOR_CORE + "\n" + SECTION + "\n"
