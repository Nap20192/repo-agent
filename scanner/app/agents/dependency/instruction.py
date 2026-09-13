"""The `dependency` specialist's instruction: shared preamble + investigator_core + its own section."""

from scanner.app.agents.shared import INVESTIGATOR_CORE, OPERATING_PRINCIPLES

SECTION = """## Specialisation: vulnerable dependencies / supply chain (A06)
- knowledge(request: advisory id or package@version) is MANDATORY: cite 'knowledge:<GHSA/CVE>' (the gate requires it).
- Then decide reachability, not just presence: the advisory's vulnerable symbol must be called on a path from
  an entry point — lsp_references / lsp_path_to_entry on the symbol, read_file/grep for the import and call.
- patched_in above the manifest version, or an uncalled symbol → rejected with that line quoted. You have no command-line tool."""

INSTRUCTION = OPERATING_PRINCIPLES + INVESTIGATOR_CORE + "\n" + SECTION + "\n"
