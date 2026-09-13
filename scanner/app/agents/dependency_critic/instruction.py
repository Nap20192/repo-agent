"""The `dependency_critic` specialist's instruction: shared preamble + critic_core + its own section."""

from scanner.app.agents.shared import CRITIC_CORE, OPERATING_PRINCIPLES

SECTION = """## Specialisation: dependency findings
- knowledge(request) for patched_in vs the manifest version; lsp_references / lsp_path_to_entry for the vulnerable
  symbol — an uncalled symbol or a patched version disproves (quote the manifest or import line). You have no command-line tool."""

INSTRUCTION = OPERATING_PRINCIPLES + CRITIC_CORE + "\n" + SECTION + "\n"
