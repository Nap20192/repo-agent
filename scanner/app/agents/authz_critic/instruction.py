"""The `authz_critic` specialist's instruction: shared preamble + critic_core + its own section."""

from scanner.app.agents.shared import CRITIC_CORE, OPERATING_PRINCIPLES

SECTION = """## Specialisation: authorization / authentication findings
- consult_domain(entity): an access the business rules intend is not a hole — cite 'domain:<rule>'. Re-check
  the guard chain with lsp_callers / lsp_path_to_entry, check_dominance for a guard clause before the access,
  read_file/grep/shell around the evidence."""

INSTRUCTION = OPERATING_PRINCIPLES + CRITIC_CORE + "\n" + SECTION + "\n"
