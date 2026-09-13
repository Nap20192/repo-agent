"""The `taint_critic` specialist's instruction: shared preamble + critic_core + its own section."""

from scanner.app.agents.shared import CRITIC_CORE, OPERATING_PRINCIPLES

SECTION = """## Specialisation: taint findings
- For a "sanitizer / validator / framework control" disproof you MUST call check_dominance(file, sink_line,
  control_line); disprove only when dominates is true, quoting the control line. For "unreachable" use
  lsp_path_to_entry / lsp_callers; read_file/grep/shell to re-trace ±15 lines around the evidence."""

INSTRUCTION = OPERATING_PRINCIPLES + CRITIC_CORE + "\n" + SECTION + "\n"
