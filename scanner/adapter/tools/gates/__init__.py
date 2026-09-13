"""The two verdict gates: report_finding (Investigator) and disprove_finding (Critic).

A finding exists only if the gate accepted it: anchor exists, coordinates agree with the anchor, the required
consult reference is cited, and a confirmed verdict quotes a line really present at the anchor."""

from scanner.adapter.tools.gates.finding import gate_finding

__all__ = ["gate_finding"]
