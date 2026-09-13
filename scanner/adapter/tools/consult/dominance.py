"""check_dominance: does a control (sanitizer/validator) dominate a sink? (adapter.dominance over the index)"""

from __future__ import annotations

from scanner.adapter.dominance import make_check_dominance
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    return make_check_dominance(ctx.target, ctx.idx)
