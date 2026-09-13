"""build_skeleton: the target and its entry points — what the modelling stages receive."""

from __future__ import annotations

from collections.abc import Callable

from google.adk.workflow import FunctionNode

from scanner.core import Anchor, Candidate
from scanner.core.ports import RunStore
from scanner.core.workflow import ScanSkeleton


def skeleton(target: str, entry_points_fn: Callable[[], list[Candidate]] | None) -> ScanSkeleton:
    """What the modelling stages receive: the target and its entry points (anchors are read from the store by plan)."""
    return ScanSkeleton(target=target, entry_points=list(entry_points_fn()) if entry_points_fn else [])


def anchor_view(anchors: list[Anchor]) -> list[dict]:
    """The trimmed anchor list the modelling stages see."""
    return [{"id": a.id, "tool": a.tool, "cwe": a.cwe, "file": a.file, "line": a.line, "message": a.message[:120]}
            for a in anchors]


def build_skeleton_node(store: RunStore, target: str, entry_points_fn: Callable[[], list[Candidate]] | None) -> FunctionNode:
    """scan → skeleton. The pre-pass already ran; this node reads its anchors."""
    def build_skeleton(node_input) -> ScanSkeleton:  # node_input: the user turn that started the run, unused
        return skeleton(target, entry_points_fn)
    return FunctionNode(func=build_skeleton, name="build_skeleton")
