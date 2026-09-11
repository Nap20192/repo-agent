"""Pure call-graph helpers shared by the index adapters: enclosing-symbol lookup and the BFS to an entry."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable


def enclosing(spans: Iterable[tuple[int, int, str]], line: int) -> str:
    """Innermost (start, end, name) span containing `line`; "" when none."""
    best = ""
    best_start = -1
    for start, end, name in spans:
        if start <= line <= end and start > best_start:
            best, best_start = name, start
    return best


def path_to_entry(
    callers: Callable[[str], list[tuple[str, int, str]]], fqn: str, entries: Iterable[str], max_depth: int = 6
) -> list[str] | None:
    """BFS up the caller graph from `fqn` until a symbol in `entries`; returns [entry, ..., fqn] or None."""
    goals = set(entries)
    if fqn in goals:
        return [fqn]
    prev: dict[str, str | None] = {fqn: None}
    queue: deque[tuple[str, int]] = deque([(fqn, 0)])
    while queue:
        cur, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for _, _, name in callers(cur):
            if not name or name in prev:
                continue
            prev[name] = cur
            if name in goals:
                chain = [name]
                while chain[-1] != fqn:
                    chain.append(prev[chain[-1]])  # type: ignore[arg-type]
                return chain
            queue.append((name, depth + 1))
    return None
