"""deps_dev: advisories and licenses for one package version."""

from __future__ import annotations

from scanner.adapter import knowledge as kn
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    def deps_dev(system: str, package: str, version: str) -> dict:
        """deps.dev: advisory ids and licenses for one package version (system: npm|pypi|go|cargo|maven|rubygems)."""
        return kn.deps_dev(system, package, version) or {"status": "error", "reason": "no deps.dev data"}

    return deps_dev
