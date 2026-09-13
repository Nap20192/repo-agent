"""Architecture guards (docs/architecture.md → Conventions): the dependency rule and the tests-as-library ban.

Mirrors git-agent3's archtest: `core` imports nothing of ours but `core`; `adapter` never imports `app`;
test modules never import other test modules (shared fakes live in tests/fakes.py)."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPORT = re.compile(r"^\s*(?:from|import)\s+(scanner(?:\.\w+)*|tests(?:\.\w+)*)", re.MULTILINE)


def _imports(path: Path) -> set[str]:
    return set(IMPORT.findall(path.read_text(encoding="utf-8")))


def test_core_is_a_leaf():
    for p in (ROOT / "scanner" / "core").rglob("*.py"):
        bad = {m for m in _imports(p) if not m.startswith("scanner.core") and m != "scanner"}
        assert not bad, f"{p.relative_to(ROOT)} imports outside core: {sorted(bad)}"


def test_adapter_never_imports_app():
    for p in (ROOT / "scanner" / "adapter").rglob("*.py"):
        bad = {m for m in _imports(p) if m.startswith("scanner.app")}
        assert not bad, f"{p.relative_to(ROOT)} imports app: {sorted(bad)}"


def test_test_modules_do_not_import_each_other():
    for p in (ROOT / "tests").rglob("test_*.py"):
        bad = {m for m in _imports(p) if m.startswith("tests.test_")}
        assert not bad, f"{p.relative_to(ROOT)} imports a test module: {sorted(bad)} — use tests/fakes.py"


def test_app_packages_keep_their_direction():
    """Card 47: inside `app`, agents/ know nothing of the graph or the runner, graph/ knows nothing of the runner —
    the composition root is the only place that wires them together."""
    for p in (ROOT / "scanner" / "app" / "agents").rglob("*.py"):
        bad = {m for m in _imports(p) if m.startswith("scanner.app.graph") or m == "scanner.app.runner"}
        assert not bad, f"{p.relative_to(ROOT)} imports the graph/runner: {sorted(bad)}"
    for p in (ROOT / "scanner" / "app" / "graph").rglob("*.py"):
        bad = {m for m in _imports(p) if m == "scanner.app.runner"}
        assert not bad, f"{p.relative_to(ROOT)} imports the runner: {sorted(bad)}"


def test_every_agent_folder_and_tool_file_follow_the_template():
    """One folder per agent (4 files), one tool per file exposing `make(ctx)`, one node per file exposing `<name>_node`."""
    agents = ROOT / "scanner" / "app" / "agents"
    folders = [p for p in agents.iterdir() if p.is_dir() and not p.name.startswith("_")]
    assert len(folders) == 5
    for f in folders:
        assert {x.name for x in f.glob("*.py")} == {"__init__.py", "agent.py", "instruction.py", "tools.py"}, f.name
    tools = ROOT / "scanner" / "adapter" / "tools"
    helpers = {"gates/finding.py"}  # the pure gate check behind report_finding, not a tool itself
    for p in tools.rglob("*.py"):
        if p.parent != tools and p.name != "__init__.py" and p.relative_to(tools).as_posix() not in helpers:
            assert "def make(ctx: ToolContext)" in p.read_text(encoding="utf-8"), p.relative_to(ROOT)
    nodes = ROOT / "scanner" / "app" / "graph" / "nodes"
    for p in nodes.glob("*.py"):
        if p.name != "__init__.py":
            assert "_node(" in p.read_text(encoding="utf-8"), p.relative_to(ROOT)
