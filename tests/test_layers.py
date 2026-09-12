"""Architecture guards (docs/architecture.md → Conventions): the dependency rule and the tests-as-library ban.

Mirrors git-agent3's archtest: `core` imports nothing of ours but `core`; `adapter` never imports `app`;
test modules never import other test modules (shared fakes live in tests/fakes.py)."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPORT = re.compile(r"^\s*(?:from|import)\s+(scanner(?:\.\w+)*|tests(?:\.\w+)*)", re.MULTILINE)


def _imports(path: Path) -> set[str]:
    return set(IMPORT.findall(path.read_text()))


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
