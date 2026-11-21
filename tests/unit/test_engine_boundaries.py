"""The engine modules never open a file, exec, eval or shell out (#27).

`AGENTS.md` section 4 forbids executing, importing or evaluating scanned content and forbids
running scanner code from the scanned checkout. The architecture concentrates filesystem and
subprocess access in `collector.py`, but nothing stopped `runner.py`, `model.py`, `fingerprint.py`
or `roles.py` from gaining an `open` or a `subprocess.run`. This test reads their source as text
and rejects those calls, so the boundary is visible in a diff and fails a pull request.

A future engine module joins the scanned set with one line in `ENGINE_MODULES`.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = REPO_ROOT / "src" / "airlock"

#: The modules this test holds to the boundary. Adding one is a one-line edit.
ENGINE_MODULES = (
    "fingerprint.py",
    "model.py",
    "roles.py",
    "runner.py",
)

#: A bare call that reaches the filesystem, the interpreter or the shell.
DENIED_NAMES = frozenset({"open", "eval", "exec", "compile", "__import__"})

#: Dotted calls that do the same through a module rather than a builtin.
DENIED_DOTTED = frozenset({"os.system", "os.popen", "os.execv", "os.execvp", "os.spawnv"})

#: `Path` methods that read or write bytes. `re.compile` is deliberately not here: the builtin
#: `compile` is denied by name, and the regex form is how the engine compiles patterns.
DENIED_PATH_METHODS = frozenset({"read_text", "read_bytes", "write_text", "write_bytes"})


def _dotted(node: ast.expr) -> str | None:
    """Render `a.b.c` from a Name/Attribute chain, or None for anything else."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _imports_subprocess(node: ast.Import | ast.ImportFrom) -> str | None:
    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.name == "subprocess" or alias.name.startswith("subprocess."):
                return alias.name
        return None
    if node.module and (node.module == "subprocess" or node.module.startswith("subprocess.")):
        return node.module
    return None


def violations(source: str, module: str = "<source>") -> list[tuple[str, int, str]]:
    """Every denied call or import in one source string, as (module, line, name)."""
    found: list[tuple[str, int, str]] = []
    for node in ast.walk(ast.parse(source, filename=module)):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name is None:
                continue
            if (
                name in DENIED_NAMES
                or name in DENIED_DOTTED
                or name.startswith("subprocess.")
                or name.rsplit(".", 1)[-1] in DENIED_PATH_METHODS
            ):
                found.append((module, node.lineno, name))
        elif isinstance(node, ast.Import | ast.ImportFrom):
            imported = _imports_subprocess(node)
            if imported is not None:
                found.append((module, node.lineno, f"import {imported}"))
    return found


@pytest.mark.parametrize("module", ENGINE_MODULES)
def test_an_engine_module_makes_no_denied_call(module: str) -> None:
    path = PACKAGE_ROOT / module
    assert path.is_file(), f"{module} is in ENGINE_MODULES but does not exist"

    found = violations(path.read_text(encoding="utf-8"), module)

    assert found == [], f"{module} reaches outside the collector: {found}"


def test_the_scanned_set_names_each_module() -> None:
    assert [module for module in ENGINE_MODULES] == [
        "fingerprint.py",
        "model.py",
        "roles.py",
        "runner.py",
    ]


def test_the_checker_rejects_open_in_a_doctored_runner() -> None:
    source = 'def run() -> None:\n    open("x")\n'

    assert violations(source, "runner.py") == [("runner.py", 2, "open")]


def test_the_checker_rejects_subprocess_run_and_names_the_line() -> None:
    source = "import subprocess\n\n\ndef run() -> None:\n    subprocess.run(['ls'])\n"

    assert violations(source, "runner.py") == [
        ("runner.py", 1, "import subprocess"),
        ("runner.py", 5, "subprocess.run"),
    ]


def test_the_checker_rejects_from_subprocess_import() -> None:
    assert violations("from subprocess import run\n", "runner.py") == [
        ("runner.py", 1, "import subprocess")
    ]


def test_the_checker_accepts_re_compile() -> None:
    assert violations("import re\n\nre.compile('x')\n", "roles.py") == []


def test_only_the_collector_imports_subprocess() -> None:
    importers = sorted(
        path.name
        for path in PACKAGE_ROOT.glob("*.py")
        if "import subprocess"
        in {
            item[2]
            for item in violations(path.read_text(encoding="utf-8"), path.name)
            if item[2].startswith("import subprocess")
        }
    )

    assert importers == ["collector.py"]
