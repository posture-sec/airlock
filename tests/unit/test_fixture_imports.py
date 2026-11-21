"""`tests.fixtures` must import without touching disk or the network (issue #86, task 9.30).

`tests/fixtures/__init__.py` deliberately defers every file read: `builders()` imports the
builder modules on call, `shipped_rules()` reads the rule tree on call, and the only thing at
module level is `REPO_ROOT = Path(__file__).resolve().parents[2]`. Nothing enforces that. If a
future commit replaces `shipped_rules()` with a module-level `RULES = shipped_rules()`, every
importing test file will read the rule tree during collection and depend on the working
directory -- a real slowdown and a real fragility.

A subprocess is the only honest witness: the parent pytest run already has the package
imported, so `monkeypatch` cannot catch what happened at import time. `sys.addaudithook`
observes every `open`, `path` and `socket.connect` event the interpreter emits during the
child's import, and the child prints a summary the parent asserts on.

`.pyc` reads bypass `builtins.open`, so `io.open_code` is guarded too -- otherwise a
bytecode write on first import (which happens under pytest) would look like a file open
against a rule TOML. The audit hook filters any path ending in `.py`/`.pyc`/`.pyo` or
containing `__pycache__`: those are the interpreter loading its own source, not the
package reading the rule tree. The property under test is "no application file reads",
not "no interpreter file reads".
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Child script: install an audit hook that records every open / connect / module-load, then
# import tests.fixtures, then print the summary as JSON. Exit 0 always -- the assertions
# belong in the parent so a failing child is still readable. The parent passes
# `PYTHONPATH` covering `src` and `.` (issue #86 §5), which is what the child imports from.
GUARD_SCRIPT = textwrap.dedent(
    """
    import json
    import sys

    opens: list[str] = []
    connects: list[str] = []

    _SKIP_SUFFIXES = (".py", ".pyc", ".pyo")
    _SKIP_MARKER = "__pycache__"


    def _application_file(path: object) -> str | None:
        # Interpreter bytecode reads are not the property under test; a rule TOML or a
        # source file the fixture package opened is. `.py` is included on the skip list
        # because `Path.read_text()` on the package's own module source would be indistinguishable
        # from the loader's `SourceFileLoader.get_code` under the audit event -- but that
        # call never goes through the audit `open` path from inside `tests.fixtures`,
        # which does not read its own source at import.
        if not isinstance(path, (str, bytes)):
            return None
        text = path.decode() if isinstance(path, bytes) else path
        if text.endswith(_SKIP_SUFFIXES) or _SKIP_MARKER in text:
            return None
        return text


    def _audit(event: str, args: tuple) -> None:
        if event == "open":
            hit = _application_file(args[0])
            if hit is not None:
                opens.append(hit)
        elif event == "socket.connect":
            connects.append(repr(args[1]))


    sys.addaudithook(_audit)

    import tests.fixtures  # noqa: F401

    loaded_builders = sorted(
        name
        for name in sys.modules
        if name.startswith("tests.fixtures.")
    )

    print(json.dumps({"opens": opens, "connects": connects, "builders": loaded_builders}))
    """
)

# Every builder module under `tests/fixtures/`. Nine are imported on demand by
# `tests/fixtures/__init__.py:builders()`; the other three are reached by the tests that own
# their rules instead of by the registry. The list is deliberately manual: a module added
# there has to be named here, and the coverage test fails until it is, because the eager-load
# assertion only means something if it covers the whole package.
EXPECTED_BUILDER_MODULES = (
    "tests.fixtures.builtin_patterns",
    "tests.fixtures.cargo_vectors_patch",
    "tests.fixtures.cfg_network_url",
    "tests.fixtures.ci_surface",
    "tests.fixtures.ci_surface_hook_window",
    "tests.fixtures.config_role",
    "tests.fixtures.editor_profile_fp",
    "tests.fixtures.native_binary_artifact",
    "tests.fixtures.npm_lockfile_registry",
    "tests.fixtures.pr_mode",
    "tests.fixtures.stellar_seed",
    "tests.fixtures.wasm_lfs_pointer",
    "tests.fixtures.wasm_manifest",
)


def run_guard_script(env_pythonpath: str, cwd: Path | None = None) -> dict:
    """Import `tests.fixtures` in a clean subprocess and return what the audit hook recorded.

    No `-I` (isolated mode): issue #86 §5 asks the subprocess to run with `PYTHONPATH`
    covering `src` and ``,`, and `-I` ignores that variable. The child is otherwise fully
    contained -- no pytest, no network calls beyond what the guard records.

    `cwd` defaults to the repository root (issue §5). A shim caller passes its own tree so
    `import tests.fixtures` resolves to the shim first: with `-c`, sys.path[0] is the cwd
    and that entry outranks `PYTHONPATH`.
    """
    result = subprocess.run(
        [sys.executable, "-c", GUARD_SCRIPT],
        cwd=cwd or REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
        env={"PYTHONPATH": env_pythonpath, "PATH": "/usr/bin:/bin", "HOME": str(REPO_ROOT)},
    )
    payload = result.stdout.strip().splitlines()[-1]
    return json.loads(payload)


@pytest.fixture
def env_pythonpath() -> str:
    """The same `src` + repo root pytest puts on `pythonpath` (`pyproject.toml:42`)."""
    return f"{REPO_ROOT / 'src'}:{REPO_ROOT}"


class TestFixturesImportIsSideEffectFree:
    def test_importing_tests_fixtures_opens_no_application_file(self, env_pythonpath: str) -> None:
        recorded = run_guard_script(env_pythonpath)["opens"]
        assert recorded == [], f"tests.fixtures import opened: {recorded}"

    def test_importing_tests_fixtures_opens_no_socket(self, env_pythonpath: str) -> None:
        recorded = run_guard_script(env_pythonpath)["connects"]
        assert recorded == [], f"tests.fixtures import touched the network: {recorded}"

    def test_importing_tests_fixtures_loads_no_builder_module(self, env_pythonpath: str) -> None:
        loaded = run_guard_script(env_pythonpath)["builders"]
        # Any `tests.fixtures.<module>` in `sys.modules` means `builders()` ran at import.
        assert loaded == [], f"builder modules loaded eagerly: {loaded}"

    def test_the_guard_list_covers_every_builder(self) -> None:
        """If a builder is added under `tests/fixtures/`, `EXPECTED_BUILDER_MODULES` must grow."""
        on_disk = {
            f"tests.fixtures.{path.stem}"
            for path in (REPO_ROOT / "tests" / "fixtures").glob("*.py")
            if path.stem != "__init__"
        }
        listed = set(EXPECTED_BUILDER_MODULES)
        assert on_disk == listed, (
            f"tests/fixtures drift: on disk but not listed: {sorted(on_disk - listed)}; "
            f"listed but not on disk: {sorted(listed - on_disk)}"
        )


class TestTheGuardBites:
    def test_eager_shipped_rules_is_reported_as_a_file_read(self, tmp_path: Path) -> None:
        """Issue #86 §2 requires a demonstration that the guard catches an eager `shipped_rules`.

        The real mutation ("add RULES = shipped_rules() at module level") would race a
        teammate's parallel run against the same tree, so the shim is a self-contained
        stand-in: one line that opens a rule TOML at import time, which is exactly what
        `shipped_rules()` does on the caller's behalf. Any open on `.toml` in the audit
        hook proves the guard would fire on the real mutation.
        """
        shim_tests = tmp_path / "tests"
        shim_fixtures = shim_tests / "fixtures"
        shim_fixtures.mkdir(parents=True)
        (shim_tests / "__init__.py").write_text("", encoding="utf-8")
        rule_sample = next((REPO_ROOT / "rules" / "builtin").glob("*.toml"))
        (shim_fixtures / "__init__.py").write_text(
            f"from pathlib import Path\n\nRULES_EAGER = Path({str(rule_sample)!r}).read_text()\n",
            encoding="utf-8",
        )
        env_pythonpath = f"{REPO_ROOT / 'src'}:{tmp_path}"

        recorded = run_guard_script(env_pythonpath, cwd=tmp_path)["opens"]

        assert recorded, "guard did not catch an eager `.toml` read at import time"
        assert any(path.endswith(".toml") for path in recorded), recorded
