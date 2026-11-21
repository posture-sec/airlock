"""Issue #94 / task 9.67: every module shipped under `src/airlock/` is reachable from the suite.

`project_structure.md:91` states the convention: one test module per source module under
`tests/unit/`. Nothing asserted it, so a new file, or a split that leaves a module with no importer,
moved the ratio without a signal. The example the issue named was `src/airlock/strkey.py`, whose
behaviour was asserted only through CLI checks; `tests/unit/test_strkey.py` has covered it directly
since PR #120, so the tree today reports no gap and this guard exists to keep it that way.

Three decisions shape the file:

* Imports are read with `ast`, not by regex over the lines and not through a coverage tool. A regex
  cannot tell `from airlock import strkey` from a string that mentions it, and a coverage tool
  measures what executed rather than what the suite declares it exercises.
* The allowlist maps a module to one sentence naming the file that covers it, and an entry whose
  file is absent fails. An allowlist that only needs a name would be a way to forget a module.
* Nothing here edits `src/`. Where the check finds a module with no importer the answer is a test
  for it, which is follow-up work, or an allowlist entry that points at the coverage
  that already exists.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src" / "airlock"
TEST_DIRS = (REPO_ROOT / "tests" / "unit", REPO_ROOT / "tests" / "bypass")
PACKAGE = "airlock"

#: `__init__` runs as a side effect of importing any `airlock.*` module, and `__main__` is the body
#: `python -m airlock` executes, which `tests/unit/test_dunder_main.py` asserts on its own. Neither
#: is something a test can import without the package already being imported, so they are named here
#: rather than left to the allowlist.
SKIPPED = frozenset({"__init__", "__main__"})

#: module name -> one sentence naming the file that covers it. Empty today: every shipped module is
#: imported by the suite. An entry is only allowed to stand while the file it names exists.
ALLOWLIST: dict[str, str] = {}

#: A reason has to carry a repo-relative path to a Python file, or it is a note
#: rather than evidence.
_PATH_IN_REASON = re.compile(r"(?P<path>[^\s,;()]+\.py)")


def source_modules(src_dir: Path = SRC_DIR) -> list[str]:
    """Every module shipped directly under `src/airlock/`, in the order the filesystem gives."""
    return sorted(path.stem for path in src_dir.glob("*.py"))


def _module_of(node: ast.Import | ast.ImportFrom) -> Iterable[str]:
    """The top-level `airlock` module names one import statement touches, if any."""
    if isinstance(node, ast.Import):
        for alias in node.names:
            parts = alias.name.split(".")
            if parts[0] == PACKAGE and len(parts) > 1:
                yield parts[1]
        return
    if node.level or node.module is None:
        return
    parts = node.module.split(".")
    if parts[0] != PACKAGE:
        return
    if len(parts) > 1:
        yield parts[1]
        return
    # `from airlock import strkey, rules`: the names are the modules, and `import airlock` alone
    # binds the package rather than a module, so only names that are modules can count here.
    for alias in node.names:
        if alias.name != "*":
            yield alias.name


def imported_modules(test_dirs: Iterable[Path] = TEST_DIRS) -> dict[str, list[str]]:
    """Map each `airlock` module the suite imports to the files that import it.

    A submodule import counts its top-level parent, because importing `airlock.detectors.x` executes
    `airlock/detectors/__init__.py`, not `airlock/x.py`: only the names returned here are scored.
    """
    found: dict[str, set[str]] = {}
    for test_dir in test_dirs:
        for path in sorted(test_dir.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, (ast.Import, ast.ImportFrom)):
                    continue
                for name in _module_of(node):
                    # A file that imports the module two ways covers it once, so the report names it
                    # once; a list would repeat it and read like two independent covering files.
                    found.setdefault(name, set()).add(str(path.relative_to(REPO_ROOT)))
    return {name: sorted(paths) for name, paths in found.items()}


def allowlist_problems(allowlist: dict[str, str], known: Iterable[str]) -> list[str]:
    """Every allowlist entry that is not evidence: no file named, or a file that is not there."""
    problems: list[str] = []
    for module, reason in sorted(allowlist.items()):
        if module not in known:
            problems.append(f"allowlist names `{module}`, which is not a module under {SRC_DIR}")
        match = _PATH_IN_REASON.search(reason)
        if match is None:
            problems.append(
                f"allowlist entry for `{module}` names no file: the reason has to point at the "
                "coverage that stands in for a test module"
            )
            continue
        path = REPO_ROOT / match.group("path")
        if not path.is_file():
            problems.append(
                f"allowlist entry for `{module}` names {match.group('path')}, which does not exist"
            )
    return problems


def gaps(
    modules: Iterable[str], importers: dict[str, list[str]], allowlist: dict[str, str]
) -> list[str]:
    """Shipped modules with neither an importing test nor a standing allowlist entry."""
    return [
        module
        for module in modules
        if module not in SKIPPED and module not in importers and module not in allowlist
    ]


def report_for(modules: list[str], importers: dict[str, list[str]]) -> str:
    lines = [f"  {module}: imported by {', '.join(importers[module])}" for module in modules]
    return "\n".join(lines) if lines else "  (nothing)"


class TestEveryModuleIsReachable:
    def test_the_walk_finds_the_shipped_modules(self) -> None:
        """A guard whose inventory is empty proves nothing, so the inventory itself is asserted."""
        modules = source_modules()
        for expected in ("policy", "collector", "rules", "runner", "fingerprint", "strkey"):
            assert expected in modules, f"{SRC_DIR} walked to {modules}, which has no `{expected}`"

    def test_every_source_module_is_imported_or_allowlisted(self) -> None:
        modules = source_modules()
        importers = imported_modules()
        missing = gaps(modules, importers, ALLOWLIST)
        assert not missing, (
            f"{', '.join(missing)} in {SRC_DIR.relative_to(REPO_ROOT)} has no importing test under "
            f"tests/unit/ or tests/bypass/. Give it a test module, or an entry in ALLOWLIST naming "
            "the file that already covers it.\nCovered today:\n"
            f"{report_for([m for m in modules if m in importers], importers)}"
        )

    def test_strkey_is_covered_by_its_own_test_module(self) -> None:
        """The module this issue was written about, pinned so it cannot drift back to indirect."""
        importers = imported_modules()
        assert "tests/unit/test_strkey.py" in importers.get("strkey", []), (
            f"strkey is imported by {importers.get('strkey', [])}; the issue asked for direct "
            "coverage rather than an allowlist note"
        )


class TestTheAllowlistIsEvidence:
    def test_an_entry_that_names_no_file_fails(self) -> None:
        problems = allowlist_problems({"strkey": "covered indirectly by the CLI tests"}, ["strkey"])
        assert problems, "an allowlist reason with no file was accepted as evidence"

    def test_an_entry_naming_an_absent_file_fails(self) -> None:
        problems = allowlist_problems(
            {"strkey": "covered by tests/unit/test_strkey_that_was_deleted.py"}, ["strkey"]
        )
        assert problems, "an allowlist reason pointing at a file that is not there was accepted"

    def test_an_entry_naming_a_real_file_clears_the_gap(self) -> None:
        allowlist = {"strkey": "covered by tests/unit/test_strkey.py"}
        assert not allowlist_problems(allowlist, ["strkey"])
        assert "strkey" not in gaps(source_modules(), {}, allowlist)

    def test_the_committed_allowlist_is_current(self) -> None:
        problems = allowlist_problems(ALLOWLIST, source_modules())
        assert not problems, "\n".join(problems)

    def test_a_module_the_allowlist_does_not_name_is_still_a_gap(self) -> None:
        """The other direction: an allowlist entry cannot cover a module it does not mention."""
        missing = gaps(["policy", "strkey"], {}, {"strkey": "covered by tests/unit/test_strkey.py"})
        assert missing == ["policy"]


class TestTheImporterReadsImports:
    """The scanner is only as good as its reading of an import statement."""

    FORMS = """
from airlock import strkey
from airlock.strkey import decode_seed
import airlock.policy
import airlock.detectors.ci_surface as ci
import airlock
from airlock.model import Finding
from . import not_airlock
from pathlib import Path
"""

    def _modules(self, source: str) -> set[str]:
        tree = ast.parse(source)
        found: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                found.update(_module_of(node))
        return found

    def test_every_way_of_naming_a_top_level_module_is_read(self) -> None:
        """`from airlock import x`, `from airlock.x import y`, `import airlock.x`;
        nothing else counts."""
        assert self._modules(self.FORMS) == {"strkey", "policy", "detectors", "model"}

    def test_a_bare_package_import_names_no_module(self) -> None:
        assert self._modules("import airlock\n") == set()

    def test_a_submodule_import_counts_at_its_top_level_parent(self) -> None:
        # `airlock.detectors.ci_surface` executes `airlock/detectors/__init__.py`, not some other
        # module's top level, so reading it as anything but `detectors` would credit the wrong file.
        assert self._modules("import airlock.detectors.ci_surface\n") == {"detectors"}

    def test_imports_outside_the_package_are_ignored(self) -> None:
        source = "from pathlib import Path\nimport pytest\nfrom . import sibling\n"
        assert self._modules(source) == set()
