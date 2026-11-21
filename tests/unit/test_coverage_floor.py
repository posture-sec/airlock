"""Issue #107 / task 9.70: a per-module execution floor, measured with `python -m trace`.

The suite's total coverage is the wrong gate for this repository. `tests/unit/test_fixtures.py`
parametrizes every rule over the corpus, so a few fixture-heavy modules hold the total in the low
nineties while one unexercised fail-closed branch in `policy.py` moves it by a fraction of a
percent. The properties that matter -- the shipped-default fallback, the refused read, the
suppression that does not apply -- are branches, so the number is recorded per module and the
failure names the module.

Five decisions shape this file.

* The measurement is the standard library's `trace`, not `coverage`. CI's install line is
  `python -m pip install --quiet . pytest ruff mypy` (`.github/workflows/ci.yml`), so a plugin in
  `addopts` would break every run, and `AGENTS.md` 4 keeps third-party runtime tooling out of the
  gates. `coverage` is in the dev group so a contributor can still print an HTML report, and the
  one table it reads, `[tool.coverage.run]`, is read here too, so a printed report and an asserted
  floor cannot disagree about which files count.
* Each module is measured through its own unit test file, `tests/unit/test_<module>.py`, which is
  the convention task 9.67 (`tests/unit/test_module_coverage.py`) already asserts. A floor is only
  worth having if one command reproduces it, and that command is
  `python -m trace --count --missing --module pytest tests/unit/test_<module>.py`.
* `--ignore-dir` names `tests/`, but NOT the standard library or the directory the installed copy
  of the package lives in. `trace.globaltrace_lt` decides whether to ignore a frame from
  `_modname(filename)`, which is the file's *basename*, and `_Ignore.names` memoizes that answer by
  basename for the whole run. So an ignore list that covers `stdlib` (which contains
  `unittest/runner.py` and houses `site-packages/_pytest/runner.py` in CI) also deletes
  `src/airlock/runner.py` from the measurement, silently: the first sighting wins. Measured on this
  tree, that configuration reports no cover file for `runner` at all. The safe answer is to measure
  more than is interesting rather than less, and then assert where the number came from -- which is
  what `trace`'s own `--summary` row gives, because its last column is the path it measured.
* Nothing here can pass by being empty. The table is checked against the filesystem before any
  subprocess runs, so a missing entry, a missing mapped test, a typo in a key, a floor above 100 and
  a floor that no longer matches the fraction justified above it all fail.
* The eight runs are taken together in the session fixture, four at a time. `tests/conftest.py`
  budgets the suite on wall clock (task 9.61) and a traced run costs several times its untraced
  one, so eight of them end to end is more of the 45s ceiling than the rest of the suite. They are
  separate processes, so taking four at a time spends the runner's other cores instead of queueing.
"""

from __future__ import annotations

import fnmatch
import os
import re
import subprocess
import sys
import tomllib
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from test_module_coverage import SKIPPED, source_modules

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src" / "airlock"
UNIT_DIR = REPO_ROOT / "tests" / "unit"
PYPROJECT = REPO_ROOT / "pyproject.toml"
PACKAGE = "airlock"

#: The pyproject table this gate is about.
FLOOR_TABLE = ("tool", "airlock", "coverage", "floors")
FLOOR_TABLE_HEADING = f"[{'.'.join(FLOOR_TABLE)}]"

#: A hit line is the execution count right-aligned in five columns and then ": ". A miss is the six
#: `>` markers `trace` calls its missing-line flag. Anything else is a line the file does not count,
#: which is how a docstring, a comment or a blank line arrives.
HIT_MARKER = re.compile(r"[ 0-9]{5}: ")
MISS_MARKER = ">>>>>> "

#: One row of the `--summary` table `trace` prints. Its last column names the file it measured, so
#: it is the only evidence in the output of which copy of the module produced the number.
SUMMARY_ROW = re.compile(
    r"^\s*(?P<lines>\d+)\s+(?P<percent>\d+)%\s+(?P<module>\S+)\s+\((?P<path>.*)\)\s*$"
)

#: A justified line in the comment block above the table: the module, its hits, its executable
#: lines, and the percentage they make.
JUSTIFICATION_ROW = re.compile(
    r"^#\s+(?P<module>\w+)\s+(?P<hits>\d+)/(?P<executable>\d+)\s*=\s*(?P<percent>\d+(?:\.\d+)?)%"
)

#: One traced pytest session per entry. Generous, because a traced corpus run on a loaded runner is
#: slow in a way an untraced one is not, and a timeout that fires in CI reads like a hang.
TRACE_TIMEOUT_SECONDS = 900.0

#: Traced runs taken at the same time. `tests/conftest.py` budgets the whole suite on wall clock
#: (task 9.61), and a traced run costs several times its untraced one, so eight of them end to end
#: is more of the 45s ceiling than the suite itself. Measured on 3.11 here: the eight runs sum to
#: 38.1s taken one after another, and the file that takes them four at a time runs in 14.2s. They
#: are separate processes, so this spends the runner's other cores instead of queueing.
TRACED_WORKERS = 4


def load_pyproject() -> dict[str, Any]:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def table_at(pyproject: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any]:
    """One table by dotted path, or a message that names the path and the file."""
    wanted = ".".join(path)
    node: Any = pyproject
    for key in path:
        if not isinstance(node, dict) or key not in node:
            raise AssertionError(f"[{wanted}] is missing from {PYPROJECT}")
        node = node[key]
    if not isinstance(node, dict):
        raise AssertionError(f"[{wanted}] in {PYPROJECT} is not a table")
    return node


def floors(pyproject: dict[str, Any]) -> dict[str, int]:
    """`[tool.airlock.coverage.floors]`: module name to floor percentage."""
    return dict(table_at(pyproject, FLOOR_TABLE))


def omit_patterns(pyproject: dict[str, Any]) -> list[str]:
    """`[tool.coverage.run] omit`, the same list a printed report excludes."""
    patterns = table_at(pyproject, ("tool", "coverage", "run")).get("omit", [])
    if not isinstance(patterns, list):
        raise AssertionError(f"[tool.coverage.run] omit in {PYPROJECT} is not a list")
    return [str(pattern) for pattern in patterns]


def source_setting(pyproject: dict[str, Any]) -> list[str]:
    """`[tool.coverage.run] source`, which says which package the numbers are about."""
    source = table_at(pyproject, ("tool", "coverage", "run")).get("source", [])
    if not isinstance(source, list):
        raise AssertionError(f"[tool.coverage.run] source in {PYPROJECT} is not a list")
    return [str(item) for item in source]


def mapped_test(module: str) -> Path:
    """The one unit test file a floor is measured through, by the task 9.67 convention."""
    return UNIT_DIR / f"test_{module}.py"


def is_omitted(module: str, patterns: list[str]) -> bool:
    """Whether `[tool.coverage.run] omit` excludes this module, matched the way coverage matches."""
    candidates = (f"src/{PACKAGE}/{module}.py", str(SRC_DIR / f"{module}.py"))
    return any(
        fnmatch.fnmatch(candidate, pattern) for pattern in patterns for candidate in candidates
    )


def required_modules(patterns: list[str]) -> list[str]:
    """Every shipped module the table has to carry an entry for.

    `SKIPPED` is the pair task 9.67 exempts from the one-test-module-per-module convention, so the
    two gates cannot drift apart about which names a mapped test could even exist for. `__init__` is
    the package body every measurement already executes as an import side effect, and `__main__`
    runs only in a child process, which `trace` does not follow.
    """
    return [
        module
        for module in source_modules()
        if module not in SKIPPED and not is_omitted(module, patterns)
    ]


def justifications(text: str) -> dict[str, float]:
    """The measured percentage justified for each module in the block above the floors table.

    Read backwards from the table heading, so a justification moved below the table, or one for a
    module nobody recorded, stops counting.
    """
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip() == FLOOR_TABLE_HEADING), None)
    if start is None:
        raise AssertionError(f"{FLOOR_TABLE_HEADING} not found in {PYPROJECT}")
    block: list[str] = []
    for line in reversed(lines[:start]):
        if not line.lstrip().startswith("#"):
            break
        block.append(line)
    found: dict[str, float] = {}
    for line in block:
        match = JUSTIFICATION_ROW.match(line.strip())
        if match is not None:
            found[match.group("module")] = float(match.group("percent"))
    return found


@dataclass(frozen=True)
class Measurement:
    """What one traced run said about one module."""

    module: str
    test: str
    returncode: int
    hits: int
    misses: int
    uncounted: int
    source_path: Path | None
    summary_lines: int | None
    detail: str

    @property
    def executable(self) -> int:
        return self.hits + self.misses

    @property
    def measured(self) -> float:
        return 100.0 * self.hits / self.executable if self.executable else 0.0

    @property
    def fraction(self) -> str:
        return f"{self.hits}/{self.executable}"


def parse_cover(text: str) -> tuple[int, int, int]:
    """Hits, misses and uncounted lines, read from the columns `trace` writes in front of each line.

    Only the first seven characters count, so a docstring that opens with `1: ` stays uncounted the
    way the interpreter counts it.
    """
    hits = misses = uncounted = 0
    for line in text.splitlines():
        marker = line[:7]
        if HIT_MARKER.fullmatch(marker):
            hits += 1
        elif marker == MISS_MARKER:
            misses += 1
        else:
            uncounted += 1
    return hits, misses, uncounted


def summary_row(stdout: str, dotted: str) -> tuple[int, Path] | None:
    """The `(lines counted, file measured)` pair `trace` reported for one dotted module name."""
    for line in stdout.splitlines():
        match = SUMMARY_ROW.match(line)
        if match and match.group("module") == dotted:
            return int(match.group("lines")), Path(match.group("path"))
    return None


def trace_command(test: Path, coverdir: Path) -> list[str]:
    """The command the issue names, with the ignores this file's docstring argues for."""
    ignored = [str(REPO_ROOT / "tests")]
    return [
        sys.executable,
        "-m",
        "trace",
        "--count",
        "--missing",
        "--summary",
        "--coverdir",
        str(coverdir),
        "--ignore-dir",
        os.pathsep.join(ignored),
        "--module",
        "pytest",
        str(test.relative_to(REPO_ROOT)),
        "-q",
        "-p",
        "no:cacheprovider",
    ]


class TraceRunner:
    """One traced run per module, reused for the rest of the session.

    The cache lives on this object rather than in a module global because `AGENTS.md` 6 rules out
    module-level mutable state, and pytest builds one of these per session, which is the lifetime a
    measurement wants.
    """

    def __init__(self, coverdir: Path) -> None:
        self._coverdir = coverdir
        self._cache: dict[str, Measurement] = {}

    def measure(self, module: str) -> Measurement:
        self.measure_all((module,))
        return self._cache[module]

    def measure_all(self, modules: Iterable[str]) -> None:
        """Every measurement not yet taken, with at most `TRACED_WORKERS` runs live at a time.

        The cache is written only by this thread: the workers return `Measurement` objects and the
        results land here as `pool.map` yields them. Each run writes its own cover directory, so
        there is nothing for two of them to contend for.
        """
        missing = [module for module in dict.fromkeys(modules) if module not in self._cache]
        if not missing:
            return
        if len(missing) == 1:
            measured = [self._trace(missing[0])]
        else:
            workers = min(TRACED_WORKERS, len(missing))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                measured = list(pool.map(self._trace, missing))
        for item in measured:
            self._cache[item.module] = item

    def _trace(self, module: str) -> Measurement:
        test = mapped_test(module)
        if not test.is_file():
            return Measurement(module, _relative(test), -1, 0, 0, 0, None, None, "")
        coverdir = self._coverdir / module
        coverdir.mkdir(parents=True, exist_ok=True)
        environment = {**os.environ, "PYTHONPATH": str(SRC_DIR.parent)}
        try:
            completed = subprocess.run(
                trace_command(test, coverdir),
                cwd=REPO_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=TRACE_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as error:
            raise AssertionError(
                f"the traced run of {_relative(test)} did not finish in "
                f"{TRACE_TIMEOUT_SECONDS:.0f}s, so the floor for `{module}` was not measured"
            ) from error
        detail = (completed.stdout + completed.stderr)[-1500:]
        if completed.returncode != 0:
            return Measurement(
                module, _relative(test), completed.returncode, 0, 0, 0, None, None, detail
            )
        hits, misses, uncounted = _read_cover(coverdir, module)
        row = summary_row(completed.stdout, f"{PACKAGE}.{module}")
        return Measurement(
            module=module,
            test=_relative(test),
            returncode=completed.returncode,
            hits=hits,
            misses=misses,
            uncounted=uncounted,
            source_path=row[1] if row else None,
            summary_lines=row[0] if row else None,
            detail=detail,
        )


def _relative(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))


def _read_cover(coverdir: Path, module: str) -> tuple[int, int, int]:
    cover = coverdir / f"{PACKAGE}.{module}.cover"
    if not cover.is_file():
        return 0, 0, 0
    return parse_cover(cover.read_text(encoding="utf-8", errors="replace"))


def coverage_problems(entries: dict[str, int], results: dict[str, Measurement]) -> list[str]:
    """Every reason a recorded number cannot stand: not measured, wrong file, or a drop."""
    problems: list[str] = []
    for module, floor in sorted(entries.items()):
        result = results.get(module)
        if result is None:
            problems.append(
                f"{module}: no measurement was taken, so the {floor}% floor is unchecked"
            )
            continue
        shipped = SRC_DIR / f"{module}.py"
        if result.returncode == -1:
            problems.append(
                f"{module}: the floor is measured through {result.test}, which does not exist. "
                f"Write that unit test, or move {module} out of {FLOOR_TABLE_HEADING}"
            )
            continue
        if result.returncode != 0:
            problems.append(
                f"{module}: the traced run of {result.test} exited {result.returncode}, so its "
                f"{floor}% floor was not measured\n{result.detail}"
            )
            continue
        if result.executable == 0:
            problems.append(
                f"{module}: no measurement of {_relative(shipped)} was written for the run of "
                f"{result.test}. The test file passed, so `trace` ignored the module, most often "
                "because another ignored file shares its basename -- which is exactly how a floor "
                "goes unchecked"
            )
            continue
        if result.source_path is None:
            problems.append(
                f"{module}: trace printed no summary row naming the file it measured, so the "
                f"{result.measured:.2f}% for {_relative(shipped)} cannot be attributed"
            )
            continue
        if result.source_path.resolve() != shipped.resolve():
            problems.append(
                f"{module}: trace measured {result.source_path}, not {_relative(shipped)}. A floor "
                "number has to describe the checkout, and this one describes a copy that does "
                "not live under src/"
            )
            continue
        if result.summary_lines is not None and result.summary_lines != result.executable:
            problems.append(
                f"{module}: trace counted {result.summary_lines} lines in its summary and "
                f"{result.executable} in the cover file. This gate reads the cover columns, so a "
                "mismatch means the marker format moved and the floor is not being parsed"
            )
            continue
        if result.measured < floor:
            problems.append(
                f"{module} executed {result.measured:.2f}% ({result.fraction}) of its lines "
                f"through {result.test}, below the {floor}% floor in {FLOOR_TABLE_HEADING} of "
                "pyproject.toml. Lines that never ran carry `>>>>>>` in the cover file. Add the "
                "test that reaches them, or lower the floor in the pull request and say why."
            )
    return problems


def table_problems(
    entries: dict[str, int],
    patterns: list[str],
    justified: dict[str, float],
) -> list[str]:
    """Every reason the table itself is not a gate: a gap, a typo, an entry that cannot hold."""
    problems: list[str] = []
    for module in required_modules(patterns):
        if module not in entries:
            problems.append(
                f"{module}: no floor is recorded for "
                f"{_relative(SRC_DIR / f'{module}.py')}, which is shipped and is not excluded by "
                "[tool.coverage.run]"
            )
            continue
        if not mapped_test(module).is_file():
            problems.append(
                f"{module}: the {entries[module]}% floor is measured through "
                f"{_relative(mapped_test(module))}, which does not exist"
            )
    for module in sorted(entries):
        floor = entries[module]
        if module not in source_modules():
            problems.append(
                f"{module}: the table names {_relative(SRC_DIR / f'{module}.py')}, "
                "which is not a shipped module"
            )
        if is_omitted(module, patterns):
            problems.append(
                f"{module}: the table records a floor for a module [tool.coverage.run] omit "
                "excludes; the two cannot both apply"
            )
        if not isinstance(floor, int) or not 0 < floor <= 100:
            problems.append(f"{module}: {floor!r} is not a whole percentage between 1 and 100")
        if module not in justified:
            problems.append(
                f"{module}: no measured fraction is justified above {FLOOR_TABLE_HEADING}; "
                "the block has to state the hits, the executable lines and the percentage"
            )
        elif isinstance(floor, int) and floor != int(justified[module]):
            problems.append(
                f"{module}: the floor is {floor}% but the block above the table justifies "
                f"{justified[module]}%, whose whole percent below it is {int(justified[module])}%. "
                "One of the two is stale: the floor is the measurement truncated, on the oldest "
                "interpreter the package supports"
            )
    for module in sorted(justified):
        if module not in entries:
            problems.append(
                f"{module}: the block above {FLOOR_TABLE_HEADING} states a measurement for it, but "
                f"{FLOOR_TABLE_HEADING} records no floor"
            )
    return problems


class TestTheTableIsComplete:
    """The checks that need no subprocess: the table, the filesystem, and what agrees with which."""

    @staticmethod
    def settings() -> tuple[dict[str, int], list[str], dict[str, float]]:
        pyproject = load_pyproject()
        return (
            floors(pyproject),
            omit_patterns(pyproject),
            justifications(PYPROJECT.read_text(encoding="utf-8")),
        )

    def test_the_table_carries_the_modules_the_issue_names(self) -> None:
        entries, _patterns, _justified = self.settings()
        for module in ("policy", "collector", "rules", "runner", "fingerprint"):
            assert module in entries, f"{module} has no floor in {PYPROJECT}: {sorted(entries)}"

    def test_the_table_and_the_tree_agree(self) -> None:
        entries, patterns, justified = self.settings()
        problems = table_problems(entries, patterns, justified)
        assert not problems, "\n".join(problems)

    def test_the_walk_and_the_block_are_not_empty(self) -> None:
        """A gate that compared against nothing would pass, so both inventories are asserted."""
        entries, _patterns, justified = self.settings()
        assert len(entries) >= 5, f"the floors table holds {sorted(entries)}"
        assert "policy" in source_modules(), f"{SRC_DIR} walked to {source_modules()}"
        assert len(justified) >= len(entries), f"{FLOOR_TABLE_HEADING} is justified for {justified}"

    def test_omission_excludes_the_command_surface_and_nothing_else(self) -> None:
        patterns = omit_patterns(load_pyproject())
        assert patterns == [f"*/{PACKAGE}/cli.py"], patterns
        assert is_omitted("cli", patterns)
        for module in ("policy", "collector", "runner", "strkey"):
            assert not is_omitted(module, patterns), module

    def test_coverage_is_told_where_the_package_is(self) -> None:
        pyproject = load_pyproject()
        assert source_setting(pyproject) == [PACKAGE]

    def test_no_coverage_plugin_is_wired_into_the_suite(self) -> None:
        """CI installs no coverage tool, so a `--cov` in `addopts` would fail every run (#107 5)."""
        ini = table_at(load_pyproject(), ("tool", "pytest", "ini_options"))
        addopts = str(ini.get("addopts", ""))
        assert not [word for word in addopts.split() if word.startswith("--cov")], addopts

    def test_the_omitted_and_skipped_names_are_the_documented_exceptions(self) -> None:
        """The three exemptions are the whole reason a shipped module carries no floor."""
        entries, patterns, _justified = self.settings()
        excluded = [module for module in source_modules() if module not in entries]
        assert sorted(excluded) == ["__init__", "__main__", "cli"], excluded
        assert frozenset({"__init__", "__main__"}) == SKIPPED, SKIPPED
        assert is_omitted("cli", patterns)


class TestTheGuardBites:
    """Every failure the issue names is reproduced with data, not by editing the tree."""

    @staticmethod
    def result(
        module: str,
        hits: int,
        misses: int,
        source_path: Path | None = None,
        returncode: int = 0,
        summary_lines: int | None = None,
    ) -> Measurement:
        measured = source_path if source_path is not None else SRC_DIR / f"{module}.py"
        return Measurement(
            module=module,
            test=f"tests/unit/test_{module}.py",
            returncode=returncode,
            hits=hits,
            misses=misses,
            uncounted=0,
            source_path=measured,
            summary_lines=hits + misses if summary_lines is None else summary_lines,
            detail="1 failed in 0.31s" if returncode else "",
        )

    def test_a_drop_below_the_floor_names_the_module_the_number_the_floor_and_the_test(
        self,
    ) -> None:
        problems = coverage_problems({"policy": 84}, {"policy": self.result("policy", 470, 129)})
        assert len(problems) == 1, problems
        message = problems[0]
        for fragment in ("policy", "78.46%", "84%", "tests/unit/test_policy.py"):
            assert fragment in message, f"{fragment!r} missing from:\n{message}"

    def test_a_number_at_the_floor_passes(self) -> None:
        assert coverage_problems({"strkey": 93}, {"strkey": self.result("strkey", 93, 7)}) == []

    def test_a_measurement_of_a_copy_outside_the_checkout_is_refused(self) -> None:
        stale = REPO_ROOT / ".venv/lib/python3.11/site-packages/airlock/runner.py"
        problems = coverage_problems(
            {"runner": 76}, {"runner": self.result("runner", 56, 17, stale)}
        )
        assert problems and "site-packages" in problems[0], problems

    def test_a_module_the_run_never_measured_fails_instead_of_passing(self) -> None:
        """The `trace` basename ignore is the fail-open this gate has to survive."""
        unmeasured = Measurement("runner", "tests/unit/test_runner.py", 0, 0, 0, 0, None, None, "")
        problems = coverage_problems({"runner": 76}, {"runner": unmeasured})
        assert problems and "no measurement" in problems[0], problems

    def test_a_run_that_did_not_finish_cleanly_is_reported_as_such(self) -> None:
        problems = coverage_problems(
            {"collector": 97}, {"collector": self.result("collector", 0, 0, returncode=1)}
        )
        assert problems and "exited 1" in problems[0], problems

    def test_a_missing_mapped_test_is_reported(self) -> None:
        missing = Measurement("roles", "tests/unit/test_roles.py", -1, 0, 0, 0, None, None, "")
        problems = coverage_problems({"roles": 97}, {"roles": missing})
        assert problems and "does not exist" in problems[0], problems

    def test_summary_and_cover_disagreeing_is_a_failure_not_a_rounding_note(self) -> None:
        result = self.result("model", 270, 11, summary_lines=300)
        problems = coverage_problems({"model": 96}, {"model": result})
        assert problems and "marker format" in problems[0], problems

    def test_every_required_module_without_an_entry_is_named(self) -> None:
        patterns = omit_patterns(load_pyproject())
        problems = table_problems({}, patterns, {})
        for module in required_modules(patterns):
            assert any(problem.startswith(f"{module}:") for problem in problems), module

    def test_a_key_that_is_not_a_shipped_module_is_a_problem(self) -> None:
        problems = table_problems({"policyy": 84}, ["*/airlock/cli.py"], {"policyy": 84.31})
        assert any("not a shipped module" in problem for problem in problems), problems

    def test_a_floor_the_block_above_it_does_not_state_is_a_problem(self) -> None:
        entries, patterns, _justified = TestTheTableIsComplete.settings()
        problems = table_problems(entries, patterns, {"policy": 84.31})
        assert any("no measured fraction is justified" in item for item in problems), problems

    def test_a_floor_that_is_not_the_stated_measurement_is_a_problem(self) -> None:
        entries, patterns, justified = TestTheTableIsComplete.settings()
        problems = table_problems({**entries, "policy": 90}, patterns, justified)
        assert any("whose whole percent below it is 84" in item for item in problems), problems

    def test_a_floor_that_ignores_the_omission_is_a_problem(self) -> None:
        entries, patterns, justified = TestTheTableIsComplete.settings()
        problems = table_problems({**entries, "cli": 97}, patterns, {**justified, "cli": 97.1})
        assert any("omit excludes" in item for item in problems), problems

    def test_a_floor_outside_the_possible_is_a_problem(self) -> None:
        entries, patterns, justified = TestTheTableIsComplete.settings()
        problems = table_problems({**entries, "policy": 101}, patterns, justified)
        assert any("not a whole percentage" in item for item in problems), problems


class TestTheCoverParser:
    def test_the_markers_are_read_from_the_columns_not_the_source(self) -> None:
        hits, misses, uncounted = parse_cover(
            "    3: x = 1\n>>>>>>     return None\n       def f() -> int:\n10000: y = 2\n"
        )
        assert (hits, misses, uncounted) == (2, 1, 1)

    def test_a_docstring_that_looks_like_a_marker_stays_uncounted(self) -> None:
        hits, _misses, uncounted = parse_cover('       """1: not a hit count"""\n')
        assert (hits, uncounted) == (0, 1)

    def test_a_justification_row_is_read_out_of_the_comment_block(self) -> None:
        match = JUSTIFICATION_ROW.match(
            "#   policy        505/599 = 84.31%   resolves the base ref"
        )
        assert match is not None
        assert (match.group("module"), match.group("hits"), match.group("percent")) == (
            "policy",
            "505",
            "84.31",
        )


def floor_names() -> list[str]:
    return sorted(floors(load_pyproject()))


@pytest.fixture(scope="session")
def tracer(tmp_path_factory: pytest.TempPathFactory) -> TraceRunner:
    """One traced pytest run per floor for the whole session, taken before the first assertion.

    The runs are taken here rather than lazily per test so they share `TRACED_WORKERS` cores. A
    measurement the aggregate test would otherwise have to wait for is already in the cache.
    """
    runner = TraceRunner(tmp_path_factory.mktemp("coverage-floor"))
    runner.measure_all(floor_names())
    return runner


class TestTheMeasuredFloors:
    """The gate itself: one traced pytest run per entry, read from the columns `trace` writes."""

    @pytest.mark.parametrize("module", floor_names())
    def test_a_module_meets_the_floor_recorded_for_its_own_test_file(
        self, module: str, tracer: TraceRunner
    ) -> None:
        entries = floors(load_pyproject())
        result = tracer.measure(module)
        problems = coverage_problems({module: entries[module]}, {module: result})
        assert not problems, "\n".join(problems)

    @pytest.mark.parametrize("module", floor_names())
    def test_every_line_of_the_measured_file_is_classified(
        self, module: str, tracer: TraceRunner
    ) -> None:
        """The cover file has one row per source line, so a stray row means format drift."""
        result = tracer.measure(module)
        assert result.returncode == 0, result.detail
        assert result.source_path is not None, f"trace reported no path for {module}"
        source_lines = len(result.source_path.read_text(encoding="utf-8").splitlines())
        counted = result.hits + result.misses + result.uncounted
        assert counted == source_lines, (
            f"{module}: the cover file has {counted} rows for {source_lines} source lines in "
            f"{result.source_path}"
        )

    def test_the_floors_are_at_or_below_what_the_mapped_tests_reach(
        self, tracer: TraceRunner
    ) -> None:
        """One message with every module that drifted, because a partial list reads like a flake."""
        entries = floors(load_pyproject())
        results: dict[str, Measurement] = {module: tracer.measure(module) for module in entries}
        problems = coverage_problems(entries, results)
        assert not problems, "\n".join(problems)

    def test_the_traced_run_measures_the_package_the_tests_import(
        self, tracer: TraceRunner
    ) -> None:
        """The attribution the gate rests on: the traced run read this tree, not a copy."""
        for module in floor_names():
            result = tracer.measure(module)
            assert result.source_path is not None, f"{module}: no summary row from trace"
            assert result.source_path.resolve() == (SRC_DIR / f"{module}.py").resolve(), (
                f"{module}: trace measured {result.source_path}"
            )
