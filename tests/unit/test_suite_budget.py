"""Issue #87 / task 9.33: the numbers behind the suite budget, and the boundary either side of them.

`tests/conftest.py` holds the hook; `issue #87` section 3 puts the ceiling here, next to the
measurement it came from, because a limit nobody can trace is a limit nobody can raise on purpose.
So this file is the documentation of one constant and the test of the arithmetic around it.

The measurement is a pytest sum, not a stopwatch: the seconds pytest attributes to setup, call and
teardown across the whole session, which is what the conftest adds up. The runner quoted below is
the one the budget protects, `python -m pytest` on the CI image, because a budget that only ever fit
one laptop would be adjusted the first time it disagreed with the machine that has a deadline.

This file reaches the summing functions with `importlib` rather than `import conftest`, and that is
deliberate. `tests/` has no `__init__.py`, so pytest imports the root conftest as the top-level
module `conftest` after putting `tests/` on `sys.path`: a plain `import conftest` here works only
because pytest arranged that path first, which is exactly the import order this issue asks the test
not to depend on, and `import tests.conftest` would build a second module object under a namespace
package. Loading by file location names the one thing being tested, the bytes in the file beside
this one, and `test_the_loaded_module_is_the_conftest_next_door` checks that it is the same file.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFTEST = REPO_ROOT / "tests" / "conftest.py"

#: What `python -m pytest` summed to on the machine quoted in `MEASURED_ON`, in the run this row
#: records. Seconds, over every phase of every test the suite collected.
MEASURED_TOTAL_SECONDS = 41.0

#: The run behind that number, so a reader can tell whether their machine is the same one. The
#: interpreter and pytest version are in it because both move the total with no change here.
MEASURED_ON = (
    "GitHub Actions ubuntu-24.04 runner, 4 vCPU, Python 3.12, pytest 9.2.0, `python -m pytest`, "
    "2026-11-21"
)

#: The budget. Above the measurement so the suite passes as it stands, and close enough to it that
#: taking ten percent off puts the ceiling under the measured total, which is what makes the number
#: a limit rather than a remark.
#: `test_lowering_the_ceiling_by_ten_percent_would_have_failed_the_run` asserts exactly that gap,
#: so the constant cannot drift to a value that stops biting.
SUITE_SECONDS_CEILING = 45.0


def _load(path: Path, name: str) -> ModuleType:
    """Execute one module from a file path, without touching `sys.path` or pytest's module names."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


budget = _load(CONFTEST, "airlock_root_conftest")


def records_of(**seconds_by_phase: float) -> list[tuple[str, str, float]]:
    """One synthetic report per keyword, as `Record` triples: `call=test_a=2.0`."""
    return [
        (phase, f"tests/unit/test_synthetic.py::test_{index}", seconds)
        for index, (phase, seconds) in enumerate(sorted(seconds_by_phase.items()))
    ]


def spread(total: float, tests: int) -> list[tuple[str, str, float]]:
    """`tests` call-phase records adding up to `total`, each one second heavier than the last."""
    # Uneven on purpose: a ranking test needs a known order, and equal weights make a tie the point
    # of a different test. The base share is split first, then re-weighted by position.
    base = total / tests
    return [
        (
            "call",
            f"tests/unit/test_synthetic.py::test_number_{index}",
            base + (index - (tests - 1) / 2) * (base / tests),
        )
        for index in range(tests)
    ]


class TestTheCeilingIsAFiniteLimit:
    def test_the_ceiling_is_above_the_measured_total(self) -> None:
        """The first half of the issue's Done when: the budget is not hit today."""
        assert MEASURED_TOTAL_SECONDS < SUITE_SECONDS_CEILING, (
            f"the suite measured {MEASURED_TOTAL_SECONDS}s against a "
            f"{SUITE_SECONDS_CEILING}s ceiling, so every run on that machine fails"
        )

    def test_lowering_the_ceiling_by_ten_percent_would_have_failed_the_run(self) -> None:
        """The second half: a tenth off the ceiling lands under the measurement it was set from.

        Without this the constant can quietly grow until the budget is decoration, which is the
        failure mode a ceiling has no other defence against.
        """
        assert SUITE_SECONDS_CEILING * 0.9 < MEASURED_TOTAL_SECONDS, (
            f"{SUITE_SECONDS_CEILING}s is more than 10% above the measured "
            f"{MEASURED_TOTAL_SECONDS}s, so lowering it by a tenth still passes the run"
        )

    def test_the_measurement_names_the_machine_it_came_from(self) -> None:
        """A bare number cannot be re-verified, which is all a future editor has to go on."""
        assert "Python" in MEASURED_ON
        assert "pytest" in MEASURED_ON
        assert "ubuntu" in MEASURED_ON.lower()

    def test_the_ceiling_the_hook_reads_is_the_one_documented_here(self) -> None:
        """The conftest reaches this constant by path, so the two have to be the same number.

        A typo in that path, or a ceiling defined twice, otherwise shows up only as a run judged
        against a limit no file names.
        """
        assert budget.suite_ceiling() == SUITE_SECONDS_CEILING


class TestTheSumming:
    def test_every_phase_counts(self) -> None:
        """Setup time is CI time, and a call-only sum would miss a slow fixture."""
        records = records_of(setup=1.5, call=2.0, teardown=0.25)
        totals = budget.phase_totals(records)
        assert totals == {"setup": 1.5, "call": 2.0, "teardown": 0.25}
        assert budget.session_seconds(records) == pytest.approx(3.75)

    def test_a_phase_with_no_records_is_still_a_key(self) -> None:
        """So a report can index what it prints without a `KeyError` on the first run of a suite."""
        assert budget.phase_totals([]) == dict.fromkeys(budget.PHASES, 0.0)

    def test_an_unknown_phase_is_counted_rather_than_dropped(self) -> None:
        """Fail closed: a pytest that reports a new phase has its seconds charged, not lost."""
        records = [("call", "tests/unit/test_synthetic.py::test_0", 1.0), ("other", "x", 0.5)]
        assert budget.session_seconds(records) == pytest.approx(1.5)

    def test_the_phases_of_one_test_are_added_together(self) -> None:
        """The slowest list is per test, so one test's reports must not read as several tests."""
        nodeid = "tests/unit/test_synthetic.py::test_one"
        records = [(phase, nodeid, seconds) for phase, seconds in (("setup", 0.4), ("call", 0.6))]
        assert budget.per_test_seconds(records) == {nodeid: pytest.approx(1.0)}
        assert len(budget.slowest_tests(records)) == 1

    def test_the_sum_is_the_same_whether_read_once_or_twice(self) -> None:
        """The hook asks twice on a failure, and a spent generator reads as an empty one."""
        records = records_of(setup=1.0, call=2.0)
        assert budget.session_seconds(records) == budget.session_seconds(records)
        assert budget.budget_lines(records, 1.0)[:1] == budget.budget_lines(records, 1.0)[:1]


class TestTheBoundary:
    def test_a_run_exactly_at_the_ceiling_is_within_budget(self) -> None:
        """The ceiling is the last acceptable number, so equality passes."""
        assert not budget.over_budget(records_of(call=SUITE_SECONDS_CEILING), SUITE_SECONDS_CEILING)

    def test_one_millisecond_more_fails(self) -> None:
        assert budget.over_budget(
            records_of(call=SUITE_SECONDS_CEILING + 0.001), SUITE_SECONDS_CEILING
        )

    def test_an_empty_session_is_within_any_budget(self) -> None:
        """`--collect-only` and a filtered-out run report no phases and must not be a failure."""
        assert not budget.over_budget([], SUITE_SECONDS_CEILING)

    def test_the_documented_measurement_is_within_the_documented_ceiling(self) -> None:
        """The two constants judged as the hook judges a run, so the pair cannot be edited apart."""
        assert not budget.over_budget(
            records_of(call=MEASURED_TOTAL_SECONDS), SUITE_SECONDS_CEILING
        )


class TestTheReport:
    def test_the_five_slowest_are_named_biggest_first(self) -> None:
        records = spread(total=15.0, tests=8)
        slowest = budget.slowest_tests(records)
        assert len(slowest) == 5
        assert [seconds for _nodeid, seconds in slowest] == sorted(
            (seconds for _nodeid, seconds in slowest), reverse=True
        )

    def test_a_shorter_session_lists_what_it_has(self) -> None:
        records = spread(total=3.0, tests=2)
        assert len(budget.slowest_tests(records)) == 2

    def test_ties_are_broken_by_name_so_the_list_is_reproducible(self) -> None:
        """A reviewer pastes this list into a comment; a different order each run is noise."""
        nodeids = ("tests/unit/test_b.py::test_x", "tests/unit/test_a.py::test_y")
        records = [("call", nodeid, 1.0) for nodeid in nodeids]
        assert [nodeid for nodeid, _seconds in budget.slowest_tests(records)] == sorted(nodeids)

    def test_the_failure_report_carries_the_total_the_ceiling_and_the_names(self) -> None:
        """The Done when names all three, and a reader has to be able to act without re-running."""
        records = records_of(setup=1.0, call=9.0)
        ceiling = 2.0
        lines = budget.budget_lines(records, ceiling)
        text = "\n".join(lines)
        assert "10.00s" in text, text
        assert "2.00s" in text, text
        assert "slowest" in text
        named = [line for line in lines if "test_synthetic" in line]
        assert len(named) == 2, named
        for _phase, nodeid, _seconds in records:
            assert any(nodeid in line for line in lines)

    def test_the_passing_run_prints_the_number_it_was_judged_against(self) -> None:
        """One line, so the ceiling is reviewable against a real measurement in the same log."""
        line = budget.usage_line(12.5, 45.0)
        assert line == "suite wall clock: 12.50s of 45.00s budget"


class TestTheHookFailsTheSession:
    """The wiring, end to end, in a nested pytest whose ceiling is not this repository's.

    A subprocess is the only way to watch `session.exitstatus` become a process exit code. The
    nested run registers this conftest's own plugin with a ceiling of its choosing, so the failing
    and passing paths are both observed without editing the documented constant or adding a
    command line switch that could be used to skip the budget.
    """

    @staticmethod
    def _run(tmp_path: Path, ceiling: float) -> subprocess.CompletedProcess[str]:
        suite = tmp_path / "suite"
        suite.mkdir()
        (suite / "conftest.py").write_text(
            textwrap.dedent(f"""
                import importlib.util
                from pathlib import Path

                spec = importlib.util.spec_from_file_location(
                    "airlock_root_conftest", {str(CONFTEST)!r}
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)


                def pytest_configure(config):
                    config.pluginmanager.register(module.SuiteBudget({ceiling!r}), "budget")
            """),
            encoding="utf-8",
        )
        for name in ("slow", "slower", "fastest"):
            (suite / f"test_{name}.py").write_text(
                "import time\n\n\ndef test_it():\n    time.sleep(0.05)\n", encoding="utf-8"
            )
        return subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(suite)],
            capture_output=True,
            text=True,
            cwd=str(suite),
            check=False,
        )

    def test_a_session_over_its_ceiling_exits_non_zero_and_says_why(self, tmp_path: Path) -> None:
        result = self._run(tmp_path, ceiling=0.0)
        assert result.returncode != 0, result.stdout + result.stderr
        assert "exceeded its budget" in result.stdout, result.stdout
        assert "slowest" in result.stdout, result.stdout
        assert "0.00s" in result.stdout, result.stdout

    def test_a_session_within_its_ceiling_exits_zero(self, tmp_path: Path) -> None:
        result = self._run(tmp_path, ceiling=9_999.0)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "suite wall clock:" in result.stdout, result.stdout
