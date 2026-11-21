"""Session plumbing for the whole suite: the wall clock budget (task 9.33, issue #87).

The suite grows with the rule count, because `tests/unit/test_fixtures.py` parametrizes over every
rule id and repeats it for negatives, so a fixture with a large body can add seconds that no
assertion notices. `AGENTS.md` 8 asks for a test that fails for the right reason, and a run that
creeps from one minute to five is that failure at process level: the signal is the ceiling being
crossed, and the fix is the change that added the time.

What is measured is the sum of `report.duration` over the three phases pytest reports, not wall
clock around the session. Collection, terminal setup and interpreter start-up are outside that sum
on purpose (issue #87 section 5): they belong to pytest, and a budget that charged them could be
blown by a pytest upgrade nobody reviewed. It is a phase sum, so a test that gets slow in `setup`
is counted, which a call-phase-only measure would miss.

The state lives on a plugin instance registered in `pytest_configure` rather than in a module
global, because `AGENTS.md` 6 rules out module-level mutable state and a conftest is imported once
per session anyway. The failure is `session.exitstatus`, which `_pytest.main.wrap_session` reads
after `pytest_sessionfinish` returns, so assigning it here is what the process exits with.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from _pytest.config import Config
    from _pytest.main import Session
    from _pytest.reports import TestReport

#: The phases pytest reports a duration for. A skipped test still spends setup and teardown time,
#: and that time is part of what a reviewer waits for.
PHASES: tuple[str, ...] = ("setup", "call", "teardown")

#: How many slow tests a failing run names. Five is enough to show whether the run is broad or one
#: file is the problem, which are the two different repairs a reader can act on.
SLOWEST_COUNT = 5

#: One `(phase, nodeid, seconds)` triple as `pytest_runtest_logreport` sees it. A tuple rather than
#: a dataclass so a test can build records inline without importing anything from this file.
Record = tuple[str, str, float]

#: The module that documents the ceiling, which `issue #87` section 3 puts next to its measurement.
BUDGET_MODULE = Path(__file__).resolve().parent / "unit" / "test_suite_budget.py"

#: The name of the constant inside that module.
BUDGET_CONSTANT = "SUITE_SECONDS_CEILING"


def phase_totals(records: Iterable[Record]) -> dict[str, float]:
    """Seconds per phase, with every name in `PHASES` present even when it collected nothing."""
    totals = dict.fromkeys(PHASES, 0.0)
    for phase, _nodeid, seconds in records:
        totals[phase] = totals.get(phase, 0.0) + seconds
    return totals


def session_seconds(records: Iterable[Record]) -> float:
    """The number the budget is about: every phase of every report, summed."""
    return sum(phase_totals(records).values())


def per_test_seconds(records: Iterable[Record]) -> dict[str, float]:
    """Seconds per test nodeid, adding up that test's phases."""
    totals: dict[str, float] = {}
    for _phase, nodeid, seconds in records:
        totals[nodeid] = totals.get(nodeid, 0.0) + seconds
    return totals


def slowest_tests(records: Iterable[Record], count: int = SLOWEST_COUNT) -> list[tuple[str, float]]:
    """The `count` biggest per-test totals, biggest first.

    Ties break on the nodeid so two runs of the same session print the same list.
    """
    ranked = sorted(per_test_seconds(records).items(), key=lambda item: (-item[1], item[0]))
    return ranked[:count]


def over_budget(records: Iterable[Record], ceiling: float) -> bool:
    """The one comparison a run is judged by, shared by the hook and the tests that bound it.

    Strictly greater, so a run that lands exactly on the documented ceiling passes: the ceiling is
    the last acceptable number, and a boundary that also rejects equality would make the constant a
    measurement rather than a limit.
    """
    return session_seconds(records) > ceiling


def budget_lines(
    records: Iterable[Record], ceiling: float, count: int = SLOWEST_COUNT
) -> list[str]:
    """What a failing run prints: total, phases, the `count` slowest names and the ceiling."""
    totals = phase_totals(records)
    slowest = slowest_tests(records, count)
    return [
        f"suite wall clock exceeded its budget: "
        f"{session_seconds(records):.2f}s over a {ceiling:.2f}s ceiling",
        "  phases: "
        + "  ".join(f"{phase} {totals.get(phase, 0.0):.2f}s" for phase in PHASES)
        + f"  ({len(per_test_seconds(records))} tests)",
        f"  slowest {count}:",
        *(f"    {seconds:7.2f}s  {nodeid}" for nodeid, seconds in slowest),
        "The ceiling is `SUITE_SECONDS_CEILING` in tests/unit/test_suite_budget.py. Raise it with "
        "a new measurement from the machine that ran it, or take the seconds back out of the "
        "change that added them.",
    ]


def usage_line(total: float, ceiling: float) -> str:
    """The one line a passing run prints, so the number a reviewer judges is in the same log."""
    return f"suite wall clock: {total:.2f}s of {ceiling:.2f}s budget"


def suite_ceiling(path: Path = BUDGET_MODULE, name: str = BUDGET_CONSTANT) -> float:
    """The ceiling, read from the module that documents it, at the moment it is needed.

    Either file could own both halves, and neither does: issue #87 section 3 puts the hook here
    and the constant with its measurement, so one has to reach for the other. Loading it inside
    the hook rather than at module scope is what keeps that from being a cycle: the test module
    loads this file by path to exercise the summing functions, and a module-scope import in either
    direction would meet a half-built module.
    """
    spec = importlib.util.spec_from_file_location("airlock_suite_budget", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load the suite ceiling from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return float(getattr(module, name))


class SuiteBudget:
    """The accumulator: one list of reports for one session, held on this instance."""

    def __init__(self, ceiling: float) -> None:
        self.ceiling = ceiling
        self.records: list[Record] = []

    def pytest_runtest_logreport(self, report: TestReport) -> None:
        if report.when in PHASES:
            self.records.append((report.when, report.nodeid, report.duration))

    def pytest_sessionfinish(self, session: Session, exitstatus: pytest.ExitCode) -> None:
        if not self.records:
            return
        total = session_seconds(self.records)
        writer = session.config.get_terminal_writer()
        if not over_budget(self.records, self.ceiling):
            writer.line(usage_line(total, self.ceiling))
            return
        for line in budget_lines(self.records, self.ceiling):
            writer.line(line, red=True, bold=True)
        # The run is judged as failed even though every test passed, which is the point of a budget.
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_configure(config: Config) -> None:
    config.pluginmanager.register(SuiteBudget(suite_ceiling()), "airlock-suite-budget")
