"""Root conftest: the suite wall clock budget (#87) and the scratch repository factory (#92).

Two responsibilities live here, and each is the only place that knows its own ritual.

**The wall clock budget (task 9.33, issue #87).** The suite grows with the rule count, because
`tests/unit/test_fixtures.py` parametrizes over every rule id and repeats it for negatives, so a
fixture with a large body can add seconds that no assertion notices. `AGENTS.md` 8 asks for a test
that fails for the right reason, and a run that creeps from one minute to five is that failure at
process level: the signal is the ceiling being crossed, and the fix is the change that added the
time. What is measured is the sum of `report.duration` over the three phases pytest reports, not
wall clock around the session. Collection, terminal setup and interpreter start-up are outside that
sum on purpose (issue #87 section 5): they belong to pytest, and a budget that charged them could
be blown by a pytest upgrade nobody reviewed. It is a phase sum, so a test that gets slow in
`setup` is counted, which a call-phase-only measure would miss. The state lives on a plugin
instance registered in `pytest_configure` rather than in a module global, because `AGENTS.md` 6
rules out module-level mutable state and a conftest is imported once per session anyway. The
failure is `session.exitstatus`, which `_pytest.main.wrap_session` reads after
`pytest_sessionfinish` returns, so assigning it here is what the process exits with.

**The scratch repository factory (task 9.34, issue #92).** `build_scratch_repo` is the single place
that knows how to build a committed git tree under `tmp_path`. Before it existed, every module that
needed a real repository wrote its own incantation: `tests/bypass/conftest.py` calls through
`scripts.bypass_probe.build`, `tests/unit/test_ci_surface.py` and `tests/unit/test_policy.py` each
had a private `git` helper, and the follow-up rituals (`--initial-branch`, `user.name`, whether a
base commit existed) differed per file. Whether a payload was tracked at HEAD at scan time
therefore depended on which module defined the test. This file makes one definition, and the
modules below it now delegate to it.

`scripts/bypass_probe.py` still carries its own `build`, because that probe runs outside pytest and
must stay stdlib-only. Its shape is preserved here byte for byte: same base file, same two commit
messages, same tracked-at-HEAD semantics; only the identity arguments move to per-command `-c`
flags so nothing in a scratch tree inherits an on-disk config file.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import types
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

import pytest

from airlock.policy import MANIFEST_FILENAME

# `tests/unit/test_suite_budget.py` loads this file by path under a private module name and
# does not put it in `sys.modules`. A `@dataclass` below asks for
# `sys.modules[__name__].__dict__` to resolve its field annotations, so an unregistered module
# raises `AttributeError` at class-creation time. Binding `__name__` before the first class lets
# the same file run both as a pytest plugin and standalone; it is a no-op on the plugin path,
# where the name is already bound.
if __name__ not in sys.modules:  # pragma: no cover - import-time guard
    sys.modules[__name__] = types.ModuleType(__name__)

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


# ---------------------------------------------------------------------------
# Scratch repository factory (task 9.34, issue #92).
# ---------------------------------------------------------------------------
DEFAULT_BASE: Mapping[str, str] = {"index.js": "module.exports = {};\n"}

BASE_MESSAGE = "base: clean tree"
PAYLOAD_MESSAGE = "case under test"


@dataclass(frozen=True)
class ScratchRepo:
    """A committed git tree at `root`, plus the payload contents it was built with.

    Callers assert against `files` without re-reading the tree, and pass `.root` to
    `run_scan` or the collector directly. The empty `head` before any commit exists is
    what an init-only scratch repository looks like; the first payload commit sets it.
    """

    root: Path
    files: Mapping[str, bytes]
    base_files: Mapping[str, bytes]
    manifest: str | None

    @property
    def head(self) -> str | None:
        """The commit at HEAD, or None when the repository has no commits yet."""
        result = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "--verify", "-q", "HEAD"],
            capture_output=True,
            text=True,
        )
        return result.stdout.strip() if result.returncode == 0 else None


def _git(root: Path, *args: str) -> str:
    """One git call with the identity and hooks pinned, so a scratch tree never inherits
    a global config or fires a user hook. Kept identical to `test_ci_surface.py:94`."""
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=airlock-test",
            "-c",
            "user.email=airlock-test@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            *args,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def git_in(root: Path, *args: str) -> str:
    """Public form of `_git` for test modules that stage or commit after the factory ran.

    `test_ci_surface.py` and `test_policy.py` use init-only scratch trees and then do their
    own follow-up commits; those commits must carry the same identity and hooks as the base
    commit the factory makes. One function rather than three copies.
    """
    return _git(root, *args)


def _safe_rel(name: str) -> PurePosixPath:
    """A repository-relative path that cannot climb out of the scratch tree.

    Rejects absolute paths, POSIX `..` segments, drive-letter paths, and backslash
    separators so a caller cannot smuggle a file outside `tmp_path` even on Windows.
    """
    if not isinstance(name, str) or name == "":
        raise ValueError(f"scratch_repo path must be a non-empty string, got {name!r}")
    if "\\" in name:
        raise ValueError(f"scratch_repo path uses backslash separator: {name!r}")
    if name.startswith("/") or (len(name) >= 2 and name[1] == ":"):
        raise ValueError(f"scratch_repo path must be repository-relative: {name!r}")
    pure = PurePosixPath(name)
    if any(part == ".." for part in pure.parts):
        raise ValueError(f"scratch_repo path escapes the repository root: {name!r}")
    return pure


def _as_bytes(data: bytes | str) -> bytes:
    return data.encode("utf-8") if isinstance(data, str) else bytes(data)


def _write_all(root: Path, files: Mapping[str, bytes | str]) -> dict[str, bytes]:
    """Stage every entry under `root`, mkdirs included; return the byte form of the map."""
    out: dict[str, bytes] = {}
    for name, data in files.items():
        rel = _safe_rel(name)
        target = root.joinpath(*rel.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = _as_bytes(data)
        target.write_bytes(payload)
        out[str(rel)] = payload
    return out


def build_scratch_repo(
    root: Path,
    files: Mapping[str, bytes | str] | None = None,
    *,
    base_files: Mapping[str, bytes | str] | None = None,
    manifest: str | None = None,
    message: str = PAYLOAD_MESSAGE,
    base_message: str = BASE_MESSAGE,
) -> ScratchRepo:
    """Initialise a git repository at `root` and commit the caller's payload.

    Modes, chosen by which arguments the caller passes:

      * `files=None` (or empty), `base_files={}`  -- just `git init`. A caller that will
        stage and commit itself later (the existing `write`/`commit` helpers in
        `test_ci_surface.py` and `test_policy.py`) uses this, so the base ritual lives in
        one file and the module's own follow-up commits stay intact.
      * default `base_files=None`, non-empty `files`  -- bypass shape: `index.js` base
        commit, then a payload commit. This is the shape the trusted base scan uses.
      * any other combination  -- caller-controlled base commit, then payload commit.

    `manifest`, when present, becomes one more payload file named `MANIFEST_FILENAME`
    (imported from `airlock.policy`, not a hardcoded literal). Refuses a payload path
    containing `..`, `/`, a drive letter, or a backslash so a test cannot write outside
    the scratch tree by accident.
    """
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q", "--initial-branch=main")

    # `None` picks the bypass default; `{}` explicitly skips the base commit so the
    # caller controls every commit that follows.
    base_map = DEFAULT_BASE if base_files is None else dict(base_files)
    written_base = _write_all(root, base_map) if base_map else {}
    if base_map:
        _git(root, "add", "-A")
        _git(root, "commit", "-qm", base_message)

    payload: dict[str, bytes | str] = dict(files or {})
    if manifest is not None:
        # A caller can put the manifest in `files` explicitly to override the name;
        # `setdefault` keeps that override.
        payload.setdefault(MANIFEST_FILENAME, manifest)

    written_payload = _write_all(root, payload) if payload else {}
    if payload:
        _git(root, "add", "-A")
        _git(root, "commit", "-qm", message)

    return ScratchRepo(
        root=root,
        files=written_payload,
        base_files=written_base,
        manifest=manifest,
    )


@pytest.fixture
def scratch_repo(tmp_path: Path) -> Callable[..., ScratchRepo]:
    """Factory behind the `scratch_repo` name, one directory per call.

    Usage:

        def test_something(scratch_repo):
            repo = scratch_repo({"src/loader.js": b"require('child_process')"})
            report = run_scan(repo.root, Mode.FULL)

    `tmp_path` is already per-test, so calling the factory more than once in one test
    yields distinct repositories named `repo-1`, `repo-2`, ... unless a caller passes
    `name=`.
    """
    counter = {"n": 0}

    def build(
        files: Mapping[str, bytes | str] | None = None,
        *,
        base_files: Mapping[str, bytes | str] | None = None,
        manifest: str | None = None,
        message: str = PAYLOAD_MESSAGE,
        base_message: str = BASE_MESSAGE,
        name: str | None = None,
    ) -> ScratchRepo:
        counter["n"] += 1
        directory = tmp_path / (name or f"repo-{counter['n']}")
        return build_scratch_repo(
            directory,
            files,
            base_files=base_files,
            manifest=manifest,
            message=message,
            base_message=base_message,
        )

    return build
