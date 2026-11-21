"""Issue #76 / task 9.31: CI must run on every interpreter the package claims to support.

`pyproject.toml` declares `requires-python = ">=3.11"`, which is a promise that 3.12 and 3.13 work.
A promise nothing executes is not a promise, so this reads the workflow the way a reviewer would
and refuses the three ways it can quietly stop covering the floor and its successors: no matrix at
all, a matrix with a version missing, or a matrix with a version below the floor.

PyYAML is not a dependency of this repository and adding one to check a workflow would be the
wrong trade (`AGENTS.md` 4), so this is a line scanner over the text. It is deliberately narrow:
job spans by indentation, then key and value per line. Anything it cannot recognise is reported as
such with the path and the line number, rather than passing because the parser found nothing.

The failure the guard exists to catch is the single-version workflow this repository had, so
`test_a_workflow_without_a_matrix_is_reported_as_one` runs the same scanner over that exact file
from git rather than over an approximation of it.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
PYPROJECT = REPO_ROOT / "pyproject.toml"

#: The interpreters the matrix has to run the suite on. `3.11` is the floor in `pyproject.toml`;
#: the two after it are the versions that floor promises and that no job used to execute.
SUPPORTED_VERSIONS = ("3.11", "3.12", "3.13")

#: The step that must stay on one interpreter: its output is quoted when this repository's own
#: findings are discussed, and three of them would make that quote ambiguous.
SELF_SCAN_JOB = "self-scan"
SELF_SCAN_COMMAND = "airlock scan --mode full ."

_KEY_VALUE = re.compile(r"^(?P<key>[A-Za-z0-9_.-]+):\s*(?P<value>.*?)\s*$")
_LIST = re.compile(r"^\[(?P<items>.*)\]$")
_COMMENT = re.compile(r"^\s*#")


#: The commit whose `.github/workflows/ci.yml` is the single-version file this task replaced.
#: Pinned by SHA rather than read from a branch, because a branch moves: once the matrix lands on
#: `main`, `origin/main` would carry it and this test would assert the opposite of what it means.
#: `fetch-depth: 0` on every job is what makes the object reachable, and this file guards that too.
SINGLE_VERSION_WORKFLOW = "b323de5"


def key_values(text: str) -> list[tuple[int, str, str]]:
    """Every `key: value` line as (one-based line number, key, value), comments dropped.

    The value keeps its trailing comment out and its quotes in, because the quote is what
    distinguishes `python-version: "3.11"` (a pin) from `python-version: ${{ ... }}` (a template).
    """
    pairs: list[tuple[int, str, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or _COMMENT.match(line):
            continue
        body = line.split("#", 1)[0].rstrip() if "#" in line else line.rstrip()
        match = _KEY_VALUE.match(body.strip())
        if match is not None:
            pairs.append((number, match.group("key"), match.group("value")))
    return pairs


def job_spans(text: str) -> dict[str, tuple[int, int]]:
    """The one-based (first, last) lines of every job under the top-level `jobs:` mapping."""
    lines = text.splitlines()
    spans: dict[str, tuple[int, int]] = {}
    in_jobs = False
    current: str | None = None
    start = 0
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or _COMMENT.match(line):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            if current is not None:
                spans[current] = (start, number - 1)
                current = None
            in_jobs = stripped == "jobs:"
            continue
        if in_jobs and indent == 2:
            if current is not None:
                spans[current] = (start, number - 1)
            key = stripped.split(":", 1)[0]
            current, start = key, number
    if current is not None:
        spans[current] = (start, len(lines))
    return spans


def inside(text: str, span: tuple[int, int]) -> list[tuple[int, str, str]]:
    """The `key: value` lines belonging to one job span."""
    first, last = span
    return [(n, k, v) for n, k, v in key_values(text) if first <= n <= last]


def job_text(text: str, job: str) -> str:
    """The raw lines of one job, header included."""
    first, last = job_spans(text)[job]
    return "\n".join(text.splitlines()[first - 1 : last])


def quoted(value: str) -> str:
    return value.strip().strip("\"'")


def version_list(value: str) -> list[str]:
    """The versions in a `["3.11", "3.12"]` flow sequence, in the order written."""
    match = _LIST.match(value.strip())
    if match is None:
        return []
    return [quoted(item) for item in match.group("items").split(",") if item.strip()]


def rank(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def declared_floor(text: str | None = None) -> tuple[int, str]:
    """The `requires-python` floor as (line number, version), or (0, "") when it is absent."""
    for number, line in enumerate(
        (text if text is not None else PYPROJECT.read_text(encoding="utf-8")).splitlines(), start=1
    ):
        match = re.match(r'\s*requires-python\s*=\s*">=\s*(?P<floor>\d+\.\d+)"', line)
        if match is not None:
            return number, match.group("floor")
    return 0, ""


def matrix_versions(pairs: list[tuple[int, str, str]]) -> list[tuple[int, list[str]]]:
    """Every flow-sequence `python-version` in a job, with the line it was read from.

    A scalar `python-version: "3.11"` is deliberately absent; it is a pin, and the difference is
    the whole question this guard asks.
    """
    found: list[tuple[int, list[str]]] = []
    for number, key, value in pairs:
        if key != "python-version":
            continue
        versions = version_list(value)
        if versions:
            found.append((number, versions))
    return found


def scalar_pins(text: str) -> list[int]:
    """Lines holding a `python-version` pin that is not a matrix, job by job.

    These are what the missing-matrix message names: a lone pin is the shape this task replaced, and
    a guard that only says "no matrix" sends the reader to the wrong half of the file.
    """
    return [
        number
        for span in job_spans(text).values()
        for number, key, value in inside(text, span)
        if key == "python-version" and value and not version_list(value)
    ]


@pytest.fixture(scope="module")
def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def single_version_workflow() -> str:
    """The `.github/workflows/ci.yml` this task replaced, read from the commit that carried it."""
    ref = f"{SINGLE_VERSION_WORKFLOW}:.github/workflows/ci.yml"
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "show", ref],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"`git show {ref}` failed ({result.stderr.strip()}); the guard has lost its record of what "
        "it replaced, and `fetch-depth: 0` is what keeps that object reachable"
    )
    assert result.stdout, f"{ref} is empty, so the tests that read it prove nothing"
    return result.stdout


class TestTheMatrix:
    def test_the_workflow_declares_a_python_version_matrix(self, workflow_text: str) -> None:
        found = [
            (job, versions)
            for job, span in job_spans(workflow_text).items()
            for _, versions in matrix_versions(inside(workflow_text, span))
        ]
        # Where the scanner found a `python-version` but no matrix in it, name the line: a lone pin
        # is the exact shape this task removed, and pointing at it is the whole fix.
        pinned = scalar_pins(workflow_text)
        note = f" (single pins at line(s) {pinned})" if pinned else ""
        assert found, (
            f"{WORKFLOW.relative_to(REPO_ROOT)} has no `python-version: [...]` matrix{note}: the "
            "suite runs on one interpreter while pyproject.toml promises several"
        )

    def test_the_matrix_covers_every_supported_interpreter(self, workflow_text: str) -> None:
        versions = {
            version
            for span in job_spans(workflow_text).values()
            for _, listed in matrix_versions(inside(workflow_text, span))
            for version in listed
        }
        missing = sorted(set(SUPPORTED_VERSIONS) - versions, key=rank)
        assert not missing, f"{WORKFLOW} matrix is missing {', '.join(missing)}"

    def test_the_matrix_includes_the_declared_floor(self, workflow_text: str) -> None:
        line, floor = declared_floor()
        assert floor, f"{PYPROJECT} declares no requires-python floor"
        versions = {
            version
            for span in job_spans(workflow_text).values()
            for _, listed in matrix_versions(inside(workflow_text, span))
            for version in listed
        }
        assert floor in versions, (
            f"{PYPROJECT.relative_to(REPO_ROOT)}:{line} promises >= {floor}, but the "
            f"{WORKFLOW.relative_to(REPO_ROOT)} matrix runs {', '.join(sorted(versions, key=rank))}"
        )

    def test_no_matrix_version_is_below_the_declared_floor(self, workflow_text: str) -> None:
        _, floor = declared_floor()
        assert floor
        for job, span in job_spans(workflow_text).items():
            for number, listed in matrix_versions(inside(workflow_text, span)):
                too_old = [version for version in listed if rank(version) < rank(floor)]
                assert not too_old, (
                    f"{WORKFLOW.relative_to(REPO_ROOT)}:{number} tests job `{job}` on "
                    f"{', '.join(too_old)}, below the declared floor {floor}"
                )

    def test_the_matrix_does_not_stop_the_other_versions_when_one_fails(
        self, workflow_text: str
    ) -> None:
        """`fail-fast: false`, or a 3.13-only break hides the 3.11 answer the floor needs."""
        jobs = {
            job
            for job, span in job_spans(workflow_text).items()
            if matrix_versions(inside(workflow_text, span))
        }
        assert jobs, f"{WORKFLOW} has no matrix job to check"
        for job in sorted(jobs):
            pairs = inside(workflow_text, job_spans(workflow_text)[job])
            flags = [value for _, key, value in pairs if key == "fail-fast"]
            assert flags == ["false"], (
                f"job `{job}` in {WORKFLOW.relative_to(REPO_ROOT)} needs `fail-fast: false`, saw "
                f"{flags or 'nothing'}"
            )


class TestTheSelfScanStaysOnOneInterpreter:
    def test_the_self_scan_is_its_own_job(self, workflow_text: str) -> None:
        assert SELF_SCAN_JOB in job_spans(workflow_text), (
            f"{WORKFLOW.relative_to(REPO_ROOT)} has no `{SELF_SCAN_JOB}` job; the scan this "
            "repository quotes is meant to run once, on the floor interpreter"
        )

    def test_the_self_scan_runs_on_the_declared_floor(self, workflow_text: str) -> None:
        _, floor = declared_floor()
        span = job_spans(workflow_text)[SELF_SCAN_JOB]
        pins = [
            quoted(value)
            for _, key, value in inside(workflow_text, span)
            if key == "python-version" and not version_list(value)
        ]
        assert pins == [floor], (
            f'the `{SELF_SCAN_JOB}` job must pin `python-version: "{floor}"`, saw {pins}'
        )

    def test_the_self_scan_keeps_its_command_and_its_install(self, workflow_text: str) -> None:
        """The step is the check that the wheel carries its rule data (5.7), so it installs it."""
        text = job_text(workflow_text, SELF_SCAN_JOB)
        assert SELF_SCAN_COMMAND in text, (
            f"`{SELF_SCAN_COMMAND}` is missing from the `{SELF_SCAN_JOB}` job"
        )
        # `$` has to mean end of line: the install is not the last step in the job, and without
        # MULTILINE it is only ever the end of the job text that can satisfy the match.
        assert re.search(r"pip install[^\n]*\.\s*$", text, re.MULTILINE), (
            f"the `{SELF_SCAN_JOB}` job must install the package from the tree"
        )

    def test_the_self_scan_is_not_part_of_the_matrix(self, workflow_text: str) -> None:
        span = job_spans(workflow_text)[SELF_SCAN_JOB]
        assert not matrix_versions(inside(workflow_text, span)), (
            f"`{SELF_SCAN_JOB}` must not be matrixed: three quotes of the same scan disagree"
        )


class TestEveryJobKeepsWhatTheSuiteNeeds:
    def test_every_job_fetches_the_history_the_roadmap_gate_needs(self, workflow_text: str) -> None:
        """`test_this_branch_passes_the_gate_it_is_adding` diffs the branch against its base."""
        for job, span in sorted(job_spans(workflow_text).items()):
            pairs = inside(workflow_text, span)
            depths = [value for _, key, value in pairs if key == "fetch-depth"]
            assert depths == ["0"], (
                f"job `{job}` in {WORKFLOW.relative_to(REPO_ROOT)} must keep `fetch-depth: 0`, "
                f"saw {depths or 'no checkout with a depth'}"
            )

    def test_every_action_is_still_pinned_by_sha_with_its_tag(self, workflow_text: str) -> None:
        """A SHA pin without the tag beside it cannot be reviewed, which is the whole point (9)."""
        unpinned = [
            number
            for number, line in enumerate(workflow_text.splitlines(), start=1)
            if re.search(r"^\s*-?\s*uses:\s*", line)
            and not re.search(r"uses:\s*\S+@[0-9a-f]{40}\s*#\s*\S+", line)
        ]
        assert not unpinned, (
            f"{WORKFLOW.relative_to(REPO_ROOT)} line(s) {unpinned} are not pinned by full SHA "
            "with the tag they resolved from"
        )


class TestTheScannerItself:
    """The guard is only as good as its reading of a file it does not understand."""

    FLAT = """jobs:
  checks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0
        with:
          python-version: "3.11"
"""

    def test_the_workflow_this_branch_replaced_would_not_pass(self) -> None:
        """The real `ci.yml` from before task 9.31, read by the scanner the guard uses."""
        old = single_version_workflow()
        for span in job_spans(old).values():
            assert not matrix_versions(inside(old, span)), (
                "the scanner found a matrix in a workflow that had none"
            )
        assert 'python-version: "3.11"' in old
        assert SELF_SCAN_JOB not in job_spans(old), (
            "the single-version workflow is supposed to have the scan inside `checks`"
        )

    def test_the_missing_matrix_is_located_by_line(self) -> None:
        """The acceptance criterion asks for the file and the line, so the line is checked too."""
        old = single_version_workflow()
        pinned = scalar_pins(old)
        assert pinned, "the guard would report a missing matrix without pointing at the pin"
        for number in pinned:
            assert old.splitlines()[number - 1].strip() == 'python-version: "3.11"'

    def test_a_workflow_with_no_jobs_mapping_reads_as_no_matrix(self) -> None:
        assert job_spans("name: CI\non: [push]\n") == {}

    def test_a_scalar_pin_is_not_mistaken_for_a_matrix(self) -> None:
        assert matrix_versions(key_values(self.FLAT)) == []

    def test_a_matrix_is_read_in_the_order_written(self) -> None:
        pairs = key_values('  strategy:\n    matrix:\n      python-version: ["3.11", "3.12"]\n')
        assert matrix_versions(pairs) == [(3, ["3.11", "3.12"])]

    def test_the_floor_is_read_from_the_line_it_is_on(self) -> None:
        assert declared_floor('a = 1\nrequires-python = ">=3.11"\n') == (2, "3.11")

    def test_a_missing_floor_is_reported_as_missing(self) -> None:
        assert declared_floor("a = 1\n") == (0, "")
