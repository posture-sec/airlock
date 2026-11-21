"""Issue #103 / task 9.68: the five places that name a Python version must name the same range.

Task 9.59 put a 3.11/3.12/3.13 matrix in `.github/workflows/ci.yml`, and
`tests/unit/test_workflow_matrix.py` guards that the matrix exists and that it reaches the declared
floor. What nothing guarded is agreement between the other four declarations of the same fact:

* `requires-python` in `pyproject.toml`, the floor the package promises,
* the `Programming Language :: Python :: 3.X` classifiers, which are what an index and a dependabot
  config read, and which said only 3.11 while CI ran three interpreters,
* `[tool.ruff] target-version`, which decides which syntax ruff accepts, and
* `[tool.mypy] python_version`, which decides which stdlib stubs mypy checks against.

Four sources that can each move alone is how a range drifts. The matrix test asks "is the floor
covered"; this one asks "do all five describe the same set", derived rather than hardcoded: the
expected range is every minor from the `requires-python` floor up to the highest minor any source
names, so adding a classifier without a matrix entry, or a matrix entry without a classifier, is
reported, and so is a floor move that leaves the two static tools behind.

The workflow is read with the scanner from `test_workflow_matrix.py` rather than a second one,
because two readers of the same file drift, and the drift would look like a real disagreement.
Values come from `tomllib`; the line numbers come from a narrow scan of the same text, because
`tomllib` reports no positions, and `test_the_two_readings_of_pyproject_agree` fails if the scan and
the parse ever count different numbers of entries.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from test_workflow_matrix import (
    declared_floor,
    inside,
    job_spans,
    key_values,
    matrix_versions,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = REPO_ROOT / "pyproject.toml"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

#: The classifier line as it sits in `pyproject.toml`, and the same value as `tomllib` hands it
#: back with the quotes and the comma stripped. Two patterns because the two readings differ by
#: exactly those characters, and `test_the_two_readings_of_pyproject_agree` is what stops one of
#: them drifting and a message pointing at a line that declares something else.
_CLASSIFIER_LINE = re.compile(
    r'^\s*"Programming Language :: Python :: (?P<major>\d+)\.(?P<minor>\d+)",\s*$'
)
_CLASSIFIER_VALUE = re.compile(
    r"^Programming Language :: Python :: (?P<major>\d+)\.(?P<minor>\d+)$"
)
_RUFF_TARGET = re.compile(r'^\s*target-version\s*=\s*"py(?P<major>\d)(?P<minor>\d+)"')
_MYPY_VERSION = re.compile(r'^\s*python_version\s*=\s*"(?P<major>\d)\.(?P<minor>\d+)"')


def rank(version: str) -> tuple[int, int]:
    major, minor = version.split(".")[:2]
    return int(major), int(minor)


def supported(floor: str, named: list[str]) -> list[str]:
    """Every minor from `floor` up to the highest minor any source names, contiguous.

    Derived on purpose: the ceiling is not a constant in this file, so the range moves when a real
    3.14 row is added to the matrix, and it moves only then.
    """
    if not named:
        return [floor]
    top = max((rank(version) for version in named), default=rank(floor))
    floor_rank = rank(floor)
    return [f"3.{minor}" for minor in range(floor_rank[1], top[1] + 1)]


def classified_minors(pyproject: dict[str, Any]) -> list[str]:
    classifiers = pyproject["project"].get("classifiers", [])
    return [
        f"{match.group('major')}.{match.group('minor')}"
        for line in classifiers
        if (match := _CLASSIFIER_VALUE.match(line.strip())) and match.group("major") == "3"
    ]


def ruff_target(pyproject: dict[str, Any]) -> str:
    """`py311` as `3.11`, the way the other sources spell it."""
    raw = str(pyproject["tool"]["ruff"]["target-version"])
    match = re.fullmatch(r"py(\d)(\d+)", raw)
    if match is None:
        raise AssertionError(f"[tool.ruff] target-version is {raw!r}, which is not pyMAJORMINOR")
    return f"{match.group(1)}.{match.group(2)}"


def mypy_version(pyproject: dict[str, Any]) -> str:
    return str(pyproject["tool"]["mypy"]["python_version"])


def matrix_of(workflow_text: str) -> list[str]:
    """The versions in every matrixed job, in file order."""
    return [
        version
        for span in job_spans(workflow_text).values()
        for _, listed in matrix_versions(inside(workflow_text, span))
        for version in listed
    ]


def line_of(text: str, pattern: re.Pattern[str]) -> dict[str, int]:
    """Where each value a checker names sits in the file, keyed by the value it declares."""
    found: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        match = pattern.match(line)
        if match is None:
            continue
        groups = match.groupdict()
        if "minor" in groups and "major" in groups:
            found[f"{groups['major']}.{groups['minor']}"] = number
    return found


def disagreements(
    floor: str,
    classifiers: list[str],
    matrix: list[str],
    ruff: str,
    mypy: str,
    pyproject_lines: dict[str, int],
    workflow_line: int,
) -> list[str]:
    """Every way the five declarations can fail to describe one range, as file:line messages."""
    expected = supported(floor, [*classifiers, *matrix])
    problems: list[str] = []
    missing_classifiers = sorted(set(expected) - set(classifiers), key=rank)
    extra_classifiers = sorted(set(classifiers) - set(expected), key=rank)
    missing_matrix = sorted(set(expected) - set(matrix), key=rank)
    where = f"{WORKFLOW.relative_to(REPO_ROOT)}:{workflow_line}"
    floor_where = f"pyproject.toml:{pyproject_lines['floor']}"
    if missing_classifiers:
        problems.append(
            f"requires-python promises >= {floor} at {floor_where} and the matrix tests "
            f"{', '.join(matrix)}, so {', '.join(missing_classifiers)} must be classified too"
        )
    if extra_classifiers:
        problems.append(
            f"classifiers name {', '.join(extra_classifiers)}, which are outside the range the "
            f"floor {floor} and the matrix support: {', '.join(expected)}"
        )
    if missing_matrix:
        problems.append(
            f"{where} does not test {', '.join(missing_matrix)} although the declared range is "
            f"{', '.join(expected)}"
        )
    if ruff != floor:
        problems.append(
            f"[tool.ruff] target-version is {ruff} but requires-python floors the package at "
            f"{floor} (pyproject.toml:{pyproject_lines['ruff']})"
        )
    if mypy != floor:
        problems.append(
            f"[tool.mypy] python_version is {mypy} but requires-python floors the package at "
            f"{floor} (pyproject.toml:{pyproject_lines['mypy']})"
        )
    return problems


def current() -> tuple[str, list[str], list[str], str, str, dict[str, int], int]:
    """The five declarations as they sit on disk, plus the lines a message should point at."""
    pyproject_text = PYPROJECT.read_text(encoding="utf-8")
    workflow_text = WORKFLOW.read_text(encoding="utf-8")
    data = tomllib.loads(pyproject_text)
    floor_line, floor = declared_floor(pyproject_text)
    if not floor:
        raise AssertionError(f"{PYPROJECT} declares no requires-python floor")
    classified_lines = line_of(pyproject_text, _CLASSIFIER_LINE)
    static_lines = {
        "floor": floor_line,
        "ruff": next(iter(line_of(pyproject_text, _RUFF_TARGET).values()), 0),
        "mypy": next(iter(line_of(pyproject_text, _MYPY_VERSION).values()), 0),
    }
    matrix_lines = [
        number
        for span in job_spans(workflow_text).values()
        for number, _listed in matrix_versions(inside(workflow_text, span))
    ]
    return (
        floor,
        classified_minors(data),
        matrix_of(workflow_text),
        ruff_target(data),
        mypy_version(data),
        {**{"classifiers": classified_lines}, **static_lines},
        matrix_lines[0] if matrix_lines else 0,
    )


class TestTheDeclarationsAgree:
    def test_all_five_name_the_same_range(self) -> None:
        floor, classifiers, matrix, ruff, mypy, lines, workflow_line = current()
        problems = disagreements(floor, classifiers, matrix, ruff, mypy, lines, workflow_line)
        assert not problems, "\n".join(problems)

    def test_the_floor_is_the_requires_python_declaration(self) -> None:
        floor, _c, matrix, ruff, mypy, _lines, _line = current()
        assert rank(floor) == (3, 11), f"requires-python floors at {floor}"
        assert ruff == mypy == floor
        assert matrix, "no matrix to compare against"

    def test_the_two_readings_of_pyproject_agree(self) -> None:
        """The line scan and `tomllib` must count the same classifiers, or a
        reported line points at something else."""
        pyproject_text = PYPROJECT.read_text(encoding="utf-8")
        scanned = line_of(pyproject_text, _CLASSIFIER_LINE)
        parsed = classified_minors(tomllib.loads(pyproject_text))
        assert sorted(scanned) == sorted(parsed), (
            f"pyproject.toml classifiers parsed to {parsed} but were located at "
            f"{sorted(scanned.values())}"
        )
        for version in parsed:
            assert version in scanned, f"{version} parsed but not located"


class TestTheGuardBites:
    """Each failure mode the issue names is reproduced with data, not by editing the tree."""

    @staticmethod
    def lines(classifiers: dict[str, int]) -> dict[str, int]:
        """A synthetic line table with the same shape `current()` returns."""
        return {"floor": 14, "classifiers": classifiers, "ruff": 46, "mypy": 56}

    def test_a_classifier_the_matrix_does_not_test_is_reported(self) -> None:
        """3.14 classified but not matrixed: the range extends, and the matrix is told."""
        problems = disagreements(
            "3.11",
            ["3.11", "3.12", "3.13", "3.14"],
            ["3.11", "3.12", "3.13"],
            "3.11",
            "3.11",
            self.lines({"3.11": 17, "3.14": 20}),
            28,
        )
        assert [p for p in problems if "3.14" in p], problems
        assert any(".github/workflows/ci.yml:28" in p for p in problems), problems

    def test_a_matrix_version_with_no_classifier_is_reported(self) -> None:
        problems = disagreements(
            "3.11",
            ["3.11"],
            ["3.11", "3.12", "3.13"],
            "3.11",
            "3.11",
            self.lines({"3.11": 17}),
            28,
        )
        assert len(problems) == 1, problems
        assert "3.12, 3.13 must be classified too" in problems[0]
        assert "pyproject.toml:14" in problems[0], problems[0]

    def test_a_hole_between_two_named_versions_is_filled_in(self) -> None:
        """3.11 and 3.13 named with no 3.12 is a hole, and the derived range says so."""
        assert supported("3.11", ["3.11", "3.13"]) == ["3.11", "3.12", "3.13"]

    def test_raising_the_floor_without_the_static_tools_is_reported(self) -> None:
        problems = disagreements(
            "3.12",
            ["3.12", "3.13"],
            ["3.12", "3.13"],
            "3.11",
            "3.11",
            self.lines({"3.12": 17}),
            28,
        )
        assert any("target-version" in p and "pyproject.toml:46" in p for p in problems)
        assert any("python_version" in p and "pyproject.toml:56" in p for p in problems)

    def test_a_clean_table_reports_nothing(self) -> None:
        assert not disagreements(
            "3.11",
            ["3.11", "3.12", "3.13"],
            ["3.11", "3.12", "3.13"],
            "3.11",
            "3.11",
            self.lines({"3.11": 17}),
            28,
        )

    def test_quoted_matrix_entries_are_read_as_versions(self) -> None:
        pairs = key_values('      python-version: ["3.11", "3.12", "3.13"]\n')
        assert matrix_versions(pairs) == [(1, ["3.11", "3.12", "3.13"])]
