"""GitHub context interpolation must stay out of workflow shell bodies."""

from __future__ import annotations

import re
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github/workflows"
RUN = re.compile(r"^(\s*)(?:-\s+)?run:\s*(.*)$")


def unsafe_run_lines(text: str) -> list[int]:
    """Return source lines that interpolate a GitHub expression in a run scalar."""
    lines = text.splitlines()
    unsafe: list[int] = []
    index = 0
    while index < len(lines):
        match = RUN.match(lines[index])
        if not match:
            index += 1
            continue
        indent = len(match.group(1))
        value = match.group(2)
        if "${{ github." in value:
            unsafe.append(index + 1)
        index += 1
        if value not in ("|", "|-", "|+", ">", ">-", ">+"):
            continue
        while index < len(lines):
            line = lines[index]
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                break
            if "${{ github." in line:
                unsafe.append(index + 1)
            index += 1
    return unsafe


def test_bad_run_is_detected() -> None:
    text = "steps:\n  - run: |\n      echo ${{ github.head_ref }}\n"
    assert unsafe_run_lines(text) == [3]


def test_env_expression_is_not_a_shell_interpolation() -> None:
    text = 'steps:\n  - env:\n      BASE_REF: ${{ github.base_ref }}\n    run: echo "${BASE_REF}"\n'
    assert unsafe_run_lines(text) == []


def test_committed_workflows_have_no_direct_github_run_interpolation() -> None:
    violations = [
        f"{path.relative_to(WORKFLOWS)}:{line}"
        for path in sorted(WORKFLOWS.glob("*.yml"))
        for line in unsafe_run_lines(path.read_text(encoding="utf-8"))
    ]
    assert not violations, "GitHub context in run: " + ", ".join(violations)
