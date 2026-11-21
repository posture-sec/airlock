"""Shared setup for the Appendix B regressions (task 3.9, `PRD.md` Appendix B).

The seven shapes are `scripts.bypass_probe.CASES`, and the repository builder is the probe's
`build`, so the harness that measured the old script and these tests that judge this package cannot
drift apart on what a case is. Only the scanner differs: the probe starts an external script,
these tests call `run_scan` in this process.

Every case runs in `--mode full`, because a scratch repository has no trusted base for `pr` or
`push` mode to resolve. That is the right trust model for a payload regression: the question here
is whether a shape is reported at all, not what a base commit would have allowed.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from scripts.bypass_probe import ALLOW_MARKER, CASES, Case
from tests.conftest import build_scratch_repo

from airlock.cli import run_scan
from airlock.model import Mode, ScanReport, Severity

CASE_BY_NUMBER: dict[int, Case] = {item.num: item for item in CASES}


def _case(number: int) -> Case:
    return CASE_BY_NUMBER[number]


def _scan_files(root: Path, files: dict[str, bytes], name: str) -> ScanReport:
    """Commit one shape into a scratch repository and run the real scan over it.

    `build_scratch_repo` is the shared factory: same base commit, same payload commit,
    same tracked-at-HEAD semantics as `scripts.bypass_probe.build` produced when this
    module used to call it directly. Delegating means the harness that measured the old
    script and these tests that judge this package cannot disagree about what a case is.
    """
    repo = root / name
    build_scratch_repo(repo, files)
    return run_scan(repo, Mode.FULL)


def _verdict(report: ScanReport) -> list[tuple[str, str]]:
    """Rule ids and severities, without the INFO notes about which policy source was read.

    Under `--mode full` every scan announces that the policy came from the working tree, which is
    a fact about the mode rather than about the payload. Everything at WARN or above is the
    verdict, and a case that stops producing one of these lines fails here rather than passing on
    an unrelated HIGH.
    """
    return sorted(
        (finding.rule_id, finding.severity.name)
        for finding in report.findings
        if finding.severity is not Severity.INFO
    )


def _without_marker(files: dict[str, bytes]) -> dict[str, bytes]:
    """The same files with the old script's inline allow marker removed, nothing else."""
    marker = f" // {ALLOW_MARKER} reviewed".encode()
    return {name: data.replace(marker, b"") for name, data in files.items()}


@pytest.fixture
def scan(tmp_path: Path) -> Callable[[int], ScanReport]:
    """Scan one Appendix B case in its own scratch repository."""

    def run(number: int) -> ScanReport:
        return _scan_files(tmp_path, _case(number).files, f"case-{number}")

    return run


@pytest.fixture
def scan_shape(tmp_path: Path) -> Callable[[dict[str, bytes], str], ScanReport]:
    """Scan an edited variant of a case, for the differential tests."""

    def run(files: dict[str, bytes], name: str) -> ScanReport:
        return _scan_files(tmp_path, files, name)

    return run


@pytest.fixture
def appendix_case() -> Callable[[int], Case]:
    return _case


@pytest.fixture
def verdict() -> Callable[[ScanReport], list[tuple[str, str]]]:
    return _verdict


@pytest.fixture
def strip_marker() -> Callable[[dict[str, bytes]], dict[str, bytes]]:
    return _without_marker
