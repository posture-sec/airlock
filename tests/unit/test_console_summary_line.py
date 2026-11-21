"""Console summary line format tests (issue #62).

The console summary line must name the mode, the base as a short SHA or none when absent,
the exit code, and the tool version, while preserving existing severity counts, files scanned,
and skip accounting in the same order and wording.
"""

from __future__ import annotations

from airlock.model import EXIT_FINDINGS, EXIT_PASS, Finding, Mode, ScanReport
from airlock.report import console


def _make_report(
    *findings: Finding,
    mode: Mode = Mode.FULL,
    base: str | None = None,
    exit_code: int = EXIT_PASS,
    tool_version: str = "0.1.0",
    files_indexed: int | None = None,
    files_scanned: int = 12,
    files_skipped: dict[str, int] | None = None,
    suppressed: tuple[Finding, ...] = (),
) -> ScanReport:
    skipped = files_skipped or {}
    if files_indexed is None:
        files_indexed = files_scanned + sum(skipped.values())
    return ScanReport(
        tool_version=tool_version,
        mode=mode,
        repo_head="a" * 40,
        base=base,
        files_indexed=files_indexed,
        files_scanned=files_scanned,
        files_skipped=skipped,
        findings=findings,
        suppressed=suppressed,
        exit_code=exit_code,
    )


def test_summary_line_for_full_run_with_no_base() -> None:
    rep = _make_report(
        mode=Mode.FULL,
        base=None,
        exit_code=EXIT_PASS,
        tool_version="0.1.0",
        files_scanned=10,
    )
    line = console.summary_line(rep)

    expected_prefix = "airlock: 0 HIGH · 0 WARN · 0 INFO · 10 file(s) scanned, nothing skipped"
    assert line.startswith(expected_prefix)
    assert "mode full" in line
    assert "base none" in line
    assert "exit 0" in line
    assert "airlock 0.1.0" in line


def test_summary_line_for_pr_run_with_base_shortens_sha_to_seven_chars() -> None:
    full_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4"
    rep = _make_report(
        mode=Mode.PR,
        base=full_sha,
        exit_code=EXIT_FINDINGS,
        tool_version="0.2.0",
        files_scanned=5,
        files_skipped={"skipped-oversize": 2},
    )
    line = console.summary_line(rep)

    assert "5 file(s) scanned, 2 skipped-oversize" in line
    assert "mode pr" in line
    assert "base e3b0c44" in line
    assert full_sha not in line
    assert "exit 1" in line
    assert "airlock 0.2.0" in line


def test_summary_line_for_report_with_base_none_in_pr_mode() -> None:
    rep = _make_report(
        mode=Mode.PR,
        base=None,
        exit_code=EXIT_PASS,
        tool_version="0.1.0",
    )
    line = console.summary_line(rep)

    assert "mode pr" in line
    assert "base none" in line
    assert "exit 0" in line
    assert "airlock 0.1.0" in line


def test_summary_line_is_single_line_and_flattens_dynamic_text() -> None:
    rep = _make_report(
        mode=Mode.PR,
        base="abc\ndef\r\n12345",
        tool_version="0.1.0\nbeta",
    )
    line = console.summary_line(rep)

    assert "\n" not in line
    assert "\r" not in line
    assert "base abc def" in line
