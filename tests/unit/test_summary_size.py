"""The step summary stays under the 1 MiB upload ceiling (issue #67).

`ARCHITECTURE.md` 6.6 records that GitHub aborts a step-summary upload above 1 MiB without
failing the step. These tests pin the renderer's own budget: evidence is cut before rows, the
document says what it withheld, and the counts and mode lines are never cut.
"""

from __future__ import annotations

from airlock.model import Finding, Mode, ScanReport, Severity
from airlock.report import summary

DIGEST = "sha256:" + "a" * 64
EVIDENCE = "evidence line that is long enough to add up " * 6


def _finding(index: int, evidence: str | None) -> Finding:
    return Finding(
        rule_id="cfg-test",
        severity=Severity.HIGH,
        path="test.js",
        line=index + 1,
        roles=("tooling-config",),
        message="a short message",
        evidence=evidence,
        occurrence=0,
        fingerprint=DIGEST,
        suppressible=True,
    )


def _report(findings: list[Finding]) -> ScanReport:
    return ScanReport(
        tool_version="0.1.0",
        mode=Mode.PR,
        repo_head="a" * 40,
        base="b" * 40,
        files_indexed=1,
        files_scanned=1,
        files_skipped={},
        findings=tuple(findings),
        exit_code=1,
    )


def test_a_large_summary_stays_under_the_byte_budget() -> None:
    findings = [_finding(i, EVIDENCE) for i in range(8000)]
    text = summary.render(_report(findings))
    assert len(text.encode("utf-8")) <= summary.SUMMARY_BUDGET_BYTES


def test_evidence_is_cut_before_finding_rows() -> None:
    findings = [_finding(i, EVIDENCE) for i in range(8000)]
    text = summary.render(_report(findings))
    assert text.count("| HIGH |") == len(findings), "every row survives while evidence is cut"
    assert "0 finding row(s)" in text
    assert "and 0 evidence block(s)" not in text


def test_rows_are_cut_once_no_evidence_is_left() -> None:
    findings = [_finding(i, None) for i in range(20000)]
    text = summary.render(_report(findings))
    assert len(text.encode("utf-8")) <= summary.SUMMARY_BUDGET_BYTES
    assert text.count("| HIGH |") < len(findings)
    assert "finding row(s)" in text
    assert "0 finding row(s)" not in text


def test_the_counts_and_mode_lines_survive_truncation() -> None:
    findings = [_finding(i, None) for i in range(20000)]
    text = summary.render(_report(findings))
    assert "20000 HIGH" in text
    assert "Mode `pr` · exit 1" in text
    assert text.rstrip().endswith("airlock 0.1.0")


def test_the_notice_names_what_was_withheld() -> None:
    findings = [_finding(i, EVIDENCE) for i in range(8000)]
    text = summary.render(_report(findings))
    assert "Withheld to stay under the step-summary limit:" in text
    assert "The counts above are complete" in text


def test_a_summary_under_the_budget_is_unchanged() -> None:
    findings = [_finding(0, "one line")]
    text = summary.render(_report(findings))
    assert "Withheld" not in text
    assert len(text.encode("utf-8")) < summary.SUMMARY_BUDGET_BYTES
