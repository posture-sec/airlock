"""Tests for suppressed findings section in step summary (issue #66)."""

from __future__ import annotations

from airlock.model import EXIT_PASS, Finding, Mode, ScanReport, Severity
from airlock.report import summary

SAMPLE_FINGERPRINT = "sha256:" + "f" * 64


def test_summary_empty_suppressed_section() -> None:
    report = ScanReport(
        tool_version="0.0.1",
        mode=Mode.FULL,
        repo_head="HEAD",
        base=None,
        files_indexed=2,
        files_scanned=2,
        files_skipped={},
        findings=(),
        suppressed=(),
        exit_code=EXIT_PASS,
    )
    rendered = summary.render(report)
    assert "## Suppressed findings" in rendered
    assert "No finding was suppressed." in rendered
    assert "| Rule | Location | Fingerprint | Reason |" not in rendered


def test_summary_suppressed_table_escapes_pipes_and_backticks() -> None:
    suppressed_finding = Finding(
        rule_id="cfg-dynamic-code",
        severity=Severity.HIGH,
        path="src/file|`bad`.js",
        line=42,
        roles=("source",),
        message="Dynamic code eval",
        evidence=None,
        occurrence=0,
        fingerprint=SAMPLE_FINGERPRINT,
        suppressible=True,
        suppressed_by="Reason with | pipe and `code` backtick",
    )
    report = ScanReport(
        tool_version="0.0.1",
        mode=Mode.FULL,
        repo_head="HEAD",
        base=None,
        files_indexed=1,
        files_scanned=1,
        files_skipped={},
        findings=(),
        suppressed=(suppressed_finding,),
        exit_code=EXIT_PASS,
    )
    rendered = summary.render(report)
    assert "## Suppressed findings" in rendered
    assert "These are suppressed and not findings." in rendered
    assert "| Rule | Location | Fingerprint | Reason |" in rendered

    # Find the row corresponding to this suppression
    table_lines = [
        line
        for line in rendered.splitlines()
        if line.startswith("|") and "cfg-dynamic-code" in line
    ]
    assert len(table_lines) == 1
    row = table_lines[0]

    # Verify that pipe and backticks in Reason are escaped
    assert r"Reason with \| pipe and \`code\` backtick" in row
    # Verify that pipe and backtick in Location are escaped
    assert r"src/file\|`bad`.js:42" in row or r"src/file\|\`bad\`.js:42" in row

    # Ensure table integrity: exactly 4 columns
    # Format: "" (before first pipe), Rule, Location, Fingerprint, Reason, "" (after trailing pipe)
    # Note that splitting on escaped pipes requires checking cell count without escaped pipes
    # When split on unescaped pipe (markdown table cell boundary), there should be 4 content cells.
    import re

    # Unescaped pipe regex
    unescaped_pipes = re.split(r"(?<!\\)\|", row)
    # Strip empty tokens at start and end
    content_cells = [c.strip() for c in unescaped_pipes if c.strip()]
    assert len(content_cells) == 4, f"Expected 4 table cells, got {content_cells}"
    assert content_cells[0] == "cfg-dynamic-code"
    assert SAMPLE_FINGERPRINT in content_cells[2]
