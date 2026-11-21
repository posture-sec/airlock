"""Detector-error text must not carry scanned content into the report (issue #15).

The exception's own text stays in the evidence, escaped, so it can be read without being able
to forge a second annotation or hide the HIGH above it.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from airlock import runner
from airlock.fingerprint import PendingFinding
from airlock.model import (
    EXIT_FINDINGS,
    Finding,
    Manifest,
    Mode,
    Policy,
    ScanContext,
    ScanReport,
    Severity,
)
from airlock.report import console, github, summary

# Assembled at call time so this file does not commit a payload-shaped path (`AGENTS.md` 4).
PAYLOAD_PATH = "secrets/" + "ci.yml"
FIXTURE_TEXT = f"cannot read {PAYLOAD_PATH}\n\x1b[31mforged\rsecond line"


class ReaderBoom(Exception):
    pass


def raising_detector(ctx: ScanContext) -> Iterable[PendingFinding]:
    raise ReaderBoom(FIXTURE_TEXT)


def detector_error() -> Finding:
    ctx = ScanContext(entries=(), policy=Policy(), manifest=Manifest(), rules=())
    pending = runner._run_one(raising_detector, ctx)
    assert len(pending) == 1
    return pending[0].to_finding(0)


def report(finding: Finding) -> ScanReport:
    return ScanReport(
        tool_version="0.1.0",
        mode=Mode.PR,
        repo_head="b" * 40,
        base="c" * 40,
        files_indexed=1,
        files_scanned=1,
        files_skipped={},
        findings=(finding,),
        exit_code=EXIT_FINDINGS,
    )


def assert_no_raw_control(text: str) -> None:
    assert "\x1b" not in text
    assert "\r" not in text


class TestDetectorErrorMessage:
    def test_the_message_names_only_scanner_text_and_the_type(self) -> None:
        finding = detector_error()

        assert finding.rule_id == "detector-error"
        assert finding.severity is Severity.HIGH
        assert "ReaderBoom" in finding.message
        assert "A detector raised" in finding.message

    def test_the_message_holds_no_scanned_text(self) -> None:
        finding = detector_error()

        assert PAYLOAD_PATH not in finding.message
        assert "\x1b" not in finding.message
        assert "\n" not in finding.message
        assert "\r" not in finding.message

    def test_the_exception_text_moves_to_escaped_evidence(self) -> None:
        finding = detector_error()

        assert finding.evidence is not None
        assert "ReaderBoom" in finding.evidence
        assert "\\x1b[31mforged" in finding.evidence
        assert "\\rsecond line" in finding.evidence
        assert "\\n" in finding.evidence
        assert_no_raw_control(finding.evidence)


class TestReportersDoNotRenderRawControls:
    def test_the_annotation_holds_no_raw_control_character(self) -> None:
        text = github.render(report(detector_error()))

        assert ":error" in text
        assert_no_raw_control(text)
        assert PAYLOAD_PATH not in text

    def test_the_step_summary_holds_no_raw_control_character(self) -> None:
        text = summary.render(report(detector_error()))

        assert "detector-error" in text
        assert_no_raw_control(text)
        # The quoted text is allowed in the fenced evidence block, escaped there as well.
        assert "\\x1b[31mforged" in text

    def test_the_console_report_holds_no_raw_control_character(self) -> None:
        text = console.render(report(detector_error()))

        assert_no_raw_control(text)
        assert PAYLOAD_PATH not in text.replace("\n", "")


def test_collect_reports_the_error_once_per_raising_detector(monkeypatch: Any) -> None:
    monkeypatch.setattr(runner, "DETECTORS", (raising_detector,))
    ctx = ScanContext(entries=(), policy=Policy(), manifest=Manifest(), rules=())

    pending = runner.collect(ctx)

    assert [item.rule_id for item in pending] == ["detector-error"]
