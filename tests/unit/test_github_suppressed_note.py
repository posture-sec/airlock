"""Tests for github suppression notice phrasing (issue #64).

The github notice must not promise a JSON file was written when running in default console mode;
it specifies '--format json' as the mechanism to inspect suppressed findings and reasons.
"""

from __future__ import annotations

import json

from airlock.model import (
    EXIT_PASS,
    Finding,
    Mode,
    ScanReport,
    Severity,
)
from airlock.report import github, jsonout

SAMPLE_FINGERPRINT = "sha256:" + "0" * 64


def test_github_notice_recommends_format_flag_not_unwritten_file() -> None:
    suppressed_finding = Finding(
        rule_id="cfg-dynamic-code",
        severity=Severity.HIGH,
        path="tests/fixture.js",
        line=10,
        roles=("source",),
        message="Dynamic code evaluation",
        evidence=None,
        occurrence=0,
        fingerprint=SAMPLE_FINGERPRINT,
        suppressible=True,
        suppressed_by="reviewed and verified",
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

    rendered = github.render(report)
    assert "--format json names each one and its reason." in rendered
    assert "the JSON output names each one" not in rendered


def test_format_json_outputs_each_suppressed_finding_and_reason() -> None:
    suppressed_finding = Finding(
        rule_id="cfg-dynamic-code",
        severity=Severity.HIGH,
        path="tests/fixture.js",
        line=10,
        roles=("source",),
        message="Dynamic code evaluation",
        evidence=None,
        occurrence=0,
        fingerprint=SAMPLE_FINGERPRINT,
        suppressible=True,
        suppressed_by="test-suppression-reason",
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

    out = json.loads(jsonout.render(report))
    assert len(out["suppressed"]) == 1
    item = out["suppressed"][0]
    assert item["rule_id"] == "cfg-dynamic-code"
    assert item["fingerprint"] == SAMPLE_FINGERPRINT
    assert item["suppressed_by"] == "test-suppression-reason"
