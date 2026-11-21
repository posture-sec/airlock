"""Annotation budget and invariant pinning tests (issue #63).

Pin the arithmetic that keeps each workflow-command level under GitHub's ten-annotation cap,
covering 0 to 12 findings per level with and without suppressions, for HIGH, WARN, and INFO.
"""

from __future__ import annotations

import pytest

from airlock.model import Finding, Mode, ScanReport, Severity
from airlock.report import github

DIGEST = "sha256:" + "a" * 64


def _finding(
    severity: Severity = Severity.HIGH,
    rule_id: str = "cfg-test",
    path: str = "test.js",
    line: int = 1,
    message: str = "test message",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        path=path,
        line=line,
        roles=("tooling-config",),
        message=message,
        evidence="test evidence",
        occurrence=0,
        fingerprint=DIGEST,
        suppressible=True,
    )


def _report(*findings: Finding, suppressed: tuple[Finding, ...] = ()) -> ScanReport:
    return ScanReport(
        tool_version="0.1.0",
        mode=Mode.PR,
        repo_head="a" * 40,
        base="b" * 40,
        files_indexed=1,
        files_scanned=1,
        files_skipped={},
        findings=findings,
        suppressed=suppressed,
        exit_code=0,
    )


COMMAND_PREFIXES = {
    Severity.HIGH: "::error ",
    Severity.WARN: "::warning ",
    Severity.INFO: "::notice ",
}

CAPS = {
    Severity.HIGH: github.HIGH_ANNOTATIONS,
    Severity.WARN: github.WARN_ANNOTATIONS,
    Severity.INFO: github.INFO_ANNOTATIONS,
}


@pytest.mark.parametrize("severity", [Severity.HIGH, Severity.WARN, Severity.INFO])
@pytest.mark.parametrize("count", list(range(13)))
@pytest.mark.parametrize("with_suppressed", [False, True])
def test_no_level_exceeds_annotations_per_level_and_withheld_notes_appear(
    severity: Severity,
    count: int,
    with_suppressed: bool,
) -> None:
    findings = tuple(
        _finding(severity=severity, rule_id=f"rule-{severity.label}-{i}", path=f"file{i}.js")
        for i in range(count)
    )
    suppressed = (_finding(rule_id="suppressed-rule"),) if with_suppressed else ()
    rep = _report(*findings, suppressed=suppressed)

    text = github.render(rep)
    lines = [line for line in text.splitlines() if line]

    errors = [item for item in lines if item.startswith("::error ")]
    warnings = [item for item in lines if item.startswith("::warning ")]
    notices = [item for item in lines if item.startswith("::notice ")]

    # Invariant: No workflow command level ever exceeds ANNOTATIONS_PER_LEVEL
    assert len(errors) <= github.ANNOTATIONS_PER_LEVEL
    assert len(warnings) <= github.ANNOTATIONS_PER_LEVEL
    assert len(notices) <= github.ANNOTATIONS_PER_LEVEL

    # Target level assertions
    prefix = COMMAND_PREFIXES[severity]
    level_lines = [item for item in lines if item.startswith(prefix)]
    cap = CAPS[severity]

    if count > cap:
        withheld = count - cap
        expected_note = f"{withheld} {severity.label.upper()} finding(s) are not annotated above"
        assert any(expected_note in item for item in level_lines), (
            f"Expected withheld note {expected_note!r} in {level_lines}"
        )
    else:
        assert not any("are not annotated above" in item for item in level_lines)

    # Suppression note always routes to ::notice
    if with_suppressed:
        assert any("hidden by the trusted airlock.toml" in item for item in notices)
    else:
        assert not any("hidden by the trusted airlock.toml" in item for item in notices)


def test_budget_fails_if_info_annotations_raised_to_nine() -> None:
    """Proves that raising INFO_ANNOTATIONS to 9 breaks the 10-line budget under suppression."""
    count = 10
    findings = tuple(
        _finding(severity=Severity.INFO, rule_id=f"info-{i}", path=f"info{i}.js")
        for i in range(count)
    )
    rep = _report(*findings, suppressed=(_finding(rule_id="suppressed-rule"),))

    # With info_cap=9 (simulating INFO_ANNOTATIONS = 9):
    # 9 findings + 1 withheld note + 1 suppression note = 11 notice lines!
    text_mutated = github.render(rep, info_cap=9)
    mutated_notices = [item for item in text_mutated.splitlines() if item.startswith("::notice ")]
    assert len(mutated_notices) == 11
    assert len(mutated_notices) > github.ANNOTATIONS_PER_LEVEL

    # Under standard budget (info_cap = 8):
    # 8 findings + 1 withheld note + 1 suppression note = 10 notice lines <= 10.
    text_standard = github.render(rep)
    standard_notices = [item for item in text_standard.splitlines() if item.startswith("::notice ")]
    assert len(standard_notices) == github.ANNOTATIONS_PER_LEVEL
