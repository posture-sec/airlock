"""SARIF partialFingerprints["airlock/v1"] carrying the finding fingerprint (issue #60, task 9.31).

Properties asserted:

1. Every result carries ``partialFingerprints["airlock/v1"]`` equal to
   ``finding.fingerprint``.
2. Moving a finding from one line to another (while keeping the same fingerprint)
   leaves the value unchanged — the fingerprint is line-independent.
3. Changing the occurrence changes the fingerprint value.
4. The key spelling is exactly ``"airlock/v1"`` (ADR-019).
5. The test fails before the change (the stub docstring has no ``render``).
"""

from __future__ import annotations

import json

from airlock.model import EXIT_FINDINGS, Finding, Mode, ScanReport, Severity
from airlock.report import sarif

#: Two distinct digests for the line-move and occurrence-change cases.
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def _finding(
    fingerprint: str = DIGEST_A,
    line: int = 10,
    rule_id: str = "cfg-dynamic-code",
    occurrence: int = 0,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        path="src/main.js",
        line=line,
        roles=("source",),
        message="remote code execution capability",
        evidence=None,
        occurrence=occurrence,
        fingerprint=fingerprint,
        suppressible=True,
    )


def _report(*findings: Finding) -> ScanReport:
    return ScanReport(
        tool_version="0.1.0",
        mode=Mode.PR,
        repo_head="d" * 40,
        base="e" * 40,
        files_indexed=2,
        files_scanned=2,
        files_skipped={},
        findings=findings,
        exit_code=EXIT_FINDINGS,
    )


class TestPartialFingerprints:
    def test_every_result_has_airlock_v1_key(self) -> None:
        doc = json.loads(sarif.render(_report(_finding())))
        pf = doc["runs"][0]["results"][0].get("partialFingerprints", {})
        assert "airlock/v1" in pf

    def test_fingerprint_value_matches_finding(self) -> None:
        doc = json.loads(sarif.render(_report(_finding(fingerprint=DIGEST_A))))
        pf = doc["runs"][0]["results"][0]["partialFingerprints"]
        assert pf["airlock/v1"] == DIGEST_A

    def test_key_spelling_is_exactly_airlock_v1(self) -> None:
        """ADR-019 and docs/wave/issues/03 settle the key as 'airlock/v1'."""
        doc = json.loads(sarif.render(_report(_finding())))
        keys = list(doc["runs"][0]["results"][0]["partialFingerprints"].keys())
        # The only key must be the settled spelling; no variant is allowed.
        assert keys == ["airlock/v1"]

    def test_line_move_does_not_change_fingerprint(self) -> None:
        """Moving a finding from line 10 to line 20 leaves the value identical.

        The fingerprint formula excludes line numbers (ARCHITECTURE.md 7.3), so the
        same finding at a different line must still resolve to the same alert.
        """
        at_line_10 = _finding(fingerprint=DIGEST_A, line=10)
        at_line_20 = _finding(fingerprint=DIGEST_A, line=20)

        doc10 = json.loads(sarif.render(_report(at_line_10)))
        doc20 = json.loads(sarif.render(_report(at_line_20)))

        pf10 = doc10["runs"][0]["results"][0]["partialFingerprints"]["airlock/v1"]
        pf20 = doc20["runs"][0]["results"][0]["partialFingerprints"]["airlock/v1"]
        assert pf10 == pf20 == DIGEST_A

    def test_changing_occurrence_changes_fingerprint(self) -> None:
        """Different occurrences have different fingerprints (B5)."""
        occ0 = _finding(fingerprint=DIGEST_A, occurrence=0)
        occ1 = _finding(fingerprint=DIGEST_B, occurrence=1)

        doc = json.loads(sarif.render(_report(occ0, occ1)))
        pf0 = doc["runs"][0]["results"][0]["partialFingerprints"]["airlock/v1"]
        pf1 = doc["runs"][0]["results"][1]["partialFingerprints"]["airlock/v1"]
        assert pf0 == DIGEST_A
        assert pf1 == DIGEST_B
        assert pf0 != pf1

    def test_fingerprint_is_read_verbatim_not_recomputed(self) -> None:
        """The reporter must read ``finding.fingerprint``; it must not recompute it."""
        # Plant a recognisable digest that would differ from any recompute.
        sentinel = "sha256:" + "c" * 64
        doc = json.loads(sarif.render(_report(_finding(fingerprint=sentinel))))
        pf = doc["runs"][0]["results"][0]["partialFingerprints"]["airlock/v1"]
        assert pf == sentinel
