"""SARIF 2.1.0 document shape, mapping and byte stability (issue #58, task 9.29).

Three properties carry the task:

1. The document has ``version``, ``$schema``, one run and a ``tool.driver`` with
   ``name``, ``version`` and ``informationUri``.
2. Each finding maps to exactly one result with the correct ``ruleId``,
   ``message.text`` and ``physicalLocation``.  A file-level finding (line 0) omits
   ``startLine``.
3. ``message.text`` never contains the evidence excerpt; a unique sentinel marker that
   must be absent is asserted.
4. Two renders of the same report are byte-identical.
5. The test fails before the change (the stub docstring has no ``render``).
"""

from __future__ import annotations

import json

from airlock.model import EXIT_FINDINGS, EXIT_PASS, Finding, Mode, ScanReport, Severity
from airlock.report import sarif

DIGEST = "sha256:" + "a" * 64
# A unique sentinel that must NOT appear in message.text — it is attacker-controlled
# evidence (AGENTS.md section 4).
EVIDENCE_SENTINEL = "SARIF_EVIDENCE_MUST_NOT_APPEAR_IN_MESSAGE_TEXT"


def _finding(
    rule_id: str = "cfg-dynamic-code",
    severity: Severity = Severity.HIGH,
    path: str = "src/index.js",
    line: int = 42,
    message: str = "remote code execution capability in a tooling config",
    evidence: str | None = EVIDENCE_SENTINEL,
    occurrence: int = 0,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        path=path,
        line=line,
        roles=("source",),
        message=message,
        evidence=evidence,
        occurrence=occurrence,
        fingerprint=DIGEST,
        suppressible=True,
    )


def _report(*findings: Finding, tool_version: str = "0.1.0") -> ScanReport:
    return ScanReport(
        tool_version=tool_version,
        mode=Mode.PR,
        repo_head="b" * 40,
        base="c" * 40,
        files_indexed=5,
        files_scanned=5,
        files_skipped={},
        findings=findings,
        exit_code=EXIT_FINDINGS if findings else EXIT_PASS,
    )


class TestDocumentEnvelope:
    def test_version_field_is_2_1_0(self) -> None:
        doc = json.loads(sarif.render(_report()))
        assert doc["version"] == "2.1.0"

    def test_schema_uri_is_present(self) -> None:
        doc = json.loads(sarif.render(_report()))
        assert doc["$schema"].startswith("https://")
        assert "sarif" in doc["$schema"]

    def test_exactly_one_run(self) -> None:
        doc = json.loads(sarif.render(_report()))
        assert len(doc["runs"]) == 1

    def test_driver_name_is_airlock(self) -> None:
        doc = json.loads(sarif.render(_report()))
        assert doc["runs"][0]["tool"]["driver"]["name"] == "airlock"

    def test_driver_version_comes_from_report(self) -> None:
        doc = json.loads(sarif.render(_report(tool_version="1.2.3")))
        assert doc["runs"][0]["tool"]["driver"]["version"] == "1.2.3"

    def test_driver_information_uri_is_present(self) -> None:
        doc = json.loads(sarif.render(_report()))
        uri = doc["runs"][0]["tool"]["driver"]["informationUri"]
        assert "posture-sec" in uri or "airlock" in uri

    def test_empty_report_has_zero_results(self) -> None:
        doc = json.loads(sarif.render(_report()))
        assert doc["runs"][0]["results"] == []


class TestResultMapping:
    def test_one_result_per_finding(self) -> None:
        report = _report(_finding(), _finding(rule_id="cfg-network", line=10))
        doc = json.loads(sarif.render(report))
        assert len(doc["runs"][0]["results"]) == 2

    def test_rule_id_matches_finding(self) -> None:
        doc = json.loads(sarif.render(_report(_finding(rule_id="cfg-dynamic-code"))))
        assert doc["runs"][0]["results"][0]["ruleId"] == "cfg-dynamic-code"

    def test_message_text_is_the_rule_message(self) -> None:
        doc = json.loads(
            sarif.render(_report(_finding(message="remote code execution capability")))
        )
        assert doc["runs"][0]["results"][0]["message"]["text"] == "remote code execution capability"

    def test_evidence_sentinel_is_absent_from_message_text(self) -> None:
        """Evidence must never reach message.text (AGENTS.md section 4)."""
        doc = json.loads(sarif.render(_report(_finding(evidence=EVIDENCE_SENTINEL))))
        result = doc["runs"][0]["results"][0]
        assert EVIDENCE_SENTINEL not in result["message"]["text"]

    def test_location_has_correct_uri(self) -> None:
        doc = json.loads(sarif.render(_report(_finding(path="lib/helpers.js"))))
        uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
            "uri"
        ]
        assert uri == "lib/helpers.js"

    def test_line_finding_carries_start_line(self) -> None:
        doc = json.loads(sarif.render(_report(_finding(line=99))))
        region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"].get("region")
        assert region is not None
        assert region["startLine"] == 99

    def test_file_level_finding_omits_start_line(self) -> None:
        """A file-level finding (line 0) must not write startLine at all."""
        doc = json.loads(sarif.render(_report(_finding(line=0))))
        phys = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert "region" not in phys

    def test_result_order_follows_findings_order(self) -> None:
        f1 = _finding(rule_id="cfg-dynamic-code", path="a.js")
        f2 = _finding(rule_id="cfg-network", path="b.js")
        doc = json.loads(sarif.render(_report(f1, f2)))
        ids = [r["ruleId"] for r in doc["runs"][0]["results"]]
        assert ids == ["cfg-dynamic-code", "cfg-network"]


class TestByteStability:
    def test_two_renders_are_byte_identical(self) -> None:
        report = _report(
            _finding(),
            _finding(rule_id="cfg-network", path="config.js", line=0),
        )
        first = sarif.render(report)
        second = sarif.render(report)
        assert first == second

    def test_output_is_valid_json(self) -> None:
        rendered = sarif.render(_report(_finding()))
        parsed = json.loads(rendered)
        assert isinstance(parsed, dict)
