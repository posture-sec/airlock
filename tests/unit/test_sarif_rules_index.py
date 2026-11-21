"""SARIF tool.driver.rules array and per-result ruleIndex (issue #59, task 9.30).

Properties asserted:

1. ``tool.driver.rules`` holds one entry per distinct rule id cited by findings, in
   first-seen order, with ``id``, ``name`` and ``shortDescription.text`` set to the id.
2. Every result carries ``ruleIndex`` equal to the matching entry's position in that
   array.
3. The number of distinct entries equals the number of distinct ids, even when one rule
   fires multiple times.
4. An empty report produces an empty rules array.
5. The test fails before the change (the stub docstring has no ``render``).
"""

from __future__ import annotations

import json

from airlock.model import EXIT_FINDINGS, EXIT_PASS, Finding, Mode, ScanReport, Severity
from airlock.report import sarif

DIGEST = "sha256:" + "b" * 64


def _finding(
    rule_id: str = "cfg-dynamic-code",
    path: str = "src/index.js",
    line: int = 1,
    occurrence: int = 0,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        path=path,
        line=line,
        roles=("source",),
        message=f"finding from {rule_id}",
        evidence=None,
        occurrence=occurrence,
        fingerprint=DIGEST,
        suppressible=True,
    )


def _report(*findings: Finding) -> ScanReport:
    return ScanReport(
        tool_version="0.1.0",
        mode=Mode.PR,
        repo_head="b" * 40,
        base="c" * 40,
        files_indexed=3,
        files_scanned=3,
        files_skipped={},
        findings=findings,
        exit_code=EXIT_FINDINGS if findings else EXIT_PASS,
    )


class TestRulesArray:
    def test_empty_report_has_empty_rules_array(self) -> None:
        doc = json.loads(sarif.render(_report()))
        assert doc["runs"][0]["tool"]["driver"]["rules"] == []

    def test_one_rule_per_distinct_id(self) -> None:
        """One rule firing three times produces one entry, not three."""
        report = _report(
            _finding("cfg-dynamic-code", occurrence=0),
            _finding("cfg-dynamic-code", path="other.js", occurrence=1),
            _finding("cfg-dynamic-code", path="third.js", occurrence=2),
        )
        doc = json.loads(sarif.render(report))
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "cfg-dynamic-code"

    def test_distinct_id_count_matches_entry_count(self) -> None:
        """Two distinct ids over three findings → two entries."""
        report = _report(
            _finding("cfg-dynamic-code", occurrence=0),
            _finding("cfg-network", occurrence=0),
            _finding("cfg-dynamic-code", occurrence=1),
        )
        doc = json.loads(sarif.render(report))
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2

    def test_rule_entry_has_id_name_and_short_description(self) -> None:
        doc = json.loads(sarif.render(_report(_finding("cfg-dynamic-code"))))
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["id"] == "cfg-dynamic-code"
        assert rule["name"] == "cfg-dynamic-code"
        assert rule["shortDescription"]["text"] == "cfg-dynamic-code"

    def test_first_seen_order_is_preserved(self) -> None:
        """Rules must appear in first-appearance order over the findings."""
        report = _report(
            _finding("cfg-network"),
            _finding("cfg-dynamic-code"),
            _finding("cfg-network"),
        )
        doc = json.loads(sarif.render(report))
        ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
        assert ids == ["cfg-network", "cfg-dynamic-code"]


class TestRuleIndex:
    def test_every_result_carries_rule_index(self) -> None:
        report = _report(_finding("cfg-dynamic-code"), _finding("cfg-network"))
        doc = json.loads(sarif.render(report))
        for result in doc["runs"][0]["results"]:
            assert "ruleIndex" in result

    def test_rule_index_resolves_to_correct_rule(self) -> None:
        """ruleIndex must point at the entry for that result's ruleId."""
        report = _report(
            _finding("cfg-dynamic-code"),
            _finding("cfg-network"),
            _finding("cfg-dynamic-code"),
        )
        doc = json.loads(sarif.render(report))
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        for result in doc["runs"][0]["results"]:
            idx = result["ruleIndex"]
            assert rules[idx]["id"] == result["ruleId"], (
                f"ruleIndex {idx} resolved to {rules[idx]['id']!r}, expected {result['ruleId']!r}"
            )

    def test_multiple_results_for_same_rule_share_index(self) -> None:
        report = _report(
            _finding("cfg-dynamic-code", occurrence=0),
            _finding("cfg-dynamic-code", occurrence=1),
            _finding("cfg-dynamic-code", occurrence=2),
        )
        doc = json.loads(sarif.render(report))
        indices = {r["ruleIndex"] for r in doc["runs"][0]["results"]}
        assert indices == {0}
