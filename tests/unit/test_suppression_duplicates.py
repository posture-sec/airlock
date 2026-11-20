"""A duplicate suppression entry is reported, not silently ignored (issue #13).

Renewing an entry by copying it and moving the date leaves two entries for one key. The first
one keeps deciding, and the second becomes a HIGH `suppression-invalid` naming both positions.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from airlock.fingerprint import PendingFinding, number_occurrences
from airlock.model import Policy, Rule, RulePattern, RuleTests, Severity, Suppression
from airlock.policy import suppress

TODAY = date(2026, 10, 27)
RULE_ID = "cfg-dynamic-code"
PATH = "postcss.config.mjs"


def rule() -> Rule:
    return Rule(
        id=RULE_ID,
        title="Dynamic code execution in tooling config",
        roles=("tooling-config",),
        detector="pattern",
        severity=Severity.HIGH,
        suppressible=True,
        rationale="Build configs have no reason to evaluate strings.",
        pattern=RulePattern(kind="regex", value=(r"eval\(",)),
        tests=RuleTests(positive=RULE_ID, negative=RULE_ID),
    )


def finding() -> Any:
    pending = PendingFinding(
        rule_id=RULE_ID,
        severity=Severity.HIGH,
        path=PATH,
        line=7,
        roles=("tooling-config",),
        message="remote code execution capability in a tooling config",
        evidence="eval(payload)",
        suppressible=True,
    )
    return number_occurrences((pending,))[0]


def entry(
    item: Any,
    *,
    reason: str,
    expires: date | None = None,
) -> Suppression:
    return Suppression(
        rule=item.rule_id,
        path=item.path,
        fingerprint=item.fingerprint,
        reason=reason,
        expires=expires,
    )


def run(*entries: Suppression):
    item = finding()
    return suppress((item,), Policy(suppressions=entries), [rule()], today=TODAY)


def invalid(result) -> list[Any]:
    return [item for item in result.findings if item.rule_id == "suppression-invalid"]


class TestLaterEntryShadowed:
    def test_the_second_entry_is_reported_and_the_first_applies(self) -> None:
        item = finding()
        result = run(
            entry(item, reason="audited upstream"),
            entry(item, reason="renewed", expires=TODAY + timedelta(days=30)),
        )

        assert [found.suppressed_by for found in result.suppressed] == ["audited upstream"]
        reports = invalid(result)
        assert len(reports) == 1
        assert "#1" in reports[0].message
        assert "#2" in reports[0].message
        assert reports[0].severity is Severity.HIGH

    def test_the_duplicate_covers_nothing(self) -> None:
        item = finding()
        result = run(
            entry(item, reason="audited upstream"),
            entry(item, reason="duplicate", expires=TODAY + timedelta(days=30)),
        )

        assert "duplicate" not in [found.suppressed_by for found in result.suppressed]
        assert [found.suppressed_by for found in result.suppressed] == ["audited upstream"]

    def test_a_single_entry_still_behaves_as_before(self) -> None:
        item = finding()
        result = run(entry(item, reason="audited upstream"))

        assert result.findings == ()
        assert len(result.suppressed) == 1
        assert result.suppressed[0].suppressed_by == "audited upstream"


class TestEarlierExpiredEntryShadowed:
    def test_the_later_valid_entry_is_reported_and_suppresses_nothing(self) -> None:
        item = finding()
        expired = entry(item, reason="old", expires=TODAY - timedelta(days=1))
        renewed = entry(item, reason="renewed", expires=TODAY + timedelta(days=30))
        result = run(expired, renewed)

        assert [found.rule_id for found in result.findings] == [
            "suppression-invalid",
            RULE_ID,
        ]
        reports = invalid(result)
        assert len(reports) == 1
        assert "#1" in reports[0].message
        assert "#2" in reports[0].message
        assert result.suppressed == ()
