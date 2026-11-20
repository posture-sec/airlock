"""Suppression application tests (task 2.8, `ARCHITECTURE.md` 7.6).

`suppress` runs after numbering, so these build real `Finding` objects through
`number_occurrences` instead of hand-writing fingerprints: the property under test is that an
entry matches the digest the scanner actually produced, which a fabricated one would not prove.
"""

from __future__ import annotations

from datetime import date

import pytest
from tests.fixtures import assemble

from airlock.fingerprint import PendingFinding, number_occurrences
from airlock.model import (
    STATE_RULE_IDS,
    SUPPRESSION_EXPIRY_DAYS,
    Policy,
    Rule,
    RulePattern,
    RuleTests,
    Severity,
    Suppression,
)
from airlock.policy import (
    POLICY_FILENAME,
    Suppressed,
    suppress,
)

CONFIG = "postcss.config.mjs"
OTHER_CONFIG = "next.config.mjs"
PAYLOAD = f"{assemble('ev', 'al')}({assemble('Buf', 'fer.from')}(process.env.P, 'base64'))"
TODAY = date(2026, 10, 27)

DYNAMIC = "cfg-dynamic-code"
ORPHANED = "cfg-renamed-away"
WARNER = "cfg-long-line-literal"


def rule(rule_id: str = DYNAMIC, *, suppressible: bool = True) -> Rule:
    return Rule(
        id=rule_id,
        title="Dynamic code execution in tooling config",
        roles=("tooling-config",),
        detector="pattern",
        severity=Severity.HIGH,
        suppressible=suppressible,
        rationale="Build configs have no reason to evaluate strings.",
        pattern=RulePattern(kind="regex", value=(r"eval\(",)),
        tests=RuleTests(positive=rule_id, negative=rule_id),
    )


def pending(
    *,
    rule_id: str = DYNAMIC,
    path: str = CONFIG,
    line: int = 7,
    severity: Severity = Severity.HIGH,
    evidence: str | None = PAYLOAD,
    message: str = "remote code execution capability in a tooling config",
    suppressible: bool = True,
) -> PendingFinding:
    return PendingFinding(
        rule_id=rule_id,
        severity=severity,
        path=path,
        line=line,
        roles=("tooling-config",),
        message=message,
        evidence=evidence,
        suppressible=suppressible,
    )


def entry_for(item: PendingFinding, reason: str = "audited upstream", **kwargs: object):
    """An entry aimed at exactly one finding, the way a policy author writes one."""
    return Suppression(
        rule=item.rule_id,
        path=item.path,
        fingerprint=item.to_finding(0).fingerprint,
        reason=reason,
        **kwargs,
    )


def entry(rule_id: str, path: str, digest: str, **kwargs: object) -> Suppression:
    return Suppression(rule=rule_id, path=path, fingerprint=digest, reason="audited", **kwargs)


def digest_of(letter: str) -> str:
    return "sha256:" + letter * 64


def policy_with(*entries: Suppression) -> Policy:
    return Policy(suppressions=entries)


def run(
    *items: PendingFinding,
    policy: Policy,
    rules: list[Rule] | None = None,
    **kwargs: object,
) -> Suppressed:
    return suppress(
        tuple(number_occurrences(items)),
        policy,
        [rule()] if rules is None else rules,
        today=TODAY,
        **kwargs,
    )


def ids(result: Suppressed) -> list[str]:
    return [finding.rule_id for finding in result.findings]


def only(result: Suppressed, rule_id: str):
    matches = [item for item in result.findings if item.rule_id == rule_id]
    assert len(matches) == 1, f"expected one {rule_id} in {ids(result)}"
    return matches[0]


class TestMatching:
    def test_a_matching_entry_covers_the_finding(self) -> None:
        item = pending()
        result = run(item, policy=policy_with(entry_for(item)))

        assert result.findings == ()
        assert len(result.suppressed) == 1

    def test_the_reason_travels_with_the_suppressed_finding(self) -> None:
        """The finding is hidden, not deleted: a reader has to see why it is missing."""
        item = pending()
        result = run(item, policy=policy_with(entry_for(item, reason="vendored by ops")))

        assert result.suppressed[0].suppressed_by == "vendored by ops"
        assert result.suppressed[0].fingerprint == item.to_finding(0).fingerprint

    def test_a_different_rule_does_not_suppress(self) -> None:
        item = pending()
        result = run(
            item,
            policy=policy_with(entry(WARNER, CONFIG, item.to_finding(0).fingerprint)),
            rules=[rule(), rule(WARNER)],
        )

        assert len(result.findings) == 1
        assert result.suppressed == ()

    def test_a_different_path_does_not_suppress(self) -> None:
        item = pending()
        result = run(
            item, policy=policy_with(entry(DYNAMIC, OTHER_CONFIG, item.to_finding(0).fingerprint))
        )

        assert [finding.path for finding in result.findings] == [CONFIG]
        assert result.suppressed == ()

    def test_a_different_fingerprint_does_not_suppress(self) -> None:
        item = pending()
        result = run(item, policy=policy_with(entry(DYNAMIC, CONFIG, digest_of("1"))))

        assert len(result.findings) == 1
        assert result.suppressed == ()

    def test_a_suppressed_line_that_moved_stays_suppressed(self) -> None:
        """Line numbers sit outside the fingerprint, so a rebase above the line keeps the entry."""
        result = run(pending(line=91), policy=policy_with(entry_for(pending(line=7))))

        assert result.findings == ()
        assert result.suppressed[0].line == 91

    def test_a_different_evidence_on_the_same_line_is_not_covered(self) -> None:
        result = run(
            pending(evidence="new Function(input)"),
            policy=policy_with(entry_for(pending())),
        )

        assert len(result.findings) == 1
        assert result.suppressed == ()

    def test_the_first_entry_wins_when_two_cover_one_fingerprint(self) -> None:
        """The second entry is a duplicate, so it is reported instead of quietly dropped."""
        item = pending()
        result = run(
            item,
            policy=policy_with(
                entry_for(item, reason="first entry"), entry_for(item, reason="second entry")
            ),
        )

        assert len(result.suppressed) == 1
        assert result.suppressed[0].suppressed_by == "first entry"
        assert ids(result) == ["suppression-invalid"]


class TestOccurrences:
    def test_B5_a_second_copy_of_a_suppressed_line_is_reported(self) -> None:
        """Identical evidence at occurrence 1 has its own fingerprint, so it is not covered."""
        first = pending(line=7)
        second = pending(line=12)
        result = run(first, second, policy=policy_with(entry_for(first)))

        assert len(result.findings) == 1
        assert result.findings[0].occurrence == 1
        assert result.suppressed[0].occurrence == 0

    def test_each_copy_needs_its_own_entry(self) -> None:
        first = pending(line=7)
        second = pending(line=12)
        result = run(
            first,
            second,
            policy=policy_with(
                entry_for(first),
                entry(DYNAMIC, CONFIG, second.to_finding(1).fingerprint),
            ),
        )

        assert result.findings == ()
        assert len(result.suppressed) == 2

    def test_deleting_the_first_copy_returns_the_later_suppression(self) -> None:
        """Numbering shifts when a duplicate goes away, so the entry stops applying. Fail closed."""
        survivor = pending(line=12)
        covered = entry(DYNAMIC, CONFIG, survivor.to_finding(1).fingerprint)

        both = run(pending(line=7), survivor, policy=policy_with(covered))
        assert len(both.findings) == 1
        assert len(both.suppressed) == 1

        alone = run(survivor, policy=policy_with(covered))
        assert len(alone.findings) == 1
        assert alone.suppressed == ()

    def test_occurrences_are_counted_per_rule_as_well_as_per_path(self) -> None:
        """Two rules on one line have different fingerprints, so one entry covers neither."""
        dynamic = pending(line=7)
        other = pending(rule_id=WARNER, line=7, severity=Severity.WARN)
        result = run(
            dynamic,
            other,
            policy=policy_with(entry_for(dynamic)),
            rules=[rule(), rule(WARNER)],
        )

        assert len(result.findings) == 1
        assert result.findings[0].rule_id == WARNER


class TestInvalidEntries:
    @pytest.mark.parametrize("rule_id", sorted(STATE_RULE_IDS))
    @pytest.mark.parametrize("loaded", [False, True])
    def test_state_membership_overrides_a_loaded_suppressible_rule(
        self, rule_id: str, loaded: bool
    ) -> None:
        item = pending(rule_id=rule_id)
        result = run(
            item,
            policy=policy_with(entry_for(item)),
            rules=[rule(rule_id, suppressible=True)] if loaded else [],
        )

        assert result.suppressed == ()
        assert item.to_finding(0) in result.findings
        invalid = next(f for f in result.findings if f.path == POLICY_FILENAME)
        assert invalid.rule_id == "suppression-invalid"
        assert invalid.severity is Severity.HIGH
        assert invalid.suppressible is False
        assert "scanner-state" in invalid.message

    def test_an_entry_on_a_non_suppressible_rule_is_high(self) -> None:
        item = pending()
        result = run(
            item,
            policy=policy_with(entry_for(item)),
            rules=[rule(suppressible=False)],
        )

        invalid = only(result, "suppression-invalid")
        assert invalid.severity is Severity.HIGH
        assert "is not suppressible" in invalid.message
        assert len(result.findings) == 2
        assert result.suppressed == ()

    def test_an_entry_on_an_unknown_rule_is_high(self) -> None:
        item = pending()
        result = run(
            item, policy=policy_with(entry(ORPHANED, CONFIG, item.to_finding(0).fingerprint))
        )

        assert "no rule with that id" in only(result, "suppression-invalid").message

    def test_an_entry_naming_a_state_rule_is_high(self) -> None:
        item = pending()
        result = run(
            item,
            policy=policy_with(entry("history-rewritten", CONFIG, item.to_finding(0).fingerprint)),
        )

        assert "scanner-state" in only(result, "suppression-invalid").message

    def test_an_invalid_entry_is_reported_even_when_it_matched_nothing(self) -> None:
        """Validity is checked against the rule data, not against this scan's findings."""
        result = run(policy=policy_with(entry(ORPHANED, CONFIG, digest_of("2"))))

        assert ids(result) == ["suppression-invalid"]

    def test_the_invalid_finding_points_at_the_policy_file(self) -> None:
        item = pending()
        result = run(item, policy=policy_with(entry_for(item)), rules=[rule(suppressible=False)])

        assert only(result, "suppression-invalid").path == POLICY_FILENAME

    def test_a_custom_policy_path_is_named_in_the_message(self) -> None:
        item = pending()
        result = run(
            item,
            policy=policy_with(entry(ORPHANED, CONFIG, item.to_finding(0).fingerprint)),
            policy_path="ops/airlock.toml",
        )

        invalid = only(result, "suppression-invalid")
        assert invalid.path == "ops/airlock.toml"
        assert invalid.message.startswith("ops/airlock.toml")

    def test_a_state_finding_cannot_be_hidden_by_a_matching_entry(self) -> None:
        """State findings are suppressible=False, so they stay reported whatever the policy says."""
        state = pending(rule_id="policy-changed", severity=Severity.WARN, suppressible=False)
        result = run(
            state,
            policy=policy_with(entry_for(state)),
            rules=[rule("policy-changed", suppressible=False)],
        )

        assert len(result.findings) == 2
        assert result.suppressed == ()

    def test_two_invalid_entries_are_two_findings(self) -> None:
        result = run(
            policy=policy_with(
                entry(ORPHANED, CONFIG, digest_of("4")),
                entry("history-rewritten", CONFIG, digest_of("5")),
            )
        )

        assert len(result.findings) == 2
        assert all(finding.rule_id == "suppression-invalid" for finding in result.findings)


class TestExpiry:
    def test_an_expired_entry_lets_the_finding_back_out(self) -> None:
        """B10: the returning finding is the signal, so nothing extra is said about the date."""
        result = run(
            pending(), policy=policy_with(entry_for(pending(), expires=date(2026, 10, 26)))
        )

        assert len(result.findings) == 1
        assert result.suppressed == ()
        assert "suppression-expiring" not in ids(result)

    def test_an_entry_expiring_today_still_covers(self) -> None:
        item = pending()
        result = run(item, policy=policy_with(entry_for(item, expires=TODAY)))

        assert len(result.suppressed) == 1
        assert only(result, "suppression-expiring").severity is Severity.WARN

    def test_a_boundary_entry_is_warned_about_once_and_not_duplicated(self) -> None:
        item = pending()
        result = run(item, policy=policy_with(entry_for(item, expires=TODAY)))

        assert "expires today" in only(result, "suppression-expiring").message
        assert len(result.findings) == 1

    @pytest.mark.parametrize("days_ahead", [1, SUPPRESSION_EXPIRY_DAYS])
    def test_the_warning_window_is_inclusive(self, days_ahead: int) -> None:
        item = pending()
        later = date.fromordinal(TODAY.toordinal() + days_ahead)
        result = run(item, policy=policy_with(entry_for(item, expires=later)))

        assert f"expires in {days_ahead} day(s)" in only(result, "suppression-expiring").message
        assert len(result.suppressed) == 1

    def test_past_the_window_there_is_no_warning(self) -> None:
        item = pending()
        later = date.fromordinal(TODAY.toordinal() + SUPPRESSION_EXPIRY_DAYS + 1)
        result = run(item, policy=policy_with(entry_for(item, expires=later)))

        assert result.findings == ()
        assert "suppression-expiring" not in ids(result)

    def test_an_entry_without_an_expiry_never_warns(self) -> None:
        item = pending()
        result = run(item, policy=policy_with(entry_for(item)))

        assert "suppression-expiring" not in ids(result)

    def test_a_lapsing_entry_warns_even_when_it_matched_nothing(self) -> None:
        later = date.fromordinal(TODAY.toordinal() + 3)
        result = run(policy=policy_with(entry(DYNAMIC, CONFIG, digest_of("3"), expires=later)))

        assert ids(result) == ["suppression-expiring"]

    def test_the_clock_is_injected_so_results_are_reproducible(self) -> None:
        item = pending()
        policy = policy_with(entry_for(item, expires=date(2000, 1, 1)))
        findings = tuple(number_occurrences([item]))

        lapsed = suppress(findings, policy, [rule()], today=TODAY)
        assert len(lapsed.findings) == 1
        assert lapsed.suppressed == ()

        backdated = suppress(findings, policy, [rule()], today=date(1999, 12, 31))
        assert len(backdated.suppressed) == 1
        assert ids(backdated) == ["suppression-expiring"]

    def test_without_a_supplied_day_the_scan_uses_today_in_utc(self) -> None:
        item = pending()
        # An entry that expired before this UTC date has to stop applying without any injection.
        findings = tuple(number_occurrences([item]))
        result = suppress(
            findings, policy_with(entry_for(item, expires=date(2000, 1, 1))), [rule()]
        )

        assert len(result.findings) == 1


class TestOrdering:
    def test_state_findings_sort_above_the_returned_warn(self) -> None:
        dynamic = pending(line=7)
        warning = pending(rule_id=WARNER, line=3, severity=Severity.WARN)
        result = run(
            dynamic,
            warning,
            policy=policy_with(entry(ORPHANED, CONFIG, digest_of("6"))),
            rules=[rule(), rule(WARNER)],
        )

        assert [finding.severity for finding in result.findings] == [
            Severity.HIGH,
            Severity.HIGH,
            Severity.WARN,
        ]

    def test_suppressed_findings_come_back_in_report_order(self) -> None:
        items = [pending(line=line) for line in (9, 1, 5)]
        entries = [
            entry(DYNAMIC, CONFIG, item.to_finding(occurrence).fingerprint)
            for occurrence, item in enumerate(sorted(items, key=lambda f: f.line))
        ]
        result = run(*items, policy=policy_with(*entries))

        assert len(result.suppressed) == 3
        assert [finding.line for finding in result.suppressed] == [1, 5, 9]

    def test_no_findings_and_no_entries_is_an_empty_result(self) -> None:
        result = run(policy=Policy())

        assert result.findings == ()
        assert result.suppressed == ()
