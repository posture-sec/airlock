"""Issue #30: a HIGH rule must be reachable on content the repository treats as executed.

`apply_patterns` offers a rule only the entries whose resolved roles intersect the rule's `roles`
(`src/airlock/rules.py`), so a HIGH rule scoped to `doc` alone applies to no file the repository
executes. It would still pass the fixture gate, because the fixture harness builds the roles the
case names. Nothing asserted the authored roles reached anything.

The issue names `SENSITIVE_ROLES` as the set to intersect, which is the credential-attached set
`_cap_severity` uses. Six shipped HIGH rules would fail that: `wasm-unlisted` and
`wasm-hash-mismatch` on `wasm`, and the three `cargo-*` rules plus `npm-registry-bypass` on
`source`. Those are legitimate, so this file uses the set the risk is actually about, the roles
whose content is code or an artifact (`SENSITIVE_ROLES` plus `source` and `wasm`), rather than
widening `SENSITIVE_ROLES` and changing the severity of an unreadable file. `doc`, `other` and
`archive` remain the roles a HIGH rule may not be confined to.

`cfg-long-line` is the one documented exception: it is the per-file cap, authored HIGH for the
sensitive role and demoted to WARN everywhere else by `_cap_severity`.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from tests.fixtures import shipped_rules

from airlock.model import Rule, Severity
from airlock.roles import SENSITIVE_ROLES, SOURCE_ROLE, WASM_ROLE
from airlock.rules import LONG_LINE_RULE_ID

#: Roles whose content is executed, built or installed, so a finding there can gate a change.
EXECUTED_ROLES = SENSITIVE_ROLES | {SOURCE_ROLE, WASM_ROLE}


def unreachable_high_rules(rules: Iterable[Rule]) -> list[str]:
    """One line per HIGH rule confined to roles no executed content ever resolves to."""
    problems: list[str] = []
    for rule in rules:
        if rule.severity is not Severity.HIGH or rule.id == LONG_LINE_RULE_ID:
            continue
        if not EXECUTED_ROLES.intersection(rule.roles):
            problems.append(
                f"{rule.id} is HIGH but its roles {list(rule.roles)} are outside"
                f" {sorted(EXECUTED_ROLES)}, so it applies to no executed file"
            )
    return problems


class TestEveryHighRuleReachesExecutedContent:
    def test_no_high_rule_is_confined_to_prose(self) -> None:
        assert unreachable_high_rules(shipped_rules()) == []

    def test_the_check_covers_more_than_the_cap_rule(self) -> None:
        """A guard against a predicate that only ever sees the one exempt rule."""
        high = [rule for rule in shipped_rules() if rule.severity is Severity.HIGH]
        assert len(high) > 1
        assert LONG_LINE_RULE_ID in {rule.id for rule in high}

    def test_a_high_rule_scoped_to_doc_is_reported(self) -> None:
        rule = next(rule for rule in shipped_rules() if rule.severity is Severity.HIGH)
        mutated = replace(rule, roles=("doc",))
        assert unreachable_high_rules([mutated]) == [
            f"{rule.id} is HIGH but its roles ['doc'] are outside"
            f" {sorted(EXECUTED_ROLES)}, so it applies to no executed file"
        ]

    def test_the_cap_rule_is_the_only_exception(self) -> None:
        cap = next(rule for rule in shipped_rules() if rule.id == LONG_LINE_RULE_ID)
        assert unreachable_high_rules([replace(cap, roles=("doc",))]) == []
