"""Issue #32: `pat-invisible-unicode` must not flag ZWNJ in localized source strings.

U+200C is the zero-width non-joiner, ordinary orthography in Persian, Arabic, Urdu and Hindi.
The rule matched it, so a single localized string in a `.ts` file raised a HIGH that fails a
`fail_on = "high"` scan. The fix is removing that one code point from the class; raw text has no
masking (`AGENTS.md` 4), so a context-sensitive lookaround is not available.

What must not move with it: U+200B and U+202E are still attack shapes, still HIGH. Both halves run
through `scan`, so the assertion is about the severity a user sees rather than about a regex.
"""

from __future__ import annotations

from tests.fixtures import Case, context
from tests.fixtures.unicode_locale import (
    bidi_override_positive,
    hindi_negative,
    persian_negative,
    zero_width_space_positive,
)

from airlock.model import Finding, Severity
from airlock.runner import scan

RULE = "pat-invisible-unicode"


def findings(case: Case) -> tuple[Finding, ...]:
    return tuple(finding for finding in scan(context(case)) if finding.rule_id == RULE)


class TestZwnjIsOrthography:
    def test_a_persian_string_is_not_a_finding(self) -> None:
        assert findings(persian_negative()) == ()

    def test_a_hindi_string_is_not_a_finding(self) -> None:
        assert findings(hindi_negative()) == ()


class TestTheRuleStillBites:
    def test_a_bidi_override_is_still_high(self) -> None:
        hits = findings(bidi_override_positive())
        assert [finding.severity for finding in hits] == [Severity.HIGH]

    def test_a_zero_width_space_is_still_high(self) -> None:
        hits = findings(zero_width_space_positive())
        assert [finding.severity for finding in hits] == [Severity.HIGH]
