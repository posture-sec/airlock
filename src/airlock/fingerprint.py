"""Occurrence-aware fingerprints and the finding factory detectors use.

Formula (`ARCHITECTURE.md` 7.3):

    sha256(rule_id \\0 path \\0 normalized_evidence \\0 occurrence)

When any field contains a NUL the four fields are length-prefixed behind a leading NUL
marker instead, because a `\0` join cannot tell an embedded NUL from a separator.

Line numbers stay out, so an edit above a suppressed line does not invalidate the
suppression. `occurrence` is the zero-based index of identical evidence, which is what
makes a second copy of a suppressed line a new, unsuppressed finding (B5). When an earlier
duplicate is deleted the indices shift and the suppression stops applying: that fails
closed, which is the direction the hard rules require.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass

from .model import FINGERPRINT_PREFIX, MAX_EVIDENCE_CHARS, Finding, Severity

_WS_RE = re.compile(r"\s+")

# A NUL-free payload starts with `rule_id`, which is kebab-case and therefore begins with a
# letter. A leading NUL can only be this marker, so the two encodings never collide (7.3).
_LENGTH_PREFIX_MARKER = b"\x00"
_FIELD_LENGTH_BYTES = 8

# Grouping key for occurrence counting. Scoped to a rule as well as a path and evidence, so
# suppressing one rule's finding cannot silently suppress a different rule on the same line.
OccurrenceKey = tuple[str, str, str]


def normalize_evidence(text: str | None) -> str:
    """Outer whitespace stripped, internal runs collapsed to one space."""
    if text is None:
        return ""
    return _WS_RE.sub(" ", text.strip())


def truncate_evidence(text: str | None) -> str | None:
    """Cap the excerpt before it is stored, since it is attacker-controlled text."""
    if text is None:
        return None
    cleaned = text.strip("\r\n")
    if len(cleaned) <= MAX_EVIDENCE_CHARS:
        return cleaned
    return cleaned[:MAX_EVIDENCE_CHARS] + "..."


def _payload(rule_id: str, path: str, evidence_key: str, occurrence: int) -> bytes:
    """The bytes that are hashed. NUL-free fields keep the published `\0` join.

    Evidence is attacker-controlled and can contain a NUL, which would blur the boundary
    between two fields. When any field contains one, every field is length-prefixed behind
    a marker byte instead, so the encoding stays injective. A NUL-free quadruple is byte
    identical to the original formula, so existing suppressions keep matching.
    """
    fields = (rule_id, path, evidence_key, str(occurrence))
    encoded = [field.encode("utf-8", errors="replace") for field in fields]
    if not any(b"\x00" in field for field in encoded):
        return b"\x00".join(encoded)
    return _LENGTH_PREFIX_MARKER + b"".join(
        len(field).to_bytes(_FIELD_LENGTH_BYTES, "big") + field for field in encoded
    )


def fingerprint(rule_id: str, path: str, evidence_key: str, occurrence: int) -> str:
    digest = hashlib.sha256(_payload(rule_id, path, evidence_key, occurrence)).hexdigest()
    return FINGERPRINT_PREFIX + digest


@dataclass(frozen=True, slots=True)
class PendingFinding:
    """A finding before occurrence numbering. Detectors emit these; the runner finalizes them.

    A detector cannot know the occurrence index, because it is relative to every other
    finding in the file, including those from other rules.
    """

    rule_id: str
    severity: Severity
    path: str
    line: int
    roles: tuple[str, ...]
    message: str
    evidence: str | None
    suppressible: bool
    file_sha256: str | None = None

    def evidence_key(self) -> str:
        """File-level findings (line 0) hash on the file, not on a line of text.

        A state finding has neither: the file was skipped, is the repository itself, or is a
        policy file that was read from a ref rather than collected. It keys on its message,
        which is written by the scanner and never by scanned content, and every state rule is
        non-suppressible, so a reworded message cannot move an owner's suppression. When even
        the message is blank it keys on the rule, path and line rather than failing the scan.
        """
        if self.evidence is not None:
            return normalize_evidence(self.evidence)
        if self.file_sha256 is None:
            if not self.message.strip():
                # A detector bug can produce a finding with nothing to key on. Raising here hides
                # every other finding behind the CLI's exit 2, so key on what the scanner already
                # knows. Rule, path and line are scanner-side data, and the rule is
                # non-suppressible, so the line number in this one key cannot move a suppression.
                # The prefix keeps this branch clear of the two above: a 64-hex file digest has no
                # `state:` form, and a message could only collide by spelling this same key for the
                # same rule and path, where both findings already share an occurrence counter.
                return f"state:{self.rule_id}:{self.path}:{self.line}"
            return normalize_evidence(self.message)
        return self.file_sha256

    def with_evidence(self, evidence: str | None) -> PendingFinding:
        """Return a copy carrying a different excerpt, keeping the finding immutable."""
        return PendingFinding(
            rule_id=self.rule_id,
            severity=self.severity,
            path=self.path,
            line=self.line,
            roles=self.roles,
            message=self.message,
            evidence=truncate_evidence(evidence),
            suppressible=self.suppressible,
            file_sha256=self.file_sha256,
        )

    def to_finding(self, occurrence: int) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            path=self.path,
            line=self.line,
            roles=self.roles,
            message=self.message,
            evidence=self.evidence,
            occurrence=occurrence,
            fingerprint=fingerprint(self.rule_id, self.path, self.evidence_key(), occurrence),
            suppressible=self.suppressible,
        )


def number_occurrences(pending: Iterable[PendingFinding]) -> list[Finding]:
    """Assign occurrence indices deterministically, then return findings in report order.

    Numbering walks a stable sort by path, line, rule and evidence, so the same set of
    findings always produces the same fingerprints regardless of detector order.
    """
    ordered = sorted(
        pending,
        key=lambda item: (item.path, item.line, item.rule_id, item.evidence_key()),
    )
    counters: dict[OccurrenceKey, int] = {}
    findings: list[Finding] = []
    for item in ordered:
        key: OccurrenceKey = (item.rule_id, item.path, item.evidence_key())
        occurrence = counters.get(key, 0)
        counters[key] = occurrence + 1
        findings.append(item.to_finding(occurrence))
    return sorted(findings, key=lambda finding: finding.sort_key)
