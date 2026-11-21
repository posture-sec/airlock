"""JSON reporter (task 2.9, `ARCHITECTURE.md` 6.6).

The whole `ScanReport`, including every suppressed finding with the reason that hid it, so a
consumer can diff one run against the next without reading a log. Keys are sorted and severities
are written as labels rather than ints, because the bytes have to be stable for a golden test and
readable for a human holding the file.

`evidence` stays a string or null: it is attacker-controlled text, and it is the one field a
consumer must not render as markup.
"""

from __future__ import annotations

import json

from ..model import Finding, ScanReport

SCHEMA_VERSION: int = 1


def finding_to_dict(finding: Finding) -> dict[str, object]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.label,
        "path": finding.path,
        "line": finding.line,
        "roles": list(finding.roles),
        "message": finding.message,
        "evidence": finding.evidence,
        "occurrence": finding.occurrence,
        "fingerprint": finding.fingerprint,
        "suppressible": finding.suppressible,
        "suppressed_by": finding.suppressed_by,
    }


def to_dict(report: ScanReport) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": report.tool_version,
        "mode": report.mode.value,
        "repo_head": report.repo_head,
        "base": report.base,
        "files_indexed": report.files_indexed,
        "files_scanned": report.files_scanned,
        "files_skipped": dict(sorted(report.files_skipped.items())),
        "exit_code": report.exit_code,
        "findings": [finding_to_dict(finding) for finding in report.findings],
        "suppressed": [finding_to_dict(finding) for finding in report.suppressed],
    }


def render(report: ScanReport) -> str:
    return json.dumps(to_dict(report), indent=2, sort_keys=True) + "\n"
