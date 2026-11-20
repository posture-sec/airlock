"""SARIF 2.1.0 reporter (task 7.6, `ARCHITECTURE.md` 6.6).

Settled key: ``partialFingerprints["airlock/v1"]`` (D-09, ADR-019).

Security contract (AGENTS.md section 4): evidence is attacker-controlled text and must
never reach ``message.text``.  Only the rule message, which is scanner-written, goes
there.  ``evidence`` stays on the finding and is omitted from the SARIF document.

Limits (ARCHITECTURE.md 6.6): 10 MB compressed, 25,000 results per run, 5,000 kept by
GitHub after severity-ordered trim.  The cap belongs in the reporter; this module does
not impose it, following the issue instruction that the cap is out of scope here.
"""

from __future__ import annotations

import json

from ..model import Finding, ScanReport, Severity

#: SARIF 2.1.0 schema URI, required by GitHub code scanning.
_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

#: Severity → SARIF level mapping (ARCHITECTURE.md 6.6).
_LEVEL: dict[Severity, str] = {
    Severity.HIGH: "error",
    Severity.WARN: "warning",
    Severity.INFO: "note",
}

#: Tool information URI for the driver block.
_INFO_URI = "https://github.com/posture-sec/airlock"


def _build_rules(findings: tuple[Finding, ...]) -> list[dict[str, object]]:
    """Return one rule entry per distinct rule id, in first-seen order.

    The rules array is built from the results, not from loaded rule data, because
    ``ScanReport`` does not carry ``ScanContext.rules``.  ``shortDescription.text``
    is set to the rule id, which is the only metadata the renderer has access to
    without a model change (issue #59).
    """
    seen: dict[str, int] = {}
    rules: list[dict[str, object]] = []
    for finding in findings:
        if finding.rule_id not in seen:
            seen[finding.rule_id] = len(rules)
            rules.append(
                {
                    "id": finding.rule_id,
                    "name": finding.rule_id,
                    "shortDescription": {"text": finding.rule_id},
                }
            )
    return rules


def _rule_index(findings: tuple[Finding, ...]) -> dict[str, int]:
    """Map each rule id to its position in first-seen order."""
    index: dict[str, int] = {}
    for finding in findings:
        if finding.rule_id not in index:
            index[finding.rule_id] = len(index)
    return index


def _location(finding: Finding) -> dict[str, object]:
    """Build a ``physicalLocation`` dict; ``startLine`` is omitted for file-level findings."""
    loc: dict[str, object] = {
        "artifactLocation": {"uri": finding.path, "uriBaseId": "%SRCROOT%"},
    }
    if finding.line:
        loc["region"] = {"startLine": finding.line}
    return {"physicalLocation": loc}


def _result(finding: Finding, rule_idx: dict[str, int]) -> dict[str, object]:
    """Serialize one finding to a SARIF result object.

    ``message.text`` carries the rule message only — never ``evidence``, which is
    attacker-controlled text (AGENTS.md section 4).

    ``partialFingerprints["airlock/v1"]`` carries the pre-computed fingerprint value
    verbatim (issue #60, ADR-019).  It is read from ``finding.fingerprint`` which was
    validated by ``_require_fingerprint`` before the finding was constructed.
    """
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_idx[finding.rule_id],
        "level": _LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": [_location(finding)],
        "partialFingerprints": {"airlock/v1": finding.fingerprint},
    }


def render(report: ScanReport) -> str:
    """Return a SARIF 2.1.0 JSON string for *report*.

    The document has exactly one run with one ``tool.driver`` and one result per
    finding in report order.  Suppressed findings are excluded: they are not findings
    from the caller's perspective.

    Two renders of the same report are byte-identical because ``json.dumps`` with
    ``sort_keys=True`` is deterministic and the results follow ``report.findings``
    order unchanged.
    """
    rules = _build_rules(report.findings)
    rule_idx = _rule_index(report.findings)
    results = [_result(f, rule_idx) for f in report.findings]
    doc: dict[str, object] = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "airlock",
                        "version": report.tool_version,
                        "informationUri": _INFO_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"
