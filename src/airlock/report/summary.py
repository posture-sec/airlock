"""Step-summary reporter (task 2.9, `ARCHITECTURE.md` 6.6).

Markdown for `$GITHUB_STEP_SUMMARY`: the counts, the skip accounting, every HIGH finding and the
evidence under each one. Every HIGH is listed because this is the output a reviewer actually
reads, and B8 is the failure it prevents: a flood of WARNs must not push a HIGH out of sight, so
WARNs are counted here and never enumerated.

Evidence and paths are attacker-controlled text (B11). Evidence only ever appears inside a fenced
block whose fence is longer than the longest backtick run anywhere in the rendered text, which is
what stops ``` inside a filename or a line of code from closing the block and handing the rest of
the summary to markdown. Everything outside a fence is flattened and has its markup characters
escaped, so a file called `**Deploy** [x](https://…)` renders as that string and nothing else.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..model import Finding, ScanReport, Severity

#: The summary is size-limited by GitHub, so evidence is shorter here than in the JSON.
SUMMARY_EVIDENCE_CHARS = 200

#: The byte budget for one step summary. `ARCHITECTURE.md` 6.6 records that GitHub aborts an
#: upload above 1 MiB without failing the step, which would delete the reviewer's copy of the
#: findings while CI stayed green, so the renderer stops below that ceiling on purpose.
SUMMARY_BUDGET_BYTES = 900_000
WITHHELD_NOTICE = (
    "_Withheld to stay under the step-summary limit: {rows} finding row(s) and "
    "{evidence} evidence block(s). The counts above are complete and the JSON report is not "
    "cut._"
)
SUMMARY_EVIDENCE_MARKER = " ..."
TRUNCATION_MARKER = SUMMARY_EVIDENCE_MARKER

#: `#` and `-` are deliberately absent: they only take effect at the start of a line, and no
#: attacker-controlled text is ever placed there (rows start with a pipe, bullets with a dash).
#: Escaping them would turn every rule id into `cfg\-dynamic\-code` for no safety gain.
_MARKUP_RE = re.compile(r"([\\`*_\[\]|<>])")
_BACKTICK_RUN_RE = re.compile(r"`+")


def flatten(text: str) -> str:
    """No newline survives: one finding must not become two rows or a stray heading."""
    return " ".join(text.split())


def inline(text: str) -> str:
    """Render attacker-controlled text as escaped inline content, not as markup."""
    return _MARKUP_RE.sub(r"\\\1", flatten(text))


def truncated(evidence: str | None) -> str:
    if evidence is None:
        return ""
    cleaned = flatten(evidence)
    if len(cleaned) <= SUMMARY_EVIDENCE_CHARS:
        return cleaned
    prefix_len = max(0, SUMMARY_EVIDENCE_CHARS - len(SUMMARY_EVIDENCE_MARKER))
    return cleaned[:prefix_len] + SUMMARY_EVIDENCE_MARKER


def fence_for(texts: Iterable[str]) -> str:
    """A fence longer than any backtick run in the texts, so nothing can break out of it.

    Three is the ordinary markdown fence; the length is computed over the content that goes
    inside, so a payload of twelve backticks gets thirteen.
    """
    longest = max(
        (len(run) for text in texts for run in _BACKTICK_RUN_RE.findall(text)),
        default=0,
    )
    return "`" * max(3, longest + 1)


def location(finding: Finding) -> str:
    path = inline(finding.path)
    return f"{path}:{finding.line}" if finding.line else path


def count_phrase(report: ScanReport) -> str:
    counts = {severity: 0 for severity in Severity}
    for finding in report.findings:
        counts[finding.severity] += 1
    parts = [
        f"{counts[severity]} {severity.label.upper()}" for severity in reversed(list(Severity))
    ]
    if report.suppressed:
        parts.append(f"{len(report.suppressed)} suppressed")
    return " · ".join(parts)


def skipped_section(report: ScanReport) -> list[str]:
    if not report.files_skipped:
        return ["No file was skipped."]
    rows = [
        f"| {inline(reason)} | {count} |" for reason, count in sorted(report.files_skipped.items())
    ]
    return ["| Skip reason | Files |", "|---|---|", *rows]


def finding_rows(findings: tuple[Finding, ...]) -> list[str]:
    rows = [
        f"| {finding.severity.label.upper()} | {inline(finding.rule_id)} | {location(finding)}"
        f" | {inline(finding.message)} |"
        for finding in findings
    ]
    if not rows:
        return ["No HIGH finding."]
    return rows


def evidence_blocks(findings: tuple[Finding, ...]) -> list[str]:
    """Every evidence excerpt inside one fence, sized against the longest backtick run it holds."""
    excerpted = [(finding, truncated(finding.evidence)) for finding in findings if finding.evidence]
    if not excerpted:
        return []
    fence = fence_for([excerpt for _, excerpt in excerpted])
    lines: list[str] = ["", "### Evidence", ""]
    for finding, excerpt in excerpted:
        lines += [f"- {location(finding)}", fence, excerpt, fence, ""]
    return lines


def suppressed_section(report: ScanReport) -> list[str]:
    """The suppressed findings table or empty declaration."""
    if not report.suppressed:
        return ["No finding was suppressed."]
    rows = [
        f"| {inline(finding.rule_id)} | {location(finding)} | {inline(finding.fingerprint)}"
        f" | {inline(finding.suppressed_by or '')} |"
        for finding in report.suppressed
    ]
    return [
        "These are suppressed and not findings.",
        "",
        "| Rule | Location | Fingerprint | Reason |",
        "|---|---|---|---|",
        *rows,
    ]


def _document(
    report: ScanReport,
    rows: list[str],
    evidence_pairs: list[tuple[Finding, str]],
    withheld_rows: int,
    withheld_evidence: int,
) -> str:
    """Assemble the document from the parts a caller may have cut."""
    lines = [
        "# Airlock",
        "",
        f"{count_phrase(report)} · {report.files_scanned} file(s) scanned",
        "",
        "## Skipped files",
        "",
        *skipped_section(report),
        "",
        "## HIGH findings",
        "",
        "| Severity | Rule | Location | Message |",
        "|---|---|---|---|",
        *rows,
    ]
    if evidence_pairs:
        fence = fence_for([excerpt for _, excerpt in evidence_pairs])
        lines += ["", "### Evidence", ""]
        for finding, excerpt in evidence_pairs:
            lines += [f"- {location(finding)}", fence, excerpt, fence, ""]
    if withheld_rows or withheld_evidence:
        lines += [
            "",
            WITHHELD_NOTICE.format(rows=withheld_rows, evidence=withheld_evidence),
        ]
    lines += [
        "",
        "## Suppressed findings",
        "",
        *suppressed_section(report),
    ]
    if lines[-1] != "":
        lines.append("")
    lines += [
        f"Mode `{inline(report.mode.value)}` · exit {report.exit_code}"
        f" · airlock {inline(report.tool_version)}",
    ]
    return "\n".join(lines) + "\n"


def render(report: ScanReport) -> str:
    """The whole summary as one Markdown document, under `SUMMARY_BUDGET_BYTES`.

    Evidence is cut before rows because a row still names the rule and the location, and the
    counts line and the mode/exit line are never cut: they are the only truthful signal left
    once rows are gone. A document under the budget renders byte-identically to before.
    """
    highs = tuple(finding for finding in report.findings if finding.severity is Severity.HIGH)
    rows = list(finding_rows(highs))
    trimmable_rows = bool(highs)
    evidence_pairs = [
        (finding, truncated(finding.evidence)) for finding in highs if finding.evidence
    ]
    withheld_rows = 0
    withheld_evidence = 0
    while True:
        text = _document(report, rows, evidence_pairs, withheld_rows, withheld_evidence)
        if len(text.encode("utf-8")) <= SUMMARY_BUDGET_BYTES:
            return text
        if evidence_pairs:
            step = max(1, len(evidence_pairs) // 8)
            evidence_pairs = evidence_pairs[:-step]
            withheld_evidence += step
        elif trimmable_rows and rows:
            step = max(1, len(rows) // 8)
            rows = rows[:-step]
            withheld_rows += step
        else:
            # Nothing left that may be cut without dropping the counts or the mode line.
            return text
