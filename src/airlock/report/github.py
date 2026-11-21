"""GitHub annotation reporter (task 2.9, `ARCHITECTURE.md` 6.6).

Emits `::error`, `::warning` and `::notice` workflow commands. Properties (`file`, `line`,
`title`) go through `escape_property`, which handles `%`, CR, LF, `:` and `,`; the message body
goes through `escape_data`, which handles `%`, CR and LF. Both orders matter: `%` is escaped
first, or a later substitution would inject a `%` that itself gets escaped again.

Why HIGH leads and why there are caps at all (B8): GitHub keeps only the first ten annotations of
each level from a single step; the rest are discarded, and the discarded ones never appear in the
check run at all (`ARCHITECTURE.md` 6.6, task 0.9). So the reporter chooses the survivors rather
than leaving it to the runner, and it leaves a slot for the note that names what was withheld: a
cap that spends the whole budget on findings hides the fact that anything was cut. Findings already
arrive in report order, so the first `high_cap` annotations are the first HIGHs.

Nothing is dropped quietly: when a cap bites, one more annotation of that severity says how many
went unlisted, so a flood of WARNs cannot make a HIGH look absent and a capped HIGH list cannot
look complete. INFO gets `::notice` for the same reason; the alternative was to hide it in CI.
"""

from __future__ import annotations

from ..model import Finding, ScanReport, Severity

#: Observed on a hosted runner (task 0.9): the first 10 annotations of each level from one step
#: survive, and the step's exit status is unaffected by the loss. The scan emits from one step.
ANNOTATIONS_PER_LEVEL = 10

#: Cap values live here, not in policy: a repository cannot raise them. Each level keeps one slot
#: for the withheld-count note; INFO keeps two, because the suppression note is also a `::notice`.
HIGH_ANNOTATIONS = ANNOTATIONS_PER_LEVEL - 1
WARN_ANNOTATIONS = ANNOTATIONS_PER_LEVEL - 1
INFO_ANNOTATIONS = ANNOTATIONS_PER_LEVEL - 2

#: The command name GitHub reads each severity level into.
_COMMANDS = {Severity.HIGH: "error", Severity.WARN: "warning", Severity.INFO: "notice"}


def escape_property(value: str) -> str:
    """Escape the five characters GitHub treats specially inside a workflow command property."""
    out = value.replace("%", "%25")
    out = out.replace("\r", "%0D").replace("\n", "%0A")
    return out.replace(":", "%3A").replace(",", "%2C")


def escape_data(value: str) -> str:
    """Escape the three characters that would otherwise end the message or forge a command."""
    out = value.replace("%", "%25")
    return out.replace("\r", "%0D").replace("\n", "%0A")


def _annotation(finding: Finding, command: str) -> str:
    properties = f"file={escape_property(finding.path)}"
    if finding.line:
        properties += f",line={finding.line}"
    properties += f",title={escape_property(finding.rule_id)}"
    return f"::{command} {properties}::{escape_data(finding.message)}"


def _withheld_note(severity: Severity, count: int) -> str:
    body = (
        f"{count} {severity.label.upper()} finding(s) are not annotated above; "
        "the step summary and JSON output list them all."
    )
    return f"::{_COMMANDS[severity]} title=airlock::{escape_data(body)}"


def render(
    report: ScanReport,
    *,
    high_cap: int = HIGH_ANNOTATIONS,
    warn_cap: int = WARN_ANNOTATIONS,
    info_cap: int = INFO_ANNOTATIONS,
) -> str:
    """Annotations for the report, HIGH first, with a count of anything the caps withheld."""
    caps = {Severity.HIGH: high_cap, Severity.WARN: warn_cap, Severity.INFO: info_cap}
    lines: list[str] = []
    listed = {severity: 0 for severity in Severity}
    for finding in report.findings:
        command = _COMMANDS[finding.severity]
        if listed[finding.severity] < caps[finding.severity]:
            lines.append(_annotation(finding, command))
        listed[finding.severity] += 1

    for severity in reversed(list(Severity)):
        withheld = listed[severity] - caps[severity]
        if withheld > 0:
            lines.append(_withheld_note(severity, withheld))

    if report.suppressed:
        body = (
            f"{len(report.suppressed)} finding(s) are hidden by the trusted airlock.toml; "
            "--format json names each one and its reason."
        )
        lines.append(f"::notice title=airlock::{escape_data(body)}")
    return "\n".join(lines) + ("\n" if lines else "")
