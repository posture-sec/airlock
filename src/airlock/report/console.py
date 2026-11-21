"""Console reporter (task 2.9, `ARCHITECTURE.md` 6.6).

One finding per line: severity, rule id, `path:line`, message, then a summary line a human
reading CI logs can scan in one pass. Paths arrive from the repository, so a file named with a
newline cannot be allowed to split one finding across two lines, and nothing here renders a
message as anything but text.

No color and no terminal detection: the same bytes go to a pipe, a log file and a TTY, which
keeps the output golden-testable.
"""

from __future__ import annotations

from ..model import Finding, ScanReport, Severity


def _escape_control(ch: str) -> str:
    """Return the visible escape notation for one C0 control character.

    CR, LF and CRLF are handled before this function is called: they collapse to
    a space.  Every other byte below 0x20 and 0x7f is rendered as ``\\xNN`` so it is
    visible to a reviewer and cannot manipulate a terminal or erase a previous line.
    """
    return f"\\x{ord(ch):02x}"


def flatten(text: str) -> str:
    """One line, whatever the input held.

    1. Collapse CRLF, CR and LF to a single space (existing contract).
    2. Escape every remaining C0 control character (< 0x20) and DEL (0x7f) to
       ``\\xNN`` so a path like ``ESC[2K`` cannot clear the current terminal line
       and overwrite the finding printed above it (issue #61).
    """
    # Step 1: collapse line-break sequences to a space.
    normalised = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    # Step 2: escape remaining C0 controls and DEL.
    if not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in normalised):
        return normalised
    return "".join(
        _escape_control(ch) if (ord(ch) < 0x20 or ord(ch) == 0x7F) else ch for ch in normalised
    )


def location(finding: Finding) -> str:
    """`path:line`, or the bare path for a file-level finding (line 0)."""
    path = flatten(finding.path)
    return f"{path}:{finding.line}" if finding.line else path


def render(report: ScanReport) -> str:
    """The whole report as console text, ending with the summary line."""
    lines = [
        f"{finding.severity.label.upper():<5}  {finding.rule_id:<28}  {location(finding):<48}"
        f"  {flatten(finding.message)}"
        for finding in report.findings
    ]
    lines.append(summary_line(report))
    return "\n".join(lines) + "\n"


def counts_by_severity(report: ScanReport) -> dict[Severity, int]:
    counts = {severity: 0 for severity in Severity}
    for finding in report.findings:
        counts[finding.severity] += 1
    return counts


def skipped_phrase(report: ScanReport) -> str:
    """`3 skipped-oversize, 1 submodule-present`, or `nothing skipped`."""
    if not report.files_skipped:
        return "nothing skipped"
    return ", ".join(f"{count} {reason}" for reason, count in sorted(report.files_skipped.items()))


def summary_line(report: ScanReport) -> str:
    counts = counts_by_severity(report)
    tally = " · ".join(
        f"{counts[severity]} {severity.label.upper()}" for severity in reversed(list(Severity))
    )
    hidden = f", {len(report.suppressed)} suppressed" if report.suppressed else ""
    base = flatten(report.base)[:7] if report.base else "none"
    version = flatten(report.tool_version)
    return (
        f"airlock: {tally}{hidden} · {report.files_scanned} file(s) scanned, "
        f"{skipped_phrase(report)} · mode {report.mode.value} · base {base} · "
        f"exit {report.exit_code} · airlock {version}"
    )
