"""Detector orchestration. Task 2.11 (`ARCHITECTURE.md` 6.3).

Two passes make up a scan:

1. The engine pass, over every file the collector returned text for. It runs the `pattern` rules
   and reports the lines `line_cap` withheld from any regex. It is code, not a detector, because
   a withheld line must be accounted for whatever else is registered: an empty or partial
   detector list may reduce what is matched, never what is reported.
2. The registered detectors, in registry order. Each yields pending findings; a detector that
   raises becomes one HIGH `detector-error` and the remaining detectors still run.

`number_occurrences` then assigns occurrence indices and sorts, so the same set of findings
always produces the same fingerprints and the same report order.

Suppression is applied by the caller (`cli.run_scan`), because it needs the trusted policy,
which is not part of this module.
"""

from __future__ import annotations

from .detectors import DETECTORS, Detector
from .fingerprint import PendingFinding, number_occurrences
from .model import MAX_MESSAGE_CHARS, REPO_PATH, FileEntry, Finding, ScanContext, Severity
from .rules import apply_patterns, cap_findings

DETECTOR_ERROR_RULE_ID = "detector-error"


def _engine_error(stage: str, entry: FileEntry, error: BaseException) -> PendingFinding:
    """An engine stage that raised is a HIGH gap, never a missing report.

    The engine pass runs on every file, so it has the widest exposure of any stage. Naming the
    entry and stage keeps the gap actionable, and the earlier findings stay in the report.
    """
    detail = f"{stage} on {entry.path}: {type(error).__name__}: {error}"
    return PendingFinding(
        rule_id=DETECTOR_ERROR_RULE_ID,
        severity=Severity.HIGH,
        path=REPO_PATH,
        line=0,
        roles=(),
        message=(
            "The engine pass raised and its coverage for this entry is missing from this scan: "
            + detail[:MAX_MESSAGE_CHARS]
        ),
        evidence=detail[:MAX_MESSAGE_CHARS],
        suppressible=False,
    )


def engine_findings(ctx: ScanContext) -> tuple[PendingFinding, ...]:
    """Run the pattern rules and the line-cap account over every entry with text.

    Each stage is contained per entry, matching the detector boundary: a rule that raises on
    one file must not discard the findings already collected or abort the scan.
    """
    pending: list[PendingFinding] = []
    stages = (("pattern rules", apply_patterns), ("line-cap account", cap_findings))
    for entry in ctx.entries:
        for stage, run in stages:
            try:
                pending.extend(run(ctx.rules, entry, ctx.policy.line_cap))
            except Exception as error:
                pending.append(_engine_error(stage, entry, error))
    return tuple(pending)


def _visible_escapes(text: str) -> str:
    """One line with every C0 control character spelled out.

    The text comes from an exception raised while reading scanned content, so it can hold a
    newline that forges a second annotation or a carriage return that overwrites the one above.
    Escaping keeps the diagnostic without letting any byte of it act on the renderer.
    """
    out: list[str] = []
    for char in text:
        code = ord(char)
        if char == "\n":
            out.append("\\n")
        elif char == "\r":
            out.append("\\r")
        elif char == "\t":
            out.append("\\t")
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\x{code:02x}")
        else:
            out.append(char)
    return "".join(out)


def _detector_error(detector: Detector, error: BaseException) -> PendingFinding:
    """A detector that raised is a HIGH finding, never a silent gap in coverage.

    The message is scanner-written plus the in-tree module name and the exception type: an
    exception raised while reading a file may quote a path or a line of it, and the report must
    not present that text as the scanner's own sentence. The quoted text stays in the evidence,
    with its control characters escaped so a renderer cannot be steered by it.
    """
    name = getattr(detector, "__module__", repr(detector))
    detail = f"{name}: {type(error).__name__}: {error}"
    return PendingFinding(
        rule_id=DETECTOR_ERROR_RULE_ID,
        severity=Severity.HIGH,
        path=REPO_PATH,
        line=0,
        roles=(),
        message=(
            "A detector raised and its coverage is missing from this scan: "
            f"{name}: {type(error).__name__}. The exception text is in the evidence."
        )[:MAX_MESSAGE_CHARS],
        # The detail is the evidence, so two failures of one detector on one commit collapse to
        # one fingerprint while a different exception stays a new finding.
        evidence=_visible_escapes(detail)[:MAX_MESSAGE_CHARS],
        suppressible=False,
    )


def _run_one(detector: Detector, ctx: ScanContext) -> tuple[PendingFinding, ...]:
    """Run one detector and catch anything it raises.

    Findings yielded before the failure are kept: a scan that reports the coverage gap and the
    partial result is more useful than one that throws away both. The loop is inside the `try`,
    because a generator that fails on its tenth file would otherwise escape the wrapper.
    """
    collected: list[PendingFinding] = []
    try:
        for item in detector(ctx):
            collected.append(item)
    except Exception as error:
        collected.append(_detector_error(detector, error))
    return tuple(collected)


def collect(ctx: ScanContext) -> tuple[PendingFinding, ...]:
    """Every pending finding from the engine pass and the detectors, in dispatch order."""
    pending: list[PendingFinding] = list(engine_findings(ctx))
    for detector in DETECTORS:
        pending.extend(_run_one(detector, ctx))
    return tuple(pending)


def scan(ctx: ScanContext) -> list[Finding]:
    """Run the scan and return findings in report order (HIGH first)."""
    return number_occurrences(collect(ctx))
