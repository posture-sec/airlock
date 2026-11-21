"""Argument parsing, command dispatch and exit codes. Task 2.10 (`ARCHITECTURE.md` 8).

`scan` is the whole pipeline in one place, in the order the design fixes: startup checks, trusted
base, rule data, collection, engine pass and detectors, numbering, suppression, reporters. The
CLI is the only module that knows that sequence, which is why it lives here rather than in a
`pipeline.py` the layout does not list (project_structure.md 3).

Exit codes: 0 nothing at or above `fail_on`; 1 something is; 2 configuration or usage error;
3 internal error. Anything nonzero fails the job, and nothing here returns 0 on a path where the
scan did not complete, so a green run always means a scan actually ran.

Two rules the rest of the design depends on:

- The tool never fetches and never reads policy from the tree under review except in `full` mode.
  `--mode` and `--event` decide which of the three trust models apply, and an event name that is
  not one of the four mapped ones is a usage error rather than a guess.
- Rule data ships with the tool, not with the repository being scanned (B1). `--rules-dir` and
  `--roles` point at the copy that came from the pinned Action, and a scanned repository cannot
  add, edit or delete a rule by doing anything to its own files.

`manifest add` writes the manifest from the file it is given: one command per artifact, and the
result parses with the same loader the scan reads it with. `manifest check` runs the same pipeline
as a scan and keeps the artifact findings, because "is my manifest right" is the wasm_manifest
detector's question and reimplementing it here would be a second answer to it.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

from . import __version__
from . import runner as runner_module
from .collector import check_runtime, collect
from .detectors import DETECTOR_NAMES
from .fingerprint import number_occurrences
from .model import (
    EXIT_CONFIG,
    EXIT_FINDINGS,
    EXIT_INTERNAL,
    EXIT_PASS,
    WASM_ORIGINS,
    FileEntry,
    Finding,
    Mode,
    ScanContext,
    ScanReport,
    Severity,
    severity_from_name,
)
from .policy import (
    MANIFEST_FILENAME,
    POLICY_FILENAME,
    manifest_add,
    resolve_policy,
    suppress,
)
from .report import console, github, jsonout, sarif, summary
from .roles import known_roles
from .rules import load_role_globs, load_rules

#: The repository root in a source checkout, which is also what `$GITHUB_ACTION_PATH` holds
#: when the Action runs (`ARCHITECTURE.md` 10).
REPO_ROOT = Path(__file__).resolve().parents[2]


def rules_root(package_dir: Path) -> Path:
    """Where the rule data for the copy of the tool at `package_dir` lives.

    Two install layouts have to resolve without a flag (5.7). A source checkout and the pinned
    Action keep `rules/` at the repository root, two levels above `src/airlock`; an installed
    wheel carries the data inside the package, because nothing outside the package directory is
    installed at all. The packaged copy wins when it is there, so a wheel never reads a checkout
    that happens to sit in the same filesystem.
    """
    packaged = package_dir / "rules"
    if (packaged / "roles.toml").is_file():
        return packaged
    return package_dir.parents[1] / "rules"


RULES_ROOT = rules_root(Path(__file__).resolve().parent)
DEFAULT_RULES_DIR = RULES_ROOT / "builtin"
DEFAULT_ROLES_FILE = RULES_ROOT / "roles.toml"

#: Every event this build knows how to judge. An unmapped event is a usage error, because
#: defaulting it would pick a trust model the caller never asked for.
EVENT_MODES: Mapping[str, Mode] = {
    "pull_request": Mode.PR,
    "push": Mode.PUSH,
    "workflow_dispatch": Mode.FULL,
    "schedule": Mode.FULL,
}

RENDERERS: Mapping[str, Callable[[ScanReport], str]] = {
    "console": console.render,
    "github": github.render,
    "json": jsonout.render,
    "sarif": sarif.render,
}

STEP_SUMMARY_ENV = "GITHUB_STEP_SUMMARY"

#: `manifest check` keeps only these, since the manifest answers the artifact question and nothing
#: else. The prefix is the rule family, not a string in a message, so a renamed family breaks the
#: filter at once rather than quietly widening it.
WASM_RULE_PREFIX = "wasm-"


class UsageError(ValueError):
    """A configuration or usage problem: exit 2 with a plain message, never a traceback."""


def _add_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", nargs="?", default=".", help="repository to scan (default: cwd)")
    parser.add_argument("--mode", choices=[member.value for member in Mode], help="trust model")
    parser.add_argument(
        "--event",
        help=f"github event name; implies a mode from {', '.join(sorted(EVENT_MODES))}",
    )
    parser.add_argument("--base", help="pull request base SHA (pr mode)")
    parser.add_argument("--before", help="github.event.before (push mode)")
    parser.add_argument(
        "--fail-on", choices=[severity.name.lower() for severity in Severity], dest="fail_on"
    )
    parser.add_argument("--config", default=POLICY_FILENAME, help="policy file, repo-relative")
    parser.add_argument(
        "--wasm-manifest", default=MANIFEST_FILENAME, dest="manifest", help="manifest file"
    )
    parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR, dest="rules_dir")
    parser.add_argument("--roles", type=Path, default=DEFAULT_ROLES_FILE)
    parser.add_argument("--format", choices=sorted(RENDERERS), default="console", dest="format")
    parser.add_argument("--output", help="write the report here instead of stdout")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="airlock",
        description="Scan a repository for supply-chain compromise and release-integrity gaps.",
    )
    parser.add_argument("--version", action="version", version=f"airlock {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    _add_flags(commands.add_parser("scan", help="collect, detect, suppress and report"))

    manifest = commands.add_parser("manifest", help="Wasm manifest maintenance")
    verbs = manifest.add_subparsers(dest="verb", required=True)
    add = verbs.add_parser("add", help="record one Wasm artifact by hash")
    add.add_argument("targets", nargs="+", help="artifact paths, repo-relative")
    add.add_argument("--repo", default=".", help="repository holding the manifest (default: cwd)")
    add.add_argument(
        "--wasm-manifest", default=MANIFEST_FILENAME, dest="manifest", help="manifest file"
    )
    add.add_argument("--origin", choices=sorted(WASM_ORIGINS), required=True)
    add.add_argument("--source", required=True, help="where the artifact comes from")
    add.add_argument("--build", default="", help="the command that produces it, for origin built")
    add.add_argument("--note", default="", help="anything a reviewer needs to know")
    check = verbs.add_parser("check", help="verify the manifest against the tree")
    check.add_argument("path", nargs="?", default=".", help="repository (default: cwd)")
    check.add_argument(
        "--wasm-manifest", default=MANIFEST_FILENAME, dest="manifest", help="manifest file"
    )
    check.add_argument("--config", default=POLICY_FILENAME, help="policy file, repo-relative")
    check.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR, dest="rules_dir")
    check.add_argument("--roles", type=Path, default=DEFAULT_ROLES_FILE)
    check.add_argument("--format", choices=sorted(RENDERERS), default="console", dest="format")
    check.add_argument("--output", help="write the report here instead of stdout")
    return parser


def _mode_for(args: argparse.Namespace) -> Mode:
    """Resolve `--mode` and `--event` into the one trust model that governs the scan."""
    if args.event is not None:
        implied = EVENT_MODES.get(args.event)
        if implied is None:
            raise UsageError(
                f"airlock has no trust model for event {args.event!r}; "
                f"known events are {', '.join(sorted(EVENT_MODES))}"
            )
        if args.mode is not None and args.mode != implied.value:
            raise UsageError(
                f"--event {args.event} implies mode {implied.value}, not --mode {args.mode}"
            )
        return implied
    if args.mode is not None:
        return Mode(args.mode)
    return Mode.FULL


def _file_counts(entries: tuple[FileEntry, ...], skipped: Mapping[str, int]) -> tuple[int, int]:
    """Indexed and read counts, refusing a report that loses an entry (`ARCHITECTURE.md` 7.8).

    Every indexed entry is either read (a digest and no skip reason) or skipped (a reason, which
    may still carry the digest the collector computed before it gave up on decoding). An entry in
    neither bucket is a file no reviewer can see, which is the state this raise prevents rather
    than reporting a total that quietly disagrees with the index.
    """
    indexed = len(entries)
    scanned = sum(1 for entry in entries if entry.sha256 is not None and entry.skip_reason is None)
    skipped_total = sum(skipped.values())
    if scanned + skipped_total != indexed:
        raise ValueError(
            "report does not account for every indexed file: "
            f"{indexed} indexed, {scanned} scanned, {skipped_total} skipped"
        )
    return indexed, scanned


def run_scan(
    repo: Path,
    mode: Mode,
    *,
    base: str | None = None,
    before: str | None = None,
    config: str = POLICY_FILENAME,
    manifest: str = MANIFEST_FILENAME,
    fail_on: Severity | None = None,
    rules_dir: Path = DEFAULT_RULES_DIR,
    roles_file: Path = DEFAULT_ROLES_FILE,
    keep: Callable[[Finding], bool] | None = None,
) -> ScanReport:
    """Run one scan end to end and return the report, with its exit code already decided.

    `keep` narrows what the report carries, which is how `manifest check` is one scan rather than
    a second implementation (`ARCHITECTURE.md` 7.7). Numbering and suppression still run over
    every finding, so a kept finding's occurrence index and fingerprint mean exactly what they
    mean in a full scan; only the exit code is decided over the kept set, against the same
    `fail_on` threshold.

    Raises `ValueError` for anything the operator must fix: a repository git will not open, an
    unresolvable base, unreadable rule data, a policy that does not parse.
    """
    head = check_runtime(repo)
    trusted = resolve_policy(
        repo, mode, head, base=base, before=before, policy_path=config, manifest_path=manifest
    )
    role_globs = load_role_globs(roles_file)
    rules = load_rules(
        rules_dir, known_detectors=DETECTOR_NAMES, known_roles=known_roles(role_globs)
    )
    collection = collect(repo, trusted.policy, role_globs)
    context = ScanContext(
        entries=collection.entries,
        policy=trusted.policy,
        manifest=trusted.manifest,
        rules=rules,
    )

    # One numbering pass over every source, so occurrence indices cannot depend on which
    # detector finished first: the collector's skips, the policy's state findings and the
    # findings the engine and detectors produced.
    pending = [
        *collection.pending,
        *trusted.pending,
        *runner_module.collect(context),
    ]
    threshold = fail_on if fail_on is not None else trusted.policy.fail_on
    outcome = suppress(number_occurrences(pending), trusted.policy, rules, policy_path=config)
    findings = outcome.findings
    suppressed = outcome.suppressed
    if keep is not None:
        findings = tuple(item for item in findings if keep(item))
        suppressed = tuple(item for item in suppressed if keep(item))
    files_skipped = collection.files_skipped
    files_indexed, files_scanned = _file_counts(collection.entries, files_skipped)
    return ScanReport(
        tool_version=__version__,
        mode=mode,
        repo_head=head,
        base=trusted.base,
        files_indexed=files_indexed,
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        findings=findings,
        suppressed=suppressed,
        exit_code=(
            EXIT_FINDINGS if any(item.severity >= threshold for item in findings) else EXIT_PASS
        ),
    )


def _scan_command(args: argparse.Namespace) -> int:
    repo = Path(args.path)
    report = run_scan(
        repo,
        _mode_for(args),
        base=args.base,
        before=args.before,
        config=args.config,
        manifest=args.manifest,
        fail_on=severity_from_name(args.fail_on) if args.fail_on else None,
        rules_dir=args.rules_dir,
        roles_file=args.roles,
    )
    return _emit(report, args)


def _manifest_add(args: argparse.Namespace) -> int:
    """Record each artifact by hash and write the manifest back.

    Nothing is staged or committed: `wasm-manifest.toml` is a protected path, so the operator
    reviews the diff and lands it in its own pull request, which is the flow the trusted base
    assumes (FR-06).
    """
    repo = Path(args.repo)
    change = manifest_add(
        repo,
        args.targets,
        manifest_path=args.manifest,
        origin=args.origin,
        source=args.source,
        build=args.build,
        note=args.note,
    )
    if change.unchanged:
        print(f"airlock: {args.manifest} already lists every target; nothing written")
        return EXIT_PASS
    (repo / args.manifest).write_text(change.text, encoding="utf-8")
    print(
        f"airlock: {args.manifest}: "
        + f"{len(change.added)} added, {len(change.extended)} path(s) joined"
    )
    for entry in (*change.added, *change.extended):
        print(f"  {entry.sha256[:12]}  {', '.join(sorted(entry.paths))}")
    print("land this change on its own before the pull request that adds the files (FR-06)")
    return EXIT_PASS


def _manifest_check(args: argparse.Namespace) -> int:
    """Answer one question only: does every committed artifact match the manifest.

    It is a scan with the output narrowed to the `wasm-` rules, because the accounting belongs to
    the `wasm_manifest` detector and a second implementation here would be a second answer. The
    trust model is `full`: the point is to check the file in hand against the tree in hand, and
    `untrusted-policy-source` is not this command's question.

    The exit code keeps the scan's meaning, because it is the scan's code path: 1 only when a wasm
    rule fires at or above `fail_on`, so an unlisted or swapped artifact stops the line while
    manifest rot (a stale entry, a moved path) is named without stopping it.
    """
    report = run_scan(
        Path(args.path),
        Mode.FULL,
        config=args.config,
        manifest=args.manifest,
        rules_dir=args.rules_dir,
        roles_file=args.roles,
        keep=lambda finding: finding.rule_id.startswith(WASM_RULE_PREFIX),
    )
    return _emit(report, args)


def _emit(report: ScanReport, args: argparse.Namespace) -> int:
    """Render a report to the chosen destination and return its exit code."""
    text = RENDERERS[args.format](report)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        _write_stdout(text)
    _write_step_summary(report)
    return report.exit_code


def _write_stdout(text: str) -> None:
    """Write the report to stdout and flush it here, where the exit code is still in scope.

    A reader that stops early (`airlock scan . | head -1`, a pager quit) closes the pipe, and the
    write raises `BrokenPipeError` for it. The scan found what it found, so that is not the
    internal error the broad handler in `main` would report as exit 3 (`ARCHITECTURE.md` 8).

    The flush is the part that makes the catch reachable: stdout into a pipe is block-buffered, so a
    short report would otherwise sit in the buffer and raise during interpreter shutdown instead,
    past every handler in this process. That is how a closed pipe came to exit 120 with a traceback
    on stderr rather than with the verdict.
    """
    with contextlib.suppress(BrokenPipeError):
        sys.stdout.write(text)
        sys.stdout.flush()


def _write_step_summary(report: ScanReport) -> None:
    """Append the Markdown summary when running as a GitHub step.

    Written separately from `--format` because the annotation stream and the summary are read by
    different people: the check line is for the author, the summary is for the reviewer who has
    to see every HIGH without opening a log.
    """
    target = os.environ.get(STEP_SUMMARY_ENV)
    if not target:
        return
    try:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(summary.render(report))
    except OSError as exc:
        print(
            f"airlock: warning: cannot write the step summary to {target}: {exc}", file=sys.stderr
        )


def main(argv: list[str] | None = None) -> int:
    """Dispatch one command and map every failure onto the documented exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _scan_command(args)
        if args.command == "manifest":
            if args.verb == "add":
                return _manifest_add(args)
            return _manifest_check(args)
        raise UsageError(f"no such command: {args.command!r}")
    except ValueError as error:
        print(f"airlock: {error}", file=sys.stderr)
        return EXIT_CONFIG
    except Exception as error:  # an unexpected failure is exit 3, never a traceback
        print(
            f"airlock: internal error: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return EXIT_INTERNAL
