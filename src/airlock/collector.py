"""File collection: git index listing, reads, decoding, limits and startup checks.

Tasks 2.2 and 2.3 (`ARCHITECTURE.md` 6.1). Two rules from the essentials document live here
more than anywhere else: no file is ever skipped silently, and there are no default
directory skips. Every condition that stops the scanner from reading content produces a
finding with a path attached.

This module is one of only two allowed to call `subprocess`, always with a fixed argument
list and never through a shell. Scanned files are opened for reading only; nothing collected
here is imported, executed or followed.
"""

from __future__ import annotations

import codecs
import hashlib
import os
import shutil
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .fingerprint import PendingFinding, truncate_evidence
from .model import FileEntry, Policy, Severity
from .roles import SENSITIVE_ROLES, resolve_roles, roles_from_magic

#: Roles whose content is still worth a lenient decode when strict UTF-8 fails, so one bad
#: byte cannot hide a payload behind `non-utf8-text`.
SCANNABLE_ROLES = frozenset({"tooling-config", "editor-autorun", "source"})

HEAD_BYTES = 4096
MIN_PYTHON = (3, 11)

_GITLINK_MODE = "160000"
_SYMLINK_MODE = "120000"

#: Reason strings recorded on FileEntry, counted in ScanReport.files_skipped.
SKIP_OVERSIZE = "oversize"
SKIP_UNREADABLE = "unreadable"
SKIP_SYMLINK = "symlink"
SKIP_SUBMODULE = "submodule"
SKIP_ENCODING = "encoding"
SKIP_UNMERGED = "unmerged"


@dataclass(frozen=True, slots=True)
class IndexEntry:
    """One path from `git ls-files --stage`, with the index stage it was seen at."""

    mode: str
    path: str
    stage: int = 0

    @property
    def is_unmerged(self) -> bool:
        return self.stage != 0

    @property
    def is_symlink(self) -> bool:
        return self.mode == _SYMLINK_MODE

    @property
    def is_submodule(self) -> bool:
        return self.mode == _GITLINK_MODE


@dataclass(frozen=True, slots=True)
class Collection:
    """What a collect() run produced. Detectors read entries; the runner appends pending."""

    entries: tuple[FileEntry, ...]
    pending: tuple[PendingFinding, ...]

    @property
    def files_skipped(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entry in self.entries:
            if entry.skip_reason:
                counts[entry.skip_reason] = counts.get(entry.skip_reason, 0) + 1
        return counts


def _run_git(
    repo_root: Path, args: tuple[str, ...], timeout: int
) -> subprocess.CompletedProcess[bytes]:
    argv = ["git", "-C", str(repo_root), *args]
    try:
        return subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError(f"git failed to run: {exc}") from exc


def git_bytes(repo_root: Path, *args: str, timeout: int = 120) -> bytes:
    """Run one git command in the scanned repo and return raw stdout. Never uses a shell.

    Every git call in this module goes through here, so a timeout or a missing binary fails
    the same way whoever asked git. The CLI turns that `ValueError` into exit code 2.
    """
    result = _run_git(repo_root, args, timeout)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(detail or f"git exited with code {result.returncode}")
    return result.stdout


def git_status(repo_root: Path, *args: str, timeout: int = 120) -> tuple[int, str]:
    """Run one git command and return `(exit status, stderr)` without judging the status.

    For callers that read the exit status as the answer, such as `merge-base --is-ancestor`,
    where 1 means "no" rather than "the command failed". A command that could not run still
    raises `ValueError`.
    """
    result = _run_git(repo_root, args, timeout)
    return result.returncode, result.stderr.decode("utf-8", errors="replace").strip()


def git_text(repo_root: Path, *args: str) -> str:
    """One git command as text, with the surrounding whitespace removed."""
    return git_bytes(repo_root, *args).decode("utf-8", errors="replace").strip()


def check_runtime(repo_root: Path) -> str:
    """Startup checks (2.3): interpreter, git on PATH, repository readable.

    Returns the HEAD commit of the scanned repository. Every failure raises `ValueError`
    with git's own explanation, which the CLI turns into exit code 2. A git `safe.directory`
    refusal lands here too, and its message names the fix.
    """
    if sys.version_info < MIN_PYTHON:
        needed = ".".join(str(part) for part in MIN_PYTHON)
        running = ".".join(str(part) for part in sys.version_info[:3])
        raise ValueError(f"airlock needs Python {needed} or newer, this run uses {running}")
    if shutil.which("git") is None:
        raise ValueError("airlock needs git on PATH to list tracked files")
    try:
        head = git_text(repo_root, "rev-parse", "--verify", "HEAD")
    except ValueError as exc:
        raise ValueError(f"cannot read the repository at {repo_root}: {exc}") from exc
    if len(head) != 40 or any(char not in "0123456789abcdef" for char in head):
        raise ValueError(f"git returned an unexpected HEAD reference: {head!r}")
    return head


def list_tracked_files(repo_root: Path) -> tuple[IndexEntry, ...]:
    """Tracked paths from the index, sorted, one record per path.

    An unmerged path is kept, flagged, and never dropped: git lists it once per staged
    version (stages 1, 2 and 3, with no stage 0), and a scanner that only read stage 0 would
    report nothing at all about a file sitting in a merge conflict. The repeat collapses into
    one entry so the path produces one finding.
    """
    raw = git_bytes(repo_root, "ls-files", "-z", "--stage", timeout=300)
    by_path: dict[str, IndexEntry] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        meta, _, path = record.partition(b"\t")
        fields = meta.split(b" ")
        if len(fields) != 3:
            raise ValueError(f"unparsable git index entry: {record[:120]!r}")
        mode, _, stage = fields
        entry = IndexEntry(mode=mode.decode(), path=os.fsdecode(path), stage=int(stage))
        seen = by_path.get(entry.path)
        if seen is None or entry.stage < seen.stage:
            by_path[entry.path] = entry
    return tuple(sorted(by_path.values(), key=lambda entry: entry.path))


def _state(
    rule_id: str,
    severity: Severity,
    path: str,
    roles: tuple[str, ...],
    message: str,
    evidence: str | None = None,
) -> PendingFinding:
    return PendingFinding(
        rule_id=rule_id,
        severity=severity,
        path=path,
        line=0,
        roles=roles,
        message=message,
        evidence=truncate_evidence(evidence),
        suppressible=False,
    )


def _sensitive(roles: tuple[str, ...]) -> bool:
    return bool(SENSITIVE_ROLES.intersection(roles))


def _decode(data: bytes) -> tuple[str, bool]:
    """BOM-aware decode. Returns the text and whether the strict decode failed."""
    if data.startswith(codecs.BOM_UTF8):
        try:
            return data[len(codecs.BOM_UTF8) :].decode("utf-8"), False
        except UnicodeDecodeError:
            return data.decode("utf-8", errors="replace"), True
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        try:
            return data.decode("utf-16"), False
        except UnicodeDecodeError:
            return data.decode("utf-8", errors="replace"), True
    try:
        return data.decode("utf-8"), False
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace"), True


def _collect_one(
    repo_root: Path, entry: IndexEntry, policy: Policy, role_globs: Mapping[str, tuple[str, ...]]
) -> tuple[FileEntry, tuple[PendingFinding, ...]]:
    findings: list[PendingFinding] = []
    target = repo_root / entry.path

    if entry.is_unmerged:
        # Nothing here is read, not even the working copy: its conflict markers are a merge
        # result nobody has agreed on, and scanning them would report a file that does not
        # exist yet. The roles come from the path alone, so the severity still follows
        # whether this is a file a rule would have cared about.
        roles = resolve_roles(entry.path, b"", role_globs)
        findings.append(
            _state(
                "skipped-unmerged",
                Severity.HIGH if _sensitive(roles) else Severity.WARN,
                entry.path,
                roles,
                "unmerged in the index: the path has staged versions and no committed "
                "content, so nothing was scanned",
            )
        )
        return (
            FileEntry(
                path=entry.path,
                sha256=None,
                roles=roles,
                skip_reason=SKIP_UNMERGED,
            ),
            tuple(findings),
        )

    if entry.is_submodule:
        findings.append(
            _state(
                "submodule-present",
                Severity.INFO,
                entry.path,
                (),
                "embedded repository: its contents are scanned by its own pipeline, not here",
            )
        )
        return (
            FileEntry(path=entry.path, sha256=None, roles=(), skip_reason=SKIP_SUBMODULE),
            tuple(findings),
        )

    if entry.is_symlink:
        # The target path is never read, so a tracked link cannot point the scanner outside
        # the repository or at /home/*/.ssh. A link in a sensitive role is still an unread
        # file that would have run, so it is as loud as any other unread sensitive file.
        roles = resolve_roles(entry.path, b"", role_globs)
        findings.append(
            _state(
                "skipped-symlink",
                Severity.HIGH if _sensitive(roles) else Severity.INFO,
                entry.path,
                roles,
                "symlink in the index; its target was not read",
            )
        )
        return (
            FileEntry(
                path=entry.path,
                sha256=None,
                roles=roles,
                skip_reason=SKIP_SYMLINK,
            ),
            tuple(findings),
        )

    try:
        size_bytes = os.path.getsize(target)
        with target.open("rb") as handle:
            head = handle.read(HEAD_BYTES)
    except OSError as exc:
        findings.append(
            _state(
                "skipped-unreadable",
                Severity.HIGH,
                entry.path,
                resolve_roles(entry.path, b"", role_globs),
                f"file could not be read: {type(exc).__name__}",
            )
        )
        return (
            FileEntry(
                path=entry.path,
                sha256=None,
                roles=resolve_roles(entry.path, b"", role_globs),
                skip_reason=SKIP_UNREADABLE,
            ),
            tuple(findings),
        )

    roles = resolve_roles(entry.path, head, role_globs)

    if size_bytes > policy.max_file_bytes:
        findings.append(
            _state(
                "skipped-oversize",
                Severity.HIGH if _sensitive(roles) else Severity.WARN,
                entry.path,
                roles,
                f"file is {size_bytes} bytes, over the {policy.max_file_bytes} byte limit, "
                f"and was not read past its first {HEAD_BYTES} bytes",
            )
        )
        return (
            FileEntry(
                path=entry.path,
                sha256=None,
                roles=roles,
                skip_reason=SKIP_OVERSIZE,
            ),
            tuple(findings),
        )

    data = head
    if size_bytes > len(head):
        with target.open("rb") as handle:
            data = handle.read(size_bytes + 1)
    if len(data) != size_bytes:
        # The file changed size while it was being read, in either direction. A shorter read
        # is the worse one: it is a clean prefix of the file, so hashing it would certify
        # bytes no revision contains while the report calls the file scanned. The bytes on
        # disk are untrusted either way, so keep what was read and record the mismatch as an
        # unreadable skip.
        findings.append(
            _state(
                "skipped-unreadable",
                Severity.HIGH,
                entry.path,
                roles,
                "file changed size while being read",
            )
        )
        return (
            FileEntry(
                path=entry.path,
                sha256=None,
                roles=roles,
                skip_reason=SKIP_UNREADABLE,
            ),
            tuple(findings),
        )

    sha256 = hashlib.sha256(data).hexdigest()

    magic_roles = roles_from_magic(head)
    if magic_roles:
        # Wasm, native binaries and archives are hashed and role-tagged, not decoded. Their
        # detector rules work on bytes, and running text rules over them would only produce
        # noise. The roles came from magic, so nothing here depends on the extension.
        #
        # The decision to leave the text pass is reported, not silent: a content magic role is
        # what removes a file from every text rule, and the report has to say so.
        findings.append(
            _state(
                "content-magic-role",
                Severity.INFO,
                entry.path,
                magic_roles,
                f"role {'/'.join(magic_roles)} comes from content magic, so the file was "
                "hashed but not scanned as text",
            )
        )
        return (
            FileEntry(path=entry.path, sha256=sha256, roles=roles),
            tuple(findings),
        )

    text, strict_failed = _decode(data)

    if "\x00" in text:
        findings.append(
            _state(
                "nul-in-text",
                Severity.HIGH,
                entry.path,
                roles,
                "NUL byte after BOM handling: the file is not the text its extension claims",
                evidence=_window(text, text.index("\x00")),
            )
        )

    if strict_failed:
        findings.append(
            _state(
                "non-utf8-text",
                Severity.HIGH if _sensitive(roles) else Severity.WARN,
                entry.path,
                roles,
                "bytes are not valid UTF-8 even after BOM handling",
            )
        )
        if not SCANNABLE_ROLES.intersection(roles):
            # No digest on a skipped entry: the model's skipped state means the file was not
            # decoded, and a digest here would make the report describe a file it never scanned.
            return (
                FileEntry(
                    path=entry.path,
                    sha256=None,
                    roles=roles,
                    skip_reason=SKIP_ENCODING,
                ),
                tuple(findings),
            )
        # Scannable role: the lenient decode stays in `text`, so content rules still see the
        # line that broke the encoding.

    return (
        FileEntry(
            path=entry.path,
            sha256=sha256,
            roles=roles,
            text=text,
        ),
        tuple(findings),
    )


def _window(text: str, index: int, width: int = 40) -> str:
    start = max(0, index - width)
    return text[start : index + width].replace("\x00", "<NUL>")


def collect(
    repo_root: Path,
    policy: Policy,
    role_globs: Mapping[str, tuple[str, ...]],
) -> Collection:
    """Read every tracked file once and resolve its roles.

    A file that cannot be read produces a finding and an entry with `text=None`; it never
    disappears from the report.
    """
    entries: list[FileEntry] = []
    findings: list[PendingFinding] = []
    for index_entry in list_tracked_files(repo_root):
        entry, entry_findings = _collect_one(repo_root, index_entry, policy, role_globs)
        entries.append(entry)
        findings.extend(entry_findings)
    return Collection(entries=tuple(entries), pending=tuple(findings))
