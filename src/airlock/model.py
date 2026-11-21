"""Core data models: severities, findings, rules, policy, manifest and report.

Field lists come from `ARCHITECTURE.md` section 7. This module imports nothing else from
the package (`project_structure.md` 3). Validation raises `ValueError`, which the CLI maps
to exit code 2; a model is never built from scanned content that failed to parse.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date
from enum import Enum, IntEnum

MAX_MESSAGE_CHARS = 200
MAX_EVIDENCE_CHARS = 200
FINGERPRINT_PREFIX = "sha256:"

# Exit codes (ARCHITECTURE.md 8).
EXIT_PASS = 0
EXIT_FINDINGS = 1
EXIT_CONFIG = 2
EXIT_INTERNAL = 3

SUPPORTED_POLICY_VERSION = 1
POLICY_TOP_LEVEL_KEYS = frozenset({"version", "policy", "soroban", "suppress"})
POLICY_SETTINGS_KEYS = frozenset(
    {"fail_on", "max_file_bytes", "line_cap", "tail_max_len", "tail_entropy"}
)
SOROBAN_KEYS = frozenset({"require_release_profile"})
SUPPRESSION_KEYS = frozenset({"rule", "path", "fingerprint", "reason", "expires"})
MANIFEST_TOP_LEVEL_KEYS = frozenset({"version", "wasm"})
WASM_ENTRY_KEYS = frozenset({"sha256", "paths", "origin", "source", "build", "note"})
WASM_ORIGINS = frozenset({"built", "vendored", "generated"})
PATTERN_KINDS = frozenset({"regex", "literal"})
SUPPRESSION_EXPIRY_DAYS = 30

#: A scan-level finding has no file to name. `require_repo_path` refuses an empty path, so the
#: repository itself is written as `.`.
REPO_PATH = "."

# Rule IDs for scanner states and skips rather than for data rules (ARCHITECTURE.md 8).
# Every one of these is a finding: no file is ever skipped silently.
STATE_RULE_IDS = frozenset(
    {
        "skipped-oversize",
        "skipped-unreadable",
        "skipped-symlink",
        "skipped-unmerged",
        "submodule-present",
        "nul-in-text",
        "non-utf8-text",
        "cfg-long-line",
        "detector-error",
        "history-rewritten",
        "no-trusted-base",
        "policy-changed",
        "policy-unknown-key",
        "suppression-expiring",
        "suppression-invalid",
        "untrusted-policy-source",
        "content-magic-role",
    }
)

_HEX64_RE = re.compile(r"\A[0-9a-f]{64}\Z")
# Leading letter, no trailing or doubled dash: rule ids are stable once shipped and an
# ambiguous id cannot be retired cleanly (project_structure.md 5).
_KEBAB_RE = re.compile(r"\A[a-z](?:[a-z0-9]*(?:-[a-z0-9]+)*)?\Z")
# The matcher (`roles._segment_pattern`) treats `*` and `?` as wildcards and escapes
# everything else, brackets included, so these two are the whole glob grammar.
_GLOB_CHARS = frozenset("*?")


class Severity(IntEnum):
    """Finding severity. Ordering matters: it drives fail_on and output order."""

    INFO = 0
    WARN = 1
    HIGH = 2

    @property
    def label(self) -> str:
        return self.name.lower()


class Mode(Enum):
    """How the scan was invoked, which decides where policy is read from (ARCHITECTURE.md 6.5)."""

    PR = "pr"
    PUSH = "push"
    FULL = "full"


def severity_from_name(name: str) -> Severity:
    """Parse a severity written in policy or rule files, case-insensitively."""
    try:
        return Severity[name.strip().upper()]
    except KeyError as exc:
        raise ValueError(f"unknown severity: {name!r}") from exc


def mode_from_name(name: str) -> Mode:
    """Parse a mode string passed on the command line or from the Action."""
    try:
        return Mode(name.strip().lower())
    except ValueError as exc:
        raise ValueError(f"unknown mode: {name!r}") from exc


def _require_fingerprint(value: str, field_name: str) -> None:
    if not value.startswith(FINGERPRINT_PREFIX):
        raise ValueError(f"{field_name} must start with {FINGERPRINT_PREFIX!r}")
    digest = value.removeprefix(FINGERPRINT_PREFIX)
    if not _HEX64_RE.match(digest):
        raise ValueError(f"{field_name} must be {FINGERPRINT_PREFIX} followed by 64 hex digits")


def require_repo_path(value: str, field_name: str) -> None:
    if not value:
        raise ValueError(f"{field_name} must be a non-empty repo-relative path")
    if value.startswith("/") or ".." in value.split("/") or "\\" in value:
        raise ValueError(f"{field_name} must be repo-relative with forward slashes: {value!r}")


def _require_exact_path(value: str, field_name: str) -> None:
    """Suppression paths are literal. A finding path is not checked this way: real files
    contain glob metacharacters, such as Next.js routes named `[id].tsx`, and a finding for
    one must still be constructible."""
    require_repo_path(value, field_name)
    if _GLOB_CHARS & set(value):
        raise ValueError(f"{field_name} must be an exact path, globs are not allowed: {value!r}")


@dataclass(frozen=True, slots=True)
class Finding:
    """One detection result. Attacker-controlled text lives only in `evidence`."""

    rule_id: str
    severity: Severity
    path: str
    line: int
    roles: tuple[str, ...]
    message: str
    evidence: str | None
    occurrence: int
    fingerprint: str
    suppressible: bool
    suppressed_by: str | None = None

    def __post_init__(self) -> None:
        if not _KEBAB_RE.match(self.rule_id):
            raise ValueError(f"rule_id must be kebab-case: {self.rule_id!r}")
        require_repo_path(self.path, "path")
        _require_fingerprint(self.fingerprint, "fingerprint")
        if self.line < 0:
            raise ValueError("line must be 0 for a file-level finding")
        if self.occurrence < 0:
            raise ValueError("occurrence must be a zero-based index")
        if len(self.message) > MAX_MESSAGE_CHARS:
            raise ValueError(f"message must be at most {MAX_MESSAGE_CHARS} characters")

    @property
    def sort_key(self) -> tuple[int, str, int, str]:
        """Deterministic output order: severity first so HIGH never sits below a WARN."""
        return (-int(self.severity), self.path, self.line, self.rule_id)


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Return findings in report order (ARCHITECTURE.md 6.6)."""
    return sorted(findings, key=lambda finding: finding.sort_key)


@dataclass(frozen=True, slots=True)
class RulePattern:
    """A rule's match body: one regex, or a set of literal strings applied per line."""

    kind: str
    value: tuple[str, ...]

    @classmethod
    def from_toml(cls, kind: str, value: str | list[str]) -> RulePattern:
        values = (value,) if isinstance(value, str) else tuple(value)
        return cls(kind=kind.strip().lower(), value=values)

    def __post_init__(self) -> None:
        if self.kind not in PATTERN_KINDS:
            raise ValueError(f"pattern kind must be one of {sorted(PATTERN_KINDS)}")
        if not self.value or not all(self.value):
            raise ValueError("pattern value must hold at least one non-empty string")
        if self.kind == "regex" and len(self.value) != 1:
            raise ValueError("a regex pattern holds exactly one expression")
        if self.kind == "regex":
            # Compiled once at load time so a broken rule is a config error, not a crash later.
            try:
                re.compile(self.value[0])
            except re.error as exc:
                raise ValueError(f"regex pattern does not compile: {exc}") from exc


@dataclass(frozen=True, slots=True)
class RuleTests:
    """Fixture builder names that must exist in `tests/fixtures/` (one positive, one negative)."""

    positive: str
    negative: str

    def __post_init__(self) -> None:
        if not self.positive or not self.negative:
            raise ValueError("every rule needs a positive and a negative fixture builder")


@dataclass(frozen=True, slots=True)
class Rule:
    """A validated entry from `rules/builtin/*.toml` (ARCHITECTURE.md 7.4)."""

    id: str
    title: str
    roles: tuple[str, ...]
    detector: str
    severity: Severity
    suppressible: bool
    rationale: str
    pattern: RulePattern | None
    tests: RuleTests

    def __post_init__(self) -> None:
        if not _KEBAB_RE.match(self.id):
            raise ValueError(f"rule id must be kebab-case: {self.id!r}")
        if not self.roles:
            raise ValueError(f"rule {self.id} must name at least one role")
        if not self.title or not self.rationale:
            raise ValueError(f"rule {self.id} needs a title and a rationale")
        if self.detector == "pattern":
            if self.pattern is None:
                raise ValueError(f"rule {self.id} uses detector 'pattern' but has no pattern")
        elif not self.detector.startswith("builtin:"):
            raise ValueError(f"rule {self.id} detector must be 'pattern' or 'builtin:<name>'")
        # A `builtin:` rule may carry a pattern: it is the text the code detector looks for, and
        # the engine never runs it, so the detector stays the only reporter of that line.


@dataclass(frozen=True, slots=True)
class Suppression:
    """A fingerprint-keyed suppression from `airlock.toml` (ARCHITECTURE.md 7.6)."""

    rule: str
    path: str
    fingerprint: str
    reason: str
    expires: date | None = None

    def __post_init__(self) -> None:
        if not _KEBAB_RE.match(self.rule):
            raise ValueError(f"suppression rule must be kebab-case: {self.rule!r}")
        _require_exact_path(self.path, "suppression path")
        _require_fingerprint(self.fingerprint, "suppression fingerprint")
        if not self.reason.strip():
            raise ValueError("a suppression must carry a reason")

    def expiring_soon(self, today: date) -> bool:
        """True when the entry is within the warning window, UTC dates only."""
        if self.expires is None:
            return False
        return 0 <= (self.expires - today).days <= SUPPRESSION_EXPIRY_DAYS

    def expired(self, today: date) -> bool:
        return self.expires is not None and self.expires < today


@dataclass(frozen=True, slots=True)
class ReleaseProfile:
    """Expected `[profile.release]` values for a contract crate, read from policy only."""

    overflow_checks: bool = True
    panic: str = "abort"
    lto: bool = True
    codegen_units: int = 1
    debug_assertions: bool = False


@dataclass(frozen=True, slots=True)
class SorobanPolicy:
    """Soroban expectations for `soroban_profile` (P1). Never hardcoded in a detector."""

    require_release_profile: ReleaseProfile = ReleaseProfile()


@dataclass(frozen=True, slots=True)
class Policy:
    """Resolved `airlock.toml`. Bootstrap defaults are used when no trusted base has one."""

    version: int = SUPPORTED_POLICY_VERSION
    fail_on: Severity = Severity.HIGH
    max_file_bytes: int = 5_000_000
    line_cap: int = 20_000
    tail_max_len: int = 2_000
    tail_entropy: float = 4.5
    soroban: SorobanPolicy = SorobanPolicy()
    suppressions: tuple[Suppression, ...] = ()

    def __post_init__(self) -> None:
        if self.version != SUPPORTED_POLICY_VERSION:
            raise ValueError(
                f"unsupported policy version {self.version}, this build reads "
                f"version {SUPPORTED_POLICY_VERSION}"
            )
        if self.max_file_bytes <= 0 or self.line_cap <= 0:
            raise ValueError("size limits must be positive")
        if self.tail_max_len <= 0:
            raise ValueError("tail_max_len must be positive")


#: Defaults applied when a push has no reachable base (new branch). Fail closed: the scan
#: still runs at full strength, and `no-trusted-base` is reported.
BOOTSTRAP_POLICY = Policy()


@dataclass(frozen=True, slots=True)
class WasmEntry:
    """One known Wasm artifact, keyed by hash so a rename is a WARN not a HIGH."""

    sha256: str
    paths: tuple[str, ...]
    origin: str
    source: str
    build: str
    note: str = ""

    def __post_init__(self) -> None:
        if not _HEX64_RE.match(self.sha256):
            raise ValueError("wasm entry sha256 must be 64 hex digits")
        if self.origin not in WASM_ORIGINS:
            raise ValueError(f"wasm origin must be one of {sorted(WASM_ORIGINS)}")
        if not self.paths:
            raise ValueError("wasm entry must list at least one path")
        for path in self.paths:
            require_repo_path(path, "wasm path")


@dataclass(frozen=True, slots=True)
class Manifest:
    """Resolved `wasm-manifest.toml`."""

    version: int = SUPPORTED_POLICY_VERSION
    entries: tuple[WasmEntry, ...] = ()

    def __post_init__(self) -> None:
        if self.version != SUPPORTED_POLICY_VERSION:
            raise ValueError(f"unsupported manifest version {self.version}")
        seen: set[str] = set()
        for entry in self.entries:
            if entry.sha256 in seen:
                raise ValueError(f"duplicate wasm entry for {entry.sha256}")
            seen.add(entry.sha256)


EMPTY_MANIFEST = Manifest()


@dataclass(frozen=True, slots=True)
class FileEntry:
    """One tracked file as the collector produced it (task 2.13, `ARCHITECTURE.md` 7.9).

    `sha256` and `text` are absent whenever the collector could not read the whole file; the
    matching skip finding is why the scan is still fail-closed. The byte size is deliberately not
    carried: the collector needs it to decide whether a file is oversize or only partly read, and
    it says so in those findings, but no rule is a function of it. `len(text)` is the size of any
    file whose text is here.

    Three states, and they are mutually exclusive: read (`sha256` and `text`), hashed but not
    decoded (`sha256` only) and skipped (`skip_reason` only). A skipped entry carrying text would
    let a detector scan bytes the report says were never read, which is the inversion skip
    findings exist to prevent, so the combinations are rejected here instead of trusted to the
    collector.
    """

    path: str
    sha256: str | None
    roles: tuple[str, ...]
    text: str | None = None
    skip_reason: str | None = None

    def __post_init__(self) -> None:
        require_repo_path(self.path, "path")
        if self.sha256 is not None and not _HEX64_RE.match(self.sha256):
            raise ValueError("file sha256 must be 64 hex digits")
        if self.text is not None and self.skip_reason is not None:
            raise ValueError(
                f"{self.path}: a skipped entry (skip_reason {self.skip_reason!r}) cannot carry text"
            )
        if self.text is not None and self.sha256 is None:
            raise ValueError(f"{self.path}: text requires a sha256 digest")
        if self.skip_reason is not None and self.sha256 is not None:
            raise ValueError(
                f"{self.path}: a skipped entry (skip_reason {self.skip_reason!r}) cannot carry "
                "a sha256 digest"
            )
        if self.skip_reason is None and self.sha256 is None:
            raise ValueError(
                f"{self.path}: an entry with neither text, a sha256 digest nor a skip_reason "
                "would be invisible to the report"
            )


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Everything a detector may read (task 2.13, `ARCHITECTURE.md` 7.9).

    Four fields, because that is what a rule needs: the collected files, the trusted policy, the
    trusted manifest and the loaded rule data. Detectors never fetch more and never get the trust
    model itself: `mode` decides which base the policy came from, which is settled before this
    exists, and is then recorded on the report. A rule that genuinely needs the mode will add it
    back with a task that says why.
    """

    entries: tuple[FileEntry, ...]
    policy: Policy
    manifest: Manifest
    rules: tuple[Rule, ...]


@dataclass(frozen=True, slots=True)
class ScanReport:
    """The whole scan result, serialized by the json reporter.

    `files_indexed` is the git index total, and the two counters partition it: an entry with a
    skip reason is skipped even when it carries a digest (an encoding skip is hashed before it is
    decoded), and only a digest with no skip reason counts as scanned. `run_scan` refuses a report
    whose counters do not add up, so no entry leaves the report unaccounted for.
    """

    tool_version: str
    mode: Mode
    repo_head: str
    base: str | None
    files_indexed: int
    files_scanned: int
    files_skipped: Mapping[str, int]
    findings: tuple[Finding, ...]
    suppressed: tuple[Finding, ...] = ()
    exit_code: int = EXIT_PASS
