"""Trusted-base resolution, the policy and manifest loaders and suppression application.
Tasks 2.7 and 2.8 (`ARCHITECTURE.md` 6.5 and 7.6).

Policy (`airlock.toml`, including its suppressions) and `wasm-manifest.toml` are read from a ref
the change under scan cannot edit: the pull request base in `pr` mode, `github.event.before` in
`push` mode. Only `full` mode reads the working tree, and it says so in a finding, because that
is the one mode where the change can approve itself.

The fallbacks are strict rather than convenient. A new branch, a rewritten history and a base
that carries no policy file all scan against `BOOTSTRAP_POLICY` and an empty manifest: shipped
defaults, no suppressions to inherit. Nothing here falls back to HEAD.

Invalid TOML, an unsupported or missing `version` and an unresolvable `pr` base raise
`ValueError`, which the CLI turns into exit 2. Unknown keys are the exception: they come back as
`policy-unknown-key` findings, because a misspelled key leaves its setting at the default and the
finding is the only place that says so. A protected file at the base over `MAX_CONFIG_BYTES` is
refused before it is decoded, reported as `skipped-unreadable` and the scan continues on the
shipped defaults: a huge config must not become a parse failure with no report at all.

Like `collector.py`, this is one of the two modules allowed to run `subprocess`, always through
`git_text` with a fixed argument list and never through a shell.
"""

from __future__ import annotations

import hashlib
import tomllib
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from pathlib import Path

from .collector import git_text
from .fingerprint import PendingFinding, number_occurrences, truncate_evidence
from .model import (
    BOOTSTRAP_POLICY,
    EMPTY_MANIFEST,
    MANIFEST_TOP_LEVEL_KEYS,
    MAX_MESSAGE_CHARS,
    POLICY_SETTINGS_KEYS,
    POLICY_TOP_LEVEL_KEYS,
    REPO_PATH,
    SOROBAN_KEYS,
    STATE_RULE_IDS,
    SUPPORTED_POLICY_VERSION,
    SUPPRESSION_KEYS,
    WASM_ENTRY_KEYS,
    Finding,
    Manifest,
    Mode,
    Policy,
    ReleaseProfile,
    Rule,
    Severity,
    SorobanPolicy,
    Suppression,
    WasmEntry,
    require_repo_path,
    severity_from_name,
    sort_findings,
)

#: The two protected files, named here once so a message and a test never disagree on the spelling.
POLICY_FILENAME = "airlock.toml"
MANIFEST_FILENAME = "wasm-manifest.toml"

#: GitHub sends this as `github.event.before` for the first push to a branch.
ZERO_SHA = "0" * 40

#: A config file past this size is not a configuration file. Checked before parsing, and
#: deliberately not `max_file_bytes`, which lives in the file being read.
MAX_CONFIG_BYTES = 1_000_000

HISTORY_REWRITTEN_RULE_ID = "history-rewritten"
NO_TRUSTED_BASE_RULE_ID = "no-trusted-base"
POLICY_CHANGED_RULE_ID = "policy-changed"
UNTRUSTED_SOURCE_RULE_ID = "untrusted-policy-source"
UNKNOWN_KEY_RULE_ID = "policy-unknown-key"
SUPPRESSION_INVALID_RULE_ID = "suppression-invalid"
SUPPRESSION_EXPIRING_RULE_ID = "suppression-expiring"
SKIP_UNREADABLE_RULE_ID = "skipped-unreadable"

SUPPRESSION_REQUIRED = SUPPRESSION_KEYS - {"expires"}
WASM_REQUIRED = WASM_ENTRY_KEYS - {"note"}

#: `[soroban] require_release_profile` keys, spelled the way Cargo spells them.
_RELEASE_PROFILE_KEYS = frozenset(
    {"overflow-checks", "panic", "lto", "codegen-units", "debug-assertions"}
)

HEX_DIGITS = frozenset("0123456789abcdef")


@dataclass(frozen=True, slots=True)
class TrustedConfig:
    """What the scan runs on, plus the findings that say where it came from.

    `base` is the commit the two files were read from, or None when the shipped defaults were
    used. It is the value that belongs in `ScanContext.base`.
    """

    policy: Policy
    manifest: Manifest
    base: str | None
    pending: tuple[PendingFinding, ...]


def resolve_policy(
    repo_root: Path,
    mode: Mode,
    head: str,
    *,
    base: str | None = None,
    before: str | None = None,
    policy_path: str = POLICY_FILENAME,
    manifest_path: str = MANIFEST_FILENAME,
) -> TrustedConfig:
    """Read the protected files from the trusted base and report every way it is weaker.

    Raises `ValueError` for a `pr` base that cannot be resolved, so a scan can never end up
    judged by the policy the change under review wrote.
    """
    require_repo_path(policy_path, "policy path")
    require_repo_path(manifest_path, "manifest path")

    if mode is Mode.FULL:
        return _from_working_tree(repo_root, policy_path, manifest_path)

    if not _is_sha(head):
        raise ValueError(f"HEAD is not a commit SHA: {_short(head)!r}")
    ref, pending = _trusted_ref(repo_root, mode, head, base, before)
    if ref is None:
        return TrustedConfig(BOOTSTRAP_POLICY, EMPTY_MANIFEST, None, pending)

    policy, policy_pending = _policy_at_base(repo_root, ref, head, policy_path)
    manifest, manifest_pending = _manifest_at_base(repo_root, ref, head, manifest_path)
    return TrustedConfig(
        policy=policy,
        manifest=manifest,
        base=ref,
        pending=pending + policy_pending + manifest_pending,
    )


def _trusted_ref(
    repo_root: Path,
    mode: Mode,
    head: str,
    base: str | None,
    before: str | None,
) -> tuple[str | None, tuple[PendingFinding, ...]]:
    """The commit to read policy from, or None with the finding that explains why there is none."""
    if mode is Mode.PR:
        if not base:
            raise ValueError(
                "pr mode needs the pull request base SHA. The policy is never read from the "
                "change under review, so there is nothing to fall back to."
            )
        if not _is_sha(base):
            raise ValueError(f"base is not a commit SHA: {_short(base)!r}")
        if not _is_commit(repo_root, base):
            raise ValueError(
                f"base {_short(base)} is not reachable in this checkout. The workflow needs "
                "actions/checkout with fetch-depth: 0, or a depth that reaches the base commit."
            )
        return base, ()

    if not before or before == ZERO_SHA:
        return None, (
            _state(
                NO_TRUSTED_BASE_RULE_ID,
                Severity.WARN,
                REPO_PATH,
                "this push created the branch, so no earlier commit holds "
                f"{POLICY_FILENAME} or {MANIFEST_FILENAME}: the shipped defaults and no "
                "suppressions apply",
                evidence="new-branch",
            ),
        )

    reason = _unreachable_reason(repo_root, before, head)
    if reason is not None:
        return None, (
            _state(
                HISTORY_REWRITTEN_RULE_ID,
                Severity.HIGH,
                REPO_PATH,
                f"the pushed `before` {_short(before)} is not an ancestor of HEAD, so this push "
                "rewrote history: the shipped defaults and no suppressions apply instead of the "
                "base policy",
                evidence=reason,
            ),
        )
    return before, ()


def _unreachable_reason(repo_root: Path, before: str, head: str) -> str | None:
    """Why `before` cannot serve as the base, or None when it can."""
    if not _is_sha(before):
        return f"`before` is not a commit SHA: {before[:80]!r}"
    try:
        git_text(repo_root, "merge-base", "--is-ancestor", before, head)
    except ValueError as exc:
        return str(exc)
    return None


def _is_commit(repo_root: Path, sha: str) -> bool:
    try:
        git_text(repo_root, "cat-file", "-e", f"{sha}^{{commit}}")
    except ValueError:
        return False
    return True


def _is_sha(value: str) -> bool:
    return len(value) == 40 and HEX_DIGITS.issuperset(value)


def _short(value: str | None) -> str:
    if value is None:
        return "(none)"
    return value[:12]


@dataclass(frozen=True, slots=True)
class _BaseBlob:
    """One protected file at a commit.

    `text` is None when the commit does not carry the path. `oversize` is the blob's size in
    bytes when the commit does carry it but the blob is too large to be a config file. The two
    are separate because "the base has no such file" means the change added it, while "the
    base's copy cannot be read" must never be reported that way.
    """

    text: str | None = None
    oversize: int | None = None

    @property
    def absent(self) -> bool:
        return self.text is None and self.oversize is None


def _blob_at(repo_root: Path, ref: str, path: str) -> _BaseBlob:
    """One file at a commit: its text, that it is absent, or that it is too large to read.

    The size is asked for before the content, so a base holding a multi-megabyte "config" is
    never decoded or handed to `tomllib`. `MAX_CONFIG_BYTES` is the ceiling `full` mode already
    applies to the working tree, and the trusted base was the one config read without one: a
    change could commit a huge policy, have it become the base later, and turn the next run into
    a parse failure with no report at all.
    """
    if not git_text(repo_root, "ls-tree", "--name-only", ref, "--", path):
        return _BaseBlob()
    size = int(git_text(repo_root, "cat-file", "-s", f"{ref}:{path}"))
    if size > MAX_CONFIG_BYTES:
        return _BaseBlob(oversize=size)
    return _BaseBlob(text=git_text(repo_root, "show", f"{ref}:{path}"))


def _oversize_base(path: str, size: int, ref: str) -> PendingFinding:
    """The base's copy is over the limit, so the shipped defaults apply in its place."""
    return _state(
        SKIP_UNREADABLE_RULE_ID,
        Severity.HIGH,
        path,
        f"{path} at base {_short(ref)} is {size} bytes, over the {MAX_CONFIG_BYTES} byte "
        "limit for a config file, so it was not read and the shipped defaults apply in its place",
        evidence=f"{path} {size} bytes at base {_short(ref)}",
    )


def _policy_at_base(
    repo_root: Path, ref: str, head: str, path: str
) -> tuple[Policy, tuple[PendingFinding, ...]]:
    base = _blob_at(repo_root, ref, path)
    if base.oversize is not None:
        # The base's copy cannot be read, so the change's copy is not read either: counting a
        # diff against a file that was never loaded would claim a change nobody saw, and parsing
        # the change's copy is the bypass this path exists to prevent.
        return BOOTSTRAP_POLICY, (_oversize_base(path, base.oversize, ref),)
    head_blob = _blob_at(repo_root, head, path)
    changed = _change_finding(path, "the policy", base, head_blob, ref)
    pending = () if changed is None else (changed,)
    if base.text is None:
        # The base has no policy file, so the change under review is the first to carry one. It
        # is reported and ignored: reading it would let the change set its own rules.
        return BOOTSTRAP_POLICY, pending
    policy, key_pending = policy_from_toml(base.text, path=path, source=f"base {_short(ref)}")
    return policy, pending + key_pending


def _manifest_at_base(
    repo_root: Path, ref: str, head: str, path: str
) -> tuple[Manifest, tuple[PendingFinding, ...]]:
    base = _blob_at(repo_root, ref, path)
    if base.oversize is not None:
        return EMPTY_MANIFEST, (_oversize_base(path, base.oversize, ref),)
    head_blob = _blob_at(repo_root, head, path)
    changed = _change_finding(path, "the Wasm manifest", base, head_blob, ref)
    pending = () if changed is None else (changed,)
    if base.text is None:
        return EMPTY_MANIFEST, pending
    manifest, key_pending = manifest_from_toml(base.text, path=path, source=f"base {_short(ref)}")
    return manifest, pending + key_pending


def _change_finding(
    path: str, what: str, base: _BaseBlob, head: _BaseBlob, ref: str
) -> PendingFinding | None:
    summary = _change_summary(base, head)
    if summary is None:
        return None
    return _state(
        POLICY_CHANGED_RULE_ID,
        Severity.WARN,
        path,
        f"{what} changed in this change, and this scan used the version at base "
        f"{_short(ref)}: {summary}",
        evidence=f"{path} {summary}",
    )


def _change_summary(base: _BaseBlob, head: _BaseBlob) -> str | None:
    """How the head copy differs, as line counts. None when it does not.

    Content stays out of the summary: it is a message, and the diff of a policy edit is the
    attacker's own text. The two copies are already read from git, so no `git diff` run is
    needed to count them. A head copy over `MAX_CONFIG_BYTES` was not read, so the summary says
    that rather than counting lines that were never seen.
    """
    if base.absent and head.absent:
        return None
    if base.absent:
        return "added by this change"
    if head.absent:
        return "deleted by this change"
    if head.oversize is not None:
        # The decisive phrase comes first: a message is capped at 200 characters, and the policy
        # prefix already spends about half of that before the summary starts.
        return (
            "no comparison was made: "
            f"the copy in this change is {head.oversize} bytes, over the {MAX_CONFIG_BYTES} "
            "byte limit"
        )
    if base.text == head.text:
        return None
    before = Counter((base.text or "").splitlines())
    after = Counter((head.text or "").splitlines())
    return (
        f"{sum((after - before).values())} line(s) added, {sum((before - after).values())} removed"
    )


def _from_working_tree(repo_root: Path, policy_path: str, manifest_path: str) -> TrustedConfig:
    """`full` mode: read what is on disk, then state the weaker guarantee (6.5)."""
    policy_text = _working_text(repo_root, policy_path)
    manifest_text = _working_text(repo_root, manifest_path)

    policy_pending: tuple[PendingFinding, ...] = ()
    manifest_pending: tuple[PendingFinding, ...] = ()
    if policy_text is None:
        policy = BOOTSTRAP_POLICY
    else:
        policy, policy_pending = policy_from_toml(
            policy_text, path=policy_path, source="working tree"
        )
    if manifest_text is None:
        manifest, manifest_pending = EMPTY_MANIFEST, ()
    else:
        manifest, manifest_pending = manifest_from_toml(
            manifest_text, path=manifest_path, source="working tree"
        )

    pending = (
        _untrusted_source(policy_path, policy_text is not None),
        _untrusted_source(manifest_path, manifest_text is not None),
    )
    return TrustedConfig(
        policy=policy,
        manifest=manifest,
        base=None,
        pending=pending + policy_pending + manifest_pending,
    )


def _untrusted_source(path: str, present: bool) -> PendingFinding:
    return _state(
        UNTRUSTED_SOURCE_RULE_ID,
        Severity.INFO,
        path,
        f"{path} was read from the working tree, which the change under scan can edit"
        if present
        else f"no {path} in the working tree, so the shipped defaults apply",
        evidence="working-tree" if present else "absent",
    )


def _working_text(repo_root: Path, path: str) -> str | None:
    target = repo_root / path
    try:
        data = target.read_bytes()
    except OSError:
        return None
    if len(data) > MAX_CONFIG_BYTES:
        raise ValueError(
            f"{path} is {len(data)} bytes, over the {MAX_CONFIG_BYTES} byte limit for a config file"
        )
    return data.decode("utf-8", errors="replace")


def policy_from_toml(
    text: str, *, path: str, source: str
) -> tuple[Policy, tuple[PendingFinding, ...]]:
    """Parse `airlock.toml`. Every default comes from `BOOTSTRAP_POLICY`, not a second literal."""
    document = _document(text, path)
    unknown: list[str] = []
    _unknown_keys(document, POLICY_TOP_LEVEL_KEYS, "", unknown)
    version = _require_version(document, path)

    settings = _table(document, "policy", path)
    _unknown_keys(settings, POLICY_SETTINGS_KEYS, "policy.", unknown)
    soroban_table = _table(document, "soroban", path)
    _unknown_keys(soroban_table, SOROBAN_KEYS, "soroban.", unknown)

    policy = Policy(
        version=version,
        fail_on=_opt_severity(
            settings.get("fail_on"), BOOTSTRAP_POLICY.fail_on, "policy.fail_on", path
        ),
        max_file_bytes=_opt_int(
            settings.get("max_file_bytes"),
            BOOTSTRAP_POLICY.max_file_bytes,
            "policy.max_file_bytes",
            path,
        ),
        line_cap=_opt_int(
            settings.get("line_cap"), BOOTSTRAP_POLICY.line_cap, "policy.line_cap", path
        ),
        tail_max_len=_opt_int(
            settings.get("tail_max_len"), BOOTSTRAP_POLICY.tail_max_len, "policy.tail_max_len", path
        ),
        tail_entropy=_opt_float(
            settings.get("tail_entropy"), BOOTSTRAP_POLICY.tail_entropy, "policy.tail_entropy", path
        ),
        soroban=_soroban_policy(soroban_table, path, unknown),
        suppressions=_suppressions(document, path, unknown),
    )
    return policy, _unknown_findings(path, source, unknown)


def manifest_from_toml(
    text: str, *, path: str, source: str
) -> tuple[Manifest, tuple[PendingFinding, ...]]:
    """Parse `wasm-manifest.toml` (`ARCHITECTURE.md` 7.7)."""
    document = _document(text, path)
    unknown: list[str] = []
    _unknown_keys(document, MANIFEST_TOP_LEVEL_KEYS, "", unknown)
    version = _require_version(document, path)

    entries: list[WasmEntry] = []
    for index, table in enumerate(_tables(document, "wasm", path), start=1):
        context = f"{path}: [[wasm]] #{index}"
        _unknown_keys(table, WASM_ENTRY_KEYS, f"wasm[{index}].", unknown)
        _require_keys(table, WASM_REQUIRED, context)
        entries.append(
            WasmEntry(
                sha256=_string(table["sha256"], "sha256", context),
                paths=_string_list(table["paths"], "paths", context),
                origin=_string(table["origin"], "origin", context),
                source=_string(table["source"], "source", context),
                build=_string(table["build"], "build", context),
                note=_opt_string(table.get("note"), "", "note", context),
            )
        )
    return Manifest(version=version, entries=tuple(entries)), _unknown_findings(
        path, source, unknown
    )


def _soroban_policy(table: Mapping[str, object], path: str, unknown: list[str]) -> SorobanPolicy:
    raw = table.get("require_release_profile")
    if raw is None:
        return SorobanPolicy()
    if not isinstance(raw, Mapping):
        raise ValueError(f"{path}: [soroban] require_release_profile must be a table")
    prefix = "soroban.require_release_profile."
    _unknown_keys(raw, frozenset(_RELEASE_PROFILE_KEYS), prefix, unknown)
    defaults = BOOTSTRAP_POLICY.soroban.require_release_profile
    return SorobanPolicy(
        require_release_profile=ReleaseProfile(
            overflow_checks=_opt_bool(
                raw.get("overflow-checks"),
                defaults.overflow_checks,
                f"{prefix}overflow-checks",
                path,
            ),
            panic=_opt_string(raw.get("panic"), defaults.panic, f"{prefix}panic", path),
            lto=_opt_bool(raw.get("lto"), defaults.lto, f"{prefix}lto", path),
            codegen_units=_opt_int(
                raw.get("codegen-units"), defaults.codegen_units, f"{prefix}codegen-units", path
            ),
            debug_assertions=_opt_bool(
                raw.get("debug-assertions"),
                defaults.debug_assertions,
                f"{prefix}debug-assertions",
                path,
            ),
        )
    )


def _suppressions(
    document: Mapping[str, object], path: str, unknown: list[str]
) -> tuple[Suppression, ...]:
    suppressions: list[Suppression] = []
    for index, table in enumerate(_tables(document, "suppress", path), start=1):
        context = f"{path}: [[suppress]] #{index}"
        _unknown_keys(table, SUPPRESSION_KEYS, f"suppress[{index}].", unknown)
        _require_keys(table, SUPPRESSION_REQUIRED, context)
        suppressions.append(
            Suppression(
                rule=_string(table["rule"], "rule", context),
                path=_string(table["path"], "path", context),
                fingerprint=_string(table["fingerprint"], "fingerprint", context),
                reason=_string(table["reason"], "reason", context),
                expires=_expires(table.get("expires"), context),
            )
        )
    return tuple(suppressions)


def _expires(value: object, context: str) -> date | None:
    """A UTC calendar date. A string is accepted too, because the documented example writes one."""
    if value is None:
        return None
    if isinstance(value, datetime):
        raise ValueError(f"{context}: expires must be a date, not a date and a time")
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError as exc:
            raise ValueError(f"{context}: expires is not a YYYY-MM-DD date: {value!r}") from exc
    raise ValueError(f"{context}: expires must be a date")


def _document(text: str, path: str) -> Mapping[str, object]:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"cannot parse {path}: {exc}") from exc


def _require_version(document: Mapping[str, object], path: str) -> int:
    """Required, because a file that omits `version` must not be read as the supported one."""
    if "version" not in document:
        raise ValueError(f"{path}: version is required")
    value = document["version"]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{path}: version must be a whole number")
    if value != SUPPORTED_POLICY_VERSION:
        raise ValueError(
            f"{path}: version {value} is unsupported, this build reads version "
            f"{SUPPORTED_POLICY_VERSION}"
        )
    return value


def _table(document: Mapping[str, object], key: str, path: str) -> Mapping[str, object]:
    value = document.get(key)
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{path}: [{key}] must be a table")
    return value


def _tables(
    document: Mapping[str, object], key: str, path: str
) -> tuple[Mapping[str, object], ...]:
    value = document.get(key)
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{path}: '[[{key}]]' must be a list of tables")
    tables: list[Mapping[str, object]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError(f"{path}: '[[{key}]]' entries must be tables")
        tables.append(item)
    return tuple(tables)


def _require_keys(table: Mapping[str, object], required: Iterable[str], context: str) -> None:
    missing = sorted(set(required) - set(table))
    if missing:
        raise ValueError(f"{context}: missing required key(s) {', '.join(missing)}")


def _unknown_keys(
    table: Mapping[str, object], allowed: frozenset[str], prefix: str, found: list[str]
) -> None:
    """Record the keys no loader reads. Silently dropping one is how a setting stops existing."""
    found.extend(f"{prefix}{name}" for name in sorted(set(table) - allowed))


def _unknown_findings(path: str, source: str, keys: Iterable[str]) -> tuple[PendingFinding, ...]:
    return tuple(
        _state(
            UNKNOWN_KEY_RULE_ID,
            Severity.WARN,
            path,
            f"{path} read from {source} sets {key}, which this version of airlock does not read: "
            "that setting keeps its default",
            evidence=key,
        )
        for key in keys
    )


def _string(value: object, field: str, context: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{context}: {field} must be a string")
    return value


def _string_list(value: object, field: str, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{context}: {field} must be a non-empty list of strings")
    return tuple(value)


def _opt_string(value: object, default: str, field: str, context: str) -> str:
    return default if value is None else _string(value, field, context)


def _opt_int(value: object, default: int, field: str, context: str) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{context}: {field} must be a whole number")
    if value <= 0:
        raise ValueError(f"{context}: {field} must be greater than zero")
    return value


def _opt_float(value: object, default: float, field: str, context: str) -> float:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{context}: {field} must be a number")
    if value <= 0:
        raise ValueError(f"{context}: {field} must be greater than zero")
    return float(value)


def _opt_bool(value: object, default: bool, field: str, context: str) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{context}: {field} must be a boolean")
    return value


def _opt_severity(value: object, default: Severity, field: str, context: str) -> Severity:
    if value is None:
        return default
    return severity_from_name(_string(value, field, context))


def _state(
    rule_id: str, severity: Severity, path: str, message: str, evidence: str
) -> PendingFinding:
    """A scanner-state finding: file-level, ours to word, and never suppressible."""
    return PendingFinding(
        rule_id=rule_id,
        severity=severity,
        path=path,
        line=0,
        roles=(),
        message=message[:MAX_MESSAGE_CHARS],
        evidence=truncate_evidence(evidence),
        suppressible=False,
    )


@dataclass(frozen=True, slots=True)
class Suppressed:
    """Findings after suppression: what gets reported, and what a policy entry covers.

    Both tuples are in report order. The suppressed ones stay in the result because a reader has
    to be able to see what the policy hid, and `Finding.suppressed_by` carries the entry's reason.
    """

    findings: tuple[Finding, ...]
    suppressed: tuple[Finding, ...]


def suppress(
    findings: Iterable[Finding],
    policy: Policy,
    rules: Iterable[Rule],
    *,
    policy_path: str = POLICY_FILENAME,
    today: date | None = None,
) -> Suppressed:
    """Apply the trusted policy's suppressions to numbered findings (`ARCHITECTURE.md` 7.6).

    Matching needs rule, path and fingerprint together, so a copy of a suppressed line keeps its
    own occurrence index and is not covered by its twin's entry (B5). An expired entry simply
    stops applying and nothing extra is said about the date passing (B10): a build should not go
    red on a calendar, and the returning finding is the signal.

    An entry that cannot apply, because its rule is missing or non-suppressible, is a HIGH
    `suppression-invalid` and covers nothing. Reporting the mistake and honouring it as well would
    hide the finding the report is about, so validity is decided before matching.

    This runs after numbering and before the reporters, because a fingerprint is what is matched.
    """
    day = today or datetime.now(UTC).date()
    by_rule = {rule.id: rule for rule in rules}
    entries = tuple(policy.suppressions)
    problems = [_entry_problem(entry, by_rule) for entry in entries]
    first_for: dict[tuple[str, str, str], int] = {}
    for position, entry in enumerate(entries):
        if problems[position] is not None:
            continue
        key = (entry.rule, entry.path, entry.fingerprint)
        applied = first_for.get(key)
        if applied is not None:
            # The usual way to renew an entry is to copy it and move the date, which leaves two
            # entries for one key. The first one keeps deciding, so saying so is the only way
            # the author learns the renewed date has no effect.
            problems[position] = (
                f"duplicate: entry #{applied + 1} is consulted first, and this entry "
                f"#{position + 1} covers nothing"
            )
            continue
        first_for[key] = position

    active: list[Finding] = []
    covered: list[Finding] = []
    for finding in findings:
        entry_at = first_for.get((finding.rule_id, finding.path, finding.fingerprint))
        if entry_at is None:
            active.append(finding)
            continue
        entry = entries[entry_at]
        if entry.expired(day) or not finding.suppressible:
            active.append(finding)
            continue
        covered.append(replace(finding, suppressed_by=entry.reason))

    pending: list[PendingFinding] = []
    for position, entry in enumerate(entries):
        problem = problems[position]
        if problem is not None:
            pending.append(
                _state(
                    SUPPRESSION_INVALID_RULE_ID,
                    Severity.HIGH,
                    policy_path,
                    f"{policy_path} suppresses {entry.rule} at {entry.path}, and it does not "
                    f"apply: {problem}",
                    entry.fingerprint,
                )
            )
            continue
        if entry.expires is not None and entry.expiring_soon(day):
            expires = entry.expires
            days = (expires - day).days
            when = "expires today" if days == 0 else f"expires in {days} day(s) on {expires}"
            pending.append(
                _state(
                    SUPPRESSION_EXPIRING_RULE_ID,
                    Severity.WARN,
                    policy_path,
                    f"{policy_path}: the suppression of {entry.rule} at {entry.path} {when}. "
                    "Renew it or the finding returns.",
                    entry.fingerprint,
                )
            )

    return Suppressed(
        findings=tuple(sort_findings([*active, *number_occurrences(pending)])),
        suppressed=tuple(sort_findings(covered)),
    )


def _entry_problem(entry: Suppression, by_rule: Mapping[str, Rule]) -> str | None:
    """Why this entry can never apply, or None when it can.

    Checked against the rule data rather than against a finding, so a suppression of a rule that
    was made non-suppressible, or renamed, is reported even on a scan where it matched nothing.
    """
    if entry.rule in STATE_RULE_IDS:
        return "scanner-state findings cannot be suppressed"
    rule = by_rule.get(entry.rule)
    if rule is None:
        return "no rule with that id is loaded in this build"
    if not rule.suppressible:
        return f"rule {entry.rule} is not suppressible"
    return None


# ---------------------------------------------------------------------------------------------
# Manifest maintenance: `airlock manifest add` and `manifest check` (task 3.5).
#
# There is no TOML writer in the standard library, so the writer here is hand-written. It is
# deliberately total: the file it emits is fully determined by the parsed `Manifest`, which is
# what makes `add` idempotent and `parse(render(x)) == parse(x)` testable. Anything the loader
# could not express as data (a comment inside an entry block, an unknown key) is refused rather
# than silently dropped, because a tool that rewrites a protected file must not lose a line of it.
# ---------------------------------------------------------------------------------------------

#: Content magic a manifest entry vouches for. `ARCHITECTURE.md` 6.2 identifies Wasm by these four
#: bytes, so an entry for any other content would claim a provenance the file cannot have.
WASM_MAGIC = b"\x00asm"

#: `add` cannot hash a file the scanner would not read. The ceiling is the collector's own shipped
#: default, so anything `add` accepts is something `collect` will account for later.
MAX_ARTIFACT_BYTES = BOOTSTRAP_POLICY.max_file_bytes

#: Written when the repository has no manifest yet. It states the two-step flow, because the
#: trusted base is the reason a PR cannot add its own artifact and its own entry at once.
NEW_MANIFEST_HEADER = f"""\
# Airlock's Wasm manifest, keyed by SHA-256 (ARCHITECTURE.md 7.7). Protected path.
#
# Adding an artifact is a two-step flow: land the manifest change in its own pull request first,
# then the pull request that adds the file. Policy is read from the trusted base, so a pull
# request carrying both fails until the manifest merge is the base.

version = {SUPPORTED_POLICY_VERSION}
"""

_TOML_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _toml_string(value: str) -> str:
    """Quote one string as a TOML basic string, escaping everything a path can contain."""
    chars: list[str] = []
    for char in value:
        escaped = _TOML_ESCAPES.get(char)
        if escaped is not None:
            chars.append(escaped)
        elif ord(char) < 0x20:
            chars.append(f"\\u{ord(char):04x}")
        else:
            chars.append(char)
    return '"' + "".join(chars) + '"'


def _split_entries(text: str) -> tuple[str, list[str]]:
    """Header lines and entry-block lines, cut at the first `[[wasm]]` table header."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.lstrip().startswith("[[wasm"):
            return "\n".join(lines[:index]), lines[index:]
    return text, []


def _refuse_losing(text: str, path: str) -> None:
    """Refuse to rewrite a manifest whose entry region holds anything the model cannot carry.

    `tomllib` discards comments, so a rewrite that kept them would have to reproduce them from
    the parsed data, which it cannot. The fix belongs to the operator: a comment that matters is
    a `note` field, and a misspelled key is a bug that must be fixed before the file is rewritten.
    """
    _, entries = _split_entries(text)
    commented = [line for line in entries if line.lstrip().startswith("#") or "#" in line]
    if commented:
        raise ValueError(
            f"{path}: the entry blocks carry comments, and the writer emits them from data only. "
            f"Move what matters into a note field, or edit the file by hand. First such line: "
            f"{commented[0].strip()!r}"
        )


def manifest_to_toml(manifest: Manifest, header: str) -> str:
    """Render a `Manifest` as TOML, keeping the repository's own header text untouched.

    The header carries the `version` line: TOML requires a top-level key before any table, so a
    file the loader accepted has one, and `NEW_MANIFEST_HEADER` supplies it for a file that does
    not exist yet. Entries are emitted in hash order with sorted paths, which is what makes two
    runs on the same set produce the same bytes.
    """
    blocks: list[str] = [header.rstrip("\n")]
    for entry in sorted(manifest.entries, key=lambda item: item.sha256):
        blocks.append(
            "[[wasm]]\n"
            f"sha256 = {_toml_string(entry.sha256)}\n"
            f"paths = [{', '.join(_toml_string(path) for path in sorted(entry.paths))}]\n"
            f"origin = {_toml_string(entry.origin)}\n"
            f"source = {_toml_string(entry.source)}\n"
            f"build = {_toml_string(entry.build)}" + _note_line(entry.note)
        )
    return "\n\n".join(block for block in blocks if block.strip()) + "\n"


def _note_line(note: str) -> str:
    return f"\nnote = {_toml_string(note)}" if note else ""


def artifact_entry(
    path: str,
    data: bytes,
    *,
    origin: str,
    source: str,
    build: str = "",
    note: str = "",
) -> WasmEntry:
    """One artifact file to one manifest entry, keyed by the hash of the bytes in hand."""
    require_repo_path(path, "artifact path")
    if not data.startswith(WASM_MAGIC):
        raise ValueError(
            f"{path} does not start with the Wasm magic bytes, so no entry can vouch for it as a "
            "Wasm artifact. A git LFS pointer is not the artifact (FR-20 covers those)"
        )
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError(
            f"{path} is {len(data)} bytes, over the {MAX_ARTIFACT_BYTES} byte ceiling an entry "
            "can be written for: the scanner would skip the file it is listed against"
        )
    if origin == "built" and not build:
        raise ValueError(
            f"{path}: origin built states how the artifact is produced, so --build is required"
        )
    return WasmEntry(
        sha256=hashlib.sha256(data).hexdigest(),
        paths=(path,),
        origin=origin,
        source=source,
        build=build,
        note=note,
    )


@dataclass(frozen=True, slots=True)
class ManifestAdd:
    """What `manifest add` produced: the text to write, and the two kinds of change it made."""

    text: str
    added: tuple[WasmEntry, ...]
    extended: tuple[WasmEntry, ...]

    @property
    def unchanged(self) -> bool:
        """True when every target was already listed at exactly this path.

        Stated rather than inferred from a diff, because `add` is idempotent and a CI step that
        runs it must be able to tell "already recorded" from "I wrote something".
        """
        return not self.added and not self.extended


def manifest_add(
    repo_root: Path,
    targets: Iterable[str],
    *,
    manifest_path: str = MANIFEST_FILENAME,
    origin: str,
    source: str,
    build: str = "",
    note: str = "",
) -> ManifestAdd:
    """Add each target to the manifest in the working tree and return the new text.

    The file is parsed with the same loader the scan uses, so `add` cannot write a manifest the
    scan would refuse to read. Provenance is stated once: when a hash is already listed, the new
    path joins that entry and the recorded `origin`, `source` and `build` stay as they were
    reviewed. Nothing here stages or commits anything; the operator reviews the diff, because
    this is a protected path.
    """
    require_repo_path(manifest_path, "manifest path")
    existing = _working_text(repo_root, manifest_path)
    if existing is None:
        header, manifest = NEW_MANIFEST_HEADER, Manifest()
    else:
        _refuse_losing(existing, manifest_path)
        loaded, findings = manifest_from_toml(existing, path=manifest_path, source="working tree")
        if findings:
            raise ValueError(
                f"{manifest_path}: "
                + "; ".join(finding.message for finding in findings)
                + " - fix those keys first, because the rewrite emits from parsed data only"
            )
        header, _ = _split_entries(existing)
        manifest = loaded

    entries: dict[str, WasmEntry] = {entry.sha256: entry for entry in manifest.entries}
    added: list[WasmEntry] = []
    extended: list[WasmEntry] = []
    for target in targets:
        data = _artifact_bytes(repo_root, target)
        entry = artifact_entry(target, data, origin=origin, source=source, build=build, note=note)
        known = entries.get(entry.sha256)
        if known is None:
            entries[entry.sha256] = entry
            added.append(entry)
        elif target not in known.paths:
            entries[entry.sha256] = replace(known, paths=(*known.paths, target))
            extended.append(entries[entry.sha256])

    written = Manifest(version=manifest.version, entries=tuple(entries.values()))
    if not added and not extended and existing is not None:
        # Nothing changed, so nothing is rewritten: an idempotent add must not touch the file's
        # mtime or produce an empty diff for the operator to review.
        return ManifestAdd(text=existing, added=(), extended=())
    return ManifestAdd(
        text=manifest_to_toml(written, header), added=tuple(added), extended=tuple(extended)
    )


def _artifact_bytes(repo_root: Path, target: str) -> bytes:
    require_repo_path(target, "artifact path")
    try:
        return (repo_root / target).read_bytes()
    except OSError as exc:
        raise ValueError(f"{target} could not be read: {type(exc).__name__}") from exc
