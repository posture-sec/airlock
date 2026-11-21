"""`wasm_manifest` detector: every committed Wasm artifact accounted for by hash.

Task 3.4 (`ARCHITECTURE.md` 9.2). Wasm is identified by its magic bytes, never by its
extension (ADR-010), so renaming `contract.wasm` to `contract.bin` changes nothing about how
these rules see it. The manifest is keyed by hash, so a move is a WARN and a content change is
a HIGH.

A file named `*.wasm` that carries no Wasm header is reported too. That is the git LFS pointer
shape (FR-20): the artifact lives on an LFS server, and until the pointer is resolved the scan
cannot say what will land at release time.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from ..fingerprint import PendingFinding
from ..model import FileEntry, Rule, ScanContext, WasmEntry
from ..roles import ARCHIVE_ROLE, WASM_ROLE, match_glob
from ..rules import finding_for

UNLISTED_RULE_ID = "wasm-unlisted"
MISMATCH_RULE_ID = "wasm-hash-mismatch"
MOVED_RULE_ID = "wasm-path-moved"
STALE_RULE_ID = "wasm-manifest-stale"
ARCHIVE_RULE_ID = "wasm-archive-skipped"

WASM_SUFFIX = ".wasm"
LFS_VERSION = "version https://git-lfs.github.com/spec/v1"
#: Reason on the synthetic entry a stale manifest path gets. It is not a collector skip reason
#: and never reaches `files_skipped`; the path it names has no tracked file at all.
ABSENT_PATH_REASON = "absent-from-tree"


def _require_rule(rules: dict[str, Rule], rule_id: str) -> Rule:
    rule = rules.get(rule_id)
    if rule is None:
        raise ValueError(f"wasm_manifest cannot run without the {rule_id} rule loaded")
    return rule


def _short(digest: str | None) -> str:
    return (digest or "no hash")[:12]


def _is_wasm(entry: FileEntry) -> bool:
    return WASM_ROLE in entry.roles or entry.path.lower().endswith(WASM_SUFFIX)


def _index(
    manifest_entries: Iterable[WasmEntry],
) -> tuple[dict[str, WasmEntry], dict[str, WasmEntry]]:
    by_hash: dict[str, WasmEntry] = {}
    by_path: dict[str, WasmEntry] = {}
    for entry in manifest_entries:
        by_hash[entry.sha256] = entry
        for path in entry.paths:
            by_path[path] = entry
    return by_hash, by_path


def _compare(
    entry: FileEntry,
    rules: dict[str, Rule],
    by_hash: dict[str, WasmEntry],
    by_path: dict[str, WasmEntry],
) -> PendingFinding | None:
    """One artifact against the manifest: mismatch, unknown hash, or a move."""
    if entry.sha256 is None:
        return finding_for(
            _require_rule(rules, UNLISTED_RULE_ID),
            entry,
            0,
            evidence=entry.path,
            message=(
                f"{entry.path} looks like Wasm but the collector could not hash it "
                f"({entry.skip_reason or 'unreadable'}), so no manifest entry vouches for it"
            ),
        )
    listed = by_path.get(entry.path)
    known = by_hash.get(entry.sha256)
    if listed is not None and known is not listed:
        return finding_for(
            _require_rule(rules, MISMATCH_RULE_ID),
            entry,
            0,
            evidence=entry.sha256,
            message=(
                f"{entry.path} is listed under hash {_short(listed.sha256)} and hashes to "
                f"{_short(entry.sha256)}"
            ),
        )
    if known is None:
        reason = (
            "the file holds no Wasm header, so it is a pointer or a placeholder"
            if WASM_ROLE not in entry.roles
            else "no manifest entry carries this hash"
        )
        return finding_for(
            _require_rule(rules, UNLISTED_RULE_ID),
            entry,
            0,
            evidence=entry.sha256,
            message=f"{entry.path} hashes to {_short(entry.sha256)}; {reason}",
        )
    if listed is None:
        return finding_for(
            _require_rule(rules, MOVED_RULE_ID),
            entry,
            0,
            evidence=entry.sha256,
            message=(
                f"{entry.path} holds the known artifact {_short(entry.sha256)}, which the "
                f"manifest lists at {', '.join(known.paths)}"
            ),
        )
    return None


def _lfs_pointer_oid(text: str, line_cap: int) -> str | None:
    lines = text.splitlines()
    if len(lines) != 3 or any(len(line) > line_cap for line in lines):
        return None
    version, oid_line, size_line = lines
    if version != LFS_VERSION or not oid_line.startswith("oid sha256:"):
        return None
    oid = oid_line.removeprefix("oid sha256:")
    if len(oid) != 64 or any(char not in "0123456789abcdef" for char in oid):
        return None
    if not size_line.startswith("size "):
        return None
    size = size_line.removeprefix("size ")
    if not size.isascii() or not size.isdecimal() or not any(char != "0" for char in size):
        return None
    return oid


def _attribute_matches(pattern: str, path: str) -> bool:
    if not pattern or any(char in pattern for char in "\\[]"):
        return False
    normalized = pattern.removeprefix("/")
    if "/" not in normalized:
        return match_glob(normalized, path.rsplit("/", 1)[-1])
    return match_glob(normalized, path)


def _is_lfs_path(entries: tuple[FileEntry, ...], path: str, line_cap: int) -> bool:
    attributes = sorted(
        (
            (entry.path.rpartition("/")[0], entry.text)
            for entry in entries
            if entry.path.rsplit("/", 1)[-1] == ".gitattributes" and entry.text is not None
        ),
        key=lambda item: item[0].count("/"),
    )
    tracked = False
    for base, text in attributes:
        if base:
            prefix = f"{base}/"
            if not path.startswith(prefix):
                continue
            relative_path = path.removeprefix(prefix)
        else:
            relative_path = path
        for line in text.splitlines():
            if len(line) > line_cap:
                continue
            fields = line.split()
            if not fields or fields[0].startswith("#"):
                continue
            if not _attribute_matches(fields[0], relative_path):
                continue
            for attribute in fields[1:]:
                if attribute == "filter=lfs":
                    tracked = True
                elif attribute in {"filter", "-filter", "!filter"}:
                    tracked = False
    return tracked


def _compare_lfs_pointer(
    entry: FileEntry,
    oid: str,
    rules: dict[str, Rule],
    by_hash: dict[str, WasmEntry],
    by_path: dict[str, WasmEntry],
) -> PendingFinding | None:
    if oid not in by_hash:
        return finding_for(
            _require_rule(rules, UNLISTED_RULE_ID),
            entry,
            0,
            evidence=oid,
            message=f"{entry.path} has LFS pointer oid {oid}, which is not in the manifest",
        )
    return _compare(replace(entry, sha256=oid), rules, by_hash, by_path)


def run(ctx: ScanContext) -> Iterable[PendingFinding]:
    """Compare tracked Wasm against the trusted manifest and report every gap."""
    rules = {rule.id: rule for rule in ctx.rules}
    by_hash, by_path = _index(ctx.manifest.entries)
    seen_hashes: set[str] = set()
    tracked_paths = {entry.path for entry in ctx.entries if _is_wasm(entry)}

    for entry in ctx.entries:
        if ARCHIVE_ROLE in entry.roles:
            yield finding_for(
                _require_rule(rules, ARCHIVE_RULE_ID),
                entry,
                0,
                evidence=entry.sha256,
                message=(
                    f"{entry.path} is an archive; nothing inside it was compared against the "
                    "manifest"
                ),
            )
        if not _is_wasm(entry):
            continue
        oid = (
            _lfs_pointer_oid(entry.text, ctx.policy.line_cap)
            if entry.text is not None and _is_lfs_path(ctx.entries, entry.path, ctx.policy.line_cap)
            else None
        )
        effective_hash = oid or entry.sha256
        if effective_hash is not None:
            seen_hashes.add(effective_hash)
        finding = (
            _compare_lfs_pointer(entry, oid, rules, by_hash, by_path)
            if oid is not None
            else _compare(entry, rules, by_hash, by_path)
        )
        if finding is not None:
            yield finding

    stale_rule = _require_rule(rules, STALE_RULE_ID)
    for manifest_entry in ctx.manifest.entries:
        if manifest_entry.sha256 in seen_hashes:
            continue
        # A declared path that still holds a file is already reported as a mismatch or a move.
        # Calling it stale as well would report one changed artifact twice.
        if any(path in tracked_paths for path in manifest_entry.paths):
            continue
        path = manifest_entry.paths[0]
        # No tracked file exists at this path, so the entry is synthetic rather than collected.
        # It still has to be one of `FileEntry`'s three states, and a path with neither digest
        # nor text is recorded as skipped; the reason never reaches `files_skipped`.
        yield finding_for(
            stale_rule,
            FileEntry(
                path=path,
                sha256=None,
                roles=(WASM_ROLE,),
                skip_reason=ABSENT_PATH_REASON,
            ),
            0,
            evidence=manifest_entry.sha256,
            message=(
                f"manifest entry {_short(manifest_entry.sha256)} for "
                f"{', '.join(manifest_entry.paths)} matches no tracked file"
            ),
        )
