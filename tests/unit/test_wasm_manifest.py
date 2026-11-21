"""`wasm_manifest` detector tests (task 3.4).

Hashes here are synthetic digests, not artifacts. The manifest is built in code from the
`WasmEntry` model, because the TOML loader for it is task 3.5.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from airlock import roles
from airlock.detectors import DETECTOR_NAMES, wasm_manifest
from airlock.model import FileEntry, Manifest, Policy, ScanContext, Severity, WasmEntry
from airlock.rules import load_role_globs, load_rules

REPO_ROOT = Path(__file__).resolve().parents[2]

BUILD_A = "a" * 64


def digest(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def make_rules() -> tuple[Any, ...]:
    role_globs = load_role_globs(REPO_ROOT / "rules" / "roles.toml")
    return load_rules(
        REPO_ROOT / "rules" / "builtin",
        known_detectors=DETECTOR_NAMES,
        known_roles=sorted(roles.known_roles(role_globs)),
    )


def make_entry(path: str, sha: str | None, *, entry_roles: tuple[str, ...]) -> FileEntry:
    # A digest means hashed but not decoded; no digest means the collector skipped the file.
    skip_reason = None if sha is not None else "unreadable"
    return FileEntry(path=path, sha256=sha, roles=entry_roles, text=None, skip_reason=skip_reason)


def wasm(path: str, sha: str | None = BUILD_A) -> FileEntry:
    return make_entry(path, sha, entry_roles=(roles.WASM_ROLE,))


def manifest_of(*entries: WasmEntry) -> Manifest:
    return Manifest(entries=entries)


def listed(path: str, sha: str = BUILD_A) -> WasmEntry:
    return WasmEntry(
        sha256=sha,
        paths=(path,),
        origin="built",
        source="src/counter",
        build="cargo build --release --target wasm32-unknown-unknown",
    )


def run(entries: list[FileEntry], manifest: Manifest) -> list[Any]:
    ctx = ScanContext(
        entries=tuple(entries),
        policy=Policy(),
        manifest=manifest,
        rules=make_rules(),
    )
    return list(wasm_manifest.run(ctx))


def ids(findings: list[Any]) -> list[str]:
    return [finding.rule_id for finding in findings]


class TestCleanTree:
    def test_a_listed_artifact_at_its_listed_path_is_clean(self) -> None:
        assert run([wasm("target/counter.wasm")], manifest_of(listed("target/counter.wasm"))) == []

    def test_an_empty_tree_with_an_empty_manifest_is_clean(self) -> None:
        assert run([], Manifest()) == []


class TestUnlisted:
    def test_an_unknown_hash_is_high_and_not_suppressible(self) -> None:
        findings = run([wasm("target/evil.wasm", digest("evil"))], Manifest())
        assert ids(findings) == ["wasm-unlisted"]
        assert findings[0].severity is Severity.HIGH
        assert not findings[0].suppressible

    def test_a_file_named_wasm_without_a_wasm_header_is_reported(self) -> None:
        # The git LFS pointer shape: the extension says artifact, the bytes say text.
        entry = make_entry("contract.wasm", digest("pointer"), entry_roles=(roles.OTHER_ROLE,))
        findings = run([entry], Manifest())
        assert ids(findings) == ["wasm-unlisted"]
        assert "no Wasm header" in findings[0].message

    def test_an_artifact_the_collector_could_not_hash_is_unlisted(self) -> None:
        unreadable = FileEntry(
            path="counter.wasm",
            sha256=None,
            roles=(roles.WASM_ROLE,),
            skip_reason="skipped-oversize",
        )
        findings = run([unreadable], Manifest())
        assert ids(findings) == ["wasm-unlisted"]
        assert "skipped-oversize" in findings[0].message


class TestMismatchAndMove:
    def test_a_listed_path_holding_other_bytes_is_a_mismatch(self) -> None:
        findings = run(
            [wasm("target/counter.wasm", digest("swapped"))],
            manifest_of(listed("target/counter.wasm", BUILD_A)),
        )
        assert ids(findings) == ["wasm-hash-mismatch"]
        assert findings[0].severity is Severity.HIGH
        assert not findings[0].suppressible

    def test_a_known_hash_at_an_other_path_is_a_warn_move(self) -> None:
        findings = run(
            [wasm("dist/moved.wasm", BUILD_A)], manifest_of(listed("target/counter.wasm", BUILD_A))
        )
        assert ids(findings) == ["wasm-path-moved"]
        assert findings[0].severity is Severity.WARN
        assert findings[0].suppressible
        assert "target/counter.wasm" in findings[0].message

    def test_a_mismatch_wins_over_a_move_on_the_same_file(self) -> None:
        # The path is listed and the hash is known elsewhere: the declared slot changed content,
        # which is the higher-severity reading of the same bytes.
        findings = run(
            [wasm("target/counter.wasm", digest("other"))],
            manifest_of(listed("target/counter.wasm", BUILD_A)),
        )
        assert ids(findings) == ["wasm-hash-mismatch"]

    def test_one_finding_per_artifact(self) -> None:
        findings = run(
            [wasm("target/counter.wasm", digest("other")), wasm("target/extra.wasm", digest("x"))],
            manifest_of(listed("target/counter.wasm", BUILD_A)),
        )
        assert len(findings) == 2


class TestStaleAndArchives:
    def test_a_manifest_entry_with_no_file_is_stale(self) -> None:
        findings = run([], manifest_of(listed("target/counter.wasm", BUILD_A)))
        assert ids(findings) == ["wasm-manifest-stale"]
        assert findings[0].severity is Severity.WARN
        assert findings[0].path == "target/counter.wasm"

    def test_a_matching_file_clears_the_stale_check(self) -> None:
        assert (
            ids(
                run(
                    [wasm("target/counter.wasm", BUILD_A)],
                    manifest_of(listed("target/counter.wasm", BUILD_A)),
                )
            )
            == []
        )

    def test_a_move_leaves_no_stale_entry_behind(self) -> None:
        # The hash is still in the tree, so the manifest is describing a moved artifact, which is
        # `wasm-path-moved` alone.
        findings = run([wasm("dist/new.wasm", BUILD_A)], manifest_of(listed("old.wasm", BUILD_A)))
        assert ids(findings) == ["wasm-path-moved"]

    def test_an_archive_is_reported_as_unexamined(self) -> None:
        archive = make_entry("vendor/bundle.zip", digest("zip"), entry_roles=(roles.ARCHIVE_ROLE,))
        findings = run([archive], Manifest())
        assert ids(findings) == ["wasm-archive-skipped"]
        assert findings[0].severity is Severity.WARN

    def test_an_entry_with_neither_role_nor_extension_is_ignored(self) -> None:
        source = make_entry("src/index.js", digest("js"), entry_roles=(roles.SOURCE_ROLE,))
        assert run([source], Manifest()) == []
