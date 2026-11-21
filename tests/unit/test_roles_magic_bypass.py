"""Content magic must not let two bytes remove a file from text scanning (#25).

`MZ` is both the DOS header prefix of a PE file and a legal start for any text file. The prefix
table used to return `native-binary` on those two bytes alone, and the collector then returned the
file with a hash and no text, so a `next.config.mjs` starting with them was invisible to every
text rule. These tests pin the PE structure check and the INFO finding that makes the decision to
leave the text pass visible.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from airlock import runner
from airlock.collector import collect
from airlock.detectors import DETECTOR_NAMES
from airlock.model import EMPTY_MANIFEST, Policy, ScanContext, Severity
from airlock.roles import (
    ARCHIVE_ROLE,
    NATIVE_ROLE,
    OTHER_ROLE,
    WASM_ROLE,
    known_roles,
    resolve_roles,
    roles_from_magic,
)
from airlock.rules import load_role_globs, load_rules

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_ROOT = REPO_ROOT / "rules"
ROLE_GLOBS = load_role_globs(RULES_ROOT / "roles.toml")
RULES = load_rules(
    RULES_ROOT / "builtin",
    known_detectors=DETECTOR_NAMES,
    known_roles=known_roles(ROLE_GLOBS),
)

WASM_HEAD = b"\x00asm\x01\x00\x00\x00"
GZIP_HEAD = b"\x1f\x8b\x08\x00"


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "--initial-branch=main")
    return root


def write(root: Path, rel: str, data: bytes | str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)


def commit(root: Path) -> None:
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "fixture")


def collect_repo(root: Path):
    return collect(root, Policy(), ROLE_GLOBS)


def pe_header(lfanew: int = 0x80) -> bytes:
    """A minimal DOS header whose `e_lfanew` points at a `PE\\0\\0` signature."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = lfanew.to_bytes(4, "little")
    return bytes(dos) + b"\x00" * (lfanew - len(dos)) + b"PE\x00\x00"


def rule_ids(findings) -> list[str]:
    return [finding.rule_id for finding in findings]


class TestMagicRoles:
    def test_pe_header_is_native(self) -> None:
        assert roles_from_magic(pe_header()) == (NATIVE_ROLE,)

    def test_mz_without_a_pe_signature_has_no_magic_role(self) -> None:
        assert roles_from_magic(b"MZ\n") == ()

    def test_a_truncated_mz_file_falls_through(self) -> None:
        assert roles_from_magic(b"MZ") == ()
        assert roles_from_magic(b"MZ" + b"\x00" * 10) == ()

    def test_an_out_of_bounds_lfanew_falls_through(self) -> None:
        dos = bytearray(64)
        dos[0:2] = b"MZ"
        dos[0x3C:0x40] = (0xFFFF).to_bytes(4, "little")
        assert roles_from_magic(bytes(dos) + b"PE\x00\x00") == ()

    def test_an_lfanew_pointing_at_other_bytes_falls_through(self) -> None:
        head = bytearray(pe_header())
        head[0x80:0x84] = b"PE\x01\x00"
        assert roles_from_magic(bytes(head)) == ()

    def test_mz_text_resolves_through_the_globs_and_extension(self) -> None:
        roles = resolve_roles("next.config.mjs", b"MZ\n", ROLE_GLOBS)

        assert NATIVE_ROLE not in roles
        assert "tooling-config" in roles

    def test_mz_bin_with_no_other_role_is_other(self) -> None:
        assert resolve_roles("tool.bin", b"MZ\n", ROLE_GLOBS) == (OTHER_ROLE,)


class TestCollector:
    def test_mz_text_is_read_and_reaches_a_text_rule(self, repo: Path) -> None:
        trigger = "".join(("ev", "al", "(input);"))
        write(repo, "next.config.mjs", f"MZ\n{trigger}\n".encode())
        commit(repo)

        collection = collect_repo(repo)
        entry = next(item for item in collection.entries if item.path == "next.config.mjs")

        assert entry.text == f"MZ\n{trigger}\n"
        assert entry.skip_reason is None
        assert "content-magic-role" not in rule_ids(collection.pending)
        context = ScanContext(
            entries=collection.entries,
            policy=Policy(),
            manifest=EMPTY_MANIFEST,
            rules=RULES,
        )
        assert "cfg-dynamic-code" in rule_ids(runner.collect(context))

    def test_a_minimal_pe_header_stays_native_and_is_reported(self, repo: Path) -> None:
        write(repo, "setup.exe", pe_header() + b"\x00" * 64)
        commit(repo)

        collection = collect_repo(repo)
        entry = next(item for item in collection.entries if item.path == "setup.exe")

        assert entry.roles == (NATIVE_ROLE,)
        assert entry.text is None
        reported = [item for item in collection.pending if item.rule_id == "content-magic-role"]
        assert len(reported) == 1
        assert reported[0].severity is Severity.INFO
        assert reported[0].suppressible is False
        assert reported[0].path == "setup.exe"
        assert NATIVE_ROLE in reported[0].message

    def test_wasm_and_archive_roles_are_kept_and_reported(self, repo: Path) -> None:
        write(repo, "contract.wasm", WASM_HEAD + b"\x00\x00")
        write(repo, "bundle.gz", GZIP_HEAD + b"fake")
        commit(repo)

        collection = collect_repo(repo)

        assert next(item for item in collection.entries if item.path == "contract.wasm").roles == (
            WASM_ROLE,
        )
        assert next(item for item in collection.entries if item.path == "bundle.gz").roles == (
            ARCHIVE_ROLE,
        )
        reported = {
            item.path: item.message
            for item in collection.pending
            if item.rule_id == "content-magic-role"
        }
        assert set(reported) == {"contract.wasm", "bundle.gz"}
        assert WASM_ROLE in reported["contract.wasm"]
        assert ARCHIVE_ROLE in reported["bundle.gz"]

    def test_a_truncated_mz_file_is_scanned_as_text(self, repo: Path) -> None:
        write(repo, "notes.md", b"MZ\nplain text\n")
        commit(repo)

        entry = next(item for item in collect_repo(repo).entries if item.path == "notes.md")

        assert entry.text == "MZ\nplain text\n"
        assert NATIVE_ROLE not in entry.roles
