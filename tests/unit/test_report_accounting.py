"""The report accounts for every indexed file (task 9.29, `ARCHITECTURE.md` 7.8).

`files_scanned` used to be `len(collection.entries)`, so a skipped file was counted as scanned as
well, and an entry that is hashed but never decoded (a Wasm artifact) was counted by no skip at
all. These cases build a real temporary repository with four tracked entries and assert the three
counts add up, then assert the guard that refuses a report where they do not.

The symlink is written through git's index rather than the filesystem. `os.symlink` needs
Developer Mode or elevation on Windows, and Git for Windows with `core.symlinks=false` stores a
link as a plain file, so neither would produce the mode `120000` entry the collector reads.
`update-index --cacheinfo 120000,...` writes that index record on any platform, and the collector
returns before it touches the target, so no OS support is needed to exercise the skip.

The oversize fixture is one byte over the shipped `max_file_bytes`, so the tree needs no
`airlock.toml` and stays exactly four entries; the collector reads 4096 bytes of it and stops.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from airlock import cli
from airlock.collector import Collection
from airlock.model import FileEntry, Mode, ScanReport
from airlock.report import console, jsonout, summary

#: One byte over `Policy.max_file_bytes`, which is what `full` mode falls back to here.
BIG_BYTES = 5_000_001

WASM = b"\x00asm\x01\x00\x00\x00"


def git(root: Path, *args: str, input_text: str | None = None) -> str:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=airlock-test",
            "-c",
            "user.email=airlock-test@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            *args,
        ],
        input=input_text,
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
    # Byte counts, not text, decide the oversize and the symlink cases.
    git(root, "config", "core.autocrlf", "false")
    return root


def write_text(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    git(root, "add", "-A")


def write_bytes(root: Path, rel: str, data: bytes) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    git(root, "add", "-A")


def symlink_entry(root: Path, rel: str, target: str) -> None:
    """Record a mode `120000` index entry without creating an OS symlink."""
    blob = git(root, "hash-object", "-w", "--stdin", input_text=target).strip()
    git(root, "update-index", "--add", "--cacheinfo", f"120000,{blob},{rel}")


def commit(root: Path, message: str = "fixture") -> None:
    git(root, "commit", "-q", "-m", message)


def scan(root: Path) -> ScanReport:
    return cli.run_scan(root, Mode.FULL)


def four_entries(root: Path) -> None:
    """One text file, one Wasm artifact, one symlink and one oversize file, then commit."""
    write_text(root, "notes.txt", "an ordinary file\n")
    write_bytes(root, "artifact.wasm", WASM)
    write_bytes(root, "big.py", b"x" * BIG_BYTES)
    symlink_entry(root, "link.py", "notes.txt")
    commit(root)


class TestFourEntryTree:
    def test_scanned_and_skipped_add_up_to_the_index(self, repo: Path) -> None:
        assert len(git(repo, "ls-files", "-z").split("\0")) - 1 == 0
        four_entries(repo)
        assert git(repo, "ls-files", "-s", "link.py").startswith("120000 ")

        report = scan(repo)

        assert report.files_indexed == 4
        assert report.files_scanned == 2
        assert report.files_skipped == {"symlink": 1, "oversize": 1}
        assert report.files_scanned + sum(report.files_skipped.values()) == report.files_indexed

    def test_the_json_report_carries_the_index_total(self, repo: Path, capsys) -> None:
        four_entries(repo)

        cli.main(["scan", str(repo), "--format", "json"])

        payload = json.loads(capsys.readouterr().out)
        assert payload["files_indexed"] == 4
        assert payload["files_scanned"] == 2
        assert payload["files_skipped"] == {"symlink": 1, "oversize": 1}

    def test_the_summary_line_still_counts_the_files_that_were_read(self, repo: Path) -> None:
        four_entries(repo)

        report = scan(repo)

        assert "2 file(s) scanned" in summary.render(report)
        assert "2 file(s) scanned" in console.summary_line(report)
        assert "symlink" in console.summary_line(report)
        assert "oversize" in console.summary_line(report)


class TestDigestIsNotScanned:
    def test_an_encoding_skip_with_a_digest_counts_only_as_skipped(self, repo: Path) -> None:
        # Invalid UTF-8 on an unscannable path: hashed, then returned as an encoding skip.
        write_bytes(repo, "blob.dat", b"\x80\x81\x82\x83")
        commit(repo)

        report = scan(repo)

        assert report.files_indexed == 1
        assert report.files_scanned == 0
        assert report.files_skipped == {"encoding": 1}


class TestTheInvariant:
    def test_an_entry_neither_read_nor_skipped_is_refused_by_name(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        write_text(repo, "notes.txt", "an ordinary file\n")
        commit(repo)
        lost = Collection(
            entries=(FileEntry(path="lost.txt", sha256=None, roles=()),),
            pending=(),
        )
        monkeypatch.setattr(cli, "collect", lambda *_args, **_kwargs: lost)

        with pytest.raises(ValueError) as caught:
            scan(repo)

        message = str(caught.value)
        assert "1 indexed" in message
        assert "0 scanned" in message
        assert "0 skipped" in message

    def test_the_json_renderer_writes_the_field_that_was_added(self, repo: Path) -> None:
        write_text(repo, "notes.txt", "an ordinary file\n")
        commit(repo)

        report = scan(repo)

        payload = json.loads(jsonout.render(report))
        assert payload["files_indexed"] == report.files_indexed == 1
        assert payload["files_scanned"] == report.files_scanned == 1
