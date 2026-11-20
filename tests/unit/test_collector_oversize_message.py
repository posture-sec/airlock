"""The oversize finding quotes the constant that bounded the read (issue #8).

`HEAD_BYTES` decides how much of the file was read, so the message must move with it instead
of pinning the shipped value.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from airlock import collector
from airlock.collector import collect
from airlock.model import Policy
from airlock.rules import load_role_globs

REPO_ROOT = Path(__file__).resolve().parents[2]
ROLE_GLOBS = load_role_globs(REPO_ROOT / "rules" / "roles.toml")


def git(root: Path, *args: str) -> str:
    return subprocess.run(
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
        capture_output=True,
        text=True,
        check=True,
    ).stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "--initial-branch=main")
    (root / "big.py").write_text("x" * 500 + "\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "fixture")
    return root


def oversize_message(root: Path) -> str:
    result = collect(root, Policy(max_file_bytes=200), ROLE_GLOBS)
    matches = [finding for finding in result.pending if finding.rule_id == "skipped-oversize"]
    assert len(matches) == 1
    return matches[0].message


def test_the_shipped_value_is_named(repo: Path) -> None:
    assert collector.HEAD_BYTES == 4096
    assert "first 4096 bytes" in oversize_message(repo)


def test_the_message_tracks_the_constant(repo: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(collector, "HEAD_BYTES", 1024)

    message = oversize_message(repo)

    assert "first 1024 bytes" in message
    assert "4096" not in message
