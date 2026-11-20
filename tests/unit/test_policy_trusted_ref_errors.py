"""A git failure in push mode is a config error, not a rewritten history (issue #12)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from airlock.model import Mode
from airlock.policy import POLICY_FILENAME, resolve_policy

BASE_POLICY = """version = 1

[policy]
fail_on = "high"
line_cap = 500
"""

ABSENT = "0123456789abcdef0123456789abcdef01234567"


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def write(root: Path, rel: str, data: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")
    git(root, "add", "-A")


def commit(root: Path) -> str:
    git(root, "commit", "-q", "-m", "fixture")
    return git(root, "rev-parse", "HEAD").strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "--initial-branch=main")
    write(root, POLICY_FILENAME, BASE_POLICY)
    write(root, "README.md", "clean\n")
    commit(root)
    return root


class TestPushTrustedRef:
    def test_an_absent_before_is_a_config_error_and_not_a_rewrite(self, repo: Path) -> None:
        head = git(repo, "rev-parse", "HEAD").strip()

        with pytest.raises(ValueError) as caught:
            resolve_policy(repo, Mode.PUSH, head, before=ABSENT)

        message = str(caught.value)
        assert "merge-base --is-ancestor" in message
        assert ABSENT[:7] in message
        assert "history-rewritten" not in message

    def test_a_failed_git_names_the_command_and_gits_error(self, repo: Path) -> None:
        head = git(repo, "rev-parse", "HEAD").strip()

        with pytest.raises(ValueError, match="failed with exit"):
            resolve_policy(repo, Mode.PUSH, head, before=ABSENT)

    def test_a_genuine_rewrite_is_still_history_rewritten(self, repo: Path) -> None:
        base = git(repo, "rev-parse", "HEAD").strip()
        write(repo, "README.md", "dropped\n")
        discarded = commit(repo)
        git(repo, "reset", "-q", "--hard", base)
        write(repo, "README.md", "new head\n")
        head = commit(repo)

        result = resolve_policy(repo, Mode.PUSH, head, before=discarded)

        assert result.base is None
        ids = [finding.rule_id for finding in result.pending]
        assert ids == ["history-rewritten"]
        assert result.pending[0].severity.name == "HIGH"
