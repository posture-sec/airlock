"""Full base refs are checked before any Git command receives them."""

from __future__ import annotations

from pathlib import Path

from tests.unit.test_roadmap_gate import TOUCHED, git, run


def test_full_ref_and_dash_branch_pass(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "--initial-branch=main")
    (root / "ROADMAP.md").write_text("Last updated: before\n", encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    git(root, "update-ref", "refs/heads/-dash", "HEAD")
    for ref in ("refs/heads/main", "refs/heads/-dash"):
        result = run("sh", str(TOUCHED), ref, cwd=root)
        assert result.returncode == 0, result.stdout + result.stderr


def test_rejected_ref_never_invokes_git(tmp_path: Path) -> None:
    fake_git = tmp_path / "git"
    marker = tmp_path / "called"
    fake_git.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
    fake_git.chmod(0o755)
    for ref in ("--help", "main", "refs/heads/", "refs/remotes/"):
        result = run("env", f"PATH={tmp_path}:/usr/bin:/bin", "sh", str(TOUCHED), ref)
        assert result.returncode == 1
        assert ref in result.stderr
        assert "refs/heads/<name>" in result.stderr
        assert "refs/remotes/<name>" in result.stderr
        assert not marker.exists()


def test_missing_full_ref_reports_failure(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "--initial-branch=main")
    (root / "ROADMAP.md").write_text("Last updated: before\n", encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    result = run("sh", str(TOUCHED), "refs/heads/missing", cwd=root)
    assert result.returncode == 1
    assert "not a commit" in result.stderr
