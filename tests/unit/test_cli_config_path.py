"""Config-style CLI paths cannot escape the scanned repository."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.unit.test_cli import git, seed

from airlock.cli import main


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "--initial-branch=main")
    seed(root)
    return root


@pytest.mark.parametrize("value", ["/tmp/outside.toml", "../outside.toml"])
def test_lexical_escape_is_usage_error(
    repo: Path, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["scan", str(repo), "--config", value]) == 2
    output = capsys.readouterr().err
    assert value in output and str(repo) in output


def test_outside_symlink_is_refused_before_policy_read(
    repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    outside = tmp_path / "outside.toml"
    outside.write_text('version = 1\n[policy]\nfail_on = "info"\n', encoding="utf-8")
    (repo / "linked.toml").symlink_to(outside)
    assert main(["scan", str(repo), "--config", "linked.toml"]) == 2
    output = capsys.readouterr()
    assert "linked.toml" in output.err and str(repo) in output.err
    assert "fail_on" not in output.out


def test_inside_symlink_is_allowed(repo: Path) -> None:
    (repo / "linked.toml").symlink_to("airlock.toml")
    assert main(["scan", str(repo), "--config", "linked.toml"]) == 0


def test_manifest_check_rejects_escaping_manifest(
    repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    outside = tmp_path / "outside.toml"
    outside.write_text("version = 1\n", encoding="utf-8")
    (repo / "linked.toml").symlink_to(outside)
    assert main(["manifest", "check", str(repo), "--wasm-manifest", "linked.toml"]) == 2
    assert "linked.toml" in capsys.readouterr().err
