"""Unit tests for PR-mode trusted-base fixture and workflow (issue #77)."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.fixtures.pr_mode import build_pr_mode_repo

from airlock.cli import main
from airlock.model import EXIT_FINDINGS, EXIT_PASS

WORKFLOW_FILE = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "pr-mode.yml"


def test_workflow_file_structure_and_action_pins() -> None:
    assert WORKFLOW_FILE.is_file(), f"Missing workflow file at {WORKFLOW_FILE}"
    content = WORKFLOW_FILE.read_text(encoding="utf-8")

    assert "pull_request:" in content
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in content
    assert "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0" in content
    assert "python -m pytest tests/unit/test_workflow_pr_mode.py" in content


def test_pr_mode_evaluates_base_policy_and_passes_warn_under_high_threshold(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo_dir = tmp_path / "pr_repo_warn"
    base_sha = build_pr_mode_repo(repo_dir, high=False)

    code = main(["scan", str(repo_dir), "--mode", "pr", "--base", base_sha])
    out = capsys.readouterr().out

    # Base policy has fail_on = "high".
    # Head has policy-changed (WARN) and pat-privileged-trigger (WARN).
    # Since only WARN findings exist, scan must exit EXIT_PASS (0).
    assert code == EXIT_PASS
    assert "policy-changed" in out
    assert "pat-privileged-trigger" in out
    assert "untrusted-policy-source" not in out


def test_pr_mode_fails_when_high_finding_introduced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo_dir = tmp_path / "pr_repo_high"
    base_sha = build_pr_mode_repo(repo_dir, high=True)

    code = main(["scan", str(repo_dir), "--mode", "pr", "--base", base_sha])
    out = capsys.readouterr().out

    # Base policy has fail_on = "high".
    # Head introduces cfg-dynamic-code (HIGH), so scan must exit EXIT_FINDINGS (1).
    assert code == EXIT_FINDINGS
    assert "cfg-dynamic-code" in out
    assert "policy-changed" in out
