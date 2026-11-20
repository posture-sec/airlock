"""The step summary is a convenience: a failed write must not change the verdict.

Task 9.29 (issue #73): `_write_step_summary` may not raise on `OSError`. A directory target,
a missing parent or a read-only path must warn once to stderr and leave the exit code and the
stdout report exactly as they would be without the summary variable.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from tests.fixtures import assemble

from airlock.cli import DEFAULT_ROLES_FILE, DEFAULT_RULES_DIR, main
from airlock.model import EXIT_FINDINGS, EXIT_INTERNAL, EXIT_PASS

CLEAN_CONFIG = "export default { plugins: [] }\n"
PAYLOAD = f"{assemble('ev', 'al')}({assemble('Buf', 'fer.from')}(process.env.P, 'base64'))\n"

BASE_POLICY = """version = 1

[policy]
fail_on = "high"
line_cap = 500
"""


def git(root: Path, *args: str) -> str:
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


def write(root: Path, rel: str, data: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")
    git(root, "add", "-A")


def commit(root: Path) -> str:
    git(root, "commit", "-q", "-m", "fixture")
    return git(root, "rev-parse", "HEAD").strip()


def seed(root: Path, policy: str = BASE_POLICY) -> str:
    write(root, "airlock.toml", policy)
    write(root, "wasm-manifest.toml", "version = 1\n")
    write(root, "postcss.config.mjs", CLEAN_CONFIG)
    return commit(root)


def run_scan(root: Path, *args: str) -> int:
    """Run `airlock scan` on `root` and return the exit code."""
    return main(
        [
            "scan",
            str(root),
            "--rules-dir",
            str(DEFAULT_RULES_DIR),
            "--roles",
            str(DEFAULT_ROLES_FILE),
            *args,
        ]
    )


class TestSummaryWriteFailure:
    def test_a_directory_target_warns_and_keeps_a_high_exit(
        self,
        repo: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        seed(repo)
        write(repo, "postcss.config.mjs", PAYLOAD)
        commit(repo)
        target = tmp_path / "summary-is-a-dir"
        target.mkdir()
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(target))

        code = run_scan(repo, "--mode", "full")
        captured = capsys.readouterr()

        assert code == EXIT_FINDINGS
        assert "cfg-dynamic-code" in captured.out
        assert captured.err.count("airlock: warning:") == 1
        assert str(target) in captured.err

    def test_a_missing_parent_warns_and_keeps_a_clean_exit(
        self,
        repo: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        seed(repo)
        target = tmp_path / "missing" / "parent" / "summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(target))

        code = run_scan(repo, "--mode", "full")
        captured = capsys.readouterr()

        assert code == EXIT_PASS
        assert "0 HIGH" in captured.out
        assert captured.err.count("airlock: warning:") == 1
        assert str(target) in captured.err

    def test_stdout_is_identical_to_a_scan_without_the_summary_variable(
        self,
        repo: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        seed(repo)
        write(repo, "postcss.config.mjs", PAYLOAD)
        commit(repo)

        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
        code_plain = run_scan(repo, "--mode", "full", "--format", "json")
        out_plain = capsys.readouterr().out

        target = tmp_path / "summary-is-a-dir"
        target.mkdir()
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(target))
        code_summary = run_scan(repo, "--mode", "full", "--format", "json")
        out_summary = capsys.readouterr().out

        assert code_plain == code_summary == EXIT_FINDINGS
        assert out_summary == out_plain
        assert json.loads(out_summary)["exit_code"] == EXIT_FINDINGS

    def test_a_writable_target_is_still_appended(
        self,
        repo: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        seed(repo)
        write(repo, "postcss.config.mjs", PAYLOAD)
        commit(repo)
        target = tmp_path / "step_summary.md"
        target.write_text("existing\n", encoding="utf-8")
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(target))

        code = run_scan(repo, "--mode", "full")
        capsys.readouterr()

        assert code == EXIT_FINDINGS
        body = target.read_text(encoding="utf-8")
        assert body.startswith("existing\n# Airlock")
        assert "cfg-dynamic-code" in body

    def test_an_output_write_failure_stays_fatal(
        self,
        repo: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        seed(repo)
        target = tmp_path / "output-is-a-dir"
        target.mkdir()
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

        code = main(
            [
                "scan",
                str(repo),
                "--mode",
                "full",
                "--rules-dir",
                str(DEFAULT_RULES_DIR),
                "--roles",
                str(DEFAULT_ROLES_FILE),
                "--format",
                "json",
                "--output",
                str(target),
            ]
        )
        err = capsys.readouterr().err

        assert code == EXIT_INTERNAL
        assert "airlock:" in err
        assert "warning" not in err
