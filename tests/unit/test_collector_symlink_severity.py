"""A symlinked sensitive file is HIGH, not INFO (issue #9).

The link is never followed: the collector reads the index mode only, so this proves the
severity follows the role the path resolves to.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from tests.fixtures import assemble

from airlock.collector import SKIP_SYMLINK, collect
from airlock.model import Policy, Severity
from airlock.rules import load_role_globs

REPO_ROOT = Path(__file__).resolve().parents[2]
ROLE_GLOBS = load_role_globs(REPO_ROOT / "rules" / "roles.toml")

# Assembled at call time so the fixture is not a committed payload (`AGENTS.md` 4).
DROPPER = f"{assemble('ev', 'al')}({assemble('Buf', 'fer.from')}(a,'base64'))\n"


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
    return root


def symlink_and_commit(root: Path, rel: str, target: Path) -> None:
    link = root / rel
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "fixture")


def scan(root: Path):
    return collect(root, Policy(), ROLE_GLOBS)


def finding_for(result, rel: str):
    matches = [
        finding
        for finding in result.pending
        if finding.path == rel and finding.rule_id == "skipped-symlink"
    ]
    assert len(matches) == 1
    return matches[0]


def test_a_symlinked_workflow_is_high(repo: Path, tmp_path: Path) -> None:
    target = tmp_path / "outside.yml"
    target.write_text("on: push\n")
    symlink_and_commit(repo, ".github/workflows/ci.yml", target)

    result = scan(repo)
    finding = finding_for(result, ".github/workflows/ci.yml")

    assert finding.severity is Severity.HIGH
    assert finding.message == "symlink in the index; its target was not read"


def test_a_symlinked_package_manifest_is_high(repo: Path, tmp_path: Path) -> None:
    target = tmp_path / "outside.json"
    target.write_text("{}\n")
    symlink_and_commit(repo, "package.json", target)

    assert finding_for(scan(repo), "package.json").severity is Severity.HIGH


def test_a_symlinked_ordinary_file_stays_info(repo: Path, tmp_path: Path) -> None:
    target = tmp_path / "outside.md"
    target.write_text(DROPPER)
    symlink_and_commit(repo, "docs/note.md", target)

    assert finding_for(scan(repo), "docs/note.md").severity is Severity.INFO


def test_the_link_is_never_read(repo: Path, tmp_path: Path) -> None:
    target = tmp_path / "outside.yml"
    target.write_text("on: push\n")
    symlink_and_commit(repo, ".github/workflows/ci.yml", target)

    result = scan(repo)
    entry = next(item for item in result.entries if item.path == ".github/workflows/ci.yml")

    assert entry.skip_reason == SKIP_SYMLINK
    assert entry.text is None
    assert entry.sha256 is None
