"""The two roadmap gates (task 1.9).

A gate that silently passes is worse than no gate, so both scripts are run here the way a
workflow runs them: as a subprocess, with their real arguments, against a temporary file or a
temporary repository, asserting on exit codes. The first test is the one that matters most: it
runs the generator over this repository's own `ROADMAP.md`.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PROGRESS = REPO_ROOT / "scripts" / "roadmap_progress.py"
TOUCHED = REPO_ROOT / "scripts" / "check_roadmap_touched.sh"

HEAD = "# ROADMAP\n\nLast updated: 2026-10-28 10:00 UTC\n"
STALE = (
    "<!-- PROGRESS:START -->\n"
    "| Phase | Name | Done | Total | Progress |\n"
    "|---|---|---|---|---|\n"
    "| OLD | STALE | 9 | 9 | 99% |\n"
    "<!-- PROGRESS:END -->\n"
)
FIXTURE = f"""{HEAD}
## 2. Progress

{STALE}
## 3. Readiness gates

- [x] **G1** One gate met.
- [ ] **G2** One gate open.

## 5. Phases and tasks

### Phase 0: Example work (blocks nothing)

- [x] **0.1** First.
- [ ] **0.2** Second.

### Phase 1: Later work

- [ ] **1.1** Only task.

### Phase 9: Backlog (not counted toward readiness)

- [ ] **9.1** Someday.
"""


def run(program: str, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run([program, *args], capture_output=True, text=True, check=False, cwd=cwd)


def base_ref(root: Path) -> str:
    """The first name that resolves to a commit in this checkout, or an empty string.

    The remote-tracking name is the one a workflow run has after fetching the history; the bare
    one covers a clone whose remote is not called `origin`. Returning "" instead of raising lets
    the caller state which assumption about the checkout was not met.
    """
    for ref in ("refs/remotes/origin/main", "refs/heads/main"):
        if run("git", "rev-parse", "--verify", "--quiet", ref, cwd=root).returncode == 0:
            return ref
    return ""


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
            *args,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


@pytest.fixture
def branch_repo(tmp_path: Path) -> Path:
    """A repository with a `main` commit and an empty branch on top of it."""
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "--initial-branch=main")
    (root / "README.md").write_text("base\n", encoding="utf-8")
    (root / "ROADMAP.md").write_text(HEAD, encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    git(root, "checkout", "-q", "-b", "task")
    return root


class TestProgressTable:
    def test_the_committed_roadmap_is_current(self) -> None:
        result = run("python3", str(PROGRESS), "--check", cwd=REPO_ROOT)
        assert result.returncode == 0, result.stdout + result.stderr

    def test_render_counts_each_phase_and_sums_the_readiness_phases(self, tmp_path: Path) -> None:
        roadmap = tmp_path / "ROADMAP.md"
        roadmap.write_text(FIXTURE, encoding="utf-8")
        result = run("python3", str(PROGRESS), str(roadmap))
        assert result.returncode == 0, result.stdout + result.stderr
        table = roadmap.read_text(encoding="utf-8")
        assert "| 0 | Example work | 1 | 2 | 50% |" in table
        assert "| 1 | Later work | 0 | 1 | 0% |" in table
        assert "| 9 (backlog) | Backlog | 0 | 1 | 0% |" in table
        assert "| **Phases 0 to 8** | **Readiness total** | **1** | **3** | **33%** |" in table
        assert "| Gates | G1 to G2 | 1 | 2 | 50% |" in table
        assert "STALE" not in table

    def test_a_stale_table_fails_the_check_and_prints_the_table_that_is_right(
        self, tmp_path: Path
    ) -> None:
        roadmap = tmp_path / "ROADMAP.md"
        stale = FIXTURE.replace("| OLD | STALE |", "| 0 | Example work |")
        roadmap.write_text(stale, encoding="utf-8")
        result = run("python3", str(PROGRESS), "--check", str(roadmap))
        assert result.returncode == 1
        assert "| 0 | Example work | 1 | 2 | 50% |" in result.stdout

    def test_a_progress_block_with_no_markers_is_an_error(self, tmp_path: Path) -> None:
        roadmap = tmp_path / "ROADMAP.md"
        roadmap.write_text(HEAD + "\n## 5. Phases\n\n- [ ] **0.1** Orphan.\n", encoding="utf-8")
        result = run("python3", str(PROGRESS), str(roadmap))
        assert result.returncode == 1
        assert "PROGRESS:START" in result.stderr

    def test_a_phase_with_no_tasks_is_an_error(self, tmp_path: Path) -> None:
        roadmap = tmp_path / "ROADMAP.md"
        roadmap.write_text(FIXTURE.replace("- [ ] **1.1** Only task.\n", ""), encoding="utf-8")
        result = run("python3", str(PROGRESS), str(roadmap))
        assert result.returncode == 1
        assert "Phase 1" in result.stderr


class TestRoadmapTouched:
    def test_a_change_that_skips_the_roadmap_fails(self, branch_repo: Path) -> None:
        (branch_repo / "src.py").write_text("x = 1\n", encoding="utf-8")
        git(branch_repo, "add", "-A")
        git(branch_repo, "commit", "-q", "-m", "code only")
        result = run("sh", str(TOUCHED), "refs/heads/main", cwd=branch_repo)
        assert result.returncode == 1
        assert "ROADMAP.md" in result.stdout

    def test_code_plus_an_updated_roadmap_and_timestamp_passes(self, branch_repo: Path) -> None:
        (branch_repo / "src.py").write_text("x = 1\n", encoding="utf-8")
        (branch_repo / "ROADMAP.md").write_text(
            HEAD.replace("10:00 UTC", "11:00 UTC"), encoding="utf-8"
        )
        git(branch_repo, "add", "-A")
        git(branch_repo, "commit", "-q", "-m", "code and roadmap")
        assert run("sh", str(TOUCHED), "refs/heads/main", cwd=branch_repo).returncode == 0

    def test_a_roadmap_edit_that_left_the_timestamp_alone_fails(self, branch_repo: Path) -> None:
        (branch_repo / "ROADMAP.md").write_text(HEAD + "\nA note.\n", encoding="utf-8")
        git(branch_repo, "add", "-A")
        git(branch_repo, "commit", "-q", "-m", "roadmap without a new timestamp")
        result = run("sh", str(TOUCHED), "refs/heads/main", cwd=branch_repo)
        assert result.returncode == 1
        assert "Last updated" in result.stdout

    def test_a_branch_with_no_commits_ahead_is_not_a_failure(self, branch_repo: Path) -> None:
        assert run("sh", str(TOUCHED), "refs/heads/main", cwd=branch_repo).returncode == 0

    def test_this_branch_passes_the_gate_it_is_adding(self) -> None:
        """If the gate cannot be satisfied by the work that adds it, it is the wrong gate."""
        ref = base_ref(REPO_ROOT)
        assert ref, (
            "neither origin/main nor main resolves in this checkout, so the gate has no base to "
            "compare against; ci.yml asks for fetch-depth: 0 for exactly this test"
        )
        result = run("sh", str(TOUCHED), ref, cwd=REPO_ROOT)
        assert result.returncode == 0, result.stdout + result.stderr
