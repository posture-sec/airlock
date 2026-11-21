"""The shell contract of `scripts/check_roadmap_touched.sh` (issue #93).

The gate runs in CI on every pull request, and its failure branches are statements about the diff
rather than about the tree: no base ref, a base ref that is not a commit here, no merge base at all,
a change that skips `ROADMAP.md`, and a `ROADMAP.md` whose `Last updated` line did not move or is
gone. A refactor that reorders those `if` blocks, drops the `${GITHUB_BASE_REF:-}` fallback, or
moves a message from stderr to stdout still lets a pull request merge, because the gate would then
pass what it exists to fail. `tests/unit/test_roadmap_gate.py` covers two of the branches against
its own repository and leaves the base-ref resolution untouched.

Every case here builds a throwaway repository under `tmp_path` and runs the script with `sh`, which
is how `.github/workflows/roadmap-check.yml` calls it. The script is never modified: these tests
only read its exit code and its output.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_roadmap_touched.sh"

BASE_DATE = "2026-10-28 10:00 UTC"
NEW_DATE = "2026-11-02 08:00 UTC"


def roadmap(updated: str | None = BASE_DATE) -> str:
    """A roadmap file with a date line, or without one when `updated` is `None`."""
    header = "# ROADMAP\n\n"
    if updated is not None:
        header += f"Last updated: {updated}\n"
    return header + "\n## 5. Phases and tasks\n\n### Phase 9: Backlog\n\n- [ ] **9.1** Work.\n"


def git(root: Path, *args: str, env: dict[str, str] | None = None) -> str:
    """Run git in `root` as a fixed identity, failing loudly rather than reporting a false pass.

    The identity is per repository rather than global because the test cannot assume the machine
    running it has a git identity configured, and a commit that silently inherited one from the
    developer's `~/.gitconfig` would still be a valid commit for every assertion here.
    """
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
        env=env,
    )
    return result.stdout


def run_hook(
    root: Path, *args: str, base_ref_env: str | None = None, clear_base_ref: bool = False
) -> subprocess.CompletedProcess[str]:
    """Invoke the gate the way the workflow does, with `sh` and an explicit base ref.

    `GITHUB_BASE_REF` is removed rather than left alone when the case is about a missing base,
    because the variable is inherited from the outer environment on a CI runner and a test that
    meant "no base ref" would then be testing the fallback instead.
    """
    env = dict(os.environ)
    if clear_base_ref:
        env.pop("GITHUB_BASE_REF", None)
    if base_ref_env is not None:
        env["GITHUB_BASE_REF"] = base_ref_env
    return subprocess.run(
        ["sh", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=root,
        env=env,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A repository on `main` with a roadmap, plus a `task` branch with nothing on it yet."""
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "--initial-branch=main")
    (root / "README.md").write_text("base\n", encoding="utf-8")
    (root / "ROADMAP.md").write_text(roadmap(), encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    git(root, "checkout", "-q", "-b", "task")
    return root


@pytest.fixture
def cloned_repo(tmp_path: Path, repo: Path) -> Path:
    """A clone of `repo` on a `task` branch, holding `origin/main` and no local `main`.

    The local branch is deleted on purpose: the case this exists for is the `${GITHUB_BASE_REF:-}`
    fallback, which prepends `origin/`. If plain `main` resolved too, dropping the prefix would
    still pass, and the fallback would be untested.
    """
    clone = tmp_path / "clone"
    git(tmp_path, "clone", "-q", "--branch", "main", str(repo), str(clone))
    git(clone, "checkout", "-q", "-b", "task")
    git(clone, "branch", "-D", "main")
    return clone


def commit(root: Path, **files: str) -> None:
    """Write `files` and make them one commit on the current branch."""
    for name, text in files.items():
        (root / name).write_text(text, encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "change")


class TestNoBaseRef:
    def test_with_no_argument_and_no_environment_it_exits_1_and_says_what_to_do(
        self, repo: Path
    ) -> None:
        commit(repo, **{"src.py": "x = 1\n"})
        result = run_hook(repo, clear_base_ref=True)
        assert result.returncode == 1
        assert "no base ref" in result.stderr
        assert result.stdout == ""

    def test_the_environment_variable_is_used_when_there_is_no_argument(
        self, cloned_repo: Path
    ) -> None:
        """The `${GITHUB_BASE_REF:-}` fallback the script's own header documents.

        The workflow passes the base as an argument, so nothing but a person running the script by
        hand exercises this branch. `cloned_repo` has no local `main`, only `origin/main`, so an
        implementation that read the variable without prefixing it would fail here rather than
        silently resolving a local branch.
        """
        commit(cloned_repo, **{"src.py": "x = 1\n", "ROADMAP.md": roadmap(NEW_DATE)})
        result = run_hook(cloned_repo, base_ref_env="main", clear_base_ref=True)
        assert result.returncode == 0, result.stdout + result.stderr
        assert BASE_DATE in result.stdout and NEW_DATE in result.stdout

    def test_an_unresolvable_environment_base_ref_is_refused_by_name(self, repo: Path) -> None:
        result = run_hook(repo, base_ref_env="release/9", clear_base_ref=True)
        assert result.returncode == 1
        assert "refs/remotes/origin/release/9 is not a commit here" in result.stderr


class TestUnresolvableBase:
    def test_an_argument_that_is_not_a_commit_exits_1_naming_it(self, repo: Path) -> None:
        result = run_hook(repo, "refs/heads/no-such-branch", clear_base_ref=True)
        assert result.returncode == 1
        assert "refs/heads/no-such-branch is not a commit here" in result.stderr

    def test_the_argument_wins_over_the_environment(self, repo: Path) -> None:
        """The workflow always passes the base positionally, so the argument has to decide.

        A script that consulted `GITHUB_BASE_REF` first would report an error naming the variable
        rather than the ref the caller actually typed.
        """
        result = run_hook(
            repo, "refs/heads/no-such-branch", base_ref_env="main", clear_base_ref=True
        )
        assert result.returncode == 1
        assert "refs/heads/no-such-branch is not a commit here" in result.stderr

    def test_an_unrelated_history_reports_no_merge_base_rather_than_an_empty_diff(
        self, repo: Path
    ) -> None:
        """The third exit, which no other branch can stand in for.

        A branch with no common ancestor is not "nothing changed": `git merge-base` fails, and if
        that failure were swallowed the diff would come back empty and the pull request would pass
        the gate with no roadmap edit at all.
        """
        git(repo, "checkout", "-q", "--orphan", "unrelated")
        commit(repo, **{"src.py": "x = 1\n"})
        result = run_hook(repo, "refs/heads/main", clear_base_ref=True)
        assert result.returncode == 1
        assert "cannot find a merge base with refs/heads/main" in result.stderr


class TestRoadmapMustBeTouched:
    def test_a_change_that_skips_the_roadmap_exits_1(self, repo: Path) -> None:
        commit(repo, **{"src.py": "x = 1\n"})
        result = run_hook(repo, "refs/heads/main", clear_base_ref=True)
        assert result.returncode == 1
        assert "touches files but not ROADMAP.md" in result.stdout
        assert "AGENTS.md section 1" in result.stdout

    def test_a_roadmap_edit_with_an_unchanged_date_exits_1_and_quotes_the_stale_date(
        self, repo: Path
    ) -> None:
        commit(repo, **{"src.py": "x = 1\n", "ROADMAP.md": roadmap() + "\nA note.\n"})
        result = run_hook(repo, "refs/heads/main", clear_base_ref=True)
        assert result.returncode == 1
        assert "its 'Last updated' line did not" in result.stdout
        assert BASE_DATE in result.stdout

    def test_a_roadmap_edit_with_no_date_line_at_all_exits_1(self, repo: Path) -> None:
        """The absent line is a different failure from an unchanged one, and a different message.

        Without this case a script that compared `before` and `after` first would report "did not
        change" for a roadmap that simply lost its header, sending the reader to the wrong fix.
        """
        commit(repo, **{"src.py": "x = 1\n", "ROADMAP.md": roadmap(None)})
        result = run_hook(repo, "refs/heads/main", clear_base_ref=True)
        assert result.returncode == 1
        assert "no 'Last updated:' line" in result.stderr


class TestPassingCases:
    def test_a_branch_with_nothing_ahead_of_its_base_exits_0(self, repo: Path) -> None:
        result = run_hook(repo, "refs/heads/main", clear_base_ref=True)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "nothing changed" in result.stdout

    def test_a_change_plus_a_moved_date_exits_0_and_reports_both_dates(self, repo: Path) -> None:
        commit(repo, **{"src.py": "x = 1\n", "ROADMAP.md": roadmap(NEW_DATE)})
        result = run_hook(repo, "refs/heads/main", clear_base_ref=True)
        assert result.returncode == 0, result.stdout + result.stderr
        assert f"{BASE_DATE} -> {NEW_DATE}" in result.stdout

    def test_a_roadmap_only_change_still_needs_the_date_to_move(self, repo: Path) -> None:
        """A roadmap edit that leaves the timestamp alone is the case the second check exists for,
        and the branch changes a file so the "nothing changed" exit cannot be what saves it.
        """
        commit(repo, **{"ROADMAP.md": roadmap() + "\nAnother note.\n"})
        result = run_hook(repo, "refs/heads/main", clear_base_ref=True)
        assert result.returncode == 1
        assert "its 'Last updated' line did not" in result.stdout
