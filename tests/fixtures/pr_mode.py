"""Two-commit repository fixture for PR-mode testing (issue #77).

Builds a repository where the base commit defines a trusted policy (fail_on = "high"),
and the head commit modifies policy (fail_on = "info") and introduces findings.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from tests.fixtures import assemble

BASE_POLICY = """version = 1

[policy]
fail_on = "high"
"""

HEAD_POLICY = """version = 1

[policy]
fail_on = "info"
"""

BASE_MANIFEST = """version = 1
"""


def _run_git(root: Path, *args: str) -> str:
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


def build_pr_mode_repo(dest: Path, *, high: bool = False) -> str:
    """Build a two-commit git repo fixture and return the base commit SHA.

    Base commit:
    - airlock.toml (fail_on = "high")
    - wasm-manifest.toml (version = 1)
    - README.md (clean)

    Head commit:
    - airlock.toml (fail_on = "info")
    - .github/workflows/test.yml (triggers pat-privileged-trigger WARN)
    - (if high=True) postcss.config.mjs (triggers cfg-dynamic-code HIGH)
    """
    dest.mkdir(parents=True, exist_ok=True)
    _run_git(dest, "init", "-q", "--initial-branch=main")

    # Base commit
    (dest / "airlock.toml").write_text(BASE_POLICY, encoding="utf-8")
    (dest / "wasm-manifest.toml").write_text(BASE_MANIFEST, encoding="utf-8")
    (dest / "README.md").write_text("# Test Repo\n", encoding="utf-8")
    _run_git(dest, "add", "-A")
    _run_git(dest, "commit", "-q", "-m", "base: establish trusted policy")

    base_sha = _run_git(dest, "rev-parse", "HEAD").strip()

    # Head commit
    (dest / "airlock.toml").write_text(HEAD_POLICY, encoding="utf-8")

    workflow_path = dest / ".github" / "workflows" / "test.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    # Assemble trigger string so no committed live payload exists in airlock codebase
    trigger = assemble("pull_", "request_", "target")
    workflow_content = (
        f"name: test\non:\n  {trigger}:\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo ok\n"
    )
    workflow_path.write_text(workflow_content, encoding="utf-8")

    if high:
        # Assemble eval payload in tooling config to trigger cfg-dynamic-code (HIGH)
        config_path = dest / "postcss.config.mjs"
        eval_fn = assemble("ev", "al")
        config_path.write_text(f"export default {{ payload: {eval_fn}(1) }};\n", encoding="utf-8")

    _run_git(dest, "add", "-A")
    _run_git(dest, "commit", "-q", "-m", "head: update policy and add changes")

    return base_sha


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a 2-commit PR mode fixture repo.")
    parser.add_argument("dest", type=Path, help="Destination directory for fixture repository")
    parser.add_argument("--high", action="store_true", help="Include a HIGH finding at HEAD")
    args = parser.parse_args()

    base_sha = build_pr_mode_repo(args.dest, high=args.high)
    print(f"Built PR mode fixture at {args.dest} with base SHA {base_sha} (high={args.high})")


if __name__ == "__main__":
    main()
