"""The two launch paths must agree on the exit-code contract.

Task 9.30 (issue #74): `python -m airlock` and the console script both reach
`airlock.cli:main`, and a change to one must not make the process a caller sees
depend on how the tool was started.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from tests.fixtures import assemble

REPO_ROOT = Path(__file__).resolve().parents[2]
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


def console_command() -> list[str]:
    script = shutil.which("airlock")
    if script:
        return [script]
    return [sys.executable, "-c", "from airlock.cli import main; raise SystemExit(main())"]


def module_command() -> list[str]:
    return [sys.executable, "-m", "airlock"]


def launch_paths() -> list[tuple[str, list[str]]]:
    return [("module", module_command()), ("script", console_command())]


def run_launch(
    base: list[str],
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    run_env = os.environ.copy()
    src = str(REPO_ROOT / "src")
    existing = run_env.get("PYTHONPATH", "")
    run_env["PYTHONPATH"] = src if not existing else src + os.pathsep + existing
    if env:
        run_env.update(env)
    return subprocess.run(
        [*base, *args],
        cwd=cwd,
        env=run_env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def clean_repo(tmp_path: Path) -> Path:
    root = tmp_path / "clean"
    root.mkdir()
    git(root, "init", "-q", "--initial-branch=main")
    seed(root)
    return root


@pytest.fixture
def high_repo(tmp_path: Path) -> Path:
    root = tmp_path / "high"
    root.mkdir()
    git(root, "init", "-q", "--initial-branch=main")
    seed(root)
    write(root, "postcss.config.mjs", PAYLOAD)
    commit(root)
    return root


@pytest.fixture
def injected_env(tmp_path: Path) -> dict[str, str]:
    hook = tmp_path / "inject"
    hook.mkdir()
    (hook / "sitecustomize.py").write_text(
        "import os\n"
        "if os.environ.get('AIRLOCK_TEST_INJECT_INTERNAL') == '1':\n"
        "    import airlock.collector as collector\n"
        "    def _boom(*_a, **_k):\n"
        "        raise RuntimeError('injected')\n"
        "    collector.collect = _boom\n",
        encoding="utf-8",
    )
    src = str(REPO_ROOT / "src")
    return {
        "PYTHONPATH": str(hook) + os.pathsep + src,
        "AIRLOCK_TEST_INJECT_INTERNAL": "1",
    }


class TestLaunchPathParity:
    @pytest.mark.parametrize("label,base", launch_paths(), ids=["module", "script"])
    def test_clean_repository_exits_zero(
        self, label: str, base: list[str], clean_repo: Path
    ) -> None:
        proc = run_launch(base, ["scan", str(clean_repo), "--mode", "full"])
        assert proc.returncode == 0, (label, proc.stdout, proc.stderr)

    @pytest.mark.parametrize("label,base", launch_paths(), ids=["module", "script"])
    def test_high_finding_exits_one(self, label: str, base: list[str], high_repo: Path) -> None:
        proc = run_launch(base, ["scan", str(high_repo), "--mode", "full"])
        assert proc.returncode == 1, (label, proc.stdout, proc.stderr)

    @pytest.mark.parametrize("label,base", launch_paths(), ids=["module", "script"])
    def test_usage_error_exits_two(self, label: str, base: list[str]) -> None:
        proc = run_launch(base, ["scan", "--event", "release"])
        assert proc.returncode == 2, (label, proc.stdout, proc.stderr)

    @pytest.mark.parametrize("label,base", launch_paths(), ids=["module", "script"])
    def test_internal_error_exits_three_with_one_error_line(
        self, label: str, base: list[str], clean_repo: Path, injected_env: dict[str, str]
    ) -> None:
        proc = run_launch(base, ["scan", str(clean_repo), "--mode", "full"], env=injected_env)
        assert proc.returncode == 3, (label, proc.stdout, proc.stderr)
        assert "Traceback" not in proc.stderr
        assert "Traceback" not in proc.stdout
        lines = [line for line in proc.stderr.splitlines() if line.strip()]
        assert len(lines) == 1, (label, proc.stderr)
        assert lines[0].startswith("airlock: internal error:")
        assert "injected" in lines[0]

    def test_paths_agree_on_all_four_fixtures(
        self, clean_repo: Path, high_repo: Path, injected_env: dict[str, str]
    ) -> None:
        cases = [
            ("clean", ["scan", str(clean_repo), "--mode", "full"], None, 0),
            ("high", ["scan", str(high_repo), "--mode", "full"], None, 1),
            ("usage", ["scan", "--event", "release"], None, 2),
            ("internal", ["scan", str(clean_repo), "--mode", "full"], injected_env, 3),
        ]
        rows = []
        for name, args, env, expected in cases:
            results = {}
            for label, base in launch_paths():
                proc = run_launch(base, args, env=env)
                results[label] = proc
                assert proc.returncode == expected, (name, label, proc.stdout, proc.stderr)
                assert "Traceback" not in proc.stderr
            assert results["module"].returncode == results["script"].returncode, name
            rows.append((name, expected))
        assert rows == [("clean", 0), ("high", 1), ("usage", 2), ("internal", 3)]


class TestEntryPointMetadata:
    def test_pyproject_script_target_is_airlock_cli_main(self) -> None:
        config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        assert config["project"]["scripts"]["airlock"] == "airlock.cli:main"

    def test_dunder_main_calls_main_under_main_guard(self) -> None:
        text = (REPO_ROOT / "src" / "airlock" / "__main__.py").read_text(encoding="utf-8")
        assert "from .cli import main" in text
        assert 'if __name__ == "__main__":' in text
        assert "main()" in text
        assert "raise SystemExit(" in text
