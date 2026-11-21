"""Issue #75 / task 9.30: a closed stdout is a reader that stopped, not a scanner failure.

`airlock scan . | head -1` and a pager quit both close the read end of the pipe while the report
is being written. The scan finished and its verdict was already computed, so the caller is owed
the scan's own exit code (1 with findings, 0 without) rather than exit 3, which `ARCHITECTURE.md`
8 reserves for a bug in the scanner.

Both symptoms live below `main`, so every test here runs the module as a subprocess:

- the write inside `cli._emit` raises while `report.exit_code` is still in scope, which is where
  the verdict has to be recovered;
- the interpreter's own shutdown flush of `sys.stdout` raises after `main` has returned, which is
  where the traceback came from and is why `__main__` has to deal with it.

The before-and-after evidence for the second one is the stderr these tests read: an in-process
call to `main()` can neither close the descriptor nor shut the interpreter down. A normal run's
stdout is byte-for-byte what it was, which `tests/unit/test_cli.py` already pins by asserting the
rendered report of every exit path.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from tests.fixtures import assemble

from airlock.model import EXIT_FINDINGS, EXIT_PASS

# Built from fragments at call time (`AGENTS.md` 4): this repository's own `.py` files are read as
# role `source`, so a committed literal of the assembled line would be a finding against the tree.
PAYLOAD = f"{assemble('ev', 'al')}({assemble('Buf', 'fer.from')}(process.env.P, 'base64'))\n"
CLEAN = "export default { plugins: [] }\n"
POLICY = """version = 1

[policy]
fail_on = "high"
line_cap = 500
"""

#: Anything that makes a closed pipe look like a crash instead of a reader that stopped.
CRASH_WORDS = ("internal error", "BrokenPipeError", "Traceback")

#: The `airlock` package the child must run: this checkout's, at `src/airlock`.
SRC_DIR = Path(__file__).resolve().parents[2] / "src"


def child_env(**extra: str) -> dict[str, str]:
    """The parent environment with this checkout's `src` ahead of any installed airlock.

    `python -m airlock` searches site-packages before the working directory, so a machine with
    `pip install -e .` or `pip install .` pointed at another copy would have these tests probe that
    copy and report a green run for code the repository does not contain.
    """
    env = dict(os.environ)
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(SRC_DIR) if existing is None else f"{SRC_DIR}{os.pathsep}{existing}"
    env.update(extra)
    return env


def git(root: Path, *args: str) -> None:
    subprocess.run(
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


def seed(root: Path, body: str) -> None:
    """A committed repository holding one `.js` file, so the scan has a verdict to report."""
    (root / "airlock.toml").write_text(POLICY, encoding="utf-8")
    (root / "wasm-manifest.toml").write_text("version = 1\n", encoding="utf-8")
    (root / "index.js").write_text(body, encoding="utf-8")
    git(root, "init", "-q", "--initial-branch=main")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "fixture")


def run_with_closed_stdout(
    tmp_path: Path,
    root: Path,
    *args: str,
    unbuffered: bool = False,
    summary: Path | None = None,
) -> tuple[int, str]:
    """Run `python -m airlock` with the read end of its stdout already closed.

    The pipe is made by hand rather than with `stdout=subprocess.PIPE` because `Popen` keeps that
    descriptor and reads it in `communicate`, which is the opposite of a reader that stopped.
    `stderr` goes to a file so a long traceback cannot fill a pipe and deadlock the child.
    """
    read_end, write_end = os.pipe()
    os.close(read_end)
    stderr_path = tmp_path / "stderr.txt"
    env = child_env()
    if unbuffered:
        env["PYTHONUNBUFFERED"] = "1"
    if summary is not None:
        env["GITHUB_STEP_SUMMARY"] = str(summary)
    with open(stderr_path, "wb") as handle:
        child = subprocess.Popen(
            [sys.executable, "-m", "airlock", "scan", str(root), "--mode", "full", *args],
            stdout=write_end,
            stderr=handle,
            cwd=str(root),
            env=env,
        )
    os.close(write_end)
    code = child.wait()
    return code, stderr_path.read_text(encoding="utf-8")


@pytest.fixture
def dirty(tmp_path: Path) -> Path:
    root = tmp_path / "dirty"
    root.mkdir()
    seed(root, PAYLOAD)
    return root


@pytest.fixture
def clean(tmp_path: Path) -> Path:
    root = tmp_path / "clean"
    root.mkdir()
    seed(root, CLEAN)
    return root


class TestClosedPipeKeepsTheVerdict:
    def test_a_stopped_reader_on_a_repository_with_a_high_finding_exits_one(
        self, tmp_path: Path, dirty: Path
    ) -> None:
        code, stderr = run_with_closed_stdout(tmp_path, dirty)

        assert code == EXIT_FINDINGS, stderr
        assert not [word for word in CRASH_WORDS if word in stderr], stderr

    def test_a_stopped_reader_on_a_clean_repository_exits_zero(
        self, tmp_path: Path, clean: Path
    ) -> None:
        code, stderr = run_with_closed_stdout(tmp_path, clean)

        assert code == EXIT_PASS, stderr
        assert not [word for word in CRASH_WORDS if word in stderr], stderr

    def test_a_stopped_reader_on_an_unbuffered_stream_exits_one(
        self, tmp_path: Path, dirty: Path
    ) -> None:
        """The write site, not the shutdown flush.

        A block-buffered stdout raises at the interpreter's final flush, which only `__main__` can
        see. `PYTHONUNBUFFERED` moves the failure into `sys.stdout.write` inside `_emit`, so this
        is the case that proves the exit code is recovered where `report.exit_code` is in scope.
        """
        code, stderr = run_with_closed_stdout(tmp_path, dirty, unbuffered=True)

        assert code == EXIT_FINDINGS, stderr
        assert not [word for word in CRASH_WORDS if word in stderr], stderr

    def test_the_step_summary_is_written_even_when_the_report_cannot_be(
        self, tmp_path: Path, dirty: Path
    ) -> None:
        """The annotation stream is a file, and a reviewer still needs the HIGH listed.

        `_emit` returns after the write, so catching the failure there is what keeps this step of
        the GitHub run readable when nobody is watching the console.
        """
        summary = tmp_path / "summary.md"

        code, stderr = run_with_closed_stdout(tmp_path, dirty, summary=summary)

        assert code == EXIT_FINDINGS, stderr
        assert summary.is_file(), "the step summary was skipped with the stdout write"
        assert "HIGH" in summary.read_text(encoding="utf-8")


class TestOtherDestinationsUnaffected:
    def test_a_report_written_to_a_file_survives_a_closed_stdout(
        self, tmp_path: Path, dirty: Path
    ) -> None:
        """`--output` never touches the pipe, so both the file and the exit code are intact."""
        report = tmp_path / "report.txt"

        code, stderr = run_with_closed_stdout(tmp_path, dirty, "--output", str(report))

        assert code == EXIT_FINDINGS, stderr
        assert "HIGH" in report.read_text(encoding="utf-8")

    def test_a_json_report_over_a_closed_pipe_keeps_its_exit_code(
        self, tmp_path: Path, dirty: Path
    ) -> None:
        code, stderr = run_with_closed_stdout(tmp_path, dirty, "--format", "json")

        assert code == EXIT_FINDINGS, stderr
        assert not [word for word in CRASH_WORDS if word in stderr], stderr

    def test_a_reader_that_stays_open_still_gets_the_report(
        self, tmp_path: Path, dirty: Path
    ) -> None:
        """The ordinary path, run the same way, so a fix that swallowed real output fails here."""
        child = subprocess.run(
            [
                sys.executable,
                "-m",
                "airlock",
                "scan",
                str(dirty),
                "--mode",
                "full",
            ],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(dirty),
            env=child_env(),
        )

        assert child.returncode == EXIT_FINDINGS, child.stderr
        assert "1 HIGH" in child.stdout
        assert not [word for word in CRASH_WORDS if word in child.stderr], child.stderr
