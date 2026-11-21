"""Issue #104 / task 9.69: `scripts/dev_setup.sh` builds the environment, and this proves it.

The script is the answer to "the four commands in `CONTRIBUTING.md` assume `pytest`, `ruff`, `mypy`
and an installed `airlock`, and nothing says how any of them got there". Because it is a shell
script, the only way to hold it to that is to run it, so this does: every case executes
`sh scripts/dev_setup.sh` with `VENV` under `tmp_path` and both `PIP` and `PYTHON` pointed at a
recording shim, which means the assertions are about the argv the script actually built rather than
about its text.

The venv itself is created for real, because "creates the venv only when missing" is a claim about
`python -m venv` and nothing else can answer it; `pip` is the shim, because installing the dev group
for real would put a network call in the suite, which `AGENTS.md` 4 forbids and a reviewer cannot
re-run offline. The shim stands in for the part of pip the script depends on: writing the
`airlock` console script, which is what the self-scan step then looks for.

The two refusals are the load-bearing cases. A setup script that exits 0 while the interpreter or
the console script is missing is worse than no script, because the next command then fails somewhere
that looks unrelated to the setup. Both are checked here with a shim that does not produce the file,
and each asserts the message names the file it could not find.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "dev_setup.sh"
PYPROJECT = REPO_ROOT / "pyproject.toml"

#: The checklist the script prints: the four commands from `CONTRIBUTING.md` step 4, plus the
#: self-scan that needs the console script the editable install provides.
CHECKS = (
    "python -m pytest",
    "ruff check .",
    "ruff format --check .",
    "mypy src",
    "airlock scan --mode full .",
)

#: An invocation is recorded as RS followed by US-separated arguments, RS-delimited. The separators
#: are octal escapes printed by the shim rather than literal control characters in its source. The
#: argument inside the record matters here: the script hands the interpreter a multi-line `-c`
#: program, so a newline-delimited record would split one invocation into several.
CALL_SEP = "\x1e"
ARG_SEP = "\x1f"

_STUB_HEAD = """#!/bin/sh
set -eu
printf '\\036' >> "${__RECORD__:?}"
for argument in "$@"; do
  printf '\\037%s' "$argument" >> "${__RECORD__}"
done
"""

#: Stands in for pip: records the argv, and writes the console script an editable install would.
PIP_STUB = (
    _STUB_HEAD.replace("__RECORD__", "RECORD_PIP")
    + """
if [ "${MAKE_SCRIPT:-yes}" = yes ]; then
  for argument in "$@"; do
    if [ "$argument" = -e ]; then
      mkdir -p "$BIN"
      printf '#!/bin/sh\\nexit 0\\n' > "$BIN/airlock"
      chmod +x "$BIN/airlock"
    fi
  done
fi
exit 0
"""
)

#: Records the argv, then runs the real interpreter, unless the case wants a `python -m venv` that
#: creates nothing. `DEV_SETUP_REAL` is this file's own interpreter, which is where `tomllib` lives.
PYTHON_STUB = (
    _STUB_HEAD.replace("__RECORD__", "RECORD_PYTHON")
    + """
if [ "${EXEC:-yes}" = no ]; then
  exit 0
fi
exec "$DEV_SETUP_REAL" "$@"
"""
)


@dataclass
class Setup:
    """One run of the script, with the argv its two shims recorded."""

    result: subprocess.CompletedProcess[str]
    pip_calls: list[list[str]] = field(default_factory=list)
    python_calls: list[list[str]] = field(default_factory=list)

    @property
    def returncode(self) -> int:
        return self.result.returncode

    @property
    def stdout(self) -> str:
        return self.result.stdout

    @property
    def stderr(self) -> str:
        return self.result.stderr

    @property
    def failures(self) -> str:
        return f"exit {self.returncode}\\nstdout:\\n{self.stdout}\\nstderr:\\n{self.stderr}"

    def venv_creates(self) -> list[list[str]]:
        return [call for call in self.python_calls if call[:2] == ["-m", "venv"]]


def write_stub(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)
    return path


def records(path: Path) -> list[list[str]]:
    """Every invocation recorded in `path`, as its argv, in the order they were run."""
    if not path.exists():
        return []
    raw = path.read_bytes().decode("utf-8")
    return [call.split(ARG_SEP)[1:] for call in raw.split(CALL_SEP) if call.strip(ARG_SEP) != ""]


def dev_group() -> list[str]:
    """The dev specifiers as `pyproject.toml` declares them, read the way the script reads them."""
    with PYPROJECT.open("rb") as handle:
        return list(tomllib.load(handle)["dependency-groups"]["dev"])


def present_venv(tmp_path: Path) -> str:
    """A directory the script accepts as an existing venv, without paying for a real one.

    The script only ever tests `$VENV/bin/python` for existence; the installs go through `PIP` and
    the metadata read through `PYTHON`, so nothing runs the interpreter inside the venv. That makes
    this enough for every case except the two about creating it, and keeps the suite to one real
    `python -m venv` instead of six.
    """
    bin_dir = tmp_path / ".venv" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    interpreter = bin_dir / "python"
    interpreter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    interpreter.chmod(0o755)
    return str(tmp_path / ".venv")


def run_setup(
    tmp_path: Path,
    venv: str,
    arguments: tuple[str, ...],
    cwd: Path | None,
    **flags: bool,
) -> Setup:
    """`sh dev_setup.sh` with both shims installed and nothing else on the caller's environment."""
    pip_record, python_record = tmp_path / "pip.record", tmp_path / "python.record"
    for record in (pip_record, python_record):
        if record.exists():
            record.unlink()
    run_dir = cwd if cwd is not None else tmp_path
    env = {
        # No inherited `PYTHON`, `VENV` or `PIP`, and no user PATH: the script must work from the
        # three overrides it documents, and the suite must not reach a pip the case did not name.
        "PATH": os.defpath + os.pathsep + str(Path(sys.executable).parent),
        "DEV_SETUP_REAL": sys.executable,
        "RECORD_PIP": str(pip_record),
        "RECORD_PYTHON": str(python_record),
        "BIN": str(Path(run_dir, venv) / "bin"),
        "MAKE_SCRIPT": "yes" if flags.get("make_script", True) else "no",
        "EXEC": "yes" if flags.get("execute", True) else "no",
        "VENV": venv,
        "PIP": str(write_stub(tmp_path, "pip-stub.sh", PIP_STUB)),
        "PYTHON": str(write_stub(tmp_path, "python-stub.sh", PYTHON_STUB)),
    }
    result = subprocess.run(
        ["sh", str(SCRIPT), *arguments],
        capture_output=True,
        text=True,
        cwd=str(run_dir),
        env=env,
        check=False,
    )
    return Setup(
        result=result,
        pip_calls=records(pip_record),
        python_calls=records(python_record),
    )


def setup_environment(
    tmp_path: Path,
    venv: str | None = None,
    arguments: tuple[str, ...] = (),
    cwd: Path | None = None,
    **flags: bool,
) -> Setup:
    target = str(venv if venv is not None else tmp_path / ".venv")
    return run_setup(tmp_path, target, arguments, cwd, **flags)


class TestTheScriptIsAShellScript:
    def test_it_parses_as_posix_sh(self) -> None:
        """`sh -n` is the only portable reading of "POSIX sh", and it catches an
        unbalanced quote."""
        result = subprocess.run(
            ["sh", "-n", str(SCRIPT)], capture_output=True, text=True, check=False
        )
        assert result.returncode == 0, result.stderr
        assert SCRIPT.read_text(encoding="utf-8").startswith("#!/bin/sh\n")

    def test_it_never_sources_the_activate_script(self) -> None:
        """A subprocess cannot touch the caller's shell, so the script must not pretend it can."""
        text = SCRIPT.read_text(encoding="utf-8")
        sourced = [line for line in text.splitlines() if re.match(r"^\s*(\.|source)\s", line)]
        assert not sourced, f"the script must not source anything: {sourced}"
        assert "activate" in text, "the script should say why it does not activate"


class TestWhatItBuilds:
    def test_it_creates_the_venv_then_installs_and_a_second_run_creates_nothing(
        self, tmp_path: Path
    ) -> None:
        """The only case that runs a real `python -m venv`, which is what both
        halves need to mean."""
        venv = tmp_path / ".venv"
        interpreter = venv / "bin" / "python"
        setup = setup_environment(tmp_path, str(venv))
        assert setup.returncode == 0, setup.failures
        assert interpreter.exists(), "the venv was never created"
        assert len(setup.venv_creates()) == 1, setup.python_calls
        assert setup.venv_creates()[0][2] == str(venv)
        # The order is the requirement: the console script the self-scan runs comes from the
        # editable install, so an empty dev group or a swapped order still has to produce it.
        assert setup.pip_calls == [["install", "-e", "."], ["install", *dev_group()]]

        before = interpreter.stat().st_mtime_ns
        again = setup_environment(tmp_path, str(venv))
        assert again.returncode == 0, again.failures
        assert not again.venv_creates(), f"the second run recreated the venv: {again.python_calls}"
        assert interpreter.stat().st_mtime_ns == before, "the interpreter was rewritten"
        assert len(again.pip_calls) == 2, f"installs must still run: {again.pip_calls}"
        assert again.stdout.startswith("venv: present"), again.stdout

    def test_the_dev_group_is_read_from_pyproject_and_passed_as_separate_arguments(
        self, tmp_path: Path
    ) -> None:
        setup = setup_environment(tmp_path, present_venv(tmp_path))
        assert setup.returncode == 0, setup.failures
        # Identity with the file, not equality with a list repeated in this test: a specifier the
        # script word-split, dropped or invented changes the argument count, the order or the text.
        assert setup.pip_calls[1] == ["install", *dev_group()], setup.pip_calls[1]

    def test_it_installs_nothing_from_the_network(self, tmp_path: Path) -> None:
        setup = setup_environment(tmp_path, present_venv(tmp_path))
        assert setup.returncode == 0, setup.failures
        flat = [argument for call in setup.pip_calls for argument in call]
        assert [a for a in flat if a in ("--quiet", "--no-deps")] == []
        assert not [a for a in flat if a in ("--index-url", "--find-links", "--extra-index-url")]
        assert not [a for a in flat if a.startswith(("http://", "https://", "git+"))], flat
        # Every install went through the named shim, which is why none of them could reach an index.
        assert all(call[0] == "install" for call in setup.pip_calls)

    def test_it_prints_the_four_commands_and_the_self_scan(self, tmp_path: Path) -> None:
        setup = setup_environment(tmp_path, present_venv(tmp_path))
        assert setup.returncode == 0, setup.failures
        for command in CHECKS:
            assert f"  {command}\n" in setup.stdout, f"{command} missing from:\n{setup.stdout}"

    def test_the_venv_path_resolves_against_the_directory_the_caller_ran_from(
        self, tmp_path: Path
    ) -> None:
        """The script cds to the repository, so a relative `VENV` has to mean the caller's cwd."""
        caller = tmp_path / "elsewhere"
        caller.mkdir()
        setup = setup_environment(tmp_path, "scratch-venv", cwd=caller, execute=False)
        assert setup.returncode != 0, setup.stdout
        assert str(caller / "scratch-venv" / "bin" / "python") in setup.stderr, setup.stderr


class TestWhatItRefuses:
    def test_a_create_that_made_no_interpreter_installs_nothing(self, tmp_path: Path) -> None:
        """`python -m venv` that exits 0 without an interpreter must not be answered with a pip."""
        setup = setup_environment(tmp_path, execute=False)
        assert setup.returncode != 0, setup.stdout
        assert "bin/python" in setup.stderr, setup.stderr
        assert setup.pip_calls == [], f"installs ran anyway: {setup.pip_calls}"

    def test_a_missing_console_script_is_refused(self, tmp_path: Path) -> None:
        setup = setup_environment(tmp_path, present_venv(tmp_path), make_script=False)
        assert setup.returncode != 0, setup.stdout
        assert "airlock" in setup.stderr, setup.stderr
        assert len(setup.pip_calls) == 2, "both installs should have been attempted"

    def test_an_unknown_argument_is_refused(self, tmp_path: Path) -> None:
        setup = setup_environment(tmp_path, present_venv(tmp_path), arguments=("--frobnicate",))
        assert setup.returncode != 0, setup.stdout
        assert "usage:" in setup.stderr, setup.stderr
        assert setup.pip_calls == [], setup.pip_calls


class TestTheDryRun:
    def test_print_names_the_plan_and_changes_nothing(self, tmp_path: Path) -> None:
        venv = tmp_path / ".venv"
        setup = setup_environment(tmp_path, str(venv), ("--print",))
        assert setup.returncode == 0, setup.failures
        assert not venv.exists(), "--print created the venv"
        assert setup.pip_calls == [], "--print ran pip"
        assert not setup.venv_creates(), "--print ran python -m venv"
        for fragment in ("venv", str(venv), "install"):
            assert fragment in setup.stdout, setup.stdout
        for command in CHECKS:
            assert command in setup.stdout, setup.stdout

    def test_print_reads_the_dev_group_from_pyproject(self, tmp_path: Path) -> None:
        setup = setup_environment(tmp_path, str(tmp_path / ".venv"), ("--print",))
        assert setup.returncode == 0, setup.failures
        for specifier in dev_group():
            assert f"'{specifier}'" in setup.stdout, (specifier, setup.stdout)
