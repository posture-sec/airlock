#!/bin/sh
# Issue #104 / task 9.69: build the environment the CONTRIBUTING.md checklist assumes.
#
# CONTRIBUTING.md lists four commands and never says how `pytest`, `ruff`, `mypy` or the package
# itself get onto the machine, and README.md's snippet installs the package non-editably, which
# puts a copy on the path instead of the checkout you are editing. This script is the missing step,
# and it is the only place to encode the order: venv first, then the editable install, then the
# dev group, because the console script `airlock scan --mode full .` needs comes from the second.
#
# What it deliberately does not do:
#   - activate anything. A script run as a subprocess cannot change the caller's shell, so it
#     prints the commands instead and says which PATH makes them the venv's.
#   - install 3.12 or 3.13. `requires-python` floors the package at 3.11 and CI is what runs the
#     other two interpreters (#103, task 9.59); choosing one locally is a developer decision.
#   - install a pinned tool set. The specifiers come out of `pyproject.toml`, so this file cannot
#     drift from it, and pinning is Dependabot's job (task 1.6).
#
# POSIX sh only, and no dependency beyond the standard library (AGENTS.md 4): `tomllib` is the
# only reader of the project metadata here.

set -eu

usage() {
    cat <<'USAGE'
usage: dev_setup.sh [--print]

Create the virtualenv, install the package editable and the dev group, then print the checks.

  --print          print the plan and change nothing
  PYTHON           interpreter used to create the venv and read pyproject.toml (default: python3)
  VENV             virtualenv directory (default: <repository root>/.venv)
  PIP              pip command used for both installs (default: $VENV/bin/pip)
USAGE
}

die() {
    printf 'dev_setup: %s\n' "$1" >&2
    exit 1
}

note() {
    printf '%s\n' "$1"
}

# Runs the command, or prints it instead of running it when --print was given.
run() {
    if [ "$PRINT" -eq 1 ]; then
        printf 'would run:'
        printf " '%s'" "$@"
        printf '\n'
    else
        "$@"
    fi
}

# One dev-group specifier per line, read from pyproject.toml rather than repeated here.
dev_group_args() {
    "$PYTHON" -c 'import sys
import tomllib

with open(sys.argv[1], "rb") as handle:
    data = tomllib.load(handle)
for specifier in data["dependency-groups"]["dev"]:
    print(specifier)' "$1"
}

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYPROJECT=$ROOT/pyproject.toml
PYTHON=${PYTHON:-python3}
VENV=${VENV:-$ROOT/.venv}
PRINT=0

for argument in "$@"; do
    case $argument in
    -h | --help)
        usage
        exit 0
        ;;
    --print)
        PRINT=1
        ;;
    *)
        usage >&2
        die "unknown argument: $argument"
        ;;
    esac
done

# Resolved against the caller's directory, before this script moves to the repository root so
# that `pip install -e .` and the four checks refer to the checkout.
case $VENV in
/*) ;;
*) VENV=$PWD/$VENV ;;
esac
BIN=$VENV/bin
PIP=${PIP:-$BIN/pip}
cd -- "$ROOT"

if [ -x "$BIN/python" ]; then
    note "venv: present at $VENV"
else
    note "venv: creating $VENV with $PYTHON"
    run "$PYTHON" -m venv "$VENV"
fi

# A venv directory without an interpreter is a create that did not happen, and installing into it
# would be the confusing failure. Under --print there is no interpreter to require yet.
if [ "$PRINT" -eq 0 ]; then
    [ -x "$BIN/python" ] ||
        die "no interpreter at $BIN/python after \`$PYTHON -m venv $VENV\`; the directory is present but empty"
fi

# The package first and editable: the self-scan below has to run against the working tree, and a
# non-editable copy answers for whatever was built, not for what is checked out.
note "install: the package, editable"
run "$PIP" install -e .

# Then the dev group. Each specifier is its own argument, so a specifier with a space in it cannot
# be split by the shell; an empty group is an error rather than a silent success.
note "install: the dev group named in pyproject.toml"
# Asked before the read, because a child's traceback in a script whose job is to stop a run early
# reads as the script itself crashing. Anything past a missing `tomllib` still reports with the
# child's own output, which is the detail that then matters.
if ! "$PYTHON" -c 'import tomllib' >/dev/null 2>&1; then
    die "\`$PYTHON\` has no tomllib, so it cannot read [dependency-groups] dev from $PYPROJECT; use Python 3.11 or newer (override with PYTHON=<interpreter>)"
fi
if ! specifiers=$(dev_group_args "$PYPROJECT"); then
    die "could not read [dependency-groups] dev from $PYPROJECT with \`$PYTHON\`"
fi
set --
while IFS= read -r specifier; do
    [ -n "$specifier" ] || continue
    set -- "$@" "$specifier"
done <<HEREDOC
$specifiers
HEREDOC
[ "$#" -gt 0 ] || die "$PYPROJECT has no [dependency-groups] dev entries to install"
run "$PIP" install "$@"

if [ "$PRINT" -eq 0 ]; then
    [ -x "$BIN/airlock" ] ||
        die "no \`airlock\` console script at $BIN/airlock after the editable install; the self-scan cannot run"
fi

# The checklist, printed rather than executed, so the caller sees what the environment is for.
printf '\n%s\n' "Ready. Run these from $ROOT, with $BIN first on PATH (this script does not activate):"
printf '  %s\n' \
    "python -m pytest" \
    "ruff check ." \
    "ruff format --check ." \
    "mypy src" \
    "airlock scan --mode full ."
