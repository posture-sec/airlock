"""Performance suite configuration and fixtures (issue #88, task 9.32).

Two things live here: the `perf` marker plumbing and the repository generator.

The marker registration goes through `pytest_configure` in this file, so the suite is skipped
unless `AIRLOCK_PERF=1` is set in the environment. Building 50,000 small files is slow enough
that pulling it into the ordinary pytest run would double CI time for a check that only bites
when the shape of the scan changes; the same argument is why it is a separate top-level
directory rather than an addition to `tests/unit/`.

The generator writes a role mix chosen to exercise every path the collector and detectors
reach, not one kind of file 50,000 times. A single-shape tree would understate role
dispatch (`src/airlock/collector.py`) and fingerprint cost
(`src/airlock/fingerprint.py:49`), which is the failure mode issue #88 is
guarding against. Every payload is a plain, non-triggering string, so the scan itself exits
`EXIT_PASS` and the measurement is the walk through the tree rather than through finding
handling. The trigger shapes already live in `tests/bypass/`, not here.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from tests.conftest import ScratchRepo

PERF_ENV = "AIRLOCK_PERF"
PERF_MARKER = "perf"


def pytest_configure(config: pytest.Config) -> None:
    """Register the marker (issue #88 §2: `pytest_configure` is where the marker lives).

    Registering here, in the conftest that owns the perf directory, means the marker is only
    visible when pytest reaches this file, which is only when a caller asks for `tests/perf`.
    """
    config.addinivalue_line(
        "markers",
        f"{PERF_MARKER}: scale measurement (issue #88). Runs only when {PERF_ENV}=1.",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip every `perf` item unless `AIRLOCK_PERF=1`.

    The default is off so a normal `python -m pytest` stays CI-fast. Setting the variable is
    the documented opt-in in issue #88 §2 and `ROADMAP.md` 9.32.
    """
    if os.environ.get(PERF_ENV) == "1":
        return
    skip = pytest.mark.skip(reason=f"set {PERF_ENV}=1 to run the scale measurement")
    for item in items:
        if PERF_MARKER in item.keywords:
            item.add_marker(skip)


# The role mix. Shares are documented in `BUCKETS` and are chosen so that every sensitive role
# in `src/airlock/roles.py` and both binary detectors (`native_binary`, `wasm_manifest`) see
# at least a thousand files. Nothing in a bucket is a trigger payload; the bypass suite owns
# those shapes, and issue #88 §7 says the perf harness does not judge findings.
#
# 50k files breaks down as:
#   source (`.py`)       30,000  (60%)  -- the bulk of any real tree
#   doc    (`.md`)        7,500  (15%)  -- `docs/**` in a large repository
#   package.json          4,000   (8%)  -- manifests in a monorepo
#   lockfile              2,500   (5%)  -- one per workspace
#   workflow              2,000   (4%)  -- `.github/workflows/**`
#   install hook          1,500   (3%)  -- `.husky/**` and `.githooks/**`
#   native binary         1,250 (2.5%)  -- `native_binary_artifact` detector
#   wasm artifact         1,250 (2.5%)  -- `wasm_manifest` detector
Bucket = tuple[str, str, int, int, bytes]
# (role, template, share_permille, per_file_bytes, payload)
BUCKETS: tuple[Bucket, ...] = (
    ("source", "src/mod_{n}.py", 600, 20, b"def f():\n    return 1\n"),
    ("doc", "docs/note_{n}.md", 150, 8, b"# Note\n"),
    ("package_manifest", "packages/pkg_{n}/package.json", 80, 14, b'{"name": "p"}\n'),
    ("lockfile", "packages/lock_{n}/pnpm-lock.yaml", 50, 20, b"lockfileVersion: 9\n"),
    ("workflow", ".github/workflows/job_{n}.yml", 40, 24, b"on:\n  push:\njobs: {}\n"),
    ("install_hook", ".githooks/pre-commit-{n}", 30, 17, b"#!/bin/sh\nexit 0\n"),
    # A ZIP magic header makes `roles_from_magic` claim `native-binary`; the detector
    # reads the header, the collector stores the whole file, and the file is not text.
    ("native_binary", "vendor/blob_{n}.bin", 25, 128, b"PK\x03\x04" + b"E" * 124),
    # Wasm magic + a version preamble is enough for the collector to label it `wasm`;
    # the manifest detector reports "unlisted", which is a WARN not a HIGH, so the
    # scan still exits 0 against the shipped fail_on = HIGH policy default.
    ("wasm", "contracts/art_{n}.wasm", 25, 72, b"\x00asm\x01\x00\x00\x00" + b"\x00" * 64),
)

_PERMILLE_TOTAL = sum(bucket[2] for bucket in BUCKETS)
assert _PERMILLE_TOTAL == 1000, _PERMILLE_TOTAL


def build_role_mix(count: int) -> list[tuple[str, bytes]]:
    """`count` files split by `BUCKETS` shares; the last bucket rounds the remainder.

    Deterministic and stable across runs, so the median-of-three is measuring scan cost
    rather than generator variance. Callers must not reorder without re-checking the
    ceilings in `test_large_repo.py`.
    """
    paths: list[tuple[str, bytes]] = []
    assigned = 0
    for i, (_role, template, share, _size, payload) in enumerate(BUCKETS):
        n = count * share // _PERMILLE_TOTAL
        if i == len(BUCKETS) - 1:
            # Round the last bucket to the remainder so `paths` totals exactly `count`.
            n = count - assigned
        for j in range(n):
            paths.append((template.format(n=j), payload))
        assigned += n
    assert len(paths) == count, (count, len(paths))
    return paths


def total_bytes(paths: list[tuple[str, bytes]]) -> int:
    """Sum of payload sizes; feeds the per-byte ceiling without re-walking the tree."""
    return sum(len(data) for _, data in paths)


@pytest.fixture(scope="module")
def large_repo(tmp_path_factory: pytest.TempPathFactory) -> ScratchRepo:
    """A 50k-file repository, built once for the whole perf module.

    The scan runs three times against the same tree so the median is a scan measurement
    rather than a build measurement. The tree is written by `build_scratch_repo` from
    `tests/conftest.py` -- one git HEAD commit, which is what `airlock.cli.run_scan`
    expects (`src/airlock/collector.py:121`).

    The fixture hands back the `ScratchRepo`, not just the root, because the per-file
    ceilings need the exact payload count. `root.rglob("*")` also yields every directory,
    which divides the cost by ~57k instead of 50k and quietly weakens the guard.
    """
    from tests.conftest import build_scratch_repo

    paths = build_role_mix(50_000)
    root = tmp_path_factory.mktemp("large-repo")
    files = {path: data for path, data in paths}
    return build_scratch_repo(root, files, base_files={})
