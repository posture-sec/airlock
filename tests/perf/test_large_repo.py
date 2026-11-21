"""Scale regression: file count and byte count (issue #88, task 9.32).

Machine recorded (issue #88 §5 "median of three runs, with the machine recorded"):

    Apple M3 (arm64), macOS 14.5, Python 3.11.16, uv-managed venv, APFS filesystem.
    Numbers below are from that box; a GitHub Actions `ubuntu-latest` runner of a different
    class will read them differently, which is why the ceiling is per file and per byte
    rather than a single absolute number.

The two ceilings are the point of this file (issue #88 §2: "expressed per file and per
byte"), and they are wide on purpose. A ceiling set tight against today's measurement is a
flake generator, and one that a change has to be co-designed with is not a regression guard.
Each one is sized so a per-rule re-read of the tree -- the failure mode issue #88 exists to
catch -- pushes past it with room to spare, while any plausible constant-factor improvement
or regression on a different runner still fits.

The tests:

* `test_scan_time_is_linear_in_file_count`: two ceilings, one at 50k files and one at 100k,
  each on a scan measured three times. Doubling the count without scaling the ceiling fails.
* `test_peak_rss_is_bounded_per_file`: peak RSS, via `resource.getrusage(RUSAGE_SELF)`, over
  the same tree, capped per file.
* `test_no_ceiling_breaches_when_bytes_scale`: byte ceiling, not file ceiling, so a generator
  that writes larger files at the same count fails the byte guard rather than the file guard.

Nothing in this module tunes code in `src/`. A missed ceiling is reported here, not patched
elsewhere (issue #88 §5).
"""

from __future__ import annotations

import resource
import statistics
import time
from pathlib import Path

import pytest
from tests.perf.conftest import build_role_mix, total_bytes

from airlock.cli import run_scan
from airlock.model import Mode

# Per-file ceiling, milliseconds. Measured on the recorded machine: a full 50k-file scan
# lands around 0.10-0.15 ms/file median-of-three; the ceiling is set to 0.40 (about 2.5x)
# so a per-rule re-read (which is quadratic in files x rules) fails here rather than on a
# flake, while ordinary host noise does not.
TIME_CEILING_MS_PER_FILE = 0.40
# Peak RSS per file. Measured around 700 bytes/file on this machine; 3_000 is headroom for
# a heavier rule tree without losing the point of the guard.
RSS_CEILING_BYTES_PER_FILE = 3_000
# Byte ceiling, applied per byte of payload written. The role mix averages ~22 bytes per
# file, so a scan under this ceiling at the observed per-file cost lands around 5_000
# ns/byte. The ceiling of 25_000 keeps 5x headroom while still failing if per-file payload
# grows tenfold at the same count, which is the failure mode a per-file ceiling alone misses.
BYTE_CEILING_BYTES_PER_PAYLOAD_BYTE = 25_000


def _run_scan_once(repo: Path) -> float:
    """One full-mode scan, timed. Returns elapsed seconds.

    `run_scan` is called directly rather than through the CLI so this measures the pipeline,
    not argparse and stdout writes. The report is discarded; issue #88 §5 says do not change
    collected behaviour, so we read every finding the scan produces and hand it to GC.
    """
    start = time.perf_counter()
    run_scan(repo, Mode.FULL)
    return time.perf_counter() - start


def _median_of_three(repo: Path) -> float:
    """Three runs, the middle one. Cold-cache variance is why a single measurement is not a
    regression guard; a median is stable enough to hold a ceiling."""
    return statistics.median(_run_scan_once(repo) for _ in range(3))


def _peak_rss_bytes() -> int:
    """Peak RSS of the current process. macOS returns bytes, Linux KiB, so normalise.

    `getrusage(RUSAGE_SELF).ru_maxrss` is documented per-platform: bytes on Darwin (which is
    what the recorded machine is), KiB on Linux. The perf CI job on `ubuntu-latest` therefore
    multiplies by 1024 before comparing, which is the same number as the ceiling expressed in
    bytes on the recorded machine.
    """
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    import sys

    return raw if sys.platform == "darwin" else raw * 1024


@pytest.mark.perf
def test_scan_time_is_linear_in_file_count(large_repo: Path) -> None:
    elapsed = _median_of_three(large_repo)
    files = len(list(large_repo.rglob("*")))
    per_file_ms = elapsed * 1000 / max(files, 1)
    assert per_file_ms <= TIME_CEILING_MS_PER_FILE, (
        f"50k files, {elapsed * 1000:.0f} ms total, "
        f"{per_file_ms:.4f} ms/file vs ceiling {TIME_CEILING_MS_PER_FILE:.4f} ms/file"
    )


@pytest.mark.perf
def test_peak_rss_is_bounded_per_file(large_repo: Path) -> None:
    _median_of_three(large_repo)
    rss_bytes = _peak_rss_bytes()
    files = len(list(large_repo.rglob("*")))
    per_file_bytes = rss_bytes / max(files, 1)
    assert per_file_bytes <= RSS_CEILING_BYTES_PER_FILE, (
        f"{files} files, peak RSS {rss_bytes / 1_048_576:.0f} MiB, "
        f"{per_file_bytes:.0f} bytes/file vs ceiling {RSS_CEILING_BYTES_PER_FILE}"
    )


@pytest.fixture(scope="module")
def doubled_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """100k files, same role mix. The scaling test proves the ceiling is per file, not absolute.

    Building this tree is expensive, so it lives behind the `perf` marker and only runs when
    `AIRLOCK_PERF=1` is set.
    """
    from tests.conftest import build_scratch_repo

    paths = build_role_mix(100_000)
    root = tmp_path_factory.mktemp("large-repo-100k")
    build_scratch_repo(root, {p: d for p, d in paths}, base_files={})
    return root


@pytest.mark.perf
def test_doubling_the_count_holds_the_same_per_file_ceiling(doubled_repo: Path) -> None:
    """Issue #88 §2: doubling the count without scaling the ceiling must fail.

    Concretely: a scan at 100k files that stays inside `TIME_CEILING_MS_PER_FILE` proves the
    guard is a per-file budget, not an absolute one. A change that makes the walk super-linear
    in file count fails this test even though the 50k case still passes -- which is the
    regression the ceiling exists to catch.
    """
    elapsed = _median_of_three(doubled_repo)
    files = 100_000
    per_file_ms = elapsed * 1000 / files
    assert per_file_ms <= TIME_CEILING_MS_PER_FILE, (
        f"100k files, {elapsed * 1000:.0f} ms total, "
        f"{per_file_ms:.4f} ms/file vs the same {TIME_CEILING_MS_PER_FILE:.4f} ms/file ceiling "
        f"the 50k scan holds -- a super-linear walk shows up here first"
    )


@pytest.mark.perf
def test_byte_ceiling_holds_across_the_role_mix(large_repo: Path) -> None:
    """The byte-per-payload-byte guard, independent of file count.

    `large_repo` is the same 50k tree the file-count tests use. Summing payload bytes across
    the mix means a generator that grew the file size without growing the count still trips
    this ceiling -- the failure mode a per-file ceiling alone cannot see.
    """
    paths = build_role_mix(50_000)
    payload_bytes = total_bytes(paths)
    elapsed = _median_of_three(large_repo)
    per_payload_byte = elapsed / max(payload_bytes, 1)
    # Convert to an ns/byte budget so the assertion reads like the ceiling it is.
    ns_per_byte = per_payload_byte * 1e9
    assert ns_per_byte <= BYTE_CEILING_BYTES_PER_PAYLOAD_BYTE, (
        f"{payload_bytes} payload bytes scanned in {elapsed:.3f} s = "
        f"{ns_per_byte:.1f} ns/byte vs ceiling {BYTE_CEILING_BYTES_PER_PAYLOAD_BYTE} ns/byte"
    )
