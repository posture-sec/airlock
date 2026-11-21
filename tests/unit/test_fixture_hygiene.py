"""Issue #85 / task 9.32: the fixture builders must not themselves hold a payload or a seed.

`tests/fixtures/README.md` and `AGENTS.md` 4 both say this directory never carries a live-looking
payload, a real secret or a real Stellar seed: `assemble` puts a trigger together at call time so
the committed bytes stay below the rule. Nothing checked that. The only thing standing between a
pasted trigger and a published scanner was the dogfood scan (`airlock scan --mode full .`), which
reports after pytest and mypy, depends on the role map reaching `source`, and buries the file in a
stream of other findings.

So this globs the builders and runs the shipped rules over each one's text as role `source`, which
is the role a consumer's `.py` file gets. A HIGH here means somebody committed a real trigger
instead of fragments, and the fix is the literal, not the rule.

Three constraints shape the file. `AGENTS.md` 4 forbids importing a builder before its text is
scanned, so the rules come straight from `airlock.rules` and `airlock.detectors` rather than
through `tests.fixtures`, and the fragment constants are pulled out with `ast` rather than
`import`. Nothing on disk is rewritten to prove the guard bites either: `scan_builders` takes the
reader, so a test can feed a seed through the same aggregation the real assertion uses. And the
check is HIGH-only on purpose, because a long line in a test builder is a style question and mixing
WARNs in here would train the reader to skim the output.
"""

from __future__ import annotations

import ast
import base64
import hashlib
from collections.abc import Callable
from pathlib import Path

from airlock.detectors import DETECTOR_NAMES
from airlock.fingerprint import PendingFinding
from airlock.model import EMPTY_MANIFEST, FileEntry, Policy, ScanContext, Severity
from airlock.roles import SOURCE_ROLE, known_roles, resolve_roles
from airlock.rules import load_role_globs, load_rules
from airlock.runner import collect
from airlock.strkey import SEED_VERSION, crc16_xmodem

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures"

#: How many modules have to be on the list before a clean run means something. Four is the
#: count of builder files when this was written; below it the glob is probably matching nothing,
#: and a scan of nothing stays green forever.
MINIMUM_BUILDERS = 4

#: Modules a reader would expect to find, named rather than counted: the directory gaining a fifth
#: file says nothing, while `stellar_seed.py` disappearing means the glob moved.
EXPECTED_BUILDERS = ("__init__.py", "builtin_patterns.py", "ci_surface.py", "stellar_seed.py")

#: The builder a seed would most plausibly land in, and the one the litter test writes to in memory.
SEED_BUILDER = "stellar_seed.py"

#: How wide the collector reads to decide a binary role, which is what `resolve_roles` expects.
HEAD_BYTES = 262

ROLE_GLOBS = load_role_globs(REPO_ROOT / "rules" / "roles.toml")
RULES = load_rules(
    REPO_ROOT / "rules" / "builtin",
    known_detectors=DETECTOR_NAMES,
    known_roles=sorted(known_roles(ROLE_GLOBS)),
)


def read_file(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def builder_files() -> list[Path]:
    """Every module under `tests/fixtures/`, sorted, so a failure names them in file order."""
    return sorted(FIXTURES.glob("*.py"))


def high_findings(path: Path, text: str) -> list[PendingFinding]:
    """One file's text, as role `source`, under the shipped rules and the shipped default policy.

    The role is forced rather than resolved so the question stays the one the scanner asks about any
    consumer's source file whatever this repository's role map says tomorrow.
    `test_the_forced_role_is_what_the_scanner_would_choose` proves the two agree today.
    """
    data = text.encode("utf-8")
    entry = FileEntry(
        path=str(path.relative_to(REPO_ROOT)),
        sha256=hashlib.sha256(data).hexdigest(),
        roles=(SOURCE_ROLE,),
        text=text,
    )
    ctx = ScanContext(
        entries=(entry,),
        policy=Policy(),
        manifest=EMPTY_MANIFEST,
        rules=RULES,
    )
    return [finding for finding in collect(ctx) if finding.severity == Severity.HIGH]


def scan_builders(read: Callable[[Path], str] = read_file) -> list[PendingFinding]:
    """The HIGH findings across every builder, with the reader injectable so the guard bites.

    The default reads the tree. A test hands in a function that adds a seed to one builder, which
    runs this same loop over these same paths rather than over a copy of them.
    """
    return [finding for path in builder_files() for finding in high_findings(path, read(path))]


def describe(findings: list[PendingFinding]) -> str:
    return "\n".join(
        f"  {finding.path}:{finding.line} {finding.rule_id}: {finding.message}"
        for finding in findings
    )


def module_constants(text: str) -> list[tuple[int, str, str]]:
    """Module-level `NAME = "value"` string constants as (line, name, value).

    Read with `ast` so no builder is imported: importing runs the module, and what this file checks
    is the bytes on disk.
    """
    found: list[tuple[int, str, str]] = []
    for node in ast.parse(text).body:
        value = node.value if isinstance(node, ast.Assign) else None
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    found.append((node.lineno, target.id, value.value))
    return found


def seed_candidate() -> str:
    """A checksum-valid seed shape, assembled here and never committed.

    `bytes(range(32))` is a counting pattern, not a key: any test produces the same 32 bytes from
    the loop. Encoding it is what makes the candidate long enough and well enough formed for the
    rule to accept it, which is the only way to show this guard has teeth (`AGENTS.md` 4).
    """
    body = bytes([SEED_VERSION]) + bytes(range(32))
    checksum = crc16_xmodem(body).to_bytes(2, "little")
    return base64.b32encode(body + checksum).decode("ascii")


def seed_line() -> str:
    """A seed assigned to a constant, which is what a debug paste into a builder looks like."""
    return f'SECRET = "{seed_candidate()}"\n'


def litter_seed(path: Path) -> str:
    """The tree as it stands, except that the seed builder has a seed pasted onto its last line."""
    text = read_file(path)
    return text + seed_line() if path.name == SEED_BUILDER else text


class TestTheBuildersHoldNoPayload:
    def test_scanned_every_builder_module(self) -> None:
        files = builder_files()
        names = {path.name for path in files}
        assert len(files) >= MINIMUM_BUILDERS, (
            f"{FIXTURES} yielded {len(files)} modules; the glob is not finding the builders"
        )
        missing = sorted(set(EXPECTED_BUILDERS) - names)
        assert not missing, f"{FIXTURES} no longer holds {', '.join(missing)}"

    def test_no_builder_holds_a_high_finding(self) -> None:
        high = scan_builders()
        assert not high, (
            "a committed payload in tests/fixtures, which AGENTS.md 4 forbids. Build the "
            "trigger at test time from fragments with `assemble` instead:\n"
            f"{describe(high)}"
        )

    def test_the_forced_role_is_what_the_scanner_would_choose(self) -> None:
        """A guard that scans a role no real file receives is checking a fiction."""
        wrong: list[str] = []
        for path in builder_files():
            data = read_file(path).encode("utf-8")
            roles = resolve_roles(str(path.relative_to(REPO_ROOT)), data[:HEAD_BYTES], ROLE_GLOBS)
            if SOURCE_ROLE not in roles:
                wrong.append(f"{path.name} resolves to {sorted(roles)}")
        assert not wrong, (
            "these files are not `source`, so the scan above tests a role nothing receives: "
            + "; ".join(wrong)
        )

    def test_a_fragment_constant_read_alone_stays_below_the_rule(self) -> None:
        """Each committed fragment on its own, which is what `assemble` is relying on.

        The pattern rules match a call rather than a word, so a piece of one stays below them. This
        checks that claim per constant instead of trusting it, and names any fragment that would
        fire the moment somebody completed it.
        """
        flagged: list[str] = []
        for path in builder_files():
            for lineno, name, value in module_constants(read_file(path)):
                # `!r` keeps an embedded newline escaped, so the fragment is scanned on the one line
                # it occupies in the builder rather than split across two.
                if high_findings(path, f"{name} = {value!r}\n"):
                    flagged.append(f"{path.name}:{lineno} {name}")
        assert not flagged, f"fragment constants that fire on their own: {flagged}"


class TestTheGuardHasTeeth:
    def test_a_seed_shaped_literal_of_the_right_length_is_reported(self) -> None:
        """The exact mistake: somebody pastes a seed into a builder while debugging it."""
        findings = high_findings(FIXTURES / SEED_BUILDER, seed_line())
        assert [finding.rule_id for finding in findings] == ["stellar-seed"], describe(findings)
        assert findings[0].line == 1, "the finding has to name the line it is on"
        assert findings[0].path == f"tests/fixtures/{SEED_BUILDER}"

    def test_the_tree_assertion_fails_on_the_same_litter(self) -> None:
        """The per-file check is not what CI runs; this proves the aggregation bites as well."""
        clean = scan_builders()
        littered = scan_builders(read=litter_seed)
        assert not clean, describe(clean)
        assert [finding.rule_id for finding in littered] == ["stellar-seed"], describe(littered)

    def test_the_seed_candidate_is_the_shape_the_rule_wants(self) -> None:
        """56 characters and a leading S, or the two tests above pass for the wrong reason."""
        candidate = seed_candidate()
        assert len(candidate) == 56
        assert candidate.startswith("S"), "version byte 0x90 encodes to a leading S"
