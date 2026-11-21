"""ReDoS timing harness (task 2.12, `PRD.md` FR-14 and 6.x, `ARCHITECTURE.md` 12).

The scanner's protection is structural: a line past `line_cap` never reaches a regex
(`rules.apply_patterns`), and the over-cap line is accounted for by `cfg-long-line` instead. This
module proves both halves, on inputs built to make a pattern work as hard as it can.

- Every pattern the scanner runs against attacker-controlled text is measured on cap-length
  adversarial lines: long runs of one character, unbalanced brackets, and the pattern's own literal
  fragments repeated, truncated and left dangling as a near miss.
- The 5 MB single-line file from `PRD.md` FR-14 is timed through the engine, where the length check
  is all that runs.
- A canary pattern that backtracks catastrophically is asserted to breach the same budget, so a
  green run means the bound bites rather than that it is too loose to notice.

Budgets are multiples of what the shipped patterns measure here: the worst cap-length line is
about 10 ms for the rule data and about 20 ms for `config_role`'s dangerous-command test against a
line of repeated `[a-z]`, so the per-line bound below is roughly three times the slowest real cost
while still being thousands of times smaller than what a backtracking pattern needs.
"""

from __future__ import annotations

import math
import multiprocessing
import re
import time
from pathlib import Path
from queue import Empty

import pytest

from airlock import fingerprint, runner
from airlock.detectors import DETECTOR_NAMES, ci_surface, config_role, stellar_seed
from airlock.model import EMPTY_MANIFEST, FileEntry, Policy, Rule, ScanContext
from airlock.roles import known_roles
from airlock.rules import load_role_globs, load_rules

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The longest line the engine will hand a regex: the shipped policy default.
LINE_CAP = Policy().line_cap
#: One line at the cap, times enough of them to reach the input `PRD.md` 6.x names.
ADVERSARIAL_INPUT_BYTES = 1_000_000
#: FR-14's oversized file: one line, no regex runs on it.
OVERSIZED_LINE_BYTES = 5_000_000

PER_LINE_BUDGET_MS = 60.0
ADVERSARIAL_SCAN_BUDGET_MS = 1_200.0
OVERSIZED_BUDGET_MS = 500.0

#: How long one pattern may take over the whole bait set before the measurement gives up. Several
#: times the budget above, so a slow-but-finished pattern is reported as a number and only a
#: blowing one reaches this.
MEASUREMENT_TIMEOUT_S = 10.0

#: A textbook exponential pattern, used only to show the bound discriminates. It is run against 22
#: characters, because that is already slow (about 350 ms measured): a super-linear pattern needs no
#: cap-length line to prove itself.
CANARY_PATTERN = r"(a+)+b"
CANARY_BAIT = "a" * 22

#: Regexes that reach attacker text and are not rule data: the spawn tiers, the computed
#: `require()`, the CI-surface pairings, and evidence normalization before hashing. A code rule's
#: matcher is exactly as much a ReDoS surface as a pattern rule's, and it is not in the rule data,
#: so nothing but this list would ever time it.
CODE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ci_surface._SECRETS_INTERP", ci_surface._SECRETS_INTERP),
    ("ci_surface._DISPLAY_VERB", ci_surface._DISPLAY_VERB),
    ("ci_surface._HEAD_REF", ci_surface._HEAD_REF),
    ("ci_surface._CHECKOUT_STEP", ci_surface._CHECKOUT_STEP),
    ("ci_surface._EXEC_TARGET", ci_surface._EXEC_TARGET),
    ("config_role._DANGEROUS_COMMAND", config_role._DANGEROUS_COMMAND),
    ("config_role._NON_LITERAL_REQUIRE", config_role._NON_LITERAL_REQUIRE),
    ("stellar_seed.CANDIDATE_RE", stellar_seed.CANDIDATE_RE),
    ("fingerprint._WS_RE", fingerprint._WS_RE),
)

#: Metacharacters and punctuation split a regex source into the literal fragments worth baiting.
_FRAGMENT_SPLIT = re.compile(r"[\\\[()\]{}|?*+$^.<>:=!,\s\-]+")
GENERIC_BAITS = ("a", "(", " ", '"', "[a-z]")


def shipped_rules() -> tuple[Rule, ...]:
    role_globs = load_role_globs(REPO_ROOT / "rules" / "roles.toml")
    return load_rules(
        REPO_ROOT / "rules" / "builtin",
        known_detectors=DETECTOR_NAMES,
        known_roles=sorted(known_roles(role_globs)),
    )


def fragments(source: str) -> tuple[str, ...]:
    """The literal runs inside a pattern source, long enough to start a partial match."""
    seen: list[str] = []
    for part in _FRAGMENT_SPLIT.split(source):
        if len(part) >= 3 and part not in seen:
            seen.append(part)
    return tuple(seen)


def bait_lines(source: str) -> tuple[str, ...]:
    """Cap-length lines that make this pattern work: runs, nesting, near misses of its own text."""
    lines = [bait * LINE_CAP for bait in GENERIC_BAITS]
    lines.append("(a" * (LINE_CAP // 2))
    for fragment in fragments(source):
        repeated = (fragment * (LINE_CAP // len(fragment) + 1))[:LINE_CAP]
        near = fragment[:-1]
        dangling = (near * (LINE_CAP // max(len(near), 1) + 1))[:LINE_CAP]
        lines.extend((repeated, dangling, "a" * (LINE_CAP - len(fragment)) + near))
    return tuple(lines)


def _measure(source: str, lines: tuple[str, ...], reply: multiprocessing.Queue) -> None:
    """Time one pattern over every bait line, in whichever process called for it."""
    pattern = re.compile(source)
    slowest = 0.0
    for line in lines:
        start = time.perf_counter()
        pattern.search(line)
        slowest = max(slowest, (time.perf_counter() - start) * 1000)
    reply.put(slowest)


def worst_line_ms(pattern: re.Pattern[str], lines: tuple[str, ...]) -> float:
    """The slowest line, in milliseconds, timed in a child process.

    A super-linear pattern at cap length does not come back, so the measurement cannot live in the
    test process: the rule that adds it would hang the suite rather than fail it. A pattern that has
    not answered within `MEASUREMENT_TIMEOUT_S` reads as infinite, which breaches any budget.
    """
    start_method = "fork" if "fork" in multiprocessing.get_all_start_methods() else "spawn"
    spawner = multiprocessing.get_context(start_method)
    reply: multiprocessing.Queue = spawner.Queue()
    child = spawner.Process(target=_measure, args=(pattern.pattern, lines, reply), daemon=True)
    child.start()
    try:
        return float(reply.get(timeout=MEASUREMENT_TIMEOUT_S))
    except Empty:
        return math.inf
    finally:
        child.terminate()
        child.join()
        reply.close()


def patterns_under_test() -> tuple[tuple[str, re.Pattern[str], tuple[str, ...]], ...]:
    """Every pattern, with the adversarial lines built from its own source."""
    named: list[tuple[str, re.Pattern[str]]] = list(CODE_PATTERNS)
    for rule in shipped_rules():
        pattern = rule.pattern
        if pattern is not None and pattern.kind == "regex":
            named.append((rule.id, re.compile(pattern.value[0])))
    return tuple((name, compiled, bait_lines(compiled.pattern)) for name, compiled in named)


#: Built once: the pattern set is fixed by the shipped rule data.
PATTERNS = patterns_under_test()


def entry(text: str) -> FileEntry:
    return FileEntry(
        path="postcss.config.js",
        sha256="a" * 64,
        roles=("tooling-config", "source"),
        text=text,
    )


def context(text: str) -> ScanContext:
    return ScanContext(
        entries=(entry(text),),
        policy=Policy(),
        manifest=EMPTY_MANIFEST,
        rules=shipped_rules(),
    )


def adversarial_text(bytes_target: int) -> str:
    """Cap-length adversarial lines, assembled from every shipped pattern, up to the target size."""
    lines: list[str] = []
    total = 0
    while total < bytes_target:
        for _, _, bait in patterns_under_test():
            line = bait[total % len(bait)]
            lines.append(line)
            total += len(line) + 1
            if total >= bytes_target:
                break
    return "\n".join(lines)


@pytest.mark.parametrize("name,pattern,bait", PATTERNS, ids=[item[0] for item in PATTERNS])
def test_a_cap_length_line_stays_inside_the_budget(
    name: str, pattern: re.Pattern[str], bait: tuple[str, ...]
) -> None:
    slowest = worst_line_ms(pattern, bait)
    assert slowest < PER_LINE_BUDGET_MS, f"{name} took {slowest:.1f} ms on one line"


def test_the_budget_catches_a_pattern_that_backtracks() -> None:
    slowest = worst_line_ms(re.compile(CANARY_PATTERN), (CANARY_BAIT,))
    assert slowest > PER_LINE_BUDGET_MS, (
        f"the harness no longer notices {CANARY_PATTERN}: {slowest:.1f} ms"
    )


def test_the_line_cap_holds_on_an_oversized_single_line() -> None:
    """FR-14: a 5 MB line is reported by its length, and no regex is run on it."""
    text = "a" * OVERSIZED_LINE_BYTES
    start = time.perf_counter()
    findings = runner.engine_findings(context(text))
    elapsed = (time.perf_counter() - start) * 1000

    assert elapsed < OVERSIZED_BUDGET_MS, f"a capped line took {elapsed:.0f} ms"
    assert [finding.rule_id for finding in findings] == ["cfg-long-line"]
    assert findings[0].line == 1


def test_a_megabyte_of_adversarial_text_scans_inside_the_runtime_target() -> None:
    """The whole engine, not one pattern: every rule over the input `PRD.md` 6.x names."""
    text = adversarial_text(ADVERSARIAL_INPUT_BYTES)
    assert len(text) >= ADVERSARIAL_INPUT_BYTES

    start = time.perf_counter()
    runner.scan(context(text))
    elapsed = (time.perf_counter() - start) * 1000

    assert elapsed < ADVERSARIAL_SCAN_BUDGET_MS, f"1 MB of adversarial text took {elapsed:.0f} ms"
