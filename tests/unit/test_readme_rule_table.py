"""Issue #29: pin the README rule tables and the `Builtin Rules` metric to the rule data.

`README.md` carries a hand-written table per rule family and a count in the metrics block. Nothing
compared either to `rules/builtin/*.toml`, so changing a `severity` or adding a rule published the
old answer. Gate G7 says the documents agree with the code, which is not checkable while the table
is reviewed by eye.

Two decisions keep the check honest rather than clever. The family of a table is read from the
bold name above it (`**`config_role`**`), and the rules of that family from the file whose stem is
that name, so the table cannot be matched against the wrong set by guessing from id prefixes.
Severity is compared on the first word of the cell, because `cfg-long-line` is the one rule whose
authored HIGH is demoted outside a sensitive role and the page says so in prose; the row is
correct and the third column stays for review.

`drift` is written over a table and a rule tuple so the mutated-severity case can call it with the
defect in place. It is the check, not an assertion about today's tree.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path

from tests.fixtures import shipped_rules

from airlock.model import Rule, Severity
from airlock.rules import load_rule_file

REPO_ROOT = Path(__file__).resolve().parents[2]
README = REPO_ROOT / "README.md"
RULES_DIR = REPO_ROOT / "rules" / "builtin"

_HEADER = re.compile(r"^\|\s*Rule\s*\|\s*Severity\s*\|\s*Shape\s*\|$")
_ROW = re.compile(r"^\|\s*`(?P<id>[a-z0-9][a-z0-9-]*)`\s*\|\s*(?P<severity>[^|]*?)\s*\|")
_FAMILY = re.compile(r"^\*\*`(?P<family>[a-z0-9_]+)`\*\*")
_METRIC = re.compile(r"^\|\s*Builtin Rules\s*\|\s*\*\*(?P<count>\d+) verified\*\*")


@dataclass(frozen=True)
class Row:
    """One table row: the rule id, the severity as written, and the line it is on."""

    rule_id: str
    severity: str
    line: int


@dataclass(frozen=True)
class Table:
    """One `| Rule | Severity | Shape |` table and the family heading that introduced it."""

    family: str | None
    line: int
    rows: tuple[Row, ...]


def families() -> dict[str, tuple[Rule, ...]]:
    """The shipped rules by file stem, which is the family name the page uses."""
    return {path.stem: load_rule_file(path) for path in sorted(RULES_DIR.glob("*.toml"))}


def tables(text: str) -> list[Table]:
    """Every long-form rule table, with the nearest bold family name above it."""
    found: list[Table] = []
    family: str | None = None
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = _FAMILY.match(line)
        if match:
            family = match.group("family")
        if not _HEADER.match(line):
            index += 1
            continue
        rows: list[Row] = []
        header_line = index + 1
        index += 2  # skip the header and the separator row
        while index < len(lines) and lines[index].startswith("|"):
            row = _ROW.match(lines[index])
            if row is None:
                raise AssertionError(
                    f"{README.name}:{index + 1} is a rule table row this parser cannot read:"
                    f" {lines[index]!r}"
                )
            rows.append(Row(row.group("id"), row.group("severity"), index + 1))
            index += 1
        found.append(Table(family, header_line, tuple(rows)))
    return found


def metric(text: str) -> int:
    """The `Builtin Rules` count the metrics block publishes."""
    for line in text.splitlines():
        match = _METRIC.match(line)
        if match:
            return int(match.group("count"))
    raise AssertionError(f"{README.name} has no `Builtin Rules` metric row")


def first_word(cell: str) -> str:
    return cell.strip().split(" ", 1)[0]


def drift(table: Table, rules: Iterable[Rule]) -> list[str]:
    """Every disagreement between one table and the family it claims. Empty means agreement."""
    rule_set = tuple(rules)
    problems: list[str] = []
    if table.family is None:
        problems.append(f"{README.name}:{table.line} has no bold family name above it")
    documented = {row.rule_id: row for row in table.rows}
    listed = [row.rule_id for row in table.rows]
    duplicates = sorted({rule_id for rule_id in listed if listed.count(rule_id) > 1})
    for rule_id in duplicates:
        problems.append(f"{README.name}:{documented[rule_id].line} lists {rule_id} twice")
    on_disk = {rule.id: rule for rule in rule_set}
    for rule_id in sorted(set(on_disk) - set(documented)):
        problems.append(f"{table.family}: rule {rule_id} is loaded but has no table row")
    for rule_id in sorted(set(documented) - set(on_disk)):
        row = documented[rule_id]
        problems.append(
            f"{README.name}:{row.line} lists {rule_id}, which family {table.family} does not hold"
        )
    for rule_id in sorted(set(documented) & set(on_disk)):
        row = documented[rule_id]
        authored = on_disk[rule_id].severity.name
        if first_word(row.severity) != authored:
            problems.append(
                f"{README.name}:{row.line} says {rule_id} is {row.severity!r},"
                f" but the rule data is {authored}"
            )
    return problems


class TestThePageIsRead:
    def test_the_four_rule_tables_are_found(self) -> None:
        found = tables(README.read_text(encoding="utf-8"))
        assert [table.family for table in found] == [
            "config_role",
            "wasm_manifest",
            "builtin_patterns",
            "ci_surface",
        ], "a table that moved away from its family heading is reported rather than skipped"

    def test_every_table_row_is_parsed(self) -> None:
        text = README.read_text(encoding="utf-8")
        rows = sum(len(table.rows) for table in tables(text))
        assert rows == 22, f"the parser read {rows} rows; the four tables hold 22"

    def test_the_metric_is_found(self) -> None:
        assert metric(README.read_text(encoding="utf-8")) > 0


class TestThePageMatchesTheRuleData:
    def test_each_table_matches_its_family(self) -> None:
        known = families()
        problems = [
            problem
            for table in tables(README.read_text(encoding="utf-8"))
            for problem in drift(table, known.get(table.family or "", ()))
        ]
        assert problems == []

    def test_no_rule_is_listed_twice_across_tables(self) -> None:
        listed = [
            row.rule_id
            for table in tables(README.read_text(encoding="utf-8"))
            for row in table.rows
        ]
        assert sorted(rule_id for rule_id in listed if listed.count(rule_id) > 1) == []

    def test_the_metric_equals_the_loaded_rule_count(self) -> None:
        assert metric(README.read_text(encoding="utf-8")) == len(shipped_rules())


class TestTheCheckBites:
    def test_a_mutated_severity_is_reported(self) -> None:
        text = README.read_text(encoding="utf-8")
        table = tables(text)[0]
        rule = next(rule for rule in families()["config_role"] if rule.id == table.rows[0].rule_id)
        flipped = Severity.WARN if rule.severity is Severity.HIGH else Severity.HIGH
        mutated = replace(rule, severity=flipped)
        others = [other for other in families()["config_role"] if other.id != rule.id]
        problems = drift(table, [mutated, *others])
        assert problems == [
            f"{README.name}:{table.rows[0].line} says {rule.id} is {table.rows[0].severity!r},"
            f" but the rule data is {mutated.severity.name}"
        ]

    def test_a_row_with_no_rule_is_reported(self) -> None:
        table = tables(README.read_text(encoding="utf-8"))[0]
        rules = [rule for rule in families()["config_role"] if rule.id != table.rows[0].rule_id]
        assert drift(table, rules) == [
            f"{README.name}:{table.rows[0].line} lists {table.rows[0].rule_id},"
            " which family config_role does not hold"
        ]

    def test_a_rule_with_no_row_is_reported(self) -> None:
        table = tables(README.read_text(encoding="utf-8"))[0]
        extra = Table(
            table.family,
            table.line,
            table.rows[:-1],
        )
        assert drift(extra, families()["config_role"]) == [
            f"config_role: rule {table.rows[-1].rule_id} is loaded but has no table row"
        ]
