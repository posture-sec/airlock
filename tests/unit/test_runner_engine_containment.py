"""The engine pass is contained per entry, like every detector (issue #14)."""

from __future__ import annotations

from collections.abc import Iterable

import pytest

from airlock import runner
from airlock.fingerprint import PendingFinding
from airlock.model import FileEntry, Manifest, Policy, ScanContext, Severity


class Boom(Exception):
    pass


def entry(path: str) -> FileEntry:
    return FileEntry(path=path, sha256="0" * 64, roles=("source",), text="x\n")


def context(*entries: FileEntry) -> ScanContext:
    return ScanContext(entries=entries, policy=Policy(), manifest=Manifest(), rules=())


def finding(path: str) -> PendingFinding:
    return PendingFinding(
        rule_id="cfg-dynamic-code",
        severity=Severity.HIGH,
        path=path,
        line=1,
        roles=("source",),
        message="earlier finding",
        evidence="eval(x)",
        suppressible=True,
    )


def test_a_later_entry_failure_keeps_earlier_findings_and_adds_the_gap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, second = entry("a.js"), entry("b.js")

    def patterns(
        rules: Iterable[object], item: FileEntry, line_cap: int
    ) -> tuple[PendingFinding, ...]:
        if item is second:
            raise Boom("pattern exploded")
        return (finding(item.path),)

    monkeypatch.setattr(runner, "apply_patterns", patterns)
    monkeypatch.setattr(runner, "cap_findings", lambda *args: ())

    pending = runner.engine_findings(context(first, second))

    assert [item.path for item in pending if item.rule_id == "cfg-dynamic-code"] == ["a.js"]
    gap = [item for item in pending if item.rule_id == "detector-error"]
    assert len(gap) == 1
    assert gap[0].severity is Severity.HIGH
    assert "pattern rules" in gap[0].message
    assert "b.js" in gap[0].message


def test_a_first_entry_failure_still_runs_the_next_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, second = entry("a.js"), entry("b.js")

    def patterns(
        rules: Iterable[object], item: FileEntry, line_cap: int
    ) -> tuple[PendingFinding, ...]:
        if item is first:
            raise Boom("pattern exploded")
        return (finding(item.path),)

    monkeypatch.setattr(runner, "apply_patterns", patterns)
    monkeypatch.setattr(runner, "cap_findings", lambda *args: ())

    pending = runner.engine_findings(context(first, second))

    assert [item.path for item in pending if item.rule_id == "cfg-dynamic-code"] == ["b.js"]
    assert sum(item.rule_id == "detector-error" for item in pending) == 1


def test_the_line_cap_stage_is_contained_too(monkeypatch: pytest.MonkeyPatch) -> None:
    item = entry("a.js")

    monkeypatch.setattr(runner, "apply_patterns", lambda *args: ())
    monkeypatch.setattr(
        runner,
        "cap_findings",
        lambda *args: (_ for _ in ()).throw(Boom("cap exploded")),
    )

    pending = runner.engine_findings(context(item))

    assert len(pending) == 1
    assert pending[0].rule_id == "detector-error"
    assert "line-cap account" in pending[0].message


def test_the_no_error_path_is_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    first, second = entry("a.js"), entry("b.js")

    monkeypatch.setattr(
        runner,
        "apply_patterns",
        lambda rules, item, line_cap: (finding(item.path),),
    )
    monkeypatch.setattr(runner, "cap_findings", lambda *args: ())

    pending = runner.engine_findings(context(first, second))

    assert [item.rule_id for item in pending] == ["cfg-dynamic-code", "cfg-dynamic-code"]
