"""Rule loader, validation and pattern engine tests (task 2.5).

Trigger strings here are inert (`eval(` inside a synthetic config), never a payload. Real
fixtures are assembled at test time in `tests/fixtures/` (task 3.2).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from airlock.model import STATE_RULE_IDS, FileEntry, Severity
from airlock.rules import (
    FALLBACK_LONG_LINE,
    LONG_LINE_RULE_ID,
    apply_patterns,
    cap_findings,
    line_matches,
    load_role_globs,
    load_rule_file,
    load_rules,
)

DYNAMIC_CODE = r"(?<![\w.])(?:eval|Function)[ \t]*\("
LONG_LINE_BODY = r"""
[[rule]]
id = "cfg-long-line"
title = "Line longer than the configured cap"
roles = ['tooling-config', 'source']
detector = 'pattern'
severity = 'high'
suppressible = true
rationale = 'Unbounded lines are a regex denial of service and a hiding place.'
pattern = { kind = 'literal', value = ['no literal ever matches this text'] }
tests = { positive = 'cfg_long_line', negative = 'cfg_long_line' }
"""


def rule_body(
    rule_id: str = "cfg-dynamic-code",
    *,
    roles: list[str] | None = None,
    severity: str = "high",
    suppressible: str = "false",
    detector: str = "pattern",
    kind: str = "regex",
    value: str = DYNAMIC_CODE,
    title: str = "Dynamic code execution in tooling config",
    with_pattern: bool = False,
) -> str:
    role_list = roles if roles is not None else ["tooling-config"]
    roles_toml = ", ".join(f"'{role}'" for role in role_list)
    fixture = rule_id.replace("-", "_")
    pattern = (
        f"pattern = {{ kind = '{kind}', value = '{value}' }}\n"
        if detector == "pattern" or with_pattern
        else ""
    )
    return (
        "[[rule]]\n"
        f"id = '{rule_id}'\n"
        f"title = '{title}'\n"
        f"roles = [{roles_toml}]\n"
        f"detector = '{detector}'\n"
        f"severity = '{severity}'\n"
        f"suppressible = {suppressible}\n"
        "rationale = 'Build configs have no reason to evaluate strings.'\n"
        f"{pattern}"
        f"tests = {{ positive = '{fixture}', negative = '{fixture}' }}\n"
    )


def rules_dir(tmp_path: Path, *bodies: str) -> Path:
    directory = tmp_path / "rules"
    directory.mkdir(exist_ok=True)
    for index, body in enumerate(bodies, start=1):
        (directory / f"builtin_{index}.toml").write_text(body, encoding="utf-8")
    return directory


def make_entry(
    path: str = "postcss.config.mjs",
    text: str = "eval(x)\n",
    roles: tuple[str, ...] = ("tooling-config", "source"),
    sha256: str | None = "a" * 64,
) -> FileEntry:
    return FileEntry(path=path, sha256=sha256, roles=roles, text=text)


@pytest.fixture
def dynamic_rules(tmp_path: Path) -> Path:
    return rules_dir(tmp_path, rule_body())


def test_shipped_state_rules_and_fallback_never_advertise_suppression() -> None:
    directory = Path(__file__).resolve().parents[2] / "rules" / "builtin"
    rules = (*load_rules(directory), FALLBACK_LONG_LINE)
    for rule in rules:
        if rule.id in STATE_RULE_IDS:
            assert not rule.suppressible, rule.id


def test_cap_finding_ignores_a_rules_suppressible_flag(tmp_path: Path) -> None:
    rules = load_rules(rules_dir(tmp_path, LONG_LINE_BODY))
    (finding,) = cap_findings(rules, make_entry(text="x" * 21), 20)
    assert finding.rule_id == LONG_LINE_RULE_ID
    assert not finding.suppressible


class TestLoading:
    def test_a_valid_file_loads(self, dynamic_rules: Path) -> None:
        rules = load_rules(dynamic_rules)
        assert [rule.id for rule in rules] == ["cfg-dynamic-code"]
        assert rules[0].severity is Severity.HIGH
        assert rules[0].suppressible is False
        assert rules[0].roles == ("tooling-config",)
        assert rules[0].tests.positive == "cfg_dynamic_code"

    def test_an_unknown_key_is_a_config_error(self, tmp_path: Path) -> None:
        broken = rule_body().replace("rationale", "reason")
        with pytest.raises(ValueError, match="unknown key"):
            load_rules(rules_dir(tmp_path, broken))

    @pytest.mark.parametrize(
        "field",
        ["id", "title", "roles", "detector", "severity", "rationale", "tests"],
    )
    def test_a_missing_required_key_is_a_config_error(self, tmp_path: Path, field: str) -> None:
        body = "\n".join(
            line for line in rule_body().splitlines() if not line.startswith(f"{field} ")
        )
        with pytest.raises(ValueError, match="missing required"):
            load_rules(rules_dir(tmp_path, body))

    def test_a_regex_that_does_not_compile_is_a_config_error(self, tmp_path: Path) -> None:
        body = rule_body(value=r"(?:eval|Function)[ \t*")
        with pytest.raises(ValueError, match="does not compile"):
            load_rules(rules_dir(tmp_path, body))

    def test_a_pattern_rule_without_a_pattern_is_a_config_error(self, tmp_path: Path) -> None:
        body = rule_body().replace(
            f"pattern = {{ kind = 'regex', value = '{DYNAMIC_CODE}' }}\n", ""
        )
        with pytest.raises(ValueError, match="has no pattern"):
            load_rules(rules_dir(tmp_path, body))

    def test_a_code_rule_may_carry_a_pattern_its_detector_owns(self, tmp_path: Path) -> None:
        body = rule_body(detector="builtin:config_role", with_pattern=True)
        rule = load_rule_file(rules_dir(tmp_path, body) / "builtin_1.toml")[0]
        assert rule.pattern is not None
        # The engine runs only `detector = "pattern"` rules, so the code detector stays the only
        # reporter of lines this pattern matches.
        assert apply_patterns([rule], make_entry(text="eval(x)\n"), line_cap=200) == ()

    def test_duplicate_rule_ids_are_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="duplicate rule id"):
            load_rules(rules_dir(tmp_path, rule_body(), rule_body()))

    def test_an_empty_directory_is_a_config_error(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(ValueError, match="no rule files"):
            load_rules(empty)

    def test_an_unknown_role_is_rejected(self, dynamic_rules: Path) -> None:
        with pytest.raises(ValueError, match="unknown role"):
            load_rules(dynamic_rules, known_roles=["source"])

    def test_known_roles_that_match_are_accepted(self, dynamic_rules: Path) -> None:
        assert load_rules(dynamic_rules, known_roles=["tooling-config", "source"])

    def test_an_unknown_builtin_detector_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="unknown detector"):
            load_rules(
                rules_dir(tmp_path, rule_body(detector="builtin:js_parsing")),
                known_detectors=["config_role", "wasm_manifest"],
            )

    def test_rules_from_several_files_come_back_sorted_by_id(self, tmp_path: Path) -> None:
        path = rules_dir(
            tmp_path, rule_body("cfg-network", severity="warn"), rule_body("cfg-dynamic-code")
        )
        assert [rule.id for rule in load_rules(path)] == ["cfg-dynamic-code", "cfg-network"]

    def test_a_file_with_no_rule_table_is_a_config_error(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="at least one"):
            load_rules(rules_dir(tmp_path, "rule = []\n"))


class TestRolesFile:
    def test_globs_load(self, tmp_path: Path) -> None:
        path = tmp_path / "roles.toml"
        path.write_text(
            "[roles.tooling-config]\nglobs = ['**/postcss.config.*']\n\n"
            "[roles.editor-autorun]\nglobs = ['**/.vscode/tasks.json']\n",
            encoding="utf-8",
        )
        assert load_role_globs(path) == {
            "tooling-config": ("**/postcss.config.*",),
            "editor-autorun": ("**/.vscode/tasks.json",),
        }

    def test_the_shipped_roles_file_loads(self) -> None:
        globs = load_role_globs(Path(__file__).resolve().parents[2] / "rules" / "roles.toml")
        assert set(globs) == {
            "tooling-config",
            "editor-autorun",
            "workflow",
            "package-manifest",
            "install-hook",
        }

    def test_a_role_with_no_globs_is_a_config_error(self, tmp_path: Path) -> None:
        path = tmp_path / "roles.toml"
        path.write_text("[roles.empty]\nglobs = []\n", encoding="utf-8")
        with pytest.raises(ValueError, match="non-empty list"):
            load_role_globs(path)

    def test_a_top_level_skip_list_is_rejected(self, tmp_path: Path) -> None:
        # The old script let a repo declare directories to skip. The roles file must not grow
        # that door back.
        path = tmp_path / "roles.toml"
        path.write_text('[roles.a]\nglobs = ["*"]\n[skip]\ndirs = ["vendor"]\n', encoding="utf-8")
        with pytest.raises(ValueError, match="unknown key"):
            load_role_globs(path)


class TestMatching:
    def test_a_regex_rule_hits_a_dynamic_call(self, dynamic_rules: Path) -> None:
        rule = load_rules(dynamic_rules)[0]
        assert line_matches(rule, "  const f = eval(payload);")
        assert line_matches(rule, "const g = new Function('return 1')")

    def test_a_property_or_identifier_that_only_ends_with_eval_is_not_a_call(
        self, dynamic_rules: Path
    ) -> None:
        rule = load_rules(dynamic_rules)[0]
        assert not line_matches(rule, "config.eval = false")
        assert not line_matches(rule, "windowFunction(x)")

    def test_literal_rules_are_substring_matches(self, tmp_path: Path) -> None:
        rule = load_rules(rules_dir(tmp_path, rule_body(kind="literal", value="require(")))[0]
        assert line_matches(rule, "const x = require('net')")
        assert not line_matches(rule, "const x = required('net')")

    def test_matching_a_patternless_rule_is_a_programmer_error(self, tmp_path: Path) -> None:
        rule = load_rules(rules_dir(tmp_path, rule_body(detector="builtin:config_role")))[0]
        with pytest.raises(ValueError, match="no pattern"):
            line_matches(rule, "anything")


class TestApplyPatterns:
    def test_only_rules_whose_roles_match_run(self, dynamic_rules: Path) -> None:
        rules = load_rules(dynamic_rules)
        assert apply_patterns(rules, make_entry(roles=("source",)), line_cap=200) == ()
        assert len(apply_patterns(rules, make_entry(), line_cap=200)) == 1

    def test_a_finding_carries_the_line_number_and_the_raw_line(self, dynamic_rules: Path) -> None:
        text = "export default {\n  plugins: [],\n}\nconst run = eval(payload)\n"
        finding = apply_patterns(load_rules(dynamic_rules), make_entry(text=text), line_cap=200)[0]
        assert finding.line == 4
        assert finding.evidence == "const run = eval(payload)"
        assert finding.roles == ("tooling-config", "source")
        assert finding.message == "Dynamic code execution in tooling config"

    def test_carriage_returns_do_not_reach_the_evidence(self, dynamic_rules: Path) -> None:
        finding = apply_patterns(
            load_rules(dynamic_rules), make_entry(text="eval(x)\r\n"), line_cap=200
        )[0]
        assert finding.evidence == "eval(x)"

    def test_a_file_without_text_is_not_matched(self, dynamic_rules: Path) -> None:
        binary = FileEntry(path="a.wasm", sha256="a" * 64, roles=("wasm",), text=None)
        assert apply_patterns(load_rules(dynamic_rules), binary, line_cap=200) == ()

    def test_a_bogus_line_cap_is_refused(self, dynamic_rules: Path) -> None:
        assert apply_patterns(load_rules(dynamic_rules), make_entry(), line_cap=0) == ()

    def test_the_file_hash_travels_with_the_finding(self, dynamic_rules: Path) -> None:
        digest = "cd" * 32
        finding = apply_patterns(
            load_rules(dynamic_rules), make_entry(sha256=digest), line_cap=200
        )[0]
        assert finding.file_sha256 == digest


class TestCapFindings:
    def test_a_line_over_the_cap_is_reported_and_never_matched(self, tmp_path: Path) -> None:
        rules = load_rules(rules_dir(tmp_path, rule_body(), LONG_LINE_BODY))
        payload = "eval(" + "a" * 500 + ")"
        findings = cap_findings(rules, make_entry(text=payload), line_cap=200)
        assert [finding.rule_id for finding in findings] == [LONG_LINE_RULE_ID]
        # The rule data carries the sensitive-role severity.
        assert findings[0].severity is Severity.HIGH
        assert "no pattern ran on it" in findings[0].message
        # The same line never reaches a regex, so the capability rule stays silent.
        assert apply_patterns(rules, make_entry(text=payload), line_cap=200) == ()

    def test_over_cap_lines_are_counted_once_per_file(self, tmp_path: Path) -> None:
        rules = load_rules(rules_dir(tmp_path, LONG_LINE_BODY))
        text = f"{'x' * 300}\nshort\n{'y' * 400}\n"
        findings = cap_findings(
            rules, make_entry(path="a.py", roles=("source",), text=text), line_cap=200
        )
        assert len(findings) == 1
        assert findings[0].line == 1
        assert "line 1 is 300 characters" in findings[0].message
        assert "1 more over-cap line" in findings[0].message

    def test_a_long_line_in_a_plain_source_file_is_demoted_to_warn(self, tmp_path: Path) -> None:
        rules = load_rules(rules_dir(tmp_path, rule_body(), LONG_LINE_BODY))
        findings = cap_findings(
            rules, make_entry(path="a.py", roles=("source",), text="x" * 400), line_cap=200
        )
        assert [finding.severity for finding in findings] == [Severity.WARN]

    def test_an_over_cap_line_is_still_reported_without_a_loaded_cap_rule(
        self, dynamic_rules: Path
    ) -> None:
        # The engine must never withhold a long line from the patterns without saying so,
        # even if a rule set forgets cfg-long-line.
        findings = cap_findings(
            load_rules(dynamic_rules), make_entry(roles=("source",), text="x" * 400), line_cap=200
        )
        assert [finding.rule_id for finding in findings] == [LONG_LINE_RULE_ID]
        assert findings[0].severity is Severity.WARN
