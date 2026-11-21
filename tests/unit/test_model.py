"""Unit tests for the core data models (task 2.1)."""

from __future__ import annotations

import ast
import dataclasses
import re
from datetime import date
from pathlib import Path

import pytest

from airlock import model
from airlock.model import (
    BOOTSTRAP_POLICY,
    EMPTY_MANIFEST,
    EXIT_CONFIG,
    FileEntry,
    Finding,
    Manifest,
    Mode,
    Policy,
    ReleaseProfile,
    Rule,
    RulePattern,
    RuleTests,
    ScanContext,
    ScanReport,
    Severity,
    SorobanPolicy,
    Suppression,
    WasmEntry,
    mode_from_name,
    severity_from_name,
    sort_findings,
)

DIGEST = "0" * 64
FINGERPRINT = f"sha256:{DIGEST}"


def make_finding(**overrides: object) -> Finding:
    kwargs: dict[str, object] = {
        "rule_id": "cfg-dynamic-code",
        "severity": Severity.HIGH,
        "path": "postcss.config.mjs",
        "line": 12,
        "roles": ("tooling-config",),
        "message": "Dynamic code execution in tooling config",
        "evidence": "eval(source)",
        "occurrence": 0,
        "fingerprint": FINGERPRINT,
        "suppressible": False,
    }
    kwargs.update(overrides)
    return Finding(**kwargs)  # type: ignore[arg-type]


class TestSeverityAndMode:
    def test_ordering_is_info_warn_high(self) -> None:
        assert Severity.INFO < Severity.WARN < Severity.HIGH
        assert [Severity(i).label for i in (0, 1, 2)] == ["info", "warn", "high"]

    def test_severity_parses_case_insensitively(self) -> None:
        assert severity_from_name(" High ") is Severity.HIGH

    def test_unknown_severity_is_an_error(self) -> None:
        with pytest.raises(ValueError, match="unknown severity"):
            severity_from_name("critical")

    def test_mode_parses_from_cli_string(self) -> None:
        assert mode_from_name("PR") is Mode.PR
        assert mode_from_name("full") is Mode.FULL

    def test_unknown_mode_is_an_error(self) -> None:
        with pytest.raises(ValueError, match="unknown mode"):
            mode_from_name("merge_group")


class TestFinding:
    def test_accepts_a_file_level_finding(self) -> None:
        assert make_finding(line=0, evidence=None, path="cargo.lock").line == 0

    def test_message_at_the_limit_is_accepted(self) -> None:
        assert make_finding(message="x" * model.MAX_MESSAGE_CHARS).message

    def test_over_long_message_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="message must be at most"):
            make_finding(message="x" * (model.MAX_MESSAGE_CHARS + 1))

    @pytest.mark.parametrize(
        "rule_id",
        ["CFG_dynamic code", "cfg-", "cfg--dynamic", "9cfg", ""],
    )
    def test_rule_id_must_be_kebab_case(self, rule_id: str) -> None:
        with pytest.raises(ValueError, match="kebab-case"):
            make_finding(rule_id=rule_id)

    @pytest.mark.parametrize("path", ["/etc/passwd", "src/../target/x.js", "win\\path.js", ""])
    def test_path_must_be_repo_relative(self, path: str) -> None:
        with pytest.raises(ValueError, match="repo-relative"):
            make_finding(path=path)

    @pytest.mark.parametrize(
        "fingerprint",
        [DIGEST, f"sha256:{'z' * 64}", "sha256:", "md5:" + DIGEST, ""],
    )
    def test_fingerprint_must_be_prefixed_sha256_hex(self, fingerprint: str) -> None:
        with pytest.raises(ValueError, match="fingerprint must"):
            make_finding(fingerprint=fingerprint)

    def test_negative_line_and_occurrence_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="line must be 0"):
            make_finding(line=-1)
        with pytest.raises(ValueError, match="occurrence must be a zero-based index"):
            make_finding(occurrence=-1)

    def test_findings_are_immutable(self) -> None:
        with pytest.raises(dataclasses.FrozenInstanceError):
            make_finding().message = "rewritten"  # type: ignore[misc]

    def test_bracketed_route_filenames_are_still_reportable(self) -> None:
        # A real path may contain glob metacharacters. Rejecting them when building a
        # finding would drop the file silently, which is the failure the scan must never do.
        assert make_finding(path="app/[id]/page.tsx").path == "app/[id]/page.tsx"
        assert make_finding(path="src/[...slug].js").path == "src/[...slug].js"


class TestOrdering:
    def test_high_leads_then_path_line_and_rule(self) -> None:
        low = make_finding(severity=Severity.INFO, rule_id="aaa", path="a.js")
        warn = make_finding(severity=Severity.WARN, rule_id="zzz", path="z.js")
        high_late_path = make_finding(severity=Severity.HIGH, rule_id="z-rule", path="z.js")
        high_same_line_other_rule = make_finding(severity=Severity.HIGH, rule_id="a-rule")
        high_same_rule_next_line = make_finding(severity=Severity.HIGH, rule_id="z-rule", line=13)

        ordered = sort_findings(
            [low, high_late_path, warn, high_same_line_other_rule, high_same_rule_next_line]
        )
        assert [f.sort_key for f in ordered] == sorted(f.sort_key for f in ordered)
        assert ordered[0] is high_same_line_other_rule
        assert [f.rule_id for f in ordered[:3]] == ["a-rule", "z-rule", "z-rule"]
        assert ordered[-1] is low


class TestRules:
    def make_rule(self, **overrides: object) -> Rule:
        kwargs: dict[str, object] = {
            "id": "cfg-dynamic-code",
            "title": "Dynamic code execution in tooling config",
            "roles": ("tooling-config",),
            "detector": "pattern",
            "severity": Severity.HIGH,
            "suppressible": False,
            "rationale": "Build configs have no reason to evaluate strings.",
            "pattern": RulePattern(kind="regex", value=("(?<!eval)",)),
            "tests": RuleTests(positive="cfg_dynamic_code", negative="cfg_dynamic_code"),
        }
        kwargs.update(overrides)
        return Rule(**kwargs)  # type: ignore[arg-type]

    def test_pattern_from_toml_normalizes_a_bare_string(self) -> None:
        assert RulePattern.from_toml("REGEX", "eval\\s*\\(").value == ("eval\\s*\\(",)

    def test_literal_pattern_accepts_a_set(self) -> None:
        assert RulePattern.from_toml("literal", ["a", "b"]).value == ("a", "b")

    def test_unknown_pattern_kind_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="pattern kind"):
            RulePattern(kind="glob", value=("a",))

    def test_regex_pattern_holds_exactly_one_expression(self) -> None:
        with pytest.raises(ValueError, match="exactly one"):
            RulePattern(kind="regex", value=("a", "b"))

    def test_invalid_regex_fails_at_construction(self) -> None:
        # A pattern that cannot compile is a config error (exit 2), not a crash mid-scan.
        with pytest.raises(ValueError, match="does not compile"):
            RulePattern(kind="regex", value=("([unclosed",))

    def test_pattern_detector_without_a_pattern_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="has no pattern"):
            self.make_rule(pattern=None)

    def test_a_code_rule_may_carry_the_pattern_its_detector_matches(self) -> None:
        # cfg-process-spawn is decided in code but its trigger text stays in the rule file. The
        # engine only runs `detector = "pattern"` rules, so this cannot double-report a line.
        rule = self.make_rule(detector="builtin:config_role")
        assert rule.pattern is not None

    def test_builtin_detector_without_pattern_is_valid(self) -> None:
        assert self.make_rule(detector="builtin:wasm_manifest", pattern=None).detector

    def test_unknown_detector_pointer_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="must be 'pattern'"):
            self.make_rule(detector="plugin:evil")

    def test_rule_without_roles_or_rationale_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="at least one role"):
            self.make_rule(roles=())
        with pytest.raises(ValueError, match="title and a rationale"):
            self.make_rule(rationale="")

    def test_rule_needs_both_fixtures(self) -> None:
        with pytest.raises(ValueError, match="positive and a negative"):
            RuleTests(positive="cfg_dynamic_code", negative="")


class TestSuppression:
    def make_suppression(self, **overrides: object) -> Suppression:
        kwargs: dict[str, object] = {
            "rule": "cfg-process-spawn",
            "path": "next.config.mjs",
            "fingerprint": FINGERPRINT,
            "reason": "git rev-parse HEAD for build id",
        }
        kwargs.update(overrides)
        return Suppression(**kwargs)  # type: ignore[arg-type]

    def test_blank_reason_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="must carry a reason"):
            self.make_suppression(reason="   ")

    def test_glob_in_path_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="globs are not allowed"):
            self.make_suppression(path="**/*.mjs")

    def test_expiry_window_is_thirty_days_in_utc(self) -> None:
        today = date(2027, 4, 1)
        expiring = self.make_suppression(expires=date(2027, 4, 30))
        assert expiring.expiring_soon(today) is True
        assert expiring.expired(today) is False
        assert self.make_suppression(expires=date(2027, 3, 1)).expired(today) is True
        assert self.make_suppression(expires=date(2027, 6, 1)).expiring_soon(today) is False
        assert self.make_suppression().expiring_soon(today) is False


class TestPolicyAndManifest:
    def test_defaults_match_the_documented_policy(self) -> None:
        assert BOOTSTRAP_POLICY.fail_on is Severity.HIGH
        assert BOOTSTRAP_POLICY.max_file_bytes == 5_000_000
        assert BOOTSTRAP_POLICY.line_cap == 20_000
        assert BOOTSTRAP_POLICY.version == model.SUPPORTED_POLICY_VERSION
        assert BOOTSTRAP_POLICY.soroban.require_release_profile == ReleaseProfile(
            overflow_checks=True,
            panic="abort",
            lto=True,
            codegen_units=1,
            debug_assertions=False,
        )

    def test_unsupported_policy_version_is_an_error(self) -> None:
        with pytest.raises(ValueError, match="unsupported policy version"):
            Policy(version=2)

    def test_unsupported_manifest_version_is_an_error(self) -> None:
        with pytest.raises(ValueError, match="unsupported manifest version"):
            Manifest(version=0)

    def test_nonsense_limits_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="size limits must be positive"):
            Policy(line_cap=0)
        with pytest.raises(ValueError, match="tail_max_len"):
            Policy(tail_max_len=-1)

    def test_policy_keys_are_the_documented_set(self) -> None:
        top_level = frozenset({"version", "policy", "soroban", "suppress"})
        assert top_level == model.POLICY_TOP_LEVEL_KEYS
        assert "tail_entropy" in model.POLICY_SETTINGS_KEYS

    def test_manifest_entry_needs_a_hash_origin_and_paths(self) -> None:
        entry = WasmEntry(
            sha256=DIGEST,
            paths=("contract/target/wasm32-unknown-unknown/release/x.wasm",),
            origin="built",
            source="contract",
            build="cargo build --target wasm32-unknown-unknown --release",
            note="fixture",
        )
        manifest = Manifest(entries=(entry,))
        assert manifest.entries[0].origin == "built"
        with pytest.raises(ValueError, match="wasm origin"):
            WasmEntry(
                sha256=DIGEST, paths=("a.wasm",), origin="sourced", source="", build="", note=""
            )
        with pytest.raises(ValueError, match="64 hex"):
            WasmEntry(
                sha256="nope", paths=("a.wasm",), origin="built", source="", build="", note=""
            )
        with pytest.raises(ValueError, match="at least one path"):
            WasmEntry(sha256=DIGEST, paths=(), origin="built", source="", build="", note="")

    def test_duplicate_manifest_hash_is_rejected(self) -> None:
        entry = WasmEntry(
            sha256=DIGEST, paths=("a.wasm",), origin="vendored", source="", build="", note=""
        )
        with pytest.raises(ValueError, match="duplicate wasm entry"):
            Manifest(entries=(entry, entry))

    def test_empty_manifest_constant_is_usable(self) -> None:
        assert EMPTY_MANIFEST.entries == ()


class TestContextAndReport:
    def test_context_carries_only_what_a_detector_may_read(self) -> None:
        context = ScanContext(
            entries=(FileEntry(path="a.js", sha256=DIGEST, roles=("source",)),),
            policy=BOOTSTRAP_POLICY,
            manifest=EMPTY_MANIFEST,
            rules=(),
        )
        assert context.entries[0].path == "a.js"
        assert [field.name for field in dataclasses.fields(context)] == [
            "entries",
            "policy",
            "manifest",
            "rules",
        ]
        assert [field.name for field in dataclasses.fields(context.entries[0])] == [
            "path",
            "sha256",
            "roles",
            "text",
            "skip_reason",
        ]

    def test_file_entry_may_still_record_a_skip(self) -> None:
        entry = FileEntry(
            path="big.js",
            sha256=DIGEST,
            roles=("source",),
            text=None,
            skip_reason="skipped-oversize",
        )
        assert entry.text is None and entry.skip_reason in model.STATE_RULE_IDS

    def test_report_defaults_to_pass_with_no_findings(self) -> None:
        report = ScanReport(
            tool_version="0.0.1",
            mode=Mode.FULL,
            repo_head="b4a661b",
            base=None,
            files_indexed=12,
            files_scanned=12,
            files_skipped={},
            findings=(),
        )
        assert report.exit_code == model.EXIT_PASS
        assert report.suppressed == ()

    def test_report_can_carry_a_config_error(self) -> None:
        report = ScanReport(
            tool_version="0.0.1",
            mode=Mode.FULL,
            repo_head="b4a661b",
            base=None,
            files_indexed=3,
            files_scanned=0,
            files_skipped={"skipped-unreadable": 3},
            findings=(make_finding(rule_id="detector-error", severity=Severity.HIGH),),
            exit_code=EXIT_CONFIG,
        )
        assert report.files_skipped["skipped-unreadable"] == 3
        assert report.exit_code == EXIT_CONFIG


class TestDocumentedConstants:
    def test_sarif_reporter_row_uses_the_decided_fingerprint_key(self) -> None:
        root = Path(__file__).resolve().parents[2]
        architecture = (root / "ARCHITECTURE.md").read_text(encoding="utf-8")
        # A mention in an ADR must not hide a stale key in the reporter table.
        reporters = architecture.split("### 6.6 Reporters\n", 1)[1].split("\n## ", 1)[0]
        rows = [line for line in reporters.splitlines() if line.startswith("| sarif (P1) |")]
        assert len(rows) == 1
        assert re.findall(r'partialFingerprints\["([^"]+)"\]', rows[0]) == ["airlock/v1"]

    def test_sarif_stub_documents_the_decided_fingerprint_key(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source = (root / "src/airlock/report/sarif.py").read_text(encoding="utf-8")
        docstring = ast.get_docstring(ast.parse(source))
        assert docstring is not None
        assert re.findall(r'partialFingerprints\["([^"]+)"\]', docstring) == ["airlock/v1"]

    def test_seed_scope_decision_has_cited_design_and_requirement(self) -> None:
        # Guard the resolved documentation gate, not the unimplemented detector (0.7).
        root = Path(__file__).resolve().parents[2]
        roadmap = (root / "ROADMAP.md").read_text(encoding="utf-8")
        decision = next(line for line in roadmap.splitlines() if line.startswith("| D-06 |"))
        assert "| Decided " in decision and "**KEEP**" in decision
        assert "- [x] **0.7**" in roadmap

        architecture = (root / "ARCHITECTURE.md").read_text(encoding="utf-8")
        seed_design = architecture.split("### 9.4 ", 1)[1].split("### 9.5 ", 1)[0]
        assert "[Unverified" not in seed_design
        assert "sep-0023.md" in seed_design and "strkey/main.go" in seed_design

        prd = (root / "PRD.md").read_text(encoding="utf-8")
        requirement = next(line for line in prd.splitlines() if line.startswith("| FR-17 |"))
        assert "D-06" in requirement and "checksum-valid" in requirement

    def test_every_state_rule_id_from_the_essentials_is_known(self) -> None:
        documented = {
            "skipped-oversize",
            "skipped-unreadable",
            "skipped-symlink",
            "skipped-unmerged",
            "submodule-present",
            "nul-in-text",
            "non-utf8-text",
            "cfg-long-line",
            "detector-error",
            "history-rewritten",
            "no-trusted-base",
            "policy-changed",
            "policy-unknown-key",
            "suppression-expiring",
            "suppression-invalid",
            "untrusted-policy-source",
        }
        assert documented <= model.STATE_RULE_IDS

    def test_exit_codes_are_distinct(self) -> None:
        codes = {model.EXIT_PASS, model.EXIT_FINDINGS, EXIT_CONFIG, model.EXIT_INTERNAL}
        assert codes == {0, 1, 2, 3}

    def test_soroban_expectations_are_data_not_hardcoded_in_detectors(self) -> None:
        assert SorobanPolicy().require_release_profile.codegen_units == 1
