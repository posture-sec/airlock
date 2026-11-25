"""The shipped rule files (tasks 3.1, 3.4).

These tests read `rules/builtin/*.toml` and `rules/roles.toml` as they will be loaded by the
runner. Detector behavior is covered in `test_config_role.py` and `test_wasm_manifest.py`; this
file is about the data agreeing with the engine and the role resolver.
"""

from __future__ import annotations

from pathlib import Path

from airlock import roles
from airlock.detectors import DETECTOR_NAMES
from airlock.model import Rule
from airlock.rules import LONG_LINE_RULE_ID, load_role_globs, load_rules

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / "rules" / "builtin"
ROLES_FILE = REPO_ROOT / "rules" / "roles.toml"


def shipped_rules() -> tuple[Rule, ...]:
    """Load the shipped rules with the same cross-checks the CLI will use."""
    role_globs = load_role_globs(ROLES_FILE)
    return load_rules(
        RULES_DIR,
        known_detectors=DETECTOR_NAMES,
        known_roles=sorted(roles.known_roles(role_globs)),
    )


def rule_ids() -> set[str]:
    return {rule.id for rule in shipped_rules()}


def rule(rule_id: str) -> Rule:
    return next(rule for rule in shipped_rules() if rule.id == rule_id)


class TestShippedRuleSet:
    def test_the_shipped_rules_load_against_the_shipped_roles(self) -> None:
        assert shipped_rules()

    def test_every_expected_rule_id_is_present(self) -> None:
        assert rule_ids() == {
            "cfg-appended-tail",
            "cfg-chain-endpoint",
            "cfg-dynamic-code",
            "cfg-long-line",
            "cfg-network",
            "cfg-network-exec",
            "cfg-process-spawn",
            "pat-decode-eval",
            "pat-editor-command-path",
            "pat-exfil-endpoint",
            "pat-invisible-unicode",
            "pat-jwt",
            "pat-lifecycle-exec",
            "pat-lifecycle-fetch",
            "pat-obfuscator-id",
            "pat-privileged-trigger",
            "pat-ptr-head-checkout",
            "pat-secret-dump",
            "stellar-seed",
            "wasm-archive-skipped",
            "wasm-hash-mismatch",
            "wasm-manifest-stale",
            "wasm-path-moved",
            "wasm-unlisted",
            "npm-registry-bypass",
            "cargo-git-dependency",
            "cargo-patch-override",
            "cargo-path-escape",
            "native-binary-artifact",
            "submodule-url-drift",
        }

    def test_a_pattern_rule_without_a_detector_carries_a_pattern(self) -> None:
        for rule in shipped_rules():
            if rule.detector == "pattern":
                assert rule.pattern is not None, rule.id

    def test_only_the_spawn_rule_carries_a_pattern_for_its_detector(self) -> None:
        code_patterns = [
            rule
            for rule in shipped_rules()
            if rule.pattern is not None and rule.detector != "pattern"
        ]
        assert [rule.id for rule in code_patterns] == ["cfg-process-spawn"]
        cap = rule(LONG_LINE_RULE_ID)
        assert cap.pattern is not None and cap.pattern.kind == "literal"

    def test_the_non_suppressible_rules_are_the_ones_the_owner_named(self) -> None:
        # B5: a suppression must not be able to hide remote code execution or a swapped binary.
        assert sorted(rule.id for rule in shipped_rules() if not rule.suppressible) == [
            "cfg-dynamic-code",
            "cfg-long-line",
            "cfg-network-exec",
            "wasm-hash-mismatch",
            "wasm-unlisted",
        ]

    def test_a_tooling_config_role_is_named_by_every_capability_rule(self) -> None:
        capability = {
            "cfg-appended-tail",
            "cfg-chain-endpoint",
            "cfg-dynamic-code",
            "cfg-network",
            "cfg-network-exec",
            "cfg-process-spawn",
        }
        for rule in shipped_rules():
            if rule.id in capability:
                assert roles.TOOLING_CONFIG_ROLE in rule.roles, rule.id

    def test_the_cap_rule_covers_every_text_role(self) -> None:
        # It is the engine's account of lines no regex saw, so no role may fall through it.
        cap = rule(LONG_LINE_RULE_ID)
        assert set(cap.roles) == {
            roles.TOOLING_CONFIG_ROLE,
            roles.EDITOR_AUTORUN_ROLE,
            roles.SOURCE_ROLE,
            roles.DOC_ROLE,
            roles.OTHER_ROLE,
        }
