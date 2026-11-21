"""The `builtin_patterns` rules (task 3.6, `ARCHITECTURE.md` 9.6).

The fixture gate proves each rule fires on its own positive case and not on its negative. What this
module adds is the reason the family exists: coverage outside the five config filenames, claimed by
the `roles` a rule names rather than enforced in detector code, and one Appendix B case carried all
the way to an exit code.

`PRD.md` Appendix B case 7 is a decode-and-eval line under `vendor/`. The old script missed it
because its `SKIP_DIRS` matched the prefix. Airlock opens the file, resolves it to role `source`,
and until this family existed no pattern rule read `source`, so the scan reported clean with the
same exit code as a repository holding nothing. Case 7 is therefore tested here through `run_scan`,
where the exit code is decided, rather than against a detector call.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from airlock import detectors
from airlock.cli import run_scan
from airlock.model import EXIT_FINDINGS, EXIT_PASS, FileEntry, Mode, Rule, Severity
from airlock.roles import known_roles, resolve_roles
from airlock.rules import apply_patterns, load_role_globs, load_rules

REPO_ROOT = Path(__file__).resolve().parents[2]
ROLE_GLOBS = load_role_globs(REPO_ROOT / "rules" / "roles.toml")
RULES = load_rules(
    REPO_ROOT / "rules" / "builtin",
    known_detectors=detectors.DETECTOR_NAMES,
    known_roles=sorted(known_roles(ROLE_GLOBS)),
)
FAMILY = ("pat-decode-eval", "pat-invisible-unicode", "pat-exfil-endpoint", "pat-obfuscator-id")

#: Every role a `builtin_patterns` rule may claim: text that is code, not prose, not a binary.
CODE_ROLES = ["editor-autorun", "other", "source", "tooling-config"]

POLICY = 'version = 1\n\n[policy]\nfail_on = "high"\n'

EVAL = "ev" + "al"
BUFFER_FROM = "Buf" + "fer" + "." + "from"
ATOB = "at" + "ob"
PASTEBIN = "paste" + "bin.com"
CASE_SEVEN = f"{EVAL}({BUFFER_FROM}(process.argv[2], 'base64'))"


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=airlock-test",
            "-c",
            "user.email=airlock-test@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            *args,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "--initial-branch=main")
    return root


def commit_files(root: Path, files: dict[str, str]) -> None:
    """Write and commit, so the collector sees the tree the way a push would."""
    for rel, text in {"airlock.toml": POLICY, **files}.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "fixture")


def entry(path: str, roles: tuple[str, ...], text: str) -> FileEntry:
    return FileEntry(path=path, sha256="a" * 64, roles=roles, text=text)


def hits(path: str, roles: tuple[str, ...], text: str) -> set[str]:
    """Which rules the engine would report for one file, roles and all."""
    return {finding.rule_id for finding in apply_patterns(RULES, entry(path, roles, text), 20_000)}


def shipped_rule(rule_id: str) -> Rule:
    return next(rule for rule in RULES if rule.id == rule_id)


class TestRoleCoverageIsData:
    @pytest.mark.parametrize("rule_id", FAMILY)
    def test_a_rule_claims_the_roles_it_runs_on(self, rule_id: str) -> None:
        assert sorted(shipped_rule(rule_id).roles) == CODE_ROLES

    @pytest.mark.parametrize(
        "path",
        [
            "vendor/thing/loader.js",
            "src/app.py",
            "bin/release",
            "postcss.config.mjs",
            ".vscode/tasks.json",
        ],
    )
    def test_the_family_reaches_every_code_path_a_config_glob_misses(self, path: str) -> None:
        """None of these names is in `rules/roles.toml`, and four of five are not tooling at all."""
        roles = resolve_roles(path, b"", ROLE_GLOBS)
        assert "pat-decode-eval" in hits(path, roles, CASE_SEVEN)

    def test_prose_is_out_of_scope_because_of_the_roles_list_not_a_skip(self) -> None:
        assert "doc" not in {role for rule_id in FAMILY for role in shipped_rule(rule_id).roles}
        names = hits("docs/notes.md", ("doc",), CASE_SEVEN)
        assert not any(name.startswith("pat-") for name in names)


class TestAppendixBCase7:
    def test_a_decode_and_eval_under_vendor_changes_the_exit_code(self, repo: Path) -> None:
        commit_files(repo, {"vendor/thing/loader.js": CASE_SEVEN + "\n"})

        report = run_scan(repo, Mode.FULL)

        assert report.exit_code == EXIT_FINDINGS
        found = [item for item in report.findings if item.rule_id == "pat-decode-eval"]
        assert found, [item.rule_id for item in report.findings]
        assert found[0].severity is Severity.HIGH
        assert found[0].path == "vendor/thing/loader.js"
        assert found[0].roles == ("source",)

    def test_the_same_line_in_a_prose_file_reaches_no_verdict(self, repo: Path) -> None:
        commit_files(repo, {"docs/payload-notes.md": CASE_SEVEN + "\n"})

        report = run_scan(repo, Mode.FULL)

        assert not any(item.rule_id.startswith("pat-") for item in report.findings)

    def test_a_named_endpoint_on_its_own_stays_below_the_threshold(self, repo: Path) -> None:
        """The tier choice is a real one: an endpoint mention names itself but never stops a job."""
        commit_files(repo, {"src/beacon.js": f'const drop = "https://{PASTEBIN}/raw/x";\n'})

        report = run_scan(repo, Mode.FULL)

        assert report.exit_code == EXIT_PASS
        tiers = [item.severity for item in report.findings if item.rule_id == "pat-exfil-endpoint"]
        assert tiers == [Severity.WARN]


class TestInvisibleCharacters:
    def test_a_bidi_mark_inside_an_identifier_is_a_finding(self) -> None:
        names = hits("a.js", ("source",), "const target\u200fUrl = remote;")
        assert "pat-invisible-unicode" in names

    def test_the_escape_sequence_that_names_the_character_is_not_the_character(self) -> None:
        """Raw-text matching means six ASCII bytes are not one invisible character."""
        assert "pat-invisible-unicode" not in hits("a.js", ("source",), r'const z = "\u200b";')

    def test_a_zero_width_joiner_is_left_alone(self) -> None:
        """U+200D is how an emoji sequence is spelled, so the class does not carry it."""
        flag = "\U0001f1fa\U0001f3f4\u200d\U0001f1e6\U0001f1ff"
        assert "pat-invisible-unicode" not in hits("a.js", ("source",), f"const flag = '{flag}';")


class TestTheRepositoryDoesNotTriggerItsOwnRules:
    """`AGENTS.md` 4 says a committed file must not read as a payload. These are the rules that make
    that checkable, so they run over the files that define and prove them."""

    @pytest.mark.parametrize("rule_id", FAMILY)
    def test_the_file_holding_the_patterns_does_not_trigger_them(self, rule_id: str) -> None:
        path = "rules/builtin/builtin_patterns.toml"
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        assert rule_id not in hits(path, ("source",), text)

    def test_the_fixture_builders_and_these_tests_hold_only_fragments(self) -> None:
        for path in ("tests/fixtures/builtin_patterns.py", "tests/unit/test_builtin_patterns.py"):
            text = (REPO_ROOT / path).read_text(encoding="utf-8")
            fired = sorted(n for n in hits(path, ("source",), text) if n.startswith("pat-"))
            assert fired == [], (path, fired)
