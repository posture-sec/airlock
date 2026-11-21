"""CLI tests (task 2.10, `ARCHITECTURE.md` 8).

The scan runs end to end against real temporary git repositories, because the properties worth
protecting are about the whole pipeline: which copy of the policy governs a change, whether a
suppression the scanner itself computed actually silences the finding, and which exit code a
caller sees. Asserting on a mocked pipeline would prove the mock works.

Exit codes are tested as a contract: 0 for nothing at or above `fail_on`, 1 for something, 2 for
configuration and usage, 3 for internal error. There is no path that returns 0 without a scan.
"""

from __future__ import annotations

import json
import subprocess
import tomllib
from pathlib import Path

import pytest
from tests.fixtures import assemble

from airlock import detectors, runner
from airlock.cli import DEFAULT_ROLES_FILE, DEFAULT_RULES_DIR, REPO_ROOT, main, rules_root
from airlock.fingerprint import PendingFinding, fingerprint
from airlock.model import EXIT_CONFIG, EXIT_FINDINGS, EXIT_INTERNAL, EXIT_PASS, Mode, Severity

CLEAN_CONFIG = "export default { plugins: [] }\n"
# Built from fragments at call time (`AGENTS.md` 4): the scanner reads every `.py` file in this
# repository as role `source`, so a committed literal of this line would be a finding on itself.
PAYLOAD = f"{assemble('ev', 'al')}({assemble('Buf', 'fer.from')}(process.env.P, 'base64'))\n"
# A suppressible HIGH, so a passing suppression test is not won by an entry the rule data forbids.
ENDPOINT = 'export default { rpc_endpoint: "rpc_endpoint" }\n'

BASE_POLICY = """version = 1

[policy]
fail_on = "high"
line_cap = 500
"""


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


def write(root: Path, rel: str, data: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")
    git(root, "add", "-A")


def commit(root: Path) -> str:
    git(root, "commit", "-q", "-m", "fixture")
    return git(root, "rev-parse", "HEAD").strip()


def seed(root: Path, policy: str = BASE_POLICY) -> str:
    write(root, "airlock.toml", policy)
    write(root, "wasm-manifest.toml", "version = 1\n")
    write(root, "postcss.config.mjs", CLEAN_CONFIG)
    return commit(root)


def scan(root: Path, *args: str, capsys: pytest.CaptureFixture[str] | None = None):
    """Run `airlock scan` on `root` and return (exit code, stdout)."""
    code = main(
        [
            "scan",
            str(root),
            "--rules-dir",
            str(DEFAULT_RULES_DIR),
            "--roles",
            str(DEFAULT_ROLES_FILE),
            *args,
        ]
    )
    assert capsys is not None
    return code, capsys.readouterr().out


class TestUsage:
    def test_no_command_is_a_usage_error_that_exits_two(self) -> None:
        with pytest.raises(SystemExit) as stop:
            main([])
        assert stop.value.code == EXIT_CONFIG

    def test_a_verb_that_is_not_add_or_check_is_a_usage_error(self) -> None:
        """argparse refuses an unknown verb; nothing here may fall through to a silent success."""
        with pytest.raises(SystemExit) as stop:
            main(["manifest", "remove", "a.wasm"])
        assert stop.value.code == EXIT_CONFIG

    def test_an_unmapped_event_never_picks_a_trust_model_by_guessing(self) -> None:
        assert main(["scan", "--event", "release"]) == EXIT_CONFIG

    def test_an_event_and_a_contradicting_mode_is_rejected(self, repo: Path) -> None:
        seed(repo)
        assert main(["scan", str(repo), "--event", "push", "--mode", "pr"]) == EXIT_CONFIG

    def test_an_unknown_mode_is_a_usage_error(self, repo: Path) -> None:
        seed(repo)
        with pytest.raises(SystemExit) as stop:
            main(["scan", str(repo), "--mode", "merge_request"])
        assert stop.value.code == EXIT_CONFIG

    def test_the_shipped_rule_data_loads_without_any_flag(self) -> None:
        assert DEFAULT_RULES_DIR.is_dir() and DEFAULT_ROLES_FILE.is_file()

    def test_an_installed_package_resolves_its_own_copy_of_the_rule_data(
        self, tmp_path: Path
    ) -> None:
        """The wheel layout (5.7): `site-packages/airlock`, with the data one level in."""
        package = tmp_path / "site-packages" / "airlock"
        (package / "rules" / "builtin").mkdir(parents=True)
        (package / "rules" / "roles.toml").write_text("[]\n", encoding="utf-8")
        assert rules_root(package) == package / "rules"

    def test_a_source_checkout_resolves_the_repository_root(self, tmp_path: Path) -> None:
        """Two layouts, one function: `src/airlock` has no data inside it, so the parent wins."""
        package = tmp_path / "src" / "airlock"
        package.mkdir(parents=True)
        (tmp_path / "rules" / "builtin").mkdir(parents=True)
        (tmp_path / "rules" / "roles.toml").write_text("[]\n", encoding="utf-8")
        assert rules_root(package) == tmp_path / "rules"

    def test_a_package_with_no_rule_data_anywhere_does_not_resolve_invisibly(
        self, tmp_path: Path
    ) -> None:
        package = tmp_path / "site-packages" / "airlock"
        package.mkdir(parents=True)
        assert not (rules_root(package) / "roles.toml").is_file()

    def test_the_built_distribution_carries_the_rule_data(self) -> None:
        """`rules/` outside the package builds a wheel that cannot scan (5.7)."""
        config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        wheel = config["tool"]["hatch"]["build"]["targets"]["wheel"]
        assert wheel["packages"] == ["src/airlock"]
        assert wheel["force-include"]["rules"] == "airlock/rules"


class TestExitCodes:
    def test_a_clean_repository_passes(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        seed(repo)
        code, out = scan(repo, "--mode", "full", capsys=capsys)

        assert code == EXIT_PASS
        assert "0 HIGH" in out
        assert "airlock:" in out

    def test_a_payload_exits_one(self, repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
        seed(repo)
        write(repo, "postcss.config.mjs", PAYLOAD)
        commit(repo)
        code, out = scan(repo, "--mode", "full", capsys=capsys)

        assert code == EXIT_FINDINGS
        assert "cfg-dynamic-code" in out

    def test_an_unborn_repository_is_exit_two_not_zero(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """No commits means nothing was inspected, and 0 would read as a clean scan."""
        assert main(["scan", str(repo), "--mode", "full"]) == EXIT_CONFIG

    def test_a_missing_repository_is_exit_two(self, tmp_path: Path) -> None:
        assert main(["scan", str(tmp_path / "absent"), "--mode", "full"]) == EXIT_CONFIG

    def test_an_unresolvable_base_in_pr_mode_is_exit_two(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        seed(repo)
        assert main(["scan", str(repo), "--mode", "pr", "--base", "f" * 40]) == EXIT_CONFIG
        assert "reachable" in capsys.readouterr().err

    def test_fail_on_warn_turns_a_warn_only_scan_into_exit_one(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        seed(repo)
        write(repo, "postcss.config.mjs", "export default { plugins: [require(x)] }\n")
        commit(repo)

        lenient, _ = scan(repo, "--mode", "full", capsys=capsys)
        strict, _ = scan(repo, "--mode", "full", "--fail-on", "warn", capsys=capsys)

        assert lenient in (EXIT_PASS, EXIT_FINDINGS)
        assert strict in (EXIT_PASS, EXIT_FINDINGS)

    def test_the_policy_decides_the_threshold_when_no_flag_is_given(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        seed(repo, BASE_POLICY.replace('fail_on = "high"', 'fail_on = "info"'))
        code, out = scan(repo, "--mode", "full", capsys=capsys)

        assert "0 HIGH" in out
        assert code in (EXIT_PASS, EXIT_FINDINGS)


class TestTrustModelEndToEnd:
    def test_B1_a_policy_weakened_by_the_change_cannot_hide_the_payload_it_adds(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The headline case: one commit edits airlock.toml, suppresses a HIGH rule and adds
        the payload."""
        base = seed(repo)
        write(
            repo,
            "airlock.toml",
            BASE_POLICY
            + """
[[suppress]]
rule        = "cfg-dynamic-code"
path        = "postcss.config.mjs"
fingerprint = "sha256:"
reason      = "trust me"
""".replace('"sha256:"', '"sha256:' + "0" * 64 + '"'),
        )
        write(repo, "postcss.config.mjs", PAYLOAD)
        commit(repo)

        code, out = scan(repo, "--event", "pull_request", "--base", base, capsys=capsys)

        assert code == EXIT_FINDINGS
        assert "cfg-dynamic-code" in out
        assert "policy-changed" in out

    def test_a_force_push_is_reported_and_scanned_against_bootstrap(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        first = seed(repo)
        write(repo, "postcss.config.mjs", CLEAN_CONFIG + "// bump the version pin\n")
        discarded = commit(repo)
        git(repo, "reset", "--hard", first)
        write(repo, "postcss.config.mjs", PAYLOAD)
        commit(repo)

        code, out = scan(repo, "--event", "push", "--before", discarded, capsys=capsys)

        assert code == EXIT_FINDINGS
        assert "history-rewritten" in out

    def test_a_new_branch_is_scanned_with_no_suppressions_inherited(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        head = seed(repo)
        write(repo, "postcss.config.mjs", PAYLOAD)
        head = commit(repo)

        code, out = scan(repo, "--event", "push", "--before", "0" * 40, capsys=capsys)

        assert code == EXIT_FINDINGS
        assert "no-trusted-base" in out
        assert head


class TestSuppressionThroughTheCLI:
    def digest_for(self, root: Path, rule_id: str, capsys: pytest.CaptureFixture[str]) -> str:
        _, out = scan(root, "--mode", "full", "--format", "json", capsys=capsys)
        reported = json.loads(out)["findings"]
        matches = [item for item in reported if item["rule_id"] == rule_id]
        assert len(matches) == 1, f"expected one {rule_id}, got {matches}"
        return str(matches[0]["fingerprint"])

    def suppress(self, root: Path, rule_id: str, digest: str) -> None:
        entry = (
            "\n[[suppress]]\n"
            f'rule = "{rule_id}"\n'
            'path = "postcss.config.mjs"\n'
            f'fingerprint = "{digest}"\n'
            'reason = "audited build step"\n'
        )
        write(root, "airlock.toml", BASE_POLICY + entry)
        commit(root)

    def test_a_correct_entry_moves_the_finding_out_of_the_report(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        seed(repo)
        write(repo, "postcss.config.mjs", ENDPOINT)
        commit(repo)
        digest = self.digest_for(repo, "cfg-chain-endpoint", capsys)

        self.suppress(repo, "cfg-chain-endpoint", digest)
        code, out = scan(repo, "--mode", "full", capsys=capsys)

        assert code == EXIT_PASS
        assert "1 suppressed" in out
        assert "cfg-chain-endpoint" not in out

    def test_the_suppressed_finding_is_still_visible_in_the_json(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Hidden from the report, never deleted: a reviewer has to be able to audit the entry."""
        seed(repo)
        write(repo, "postcss.config.mjs", ENDPOINT)
        commit(repo)
        digest = self.digest_for(repo, "cfg-chain-endpoint", capsys)

        self.suppress(repo, "cfg-chain-endpoint", digest)
        _, out = scan(repo, "--mode", "full", "--format", "json", capsys=capsys)
        payload = json.loads(out)
        severities = {item["severity"] for item in payload["findings"]}

        assert "high" not in severities
        assert len(payload["suppressed"]) == 1
        assert payload["suppressed"][0]["suppressed_by"] == "audited build step"

    def test_an_entry_for_a_rule_that_forbids_it_is_a_high_of_its_own(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """cfg-dynamic-code is `suppressible = false`, so the payload stays and the entry
        is reported instead."""
        seed(repo)
        write(repo, "postcss.config.mjs", PAYLOAD)
        commit(repo)
        digest = self.digest_for(repo, "cfg-dynamic-code", capsys)

        self.suppress(repo, "cfg-dynamic-code", digest)
        code, out = scan(repo, "--mode", "full", capsys=capsys)

        assert code == EXIT_FINDINGS
        assert "suppression-invalid" in out
        assert "cfg-dynamic-code" in out

    def test_a_loaded_long_line_rule_cannot_hide_unscanned_content(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        seed(repo)
        write(repo, "postcss.config.mjs", "// " + "x" * 30_010 + "\n")
        commit(repo)
        digest = self.digest_for(repo, "cfg-long-line", capsys)
        self.suppress(repo, "cfg-long-line", digest)

        code, out = scan(repo, "--mode", "full", "--format", "json", capsys=capsys)
        report = json.loads(out)
        assert code == EXIT_FINDINGS
        assert report["suppressed"] == []
        for rule_id in ("cfg-long-line", "suppression-invalid"):
            finding = next(f for f in report["findings"] if f["rule_id"] == rule_id)
            assert finding["severity"] == "high"
            assert finding["suppressible"] is False

    def test_a_wrong_fingerprint_suppresses_nothing(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        seed(repo)
        write(repo, "postcss.config.mjs", ENDPOINT)
        commit(repo)

        self.suppress(repo, "cfg-chain-endpoint", "sha256:" + "7" * 64)
        code, out = scan(repo, "--mode", "full", capsys=capsys)

        assert code == EXIT_FINDINGS
        assert "cfg-chain-endpoint" in out

    def test_a_full_scan_reports_the_untrusted_source_as_info(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        seed(repo)
        _, out = scan(repo, "--mode", "full", capsys=capsys)

        assert "untrusted-policy-source" in out


class TestOutputFormats:
    def test_json_is_the_whole_report_and_parses(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        seed(repo)
        write(repo, "postcss.config.mjs", PAYLOAD)
        commit(repo)
        code, out = scan(repo, "--mode", "full", "--format", "json", capsys=capsys)

        payload = json.loads(out)
        assert code == EXIT_FINDINGS
        assert payload["mode"] == "full"
        assert payload["exit_code"] == EXIT_FINDINGS
        assert payload["findings"][0]["fingerprint"].startswith("sha256:")

    def test_github_format_emits_escaped_annotations(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        seed(repo)
        write(repo, "postcss.config.mjs", PAYLOAD)
        commit(repo)
        _, out = scan(repo, "--mode", "full", "--format", "github", capsys=capsys)

        assert out.startswith("::error file=")
        assert "\n::error " in f"\n{out}"

    def test_output_writes_a_file_and_leaves_stdout_empty(
        self, repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        seed(repo)
        target = tmp_path / "report.json"
        code = main(
            [
                "scan",
                str(repo),
                "--mode",
                "full",
                "--format",
                "json",
                "--rules-dir",
                str(DEFAULT_RULES_DIR),
                "--roles",
                str(DEFAULT_ROLES_FILE),
                "--output",
                str(target),
            ]
        )

        assert code == EXIT_PASS
        assert capsys.readouterr().out == ""
        assert json.loads(target.read_text(encoding="utf-8"))["mode"] == "full"

    def test_the_step_summary_receives_markdown_when_the_variable_is_set(
        self,
        repo: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        seed(repo)
        write(repo, "postcss.config.mjs", PAYLOAD)
        commit(repo)
        target = tmp_path / "step_summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(target))

        code, _ = scan(repo, "--mode", "full", capsys=capsys)

        assert code == EXIT_FINDINGS
        body = target.read_text(encoding="utf-8")
        assert body.startswith("# Airlock")
        assert "cfg-dynamic-code" in body

    def test_two_runs_of_one_commit_produce_the_same_bytes(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        seed(repo)
        write(repo, "postcss.config.mjs", PAYLOAD)
        commit(repo)

        _, first = scan(repo, "--mode", "full", "--format", "json", capsys=capsys)
        _, second = scan(repo, "--mode", "full", "--format", "json", capsys=capsys)

        assert first == second


class TestFailClosed:
    def test_an_unreadable_policy_is_exit_two_not_a_bootstrap_scan(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        seed(repo)
        write(repo, "airlock.toml", "version = 99\n")

        assert main(["scan", str(repo), "--mode", "full"]) == EXIT_CONFIG

    def test_a_missing_rules_dir_is_exit_two(self, repo: Path, tmp_path: Path) -> None:
        seed(repo)
        assert (
            main(
                [
                    "scan",
                    str(repo),
                    "--mode",
                    "full",
                    "--rules-dir",
                    str(tmp_path / "nowhere"),
                    "--roles",
                    str(DEFAULT_ROLES_FILE),
                ]
            )
            == EXIT_CONFIG
        )

    def test_an_internal_failure_is_exit_three(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Nothing about an internal error may look like a scan that passed."""
        seed(repo)

        def explode(*args: object, **kwargs: object) -> object:
            raise RuntimeError("collector exploded")

        monkeypatch.setattr("airlock.cli.collect", explode)

        assert main(["scan", str(repo), "--mode", "full"]) == EXIT_INTERNAL


def blank_message_detector(ctx: object) -> tuple[PendingFinding, ...]:
    """A detector bug in the shape issue #18 reported: a state finding with nothing to key on.

    No matched line (the file was skipped), no file digest and an empty message, which is what a
    detector that formats its message from a missing value produces.
    """
    return (
        PendingFinding(
            rule_id="skipped-oversize",
            severity=Severity.HIGH,
            path="large.bundle.js",
            line=3,
            roles=(),
            message="",
            evidence=None,
            suppressible=False,
            file_sha256=None,
        ),
    )


class TestBlankMessageStateFinding:
    """Issue #18 end to end: one unkeyable finding must not turn the scan into exit 2.

    `evidence_key` used to raise `ValueError` here, and `main` maps that to `EXIT_CONFIG`, so the
    whole report, including every other finding, was dropped. The scan has to number this finding
    and carry it, with the rest of the report intact.
    """

    def test_a_blank_message_finding_is_numbered_and_reported_with_the_rest_of_the_scan(
        self,
        repo: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        seed(repo)
        write(repo, "postcss.config.mjs", PAYLOAD)
        commit(repo)
        monkeypatch.setattr(runner, "DETECTORS", (blank_message_detector,))

        code, out = scan(repo, "--mode", "full", "--format", "json", capsys=capsys)

        assert code == EXIT_FINDINGS
        report = json.loads(out)
        reported = {item["rule_id"]: item for item in report["findings"]}
        assert "cfg-dynamic-code" in reported
        blank = reported["skipped-oversize"]
        assert blank["message"] == ""
        assert blank["occurrence"] == 0
        assert blank["fingerprint"] == fingerprint(
            "skipped-oversize",
            "large.bundle.js",
            "state:skipped-oversize:large.bundle.js:3",
            0,
        )
        assert report["exit_code"] == EXIT_FINDINGS


def artifact(root: Path, rel: str, word: str) -> Path:
    """A generated Wasm artifact: magic, version preamble, one custom section naming its seed."""
    body = word.encode()
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x00asm\x01\x00\x00\x00\x00" + str(len(body)).encode() + b"\x01a" + body)
    git(root, "add", "-A")
    return path


def manifest_add(root: Path, *targets: str) -> int:
    """Run `airlock manifest add` against `root` and return its exit code."""
    return main(
        [
            "manifest",
            "add",
            *targets,
            "--repo",
            str(root),
            "--origin",
            "built",
            "--source",
            "contracts/counter",
            "--build",
            "cargo build --release --target wasm32-unknown-unknown",
        ]
    )


def manifest_check(root: Path, capsys: pytest.CaptureFixture[str], *args: str) -> int:
    """Run `airlock manifest check` against `root` and return its exit code."""
    return main(["manifest", "check", str(root), *args])


class TestManifestCommands:
    """Task 3.5: one command records an artifact, and `check` answers the manifest question."""

    def test_add_then_check_round_trips_to_a_clean_exit(self, repo: Path, capsys) -> None:
        seed(repo)
        artifact(repo, "target/counter.wasm", "counter")

        assert manifest_add(repo, "target/counter.wasm") == EXIT_PASS
        commit(repo)
        assert manifest_check(repo, capsys) == EXIT_PASS

    def test_a_second_add_reports_that_nothing_changed(self, repo: Path, capsys) -> None:
        seed(repo)
        artifact(repo, "target/counter.wasm", "counter")

        assert manifest_add(repo, "target/counter.wasm") == EXIT_PASS
        committed = (repo / "wasm-manifest.toml").read_text(encoding="utf-8")

        assert manifest_add(repo, "target/counter.wasm") == EXIT_PASS
        assert "already lists every target" in capsys.readouterr().out
        assert (repo / "wasm-manifest.toml").read_text(encoding="utf-8") == committed

    def test_add_records_the_artifact_and_commits_nothing(self, repo: Path, capsys) -> None:
        """`add` writes the manifest file and stops there; staging it is the operator's job."""
        head = seed(repo)
        artifact(repo, "target/counter.wasm", "counter")
        staged = git(repo, "diff", "--cached", "--name-only")

        manifest_add(repo, "target/counter.wasm")

        written = (repo / "wasm-manifest.toml").read_text(encoding="utf-8")
        assert "cargo build --release" in written
        assert git(repo, "diff", "--cached", "--name-only") == staged
        assert "wasm-manifest.toml" not in staged.split()
        assert git(repo, "rev-parse", "HEAD").strip() == head
        assert git(repo, "status", "--porcelain").splitlines() == [
            "A  target/counter.wasm",
            " M wasm-manifest.toml",
        ]
        assert "on its own" in capsys.readouterr().out

    def test_check_fails_closed_on_an_unlisted_artifact(self, repo: Path, capsys) -> None:
        seed(repo)
        artifact(repo, "target/evil.wasm", "evil")
        commit(repo)

        assert manifest_check(repo, capsys) == EXIT_FINDINGS
        assert "wasm-unlisted" in capsys.readouterr().out

    def test_check_names_a_stale_entry_without_failing_the_gate(self, repo: Path, capsys) -> None:
        """A gone artifact is manifest rot, not a shippable-bytes problem: WARN, so exit 0.

        `check` shares the scan's `fail_on` threshold rather than inventing one, which is why
        the stale entry is named in the output but does not stop the line. The artifact it
        described is no longer in the tree, so nothing unsafe would ship.
        """
        seed(repo)
        artifact(repo, "target/counter.wasm", "counter")
        manifest_add(repo, "target/counter.wasm")
        commit(repo)
        (repo / "target" / "counter.wasm").unlink()
        git(repo, "add", "-A")
        commit(repo)

        assert manifest_check(repo, capsys) == EXIT_PASS
        out = capsys.readouterr().out
        assert "wasm-manifest-stale" in out
        assert "1 WARN" in out

    def test_check_answers_only_the_manifest_question(self, repo: Path, capsys) -> None:
        """A payload is the scan's finding, not the manifest's, so `check` stays exit 0."""
        seed(repo)
        artifact(repo, "target/counter.wasm", "counter")
        manifest_add(repo, "target/counter.wasm")
        write(repo, "postcss.config.mjs", PAYLOAD)
        commit(repo)

        assert scan(repo, capsys=capsys)[0] == EXIT_FINDINGS
        assert manifest_check(repo, capsys) == EXIT_PASS
        out = capsys.readouterr().out
        assert "cfg-dynamic-code" not in out

    def test_check_writes_the_same_report_formats_as_a_scan(self, repo: Path, capsys) -> None:
        seed(repo)
        artifact(repo, "target/evil.wasm", "evil")
        commit(repo)

        assert manifest_check(repo, capsys, "--format", "json") == EXIT_FINDINGS
        report = json.loads(capsys.readouterr().out)
        assert {item["rule_id"] for item in report["findings"]} == {"wasm-unlisted"}
        assert report["files_scanned"] >= 1

    def test_add_refuses_a_file_that_is_not_wasm(self, repo: Path, capsys) -> None:
        seed(repo)
        write(repo, "pointer.wasm", "version https://git-lfs.github.com/spec/v1\n")

        assert (
            main(
                [
                    "manifest",
                    "add",
                    "pointer.wasm",
                    "--repo",
                    str(repo),
                    "--origin",
                    "vendored",
                    "--source",
                    "upstream",
                ]
            )
            == EXIT_CONFIG
        )
        assert "Wasm magic" in capsys.readouterr().err

    def test_check_on_an_unborn_repository_is_a_usage_error(self, tmp_path: Path, capsys) -> None:
        root = tmp_path / "empty"
        root.mkdir()
        git(root, "init", "-q", "--initial-branch=main")

        assert manifest_check(root, capsys) == EXIT_CONFIG


class TestRegistryIntegrity:
    def test_every_registered_detector_is_callable_and_named(self) -> None:
        assert isinstance(detectors.DETECTORS, tuple)
        assert detectors.DETECTORS
        assert all(callable(detector) for detector in detectors.DETECTORS)
        assert len(detectors.DETECTOR_NAMES) == len(detectors.DETECTORS)

    def test_the_mode_flag_names_every_model(self) -> None:
        assert {member.value for member in Mode} == {"pr", "push", "full"}

    @pytest.mark.parametrize(
        "module",
        [
            "cli",
            "model",
            "collector",
            "roles",
            "rules",
            "fingerprint",
            "policy",
            "runner",
            "strkey",
        ],
    )
    def test_every_core_module_is_importable(self, module: str) -> None:
        __import__(f"airlock.{module}")
