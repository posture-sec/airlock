"""Trusted-base tests (task 2.7, `ARCHITECTURE.md` 6.5).

These run against real temporary git repositories because the property under test is a git
fact: whether a commit is an ancestor of another, and what a file looked like at a ref. A mock
would let a wrong `git` argument list pass.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from tests.conftest import git_in
from tests.fixtures import assemble

from airlock import policy
from airlock.fingerprint import PendingFinding, number_occurrences
from airlock.model import (
    BOOTSTRAP_POLICY,
    EMPTY_MANIFEST,
    Mode,
    Policy,
    Severity,
)
from airlock.policy import (
    MANIFEST_FILENAME,
    POLICY_FILENAME,
    ZERO_SHA,
    ManifestAdd,
    TrustedConfig,
    manifest_add,
    manifest_from_toml,
    policy_from_toml,
    resolve_policy,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

BASE_POLICY = """version = 1

[policy]
fail_on = "high"
line_cap = 500
"""

ZERO_FINGERPRINT = "sha256:" + "0" * 64

# The change under review both weakens the policy and suppresses the payload it adds (B1).
WEAKENED_POLICY = f"""version = 1

[policy]
fail_on = "info"
line_cap = 500

[[suppress]]
rule        = "cfg-dynamic-code"
path        = "postcss.config.mjs"
fingerprint = "{ZERO_FINGERPRINT}"
reason      = "trust me"
"""

PAYLOAD = f"{assemble('ev', 'al')}({assemble('Buf', 'fer.from')}(process.env.P, 'base64'))\n"


def git(root: Path, *args: str) -> str:
    """Alias onto the factory's git call, so the follow-up commits here and the base commit
    made by `scratch_repo` share identity and hooks."""
    return git_in(root, *args)


@pytest.fixture
def repo(scratch_repo) -> Path:
    """Init-only scratch tree; the seed/write/commit helpers below make the actual commits.

    The factory owns `git init --initial-branch=main` and the identity flags so this
    trusted-base module does not redefine them, matching issue #92 §2.
    """
    return scratch_repo({}, base_files={}, name="repo").root


def write(root: Path, rel: str, data: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")
    git(root, "add", "-A")


def commit(root: Path) -> str:
    git(root, "commit", "-q", "-m", "fixture")
    return git(root, "rev-parse", "HEAD").strip()


def seed(root: Path, policy: str = BASE_POLICY) -> str:
    """A first commit holding the policy and a clean build config."""
    write(root, POLICY_FILENAME, policy)
    write(root, MANIFEST_FILENAME, "version = 1\n")
    write(root, "postcss.config.mjs", "export default { plugins: [] }\n")
    return commit(root)


def resolve_push(root: Path, before: str | None, head: str) -> TrustedConfig:
    return resolve_policy(root, Mode.PUSH, head, before=before)


def rule_ids(result: TrustedConfig) -> list[str]:
    return [finding.rule_id for finding in result.pending]


def finding_of(result: TrustedConfig, rule_id: str):
    matches = [item for item in result.pending if item.rule_id == rule_id]
    assert len(matches) == 1, f"expected exactly one {rule_id}, got {rule_ids(result)}"
    return matches[0]


class TestTrustedBase:
    def test_pr_mode_judges_the_change_by_the_base_policy(self, repo: Path) -> None:
        base = seed(repo)
        write(repo, POLICY_FILENAME, BASE_POLICY.replace("line_cap = 500", "line_cap = 2000000"))
        head = commit(repo)

        result = resolve_policy(repo, Mode.PR, head, base=base)

        assert result.base == base
        assert result.policy.line_cap == 500
        assert result.policy == Policy(line_cap=500)

    def test_a_policy_edit_plus_a_payload_keeps_the_base_suppressions(self, repo: Path) -> None:
        """B1: a push that edits the policy and adds a payload is judged by the old policy."""
        base = seed(repo)
        write(repo, POLICY_FILENAME, WEAKENED_POLICY)
        write(repo, "postcss.config.mjs", PAYLOAD)
        head = commit(repo)

        result = resolve_policy(repo, Mode.PR, head, base=base)

        assert result.policy.fail_on is Severity.HIGH
        assert result.policy.suppressions == ()
        changed = finding_of(result, "policy-changed")
        assert changed.path == POLICY_FILENAME
        assert changed.severity is Severity.WARN
        assert "base" in changed.message

    def test_unchanged_policy_produces_no_finding(self, repo: Path) -> None:
        base = seed(repo)
        write(repo, "README.md", "an ordinary change\n")
        head = commit(repo)

        result = resolve_policy(repo, Mode.PR, head, base=base)

        assert result.pending == ()
        assert result.policy.line_cap == 500

    def test_a_policy_deleted_by_the_change_still_governs_the_scan(self, repo: Path) -> None:
        """Removing the policy is not the same as the base never having had one."""
        base = seed(repo)
        git(repo, "rm", "-q", POLICY_FILENAME)
        git(repo, "commit", "-q", "-m", "drop the policy")
        head = git(repo, "rev-parse", "HEAD").strip()

        result = resolve_policy(repo, Mode.PR, head, base=base)

        assert result.policy.line_cap == 500
        assert "deleted by this change" in finding_of(result, "policy-changed").message

    def test_a_policy_added_by_the_change_is_reported_and_ignored(self, repo: Path) -> None:
        seed(repo)
        git(repo, "rm", "-q", POLICY_FILENAME)
        git(repo, "commit", "-q", "-m", "drop the policy")
        without = git(repo, "rev-parse", "HEAD").strip()
        write(repo, POLICY_FILENAME, WEAKENED_POLICY)
        write(repo, "postcss.config.mjs", PAYLOAD)
        head = commit(repo)

        result = resolve_policy(repo, Mode.PR, head, base=without)

        assert result.policy is BOOTSTRAP_POLICY
        assert result.base == without
        changed = finding_of(result, "policy-changed")
        assert "added by this change" in changed.message
        assert changed.path == POLICY_FILENAME

    def test_the_manifest_comes_from_the_base_too(self, repo: Path) -> None:
        base = seed(repo)
        write(
            repo, MANIFEST_FILENAME, "version = 1\n\n[[wasm]]\n" + _entry("a" * 64, "contract.wasm")
        )
        head = commit(repo)

        result = resolve_policy(repo, Mode.PR, head, base=base)

        assert result.manifest == EMPTY_MANIFEST
        assert finding_of(result, "policy-changed").path == MANIFEST_FILENAME

    def test_a_new_branch_gets_the_bootstrap_defaults(self, repo: Path) -> None:
        head = seed(repo)

        result = resolve_push(repo, ZERO_SHA, head)

        assert result.policy is BOOTSTRAP_POLICY
        assert result.manifest is EMPTY_MANIFEST
        assert result.base is None
        first_push = finding_of(result, "no-trusted-base")
        assert first_push.severity is Severity.WARN
        assert first_push.suppressible is False

    def test_a_force_push_is_history_rewritten(self, repo: Path) -> None:
        base = seed(repo)
        write(repo, "README.md", "dropped by the rewrite\n")
        discarded = commit(repo)
        git(repo, "reset", "-q", "--hard", base)
        write(repo, "postcss.config.mjs", PAYLOAD)
        head = commit(repo)

        result = resolve_push(repo, discarded, head)

        assert result.policy is BOOTSTRAP_POLICY
        assert result.base is None
        rewritten = finding_of(result, "history-rewritten")
        assert rewritten.severity is Severity.HIGH
        assert rewritten.suppressible is False

    def test_a_malformed_before_is_history_rewritten_not_head(self, repo: Path) -> None:
        head = seed(repo)

        result = resolve_push(repo, "not-a-sha", head)

        assert result.policy is BOOTSTRAP_POLICY
        assert "history-rewritten" in rule_ids(result)

    def test_a_weakened_policy_never_rescues_the_force_push(self, repo: Path) -> None:
        """The rewritten-history fallback is the strict default, not the file the push wrote."""
        base = seed(repo)
        write(repo, "README.md", "gone\n")
        discarded = commit(repo)
        git(repo, "reset", "-q", "--hard", base)
        write(repo, POLICY_FILENAME, WEAKENED_POLICY)
        head = commit(repo)

        result = resolve_push(repo, discarded, head)

        assert result.policy.fail_on is Severity.HIGH
        assert result.policy.suppressions == ()

    def test_pr_mode_without_a_base_is_a_config_error(self, repo: Path) -> None:
        head = seed(repo)

        with pytest.raises(ValueError, match="needs the pull request base SHA"):
            resolve_policy(repo, Mode.PR, head)

    @pytest.mark.parametrize("base", ["deadbeef", "z" * 40])
    def test_pr_mode_with_an_unresolvable_base_is_a_config_error(
        self, repo: Path, base: str
    ) -> None:
        head = seed(repo)

        with pytest.raises(ValueError, match="not a commit SHA"):
            resolve_policy(repo, Mode.PR, head, base=base)

    def test_an_unmerged_base_is_never_replaced_by_head(self, repo: Path) -> None:
        head = seed(repo, policy=WEAKENED_POLICY)

        with pytest.raises(ValueError, match="fetch-depth"):
            resolve_policy(repo, Mode.PR, head, base="f" * 40)

    def test_a_head_that_is_not_a_sha_is_a_config_error(self, repo: Path) -> None:
        seed(repo)

        with pytest.raises(ValueError, match="HEAD is not a commit SHA"):
            resolve_policy(repo, Mode.PUSH, "main", before=ZERO_SHA)

    def test_state_findings_are_finalizable(self, repo: Path) -> None:
        head = seed(repo)

        result = resolve_push(repo, ZERO_SHA, head)

        findings = number_occurrences(result.pending)
        assert [finding.rule_id for finding in findings] == ["no-trusted-base"]
        assert findings[0].fingerprint.startswith("sha256:")


def _entry(digest: str, path: str) -> str:
    return (
        f'sha256 = "{digest}"\n'
        f'paths = ["{path}"]\n'
        'origin = "built"\n'
        'source = "contracts/contract"\n'
        'build = "cargo build"\n'
    )


class TestFullMode:
    def test_the_working_tree_is_read_and_labelled(self, repo: Path) -> None:
        seed(repo)
        head = git(repo, "rev-parse", "HEAD").strip()

        result = resolve_policy(repo, Mode.FULL, head)

        assert result.base is None
        assert result.policy.line_cap == 500
        untrusted = [item for item in result.pending if item.rule_id == "untrusted-policy-source"]
        assert len(untrusted) == 2
        assert {item.path for item in untrusted} == {POLICY_FILENAME, MANIFEST_FILENAME}
        assert all(item.severity is Severity.INFO for item in untrusted)

    def test_a_missing_working_tree_policy_falls_back_to_defaults(self, repo: Path) -> None:
        seed(repo)
        (repo / POLICY_FILENAME).unlink()
        (repo / MANIFEST_FILENAME).unlink()
        head = git(repo, "rev-parse", "HEAD").strip()

        result = resolve_policy(repo, Mode.FULL, head)

        assert result.policy is BOOTSTRAP_POLICY
        assert result.manifest is EMPTY_MANIFEST
        absent = [
            item
            for item in result.pending
            if item.rule_id == "untrusted-policy-source" and "shipped defaults" in item.message
        ]
        assert {item.path for item in absent} == {POLICY_FILENAME, MANIFEST_FILENAME}

    def test_an_oversize_policy_file_is_a_config_error(self, repo: Path) -> None:
        seed(repo)
        write(repo, POLICY_FILENAME, "# " + "x" * 1_000_000)
        head = git(repo, "rev-parse", "HEAD").strip()

        with pytest.raises(ValueError, match="over the"):
            resolve_policy(repo, Mode.FULL, head)


class TestPolicyLoading:
    def parse(self, text: str) -> tuple[Policy, tuple[PendingFinding, ...]]:
        return policy_from_toml(text, path=POLICY_FILENAME, source="test")

    def test_the_shipped_policy_loads_with_no_findings(self) -> None:
        text = (REPO_ROOT / POLICY_FILENAME).read_text(encoding="utf-8")

        policy, findings = policy_from_toml(text, path=POLICY_FILENAME, source="working tree")

        assert findings == ()
        assert policy.fail_on is Severity.HIGH
        assert policy.line_cap == 20_000
        assert policy.soroban.require_release_profile.panic == "abort"
        assert policy.soroban.require_release_profile.overflow_checks is True

    def test_every_setting_is_read(self) -> None:
        policy, findings = self.parse(
            'version = 1\n[policy]\nfail_on = "warn"\nmax_file_bytes = 10\n'
            "line_cap = 20\ntail_max_len = 30\ntail_entropy = 3.5\n"
        )

        assert findings == ()
        assert policy == Policy(
            fail_on=Severity.WARN,
            max_file_bytes=10,
            line_cap=20,
            tail_max_len=30,
            tail_entropy=3.5,
        )

    def test_an_unknown_top_level_key_is_a_warning(self) -> None:
        policy, findings = self.parse("version = 1\n[plicy]\nline_cap = 10\n")

        assert policy.line_cap == BOOTSTRAP_POLICY.line_cap
        assert len(findings) == 1
        assert findings[0].rule_id == "policy-unknown-key"
        assert findings[0].severity is Severity.WARN

    def test_a_typo_in_a_setting_name_keeps_its_default_and_is_reported(self) -> None:
        policy, findings = self.parse('version = 1\n[policy]\nfail_one = "info"\n')

        assert policy.fail_on is Severity.HIGH
        assert "policy.fail_one" in findings[0].message

    def test_an_unknown_nested_key_is_reported_once_per_key(self) -> None:
        _, findings = self.parse(
            "version = 1\n[soroban]\nrequire_release_profile = { lto = true, panic-abort = true }\n"
        )

        assert len(findings) == 1
        assert "soroban.require_release_profile.panic-abort" in findings[0].message

    def test_suppressions_are_parsed_for_the_applier_to_use(self) -> None:
        policy, findings = self.parse(
            'version = 1\n[[suppress]]\nrule = "cfg-network"\npath = "next.config.mjs"\n'
            'fingerprint = "sha256:' + "b" * 64 + '"\nreason = "documented build fetch"\n'
            "expires = 2027-04-27\n"
        )

        assert findings == ()
        assert len(policy.suppressions) == 1
        entry = policy.suppressions[0]
        assert entry.rule == "cfg-network"
        assert entry.path == "next.config.mjs"
        assert entry.expires == date(2027, 4, 27)

    def test_an_expiry_written_as_a_string_is_a_date_too(self) -> None:
        policy, _ = self.parse(
            'version = 1\n[[suppress]]\nrule = "cfg-network"\npath = "a.mjs"\n'
            'fingerprint = "sha256:' + "b" * 64 + '"\nreason = "x"\nexpires = "2027-04-27"\n'
        )

        assert policy.suppressions[0].expires == date(2027, 4, 27)

    def test_an_expiry_with_a_clock_is_refused(self) -> None:
        with pytest.raises(ValueError, match="not a date and a time"):
            self.parse(
                'version = 1\n[[suppress]]\nrule = "cfg-network"\npath = "a.mjs"\n'
                'fingerprint = "sha256:' + "b" * 64 + '"\nreason = "x"\n'
                "expires = 2027-04-27T10:00:00\n"
            )

    def test_a_suppression_needs_every_required_field(self) -> None:
        with pytest.raises(ValueError, match="missing required key"):
            self.parse(
                'version = 1\n[[suppress]]\nrule = "cfg-network"\npath = "a.mjs"\n'
                'fingerprint = "sha256:' + "b" * 64 + '"\n'
            )

    def test_a_suppression_needs_a_fingerprint_applier_can_match(self) -> None:
        with pytest.raises(ValueError, match="fingerprint"):
            self.parse(
                'version = 1\n[[suppress]]\nrule = "cfg-network"\npath = "a.mjs"\n'
                'fingerprint = "sha256:short"\nreason = "x"\n'
            )

    def test_a_glob_in_a_suppression_path_is_refused(self) -> None:
        with pytest.raises(ValueError, match="exact path"):
            self.parse(
                'version = 1\n[[suppress]]\nrule = "cfg-network"\npath = "**/*.mjs"\n'
                'fingerprint = "sha256:' + "b" * 64 + '"\nreason = "x"\n'
            )

    @pytest.mark.parametrize(
        ("body", "message"),
        [
            ("[policy]\nline_cap = 20\n", "version is required"),
            ("version = 2\n", "version 2 is unsupported"),
            ('version = "1"\n', "version must be a whole number"),
            ("version = true\n", "version must be a whole number"),
            ("version = 1\n[policy]\nline_cap = 0\n", "line_cap must be greater than zero"),
            ("version = 1\n[policy]\nline_cap = true\n", "line_cap must be a whole number"),
            ('version = 1\n[policy]\nfail_on = "critical"\n', "unknown severity"),
            ('version = 1\n[policy]\ntail_entropy = "high"\n', "must be a number"),
            ("version = 1\npolicy = 3\n", r"\[policy\] must be a table"),
            ("version = 1\n[suppress]]\n", "cannot parse"),
        ],
    )
    def test_a_bad_policy_is_a_config_error(self, body: str, message: str) -> None:
        with pytest.raises(ValueError, match=message):
            self.parse(body)


class TestManifestLoading:
    def test_the_shipped_manifest_loads_with_no_findings(self) -> None:
        text = (REPO_ROOT / MANIFEST_FILENAME).read_text(encoding="utf-8")

        manifest, findings = manifest_from_toml(text, path=MANIFEST_FILENAME, source="test")

        assert findings == ()
        assert manifest.entries == ()

    def test_an_entry_is_read_in_full(self) -> None:
        digest = "c" * 64
        manifest, findings = manifest_from_toml(
            f'version = 1\n\n[[wasm]]\n{_entry(digest, "contract.wasm")}note = "fixture"\n',
            path=MANIFEST_FILENAME,
            source="test",
        )

        assert findings == ()
        assert manifest.entries[0].sha256 == digest
        assert manifest.entries[0].paths == ("contract.wasm",)

    def test_an_unknown_entry_key_is_a_warning(self) -> None:
        digest = "c" * 64
        manifest, findings = manifest_from_toml(
            f'version = 1\n\n[[wasm]]\n{_entry(digest, "contract.wasm")}signer = "nobody"\n',
            path=MANIFEST_FILENAME,
            source="test",
        )

        assert len(manifest.entries) == 1
        assert "wasm[1].signer" in findings[0].message

    @pytest.mark.parametrize(
        ("body", "message"),
        [
            ("[wasm]]\n", "cannot parse"),
            (
                'version = 1\n[[wasm]]\nsha256 = "a"\npaths = ["a.wasm"]\norigin = "built"\n'
                'source = "s"\nbuild = "b"\n',
                "sha256 must be 64 hex digits",
            ),
            ('version = 1\n[[wasm]]\npaths = ["a.wasm"]\n', "missing required key"),
            (
                'version = 1\n[[wasm]]\nsha256 = "' + "d" * 64 + '"\npaths = []\n'
                'origin = "built"\nsource = "s"\nbuild = "b"\n',
                "paths must be a non-empty list",
            ),
            (
                'version = 1\n[[wasm]]\nsha256 = "' + "d" * 64 + '"\npaths = ["a.wasm"]\n'
                'origin = "magic"\nsource = "s"\nbuild = "b"\n',
                "origin must be one of",
            ),
            (
                'version = 1\n[[wasm]]\nsha256 = "' + "d" * 64 + '"\npaths = ["/a.wasm"]\n'
                'origin = "built"\nsource = "s"\nbuild = "b"\n',
                "repo-relative",
            ),
        ],
    )
    def test_a_bad_manifest_is_a_config_error(self, body: str, message: str) -> None:
        with pytest.raises(ValueError, match=message):
            manifest_from_toml(body, path=MANIFEST_FILENAME, source="test")

    def test_two_entries_for_one_hash_is_a_config_error(self) -> None:
        digest = "e" * 64
        first = _entry(digest, "a.wasm")
        second = _entry(digest, "b.wasm")
        with pytest.raises(ValueError, match="duplicate wasm entry"):
            manifest_from_toml(
                f"version = 1\n\n[[wasm]]\n{first}\n[[wasm]]\n{second}\n",
                path=MANIFEST_FILENAME,
                source="test",
            )


class TestProtectedPaths:
    def test_a_policy_path_outside_the_repository_is_refused(self, repo: Path) -> None:
        head = seed(repo)

        with pytest.raises(ValueError, match="repo-relative"):
            resolve_policy(repo, Mode.FULL, head, policy_path="../secrets.toml")

    def test_an_absolute_manifest_path_is_refused(self, repo: Path) -> None:
        head = seed(repo)

        with pytest.raises(ValueError, match="repo-relative"):
            resolve_policy(repo, Mode.PR, head, base=head, manifest_path="/etc/passwd")


def wasm_bytes(seed_word: str) -> bytes:
    """A generated artifact: magic, version preamble, one custom section naming its seed."""
    body = seed_word.encode()
    preamble = b"\x01\x00\x00\x00"
    section = b"\x00" + str(len(body)).encode() + b"\x01a" + body
    return b"\x00asm" + preamble + section


def add(root: Path, *targets: str, **fields: str) -> ManifestAdd:
    return manifest_add(
        root,
        targets,
        origin=fields.pop("origin", "built"),
        source=fields.pop("source", "contracts/counter"),
        build=fields.pop("build", "cargo build --release"),
        **fields,
    )


def artifact(root: Path, rel: str, word: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(wasm_bytes(word))
    return path


class TestManifestAdd:
    def test_a_first_add_writes_a_manifest_that_states_the_two_step_flow(
        self, tmp_path: Path
    ) -> None:
        artifact(tmp_path, "target/counter.wasm", "counter")
        change = add(tmp_path, "target/counter.wasm")

        assert len(change.added) == 1 and change.extended == ()
        assert "two-step flow" in change.text
        assert "[[wasm]]" in change.text

    def test_the_written_text_parses_back_to_the_same_entries(self, tmp_path: Path) -> None:
        artifact(tmp_path, "target/counter.wasm", "counter")
        artifact(tmp_path, "target/other.wasm", "other")
        change = add(tmp_path, "target/counter.wasm", "target/other.wasm")

        written, findings = manifest_from_toml(change.text, path=MANIFEST_FILENAME, source="test")
        assert findings == ()
        assert {(entry.sha256, entry.paths) for entry in written.entries} == {
            (entry.sha256, tuple(sorted(entry.paths))) for entry in change.added
        }

    def test_adding_the_same_target_again_writes_nothing_new(self, tmp_path: Path) -> None:
        artifact(tmp_path, "target/counter.wasm", "counter")
        first = add(tmp_path, "target/counter.wasm").text
        (tmp_path / MANIFEST_FILENAME).write_text(first, encoding="utf-8")

        again = add(tmp_path, "target/counter.wasm")
        assert again.unchanged
        assert again.text == first

    def test_a_second_path_with_a_known_hash_joins_the_reviewed_entry(self, tmp_path: Path) -> None:
        artifact(tmp_path, "target/counter.wasm", "same")
        artifact(tmp_path, "dist/copy.wasm", "same")
        first = add(tmp_path, "target/counter.wasm", source="contracts/counter")
        (tmp_path / MANIFEST_FILENAME).write_text(first.text, encoding="utf-8")

        second = add(tmp_path, "dist/copy.wasm", source="something else", build="rm -rf")

        assert len(second.extended) == 1 and second.added == ()
        entry = second.extended[0]
        assert entry.paths == ("target/counter.wasm", "dist/copy.wasm")
        # The first stated provenance is the reviewed one, so a later add cannot restate it.
        assert entry.source == "contracts/counter" and entry.build == "cargo build --release"

    def test_the_repositories_own_header_survives_an_add(self, tmp_path: Path) -> None:
        header = (
            "# Our artifacts, and why each one is here.\n"
            "# Reviewed by the release owner.\n\nversion = 1\n"
        )
        (tmp_path / MANIFEST_FILENAME).write_text(header, encoding="utf-8")
        artifact(tmp_path, "a.wasm", "a")

        assert add(tmp_path, "a.wasm").text.startswith(header)

    def test_a_comment_inside_an_entry_block_is_refused_rather_than_dropped(
        self, tmp_path: Path
    ) -> None:
        text = (
            'version = 1\n\n[[wasm]]\nsha256 = "' + "a" * 64 + '"\n'
            'paths = ["a.wasm"]\norigin = "built"\nsource = "s"\nbuild = "b"\n'
        )
        commented = text.replace('origin = "built"', 'origin = "built"  # reviewed 2026-10-27')
        (tmp_path / MANIFEST_FILENAME).write_text(commented, encoding="utf-8")
        artifact(tmp_path, "b.wasm", "b")

        with pytest.raises(ValueError, match="the writer emits them from data only"):
            add(tmp_path, "b.wasm")

    def test_a_misspelled_key_is_refused_before_the_rewrite(self, tmp_path: Path) -> None:
        # `notes` is an unknown key, so the loader reports it as a finding instead of raising, and
        # a rewrite from parsed data would silently drop it. A misspelled *required* key is a
        # parse error, which is refused earlier.
        text = (
            'version = 1\n\n[[wasm]]\nsha256 = "' + "a" * 64 + '"\n'
            'paths = ["a.wasm"]\norigin = "built"\nsource = "s"\nbuild = "b"\nnotes = "keep me"\n'
        )
        (tmp_path / MANIFEST_FILENAME).write_text(text, encoding="utf-8")
        artifact(tmp_path, "b.wasm", "b")

        with pytest.raises(ValueError, match="fix those keys first"):
            add(tmp_path, "b.wasm")

    def test_a_file_without_the_wasm_magic_is_refused(self, tmp_path: Path) -> None:
        (tmp_path / "pointer.wasm").write_text("version https://git-lfs.github.com/spec/v1\n")

        with pytest.raises(ValueError, match="does not start with the Wasm magic"):
            add(tmp_path, "pointer.wasm", origin="vendored")

    def test_an_origin_built_without_a_build_command_is_refused(self, tmp_path: Path) -> None:
        artifact(tmp_path, "a.wasm", "a")

        with pytest.raises(ValueError, match="--build is required"):
            add(tmp_path, "a.wasm", build="")

    def test_an_artifact_the_collector_would_skip_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        artifact(tmp_path, "big.wasm", "x" * 400)
        monkeypatch.setattr(policy, "MAX_ARTIFACT_BYTES", 100)

        with pytest.raises(ValueError, match="over the 100 byte ceiling"):
            add(tmp_path, "big.wasm")

    def test_a_note_needing_escapes_round_trips(self, tmp_path: Path) -> None:
        artifact(tmp_path, "a.wasm", "a")
        note = 'copied from "upstream\\release",\nsecond line'
        change = add(tmp_path, "a.wasm", note=note)

        written, _ = manifest_from_toml(change.text, path=MANIFEST_FILENAME, source="test")
        assert written.entries[0].note == note

    def test_entries_come_out_in_hash_order_whatever_the_add_order(self, tmp_path: Path) -> None:
        artifact(tmp_path, "z.wasm", "zeta")
        artifact(tmp_path, "a.wasm", "alpha")
        first = add(tmp_path, "z.wasm", "a.wasm")
        second = add(tmp_path, "a.wasm", "z.wasm")

        assert first.text == second.text
        written, _ = manifest_from_toml(first.text, path=MANIFEST_FILENAME, source="test")
        assert [entry.sha256 for entry in written.entries] == sorted(
            entry.sha256 for entry in written.entries
        )

    def test_a_path_outside_the_repository_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="repo-relative"):
            add(tmp_path, "../elsewhere/a.wasm")

    def test_a_manifest_path_outside_the_repository_is_refused(self, tmp_path: Path) -> None:
        artifact(tmp_path, "a.wasm", "a")

        with pytest.raises(ValueError, match="repo-relative"):
            manifest_add(
                tmp_path,
                ("a.wasm",),
                manifest_path="../etc/wasm.toml",
                origin="built",
                source="s",
            )
