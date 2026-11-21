# ARCHITECTURE: Airlock

| | |
|---|---|
| Status | Draft v0.2 (red-team revision) |
| Date | 2026-10-27 |
| Companion docs | `PRD.md`, `ARCHITECTURE_ESSENTIALS.md`, `ROADMAP.md`, `project_structure.md`, `AGENTS.md`, `CLAUDE.md` |
| Tags | **[Verified]** checked against a source; **[Unverified]** believed or designed but untested |

---

> **Roadmap rule (every contribution):** any change to this repository, by a human or an agent, must update `ROADMAP.md` in the same pull request: tick or add tasks, add a changelog entry, refresh the progress table and the `Last updated` line. See section 17.

## 1. Context and constraints

Airlock scans a git repository and reports supply-chain risk. It runs in two places: a developer's machine and a GitHub Actions runner. The scanned repository is untrusted input, because the scan exists to catch a repo (or a PR to it) that has been tampered with.

Hard constraints that shape everything below:

1. **The tool must not execute scanned content.** No imports, no `eval`, no shelling out with file-derived strings.
2. **The tool must not be controlled by the scanned tree.** Code, policy and suppressions need a trust path that does not run through the PR head.
3. **Unreadable means unsafe.** Any file the tool cannot fully inspect becomes a finding.
4. **A solo maintainer must be able to own it.** Small surface area, no runtime dependencies in v0.1, no services.
5. **Offline.** No network during a scan; no telemetry.

## 2. Tech stack

| Concern | Choice | Reason |
|---|---|---|
| Language | Python 3.11 or newer | Existing scanner is Python; `tomllib` is in the standard library from 3.11; GitHub-hosted Ubuntu runners ship Python 3 [Unverified: minor version on `ubuntu-latest` at release time] |
| Runtime dependencies | None (standard library only) | Smallest supply-chain surface for a supply-chain tool; no `pip install` step in the Action |
| TOML reading | `tomllib` | Standard library |
| TOML writing | Hand-written serializer for the three known schemas | The standard library has no TOML writer; the schemas are flat enough |
| YAML | Not parsed in v0.1 | No standard-library YAML; workflow checks use conservative text heuristics (see ADR-007) |
| Git access | `subprocess` calling `git` with fixed argument lists, no shell | Reads tracked files and base-ref blobs |
| Hashing | `hashlib` (SHA-256) | Standard library |
| Output formats | Console text, GitHub workflow commands, JSON, step summary (SARIF in v0.2) | CI-native; SARIF deferred because it needs an extra permission and upload step |
| Packaging | `pyproject.toml`, `src/` layout, hatchling build backend | Build-time only |
| Distribution (v0.1) | Composite GitHub Action, consumers pin a commit SHA | The trust anchor is a git SHA; nothing to download or verify |
| Distribution (later) | PyPI with trusted publishing | Convenience for local use |
| Dev tooling | pytest, ruff, mypy | Dev-only, never shipped |
| CI | GitHub Actions, every action pinned by hash, top-level `contents: read` | Dogfoods its own rules |
| Release integrity | Tagged releases with build provenance attestations | Satisfies its own release rules |

Versions are pinned at implementation time and are deliberately not stated here.

## 3. Architecture overview

```
              (trusted: pinned action SHA)               (untrusted: scanned repo)
 +-------------------------------+                +--------------------------------+
 | Airlock code + builtin        |                | working tree / PR head         |
 | rules (rules/builtin/*.toml)  |                | policy + suppressions + manifest|
 +---------------+---------------+                +----------------+---------------+
                 |                                                 |
                 |      PR mode: policy files read from BASE ref   |
                 v                                                 v
 +-----------+   +-----------+   +--------------+   +-------------+   +-----------+
 | Collector |-->| Role      |-->| Detectors    |-->| Policy      |-->| Reporters |--> exit code
 | (git)     |   | resolver  |   | (in-tree)    |   | filter      |   | console   |
 +-----------+   +-----------+   +--------------+   | suppressions|   | github    |
                                                    +-------------+   | json/sarif|
                                                                      +-----------+
```

Pipeline stages are pure functions over immutable data where practical. A stage failure never produces a green result (see section 8).

## 4. Trust model

| Adversary | Capability | What Airlock does | Limit |
|---|---|---|---|
| Outside contributor | Opens a PR | Scans PR head with scanner from the pinned action; policy from base ref | Cannot be fooled by edits to the scanner or allowlist |
| Compromised dependency or Action | Runs code in CI | Read-only token, no secrets, pinned SHA | A compromised Airlock release is the residual risk; mitigated by attestation and SHA pinning |
| Maintainer credential theft (PolinRider entry) | Pushes to repo, may force-push, may edit workflows | Structural detectors flag the injected loader; `policy-changed` makes policy edits visible; `history-rewritten` finding on non-fast-forward pushes | If the attacker also controls repo settings, workflows and CODEOWNERS, Airlock can be disabled. No in-repo tool prevents that. Hardware-key 2FA and recovery-account protection are the real controls |
| Malicious fixture or vendored Wasm | Hides a payload in an asset | Manifest hash check; unlisted Wasm is HIGH | Does not analyze Wasm contents |
| Anyone who can push workflow files | Removes or edits the step that runs Airlock | Required status check blocks PRs whose check never reports; push-mode base check yields `history-rewritten` | A stolen credential can still disable the check. Only a scanner outside the repo (watch mode, decision D-04) is out of the attacker's reach |
| Credentialed push that edits policy | Pushes policy change and payload together | Push mode reads policy from `github.event.before` | New-branch pushes have no trusted base (WARN) |
| Determined evader | Crafts code that dodges regex rules | Capability tiers, entropy and tail checks | Regex heuristics can be beaten; parser analysis is Later |

Trust anchors:

1. The commit SHA of the Airlock Action in the consumer's workflow.
2. The trusted base: the PR base in PR mode, the pre-push SHA in push mode.

## 5. Repository layout

Full annotated tree, ownership and import rules: `project_structure.md`. Summary:

```
airlock/
  action.yml                      # composite action
  pyproject.toml
  airlock.toml                    # dogfood policy and suppressions
  wasm-manifest.toml              # dogfood Wasm manifest
  src/airlock/
    cli.py  model.py  collector.py  roles.py  rules.py  policy.py  fingerprint.py  runner.py
    strkey.py                     # P1
    detectors/{config_role,wasm_manifest,builtin_patterns,ci_surface}.py  # P0
    detectors/{soroban_profile,stellar_seed,cargo_vectors,npm_registry}.py # P1
    report/{console,github,jsonout,summary}.py                    # sarif.py in P1
  rules/{roles.toml,builtin/*.toml}
  scripts/{check_roadmap_touched.sh,roadmap_progress.py}
  tests/{unit,fixtures,bypass,corpus,golden}/
  .github/{workflows,pull_request_template.md,CODEOWNERS}
```

Removed since v0.1 of this document: `jsmask.py`, `wasmparse.py`, `detectors/deploy_gate.py`, `schema/*.json`, `templates/`, the `init` command and `report/sarif.py` (deferred). See section 16.4.

## 6. Components

### 6.1 Collector

- Lists tracked files with `git ls-files -z --stage`. Entries with mode 160000 are submodules and yield `submodule-present` (INFO, P1 hardening). Untracked files are out of scope. A path the index holds unmerged (stages 1 to 3, no stage 0) is kept as one entry and yields `skipped-unmerged`; it is never dropped for having no committed version.
- **No default directory skips.** The first draft skipped `node_modules/`, `target/`, `dist/`, `.next/` and `vendor/` and reported them as INFO. That let an attacker hide a payload in a committed vendor directory (B6). If a repo tracks a very large vendored tree, policy may list `low_priority_dirs`, which only suppress WARN-level content rules there. HIGH rules, role magic and config-role globs still apply.
- Reads each file once: size, first 4096 bytes and (lazily) the full bytes and SHA-256.
- Checks that the bytes read match the file's recorded size on both the head-only read path and the full-read path. If the file shrinks or grows between the size check and the read, it yields `skipped-unreadable` (HIGH) without producing a hash or extracting text.
- Decoding: honor a UTF-8 or UTF-16 BOM; otherwise decode UTF-8 strictly. Undecodable text yields `non-utf8-text` (HIGH in sensitive roles, WARN elsewhere). A NUL byte after BOM handling yields `nul-in-text`.
- Never follows symlinks; a symlink is recorded as `skipped-symlink` and its target path is not read. The severity is HIGH for the roles in `SENSITIVE_ROLES`, because a link in that set is an unread file that would have run, and INFO otherwise.
- Enforces `max_file_bytes` (default 5,000,000). Oversized files yield `skipped-oversize`: WARN generally, HIGH for the roles in `SENSITIVE_ROLES` (`tooling-config`, `editor-autorun`, `workflow`, `package-manifest`, `install-hook`).
- Enforces `line_cap` (default 20,000 characters). Lines over the cap are not passed to regex rules and yield `cfg-long-line`.
- Startup checks: Python 3.11 or newer, `git` on PATH, repository readable (including the git `safe.directory` case). Failure exits 2 with a plain message.

### 6.2 Role resolver

A role is a label detectors use to decide what to inspect. Resolution order:

1. Content magic: `\0asm` gives `wasm`; ELF and Mach-O magics give `native-binary`, and so does `MZ` only when the DOS header's little-endian `e_lfanew` at offset `0x3C` points, inside the bytes already read, at a `PE\0\0` signature. A file starting with `MZ` that fails that check falls through to the globs and extension and is scanned as text. Applies regardless of extension. Every magic role produces a non-suppressible INFO `content-magic-role` finding naming the role and path.
2. Glob rules from `rules/roles.toml`. No per-repo role overrides in v0.1.
3. Fallback: `source`, `doc` or `other` by extension.

A file may have several roles. Globs use a small internal matcher where `**` spans directories and `*` does not cross `/`, to avoid the `fnmatch` behavior that let a lone `*` match everything.

### 6.3 Detectors

A detector is a function `run(ctx) -> Iterable[Finding]` registered in a plain list. (An earlier draft used a Protocol class and a registry object; a list of functions is enough.) `ScanContext` exposes exactly four things: the collected file entries with their roles, the trusted policy, the trusted manifest and the loaded rule data. It does not expose the trust model itself — see 7.9.

Every call is wrapped: an exception becomes a HIGH `detector-error` and the remaining detectors still run. Findings a detector yielded before it raised are kept, so one failure on the tenth file costs the scan that file's coverage and nothing more. The message is built only from scanner-written text, the in-tree detector module name and the exception type. The exception's own text moves to the evidence, with C0 control characters escaped visibly and newlines flattened, so a path or line fragment quoted by the exception cannot forge an annotation or hide the finding. Third-party detector plugins are not supported, because loading external code would defeat the trust model.

The registry also names the valid `builtin:<name>` targets (`DETECTOR_NAMES`), so the rule loader rejects a rule pointing at a detector that does not exist. Two detectors are registered now: `config_role` and `wasm_manifest`.

`runner.engine_findings` is the pass that is not a detector: it runs the `pattern` rules over every entry with text and reports the lines `line_cap` withheld from any regex. It lives in the runner so those lines are accounted for whatever the registry holds; a registry narrowed to one family must reduce what is matched, never what is reported.

### 6.4 Rule engine

Rules are TOML data with one of:

- `pattern`: a regex or literal set applied per line, within the rule's `roles`, on raw text.
- `detector`: a pointer to a builtin function for logic a pattern cannot express.

A `detector` rule may carry a `pattern` as well, which is the text its code detector looks for and the engine never runs. `cfg-process-spawn` needs this: the same line is a WARN or a HIGH depending on what the command runs, so the detector must stay the only reporter of it.

Rule files are validated in code at load time (no JSON schema files in v0.1). An invalid rule file is a config error (exit 2). Every pattern must pass the adversarial timing test in the suite (FR-14).

### 6.5 Trusted base and policy resolution

Policy (`airlock.toml`, including suppressions) and `wasm-manifest.toml` must come from a source the change under scan cannot edit.

```
mode pr:
    base = PR base SHA (error exit 2 if unresolvable; never fall back to head)
mode push:
    base = github.event.before
    - all zeros (new branch):             bootstrap defaults + finding no-trusted-base (WARN)
    - not reachable, or not an ancestor
      of HEAD (git merge-base --is-ancestor): finding history-rewritten (HIGH), bootstrap defaults
mode full (local, manual, scheduled):
    read from the working tree, emit untrusted-policy-source (INFO) so the weaker guarantee is visible

for each policy file:
    use the version at base; if the head version differs, emit policy-changed (WARN) with a diff summary
    a base blob over MAX_CONFIG_BYTES is never decoded: skipped-unreadable (HIGH), the shipped
    defaults apply, and the change's copy is not read or compared
```

This closes B1: a credentialed push that edits the policy and adds a payload in one commit is judged by the old policy. It does not stop an attacker who also removes the workflow (B2).

Cost: a PR that adds a legitimate Wasm fixture fails until the manifest change merges first. The documented flow is two PRs, manifest first. [Unverified: friction level needs real use]

### 6.6 Reporters

| Reporter | Notes |
|---|---|
| console | Severity, rule, `path:line`, message; summary line with counts, suppressed count and skip accounting |
| github | `::error`, `::warning` and `::notice` commands; escapes `%`, `\r`, `\n`, `:` and `,` in properties; HIGH first; each severity capped one slot under the ten annotations a step keeps, and the capped list ends with the annotation naming how many went unlisted, inside the same ten |
| json | Full `ScanReport` model, including every suppressed finding and its reason |
| summary | Markdown to `$GITHUB_STEP_SUMMARY`: counts, skipped-file counts, every HIGH; evidence rendered only inside fenced code blocks with the fence length chosen to exceed any backtick run in the evidence, truncated to a fixed length. Rule ids and paths outside a fence are escaped, so no `-` or `#` is substituted where a heading or list marker could form. A step summary is capped at 1 MiB by the runner and losing it does not fail the step, so the total size needs its own budget (7.13) |
| sarif (P1) | SARIF 2.1.0 with `partialFingerprints["airlock/v1"]` (D-09, ADR-019); result count capped at or under GitHub's 5,000-after-trim figure; implementation deferred to task 7.6 |

Evidence is attacker-controlled text. It is never rendered as raw markdown (B11). Output is cut by GitHub's rendering limits, so the reporters order it by severity (B8). Task 0.9 verified those limits on 2026-10-30: every number below is attributed either to a GitHub page retrieved that day or to a hosted probe run, and the two columns stay separate because a documented number can change with the docs while an observed one records what the runner did.

**Documented limits**

| What | Value | Source (retrieved 2026-10-30 UTC) |
|---|---|---|
| Annotations per Checks API request | 50, and an update appends to those already on the check run | [REST: check runs](https://docs.github.com/en/rest/checks/runs) |
| Annotations per Actions step | 10 warning and 10 error | [REST: check runs](https://docs.github.com/en/rest/checks/runs) |
| Annotation `message`, `raw_details` | 64 KB each | [REST: check runs](https://docs.github.com/en/rest/checks/runs) |
| Annotation `title` | 255 characters | [REST: check runs](https://docs.github.com/en/rest/checks/runs) |
| Check run `output.summary`, `text` | 65,535 characters each | [REST: check runs](https://docs.github.com/en/rest/checks/runs) |
| Step summary | 1 MiB per step. Above it "the upload for the step will fail and an error annotation will be created", and "upload failures for job summaries do not affect the overall status of a step or a job" | [Workflow commands](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands) |
| Job summaries displayed per job | 20 | [Workflow commands](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands) |
| SARIF upload | "For each gzip-compressed SARIF file, SARIF upload supports a maximum size of 10 MB. Any uploads over this limit will be rejected" | [SARIF support for code scanning](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support) |
| SARIF results per run | 25,000, and "only the top 5,000 results will be included, prioritized by severity" | [REST: code scanning](https://docs.github.com/en/rest/code-scanning/code-scanning#upload-an-analysis-as-sarif-data) |
| SARIF runs per file, rules per run | 20 and 25,000 | [REST: code scanning](https://docs.github.com/en/rest/code-scanning/code-scanning#upload-an-analysis-as-sarif-data) |
| SARIF thread flow locations per result, locations per result | 10,000 (top 1,000 kept) and 1,000 (100 kept) | [REST: code scanning](https://docs.github.com/en/rest/code-scanning/code-scanning#upload-an-analysis-as-sarif-data) |

**Observed**

Probe: `wagmiiii/airlock-isolation-probe`, branch `limits-probe`, `ubuntu-latest`, workflow file `Reporter limits probe`. Run 41016320957, `annotations` job 123933359559. One step emitted 60 `::error`, 30 `::warning` and 25 `::notice`; a second step emitted 12 more `::error`. The finished check run reported 41 annotations: `probe-error-1..10`, `second-error-1..10`, `probe-warning-1..10`, `probe-notice-1..10`, and one runner notice that has nothing to do with the probe. So the documented per-step cap holds, it applies per level rather than per step in total, `::notice` is capped at 10 too even though the page names only warning and error, and the survivors are the first ten in emission order. 52 of the 72 errors and 15 of the 25 notices were discarded, and the job still reported success.

Summary probe, same run, job 123933359709: a 65,536-byte summary was accepted; a 1,048,577-byte summary was rejected with `$GITHUB_STEP_SUMMARY upload aborted, supports content up to a size of 1024k, got 1024k`, the job stayed `success` and the following step still ran; a 1,048,000-byte summary hung for over 12 minutes against `timeout-minutes: 10` and had to be cancelled. Just under the ceiling is worse than over it.

Push base, runs 41016540033, 41016922073 and 41017078745 on the same branch: a push to a new branch reports `before=0000000000000000000000000000000000000000`; an ordinary push reports the previous tip, which `actions/checkout` at its default depth does not contain (`depth=1`, base unreachable) but a full fetch recovers (`after_full_fetch_depth=5`, base reachable); a force push reports the rewritten commit (`before=65ab62a6dc…`, `sha=18ea1cf510…`), which is unreachable at both depths. `policy.py` already treats these three cases as it does, and section 10's exit 2 shallow case is the middle row measured under the default checkout.

**What the reporters do with this**

`github.py` cuts each severity one slot below the budget (9 HIGH, 9 WARN, 8 INFO) so the withheld-count note and the suppression note, which is also a `::notice`, are rendered inside the ten lines that survive. The previous values, 50 HIGH and 25 WARN, were above what a step keeps, which meant the annotation saying how many went unlisted was itself never seen: the accounting was right and the delivery was not. Caps stay reporter constants rather than policy settings; a repository must not be able to raise them. All of a scan's annotations come from the one step that runs the CLI, so the per-step cap binds and the composite Action must not spread the annotation stream across steps to buy headroom (4.1).

`summary.py` has no byte budget. Every HIGH is listed by design, so a finding set large enough to pass 1 MiB loses the whole summary without failing anything: an attacker can choose to hide the reviewer's copy of the findings. Task 7.13 carries that, along with the 20-summaries-per-job fact that a chunked summary would have to respect.

7.6 has its numbers: 10 MB compressed, 5,000 results per run after GitHub's severity-ordered cut, 20 runs per file, 100 locations kept per result. A report above 5,000 results is trimmed by GitHub rather than rejected, so the cap belongs in the reporter.

[Unverified: whether `merge_group` events deliver a usable base. GitHub documents the trigger, its `checks_requested` activity type, and that `GITHUB_SHA` and `GITHUB_REF` are the merge group's SHA and ref ([events that trigger workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)), but it documents no `before` equivalent, and measuring reachability needs a merge queue on the repository. Task 4.1 decides whether Airlock supports the event at all; it is not assumed here.]

## 7. Data models

### 7.1 Severity and mode

```python
class Severity(IntEnum):
    INFO = 0
    WARN = 1
    HIGH = 2

class Mode(Enum):
    PR = "pr"
    PUSH = "push"
    FULL = "full"
```

### 7.2 Finding

```python
@dataclass(frozen=True)
class Finding:
    rule_id: str                 # stable, kebab-case, e.g. "cfg-dynamic-code"
    severity: Severity
    path: str                    # repo-relative, forward slashes
    line: int                    # 0 for file-level
    roles: tuple[str, ...]
    message: str                 # <= 200 chars
    evidence: str | None         # short, truncated, sanitized excerpt
    occurrence: int              # nth occurrence of identical normalized evidence in this file
    fingerprint: str             # "sha256:<hex>"
    suppressible: bool
    suppressed_by: str | None
```

Ordering: severity descending, then `(path, line, rule_id)`, so output is deterministic and HIGH comes first.

### 7.3 Fingerprint

```
fingerprint = sha256(rule_id \0 normalized_path \0 normalized_evidence \0 occurrence)
```

`normalized_evidence` is the matched line with outer whitespace stripped and internal whitespace runs collapsed. Line numbers are excluded so edits above a line do not invalidate a suppression. `occurrence` is the zero-based index of that identical evidence within the file, so a second copy of a suppressed line is a new, unsuppressed finding (B5). If an earlier duplicate is removed, indices shift and the suppression must be reissued; that fails closed. For file-level findings the file's SHA-256 replaces the evidence. A scanner-state finding (`skipped-oversize`, `history-rewritten`, `policy-unknown-key`) has neither a matched line nor file bytes, so it keys on its message: the message is written by the scanner, never by scanned content, and every state rule is non-suppressible, so rewording one cannot move an owner's suppression. A state finding whose message is blank, which a detector bug can produce, keys on `state:<rule_id>:<path>:<line>` instead of raising: one such finding must not turn the whole scan into a configuration error, and the same non-suppressibility means the line number in this one key cannot move a suppression. [Unverified: churn on real edits]

### 7.4 Rule file

```toml
[[rule]]
id           = "cfg-dynamic-code"
title        = "Dynamic code execution in tooling config"
roles        = ["tooling-config"]
detector     = "pattern"                      # or "builtin:<name>"
severity     = "high"
suppressible = false
rationale    = "Build configs have no reason to evaluate strings."
pattern      = { kind = "regex", value = '(?<![\w.])(?:eval|Function)\s*\(' }
tests        = { positive = "cfg-dynamic-code", negative = "cfg-dynamic-code" }   # fixture builder names
```

### 7.5 Roles file

```toml
[roles.tooling-config]
globs = ["**/postcss.config.*", "**/tailwind.config.*", "**/next.config.*",
         "**/eslint.config.*", "**/babel.config.*"]

[roles.editor-autorun]
globs = ["**/.vscode/tasks.json", "**/.vscode/settings.json"]

[roles.workflow]
globs = ["**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"]

[roles.package-manifest]
globs = ["**/package.json"]

[roles.install-hook]
globs = ["**/.husky/**", "**/.githooks/**"]
```

Wasm and native binaries are resolved by content magic, not globs. The `tooling-config` defaults mirror the files named in the OpenSourceMalware reports. [Verified] Extra configs (`vite`, `webpack`, `jest`, and others) are P1 and need false-positive review. [Unverified]

The three added here, together with `editor-autorun`'s new settings file, are the CI surface (9.7).
Each names a path something executes with credentials attached, which is the bar for joining
`SENSITIVE_ROLES` and therefore for an incomplete read of it being a HIGH rather than a WARN. The
workflow glob spans the tree so a nested copy is still read, though only the root
`.github/workflows` is the path GitHub executes; the role's bar is the root path and the nested copy
is a file worth reporting, not a claim that it runs.

### 7.6 Policy file with suppressions

```toml
# airlock.toml
version = 1

[policy]
fail_on        = "high"
max_file_bytes = 5000000
line_cap       = 20000
tail_max_len   = 2000        # placeholder; tune on corpus (task 3.3)
tail_entropy   = 4.5         # placeholder; tune on corpus (task 3.3)

[soroban]                    # used by soroban_profile (P1)
[soroban.require_release_profile]
overflow-checks = true
panic = "abort"
lto = true
codegen-units = 1
debug-assertions = false

[[suppress]]
rule        = "cfg-process-spawn"
path        = "next.config.mjs"
fingerprint = "sha256:..."
reason      = "git rev-parse HEAD for build id"
expires     = 2027-04-27     # optional, a TOML date
```

An inline table has to stay on one line in TOML, so the release profile is written as its own table. `expires` is a date, not a string; the loader accepts the `YYYY-MM-DD` spelling too, because that is how the earlier sketch in this section wrote it.

Rules for suppressions:

- Match needs `rule`, `path` and `fingerprint`. No globs, no inline markers.
- `reason` is required. There is no `owner` field (git history records who added it).
- `expires` is optional. 30 days before expiry a `suppression-expiring` WARN appears; after expiry only that finding returns, so builds do not turn red for a reason unrelated to a change (B10).
- Entries for `suppressible = false` rules never apply and emit `suppression-invalid` (HIGH). The same holds for an entry naming a rule that is not loaded in this build, or a scanner-state rule id. State membership is checked before the rule lookup, including when a loaded rule disagrees. State findings always report `suppressible = false`; both the shipped `cfg-long-line` rule and its engine fallback agree. Validity is decided before matching, so a mistaken entry cannot hide a finding while the report complains about it.
- An entry is checked against the rule data rather than against the scan's findings, so a rule that was renamed or made non-suppressible is reported even on a scan where the entry matched nothing.
- A second valid entry with the same `rule`, `path` and `fingerprint` is a duplicate and emits `suppression-invalid` (HIGH). The report names both entry positions and says which one is consulted first. The first entry keeps deciding, including when it has expired, so the duplicate neither suppresses anything nor changes the covered finding's `suppressed_by`.
- Unknown top-level keys emit `policy-unknown-key` (WARN); a missing or unsupported `version` exits 2.
- The base copy is held to the same ceiling as the working tree. A blob over `MAX_CONFIG_BYTES` is refused before it is decoded, comes back as `skipped-unreadable` (HIGH) with the shipped defaults in its place, and the change's copy is not read, so no `policy-changed` is claimed for a comparison that never happened.

### 7.7 Wasm manifest

```toml
version = 1

[[wasm]]
sha256 = "<hex>"
paths  = ["test/fixtures/smart_account.wasm"]
origin = "built"               # built | vendored | generated
source = "contracts/smart_account"
build  = "stellar contract build --package smart_account"   # documentation only
note   = "fixture for conformance tests"
```

Keyed by hash so the same Wasm at several paths needs one entry and a rename produces a WARN instead of a HIGH.

**The writer is canonical, not an editor** (task 3.5, `policy.py`). `manifest_to_toml` emits the header verbatim, then entries sorted by `sha256` with each entry's `paths` sorted, so `parse(render(x)) == x` holds and two runs on the same tree produce the same bytes. Idempotence is what makes `manifest add` safe to run in a pipeline: a second call reports "already lists every target" and writes nothing.

Two refusals exist because a writer that silently drops what the model cannot carry is a lie:

- **Comments inside an entry block** are refused ("the writer emits them from data only"). A free-text comment attached to `[[wasm]]` has no field to live in, so keeping it would mean hand-editing the parse, and dropping it would delete a reviewer's note. `note =` is the field for that.
- **Unknown keys in the entry region** are refused before anything is written, naming them, because the rewrite emits from parsed data and would erase them. (A header outside the recognised shape is preserved as-is; only the entry region is rewritten.)

`manifest add` also checks the artifact itself: `\0asm` magic is required (a `*.wasm` LFS pointer is refused, not recorded), the file must sit inside the repo and be at most `max_file_bytes`, `--source` is always required, and `--build` is required when `origin = "built"`. Provenance is stated once per entry; joining a second path to a known hash keeps the reviewed `source`/`build` rather than overwriting it.

**Nothing is staged or committed.** `wasm-manifest.toml` is a protected path, so the command writes the file and tells the operator to land that diff on its own branch first (FR-06). A tool that auto-commits the trusted base would be the bypass it is meant to prevent.

`manifest check` is one scan with `run_scan(..., keep=wasm-* findings)`, not a second implementation of artifact accounting. Numbering and suppression still run over every finding, so fingerprints and occurrence indices match a full scan; only the exit code is decided over the kept set, against the same `fail_on` threshold. Consequently an unlisted or swapped artifact exits 1 while manifest rot (`wasm-manifest-stale`, `wasm-path-moved`) is named at WARN and exits 0 — the deleted artifact is not shipping, so there is nothing to stop.

### 7.8 ScanReport

```python
@dataclass
class ScanReport:
    tool_version: str
    mode: Mode
    repo_head: str
    base: str | None
    files_indexed: int               # every entry the index lists
    files_scanned: int               # a digest and no skip reason
    files_skipped: dict[str, int]    # reason -> count
    findings: list[Finding]
    suppressed: list[Finding]
    exit_code: int
```

The three file counts are a partition, not a summary. `files_indexed` is `len(collection.entries)`, one entry per path `git ls-files --stage` returns after the collector folds a conflict's staged versions into one entry. An entry with a `skip_reason` belongs to `files_skipped`, even when it also carries a digest: an encoding skip is hashed before it is decoded, so counting digits alone would count that file twice and break the sum. `files_scanned` is therefore an entry with a digest and no skip reason. A binary entry (Wasm, ELF, Mach-O, archive) counts as scanned: its bytes are hashed and role-tagged, and the byte detectors read it, so the report says it was read rather than skipped.

`run_scan` computes the three counts and raises `ValueError` naming all of them when scanned plus skipped does not equal the index total. The CLI maps that to exit 2, so an entry that is neither read nor named by a skip fails the run instead of disappearing from a report that claims to be complete.

### 7.9 FileEntry and ScanContext

Both were drafted before the collectors, detectors and reporters existed, so task 2.13 settled them against use rather than against opinion: a field survives only if some rule, reporter or test reads it.

```python
@dataclass(frozen=True, slots=True)
class FileEntry:
    path: str
    sha256: str | None          # absent when the whole file could not be read
    roles: tuple[str, ...]
    text: str | None = None
    skip_reason: str | None = None

@dataclass(frozen=True, slots=True)
class ScanContext:
    entries: tuple[FileEntry, ...]
    policy: Policy
    manifest: Manifest
    rules: tuple[Rule, ...]
```

Dropped from `FileEntry`: `size_bytes`. The collector needs the size to decide whether a file is oversize or only partly read, and states it in those findings, but no rule is a function of it, and any entry that carries text can be measured with `len(text)`. It stayed a local variable in `collector.py`.

Dropped from `ScanContext`: `mode`, `tool_version`, `repo_head`, `base`. Those describe the scan, not a file, and the only code that reads them is the reporters, which are handed `ScanReport` (7.8) and get them from there. Keeping them on the context would have made the trust model reachable to detector code, which is the wrong direction: `mode` decides which base the policy came from, that question is settled before a `ScanContext` exists, and a detector has no business re-opening it. A rule that genuinely needs the mode adds it back with a task that says why.

The invariant this enforces is that detector code cannot see less than it needs and cannot see more than a finding should depend on. `tests/unit/test_model.py` asserts both field lists verbatim, so a re-added field is a deliberate edit to that test rather than an unnoticed one.

`FileEntry`'s three states are mutually exclusive and `__post_init__` enforces it: text requires a `sha256`; a `skip_reason` forbids both text and a digest; an entry with none of the three is rejected. A skipped entry carrying text would let a detector scan bytes the report says were never read, inverting the guarantee skip findings exist to provide. The one skip that is hashed-but-not-decoded has no digest for that reason, and the stale-manifest detector records its synthetic path as skipped.

The engine modules `runner.py`, `model.py`, `fingerprint.py` and `roles.py` make no filesystem, `eval`, `exec`, `compile` or `subprocess` call, and only `collector.py` imports `subprocess`. `tests/unit/test_engine_boundaries.py` holds that boundary by parsing the four files with `ast`, and its self-tests prove the checker rejects a doctored `open` or `subprocess.run`. A new engine module joins the scanned set with one line in `ENGINE_MODULES`.

## 8. Fail-closed behavior

| Situation | Result |
|---|---|
| File over size limit | `skipped-oversize` (HIGH for sensitive roles, else WARN) |
| File unreadable, or changed size while being read | `skipped-unreadable` (HIGH) |
| Config file at the trusted base over `MAX_CONFIG_BYTES` | `skipped-unreadable` (HIGH); the shipped defaults apply and the change's copy is not compared |
| NUL byte in text after BOM handling | `nul-in-text` (HIGH) |
| A content magic role took the file out of text scanning | `content-magic-role` (INFO, names the role and path) |
| Undecodable text | `non-utf8-text` (HIGH sensitive roles, else WARN) |
| Line over `line_cap` | `cfg-long-line` (HIGH in a `SENSITIVE_ROLES` file, else WARN); regex skipped for that line |
| Symlink | `skipped-symlink` (HIGH for sensitive roles, else INFO) |
| Unmerged index entry (merge conflict) | `skipped-unmerged` (HIGH for sensitive roles, else WARN); no version of the file is read |
| Submodule | `submodule-present` (INFO) |
| Archive present | `wasm-archive-skipped` (WARN) |
| Detector raises | `detector-error` (HIGH) |
| Pushed `before` unreachable or non-ancestor | `history-rewritten` (HIGH) |
| New branch push | `no-trusted-base` (WARN) |
| Policy changed in this change | `policy-changed` (WARN) |
| Invalid policy, rule or manifest | exit 2 |
| Base unresolvable in PR mode | exit 2 |
| Python or git missing | exit 2 with a plain message |

Exit codes: 0 pass; 1 findings at or above `fail_on`; 2 configuration or usage error; 3 internal error. Anything nonzero fails the job.

## 9. Detector specifications

### 9.1 `config_role`

Applies to role `tooling-config`. Runs on raw text, no masking.

1. `cfg-long-line`: lines past `line_cap` reach no regex and are reported by the engine pass (`runner.engine_findings`), not by this detector, so the account holds even when the registry is partial.
2. Capability rules the engine runs: `cfg-dynamic-code`, `cfg-network`, `cfg-chain-endpoint`.
3. `cfg-process-spawn`, in this detector, two tiers off one pattern: WARN for a build step stated up front, HIGH when the command names a downloader, a decoder or an inline script.
4. Combination rule `cfg-network-exec`: network capability and (process spawn, dynamic code or `require()` of a non-literal) in one file is HIGH even when each alone would be WARN.
5. `cfg-appended-tail`: take the last non-empty line; flag if its length exceeds `tail_max_len` or if the entropy of its trailing window exceeds `tail_entropy`. Thresholds are placeholders until tuned on the corpus. [Unverified]
6. `cfg-nul`, reported by the collector for every role, so an unexpected role cannot hide it.

Capability rules were chosen because obfuscator fingerprints rotate while the mechanism (fetch remote content, decrypt, evaluate) stays. [Verified: OpenSourceMalware reporting] Known limit: string concatenation such as `globalThis['ev'+'al']` evades regex. The long-line and tail rules give partial coverage; parser analysis is Later.

### 9.2 `wasm_manifest`

1. For every tracked file with role `wasm`, compute SHA-256.
2. Build `path -> expected hash` and `hash -> entry` maps from the trusted manifest.
3. Emit `wasm-unlisted` (hash unknown), `wasm-hash-mismatch` (listed path, different hash) or `wasm-path-moved` (known hash, unlisted path).
4. Emit `wasm-manifest-stale` for entries with no matching file. An entry whose declared path still holds a Wasm file is not called stale as well as mismatched or moved: one changed artifact, one finding.
5. Detect archives and report `wasm-archive-skipped`. A `*.wasm` Git LFS pointer is resolved from its `oid sha256` only when `.gitattributes` marks the path with `filter=lfs`. The oid is compared to the trusted manifest without fetching the object, and a matching oid counts as seen for stale-entry accounting. An unknown oid is `wasm-unlisted` HIGH and names the full oid. A malformed pointer, invalid oid or size field, or pointer not marked LFS keeps the existing unlisted result. The size field is syntax-checked only: verifying the remote object's byte count would require fetching it, and the manifest stores no size.

Wasm binary basics: magic `00 61 73 6D`, then version `01 00 00 00`. [Verified: Wasm binary format] No section parsing in v0.1; the SEP-58 metadata check is Later.

### 9.3 `soroban_profile` (P1)

- Contract crates are packages whose `crate-type` includes `cdylib`. Apply rules only to them.
- Check `[profile.release]` in the workspace root manifest (or the single-package root) against `policy.soroban.require_release_profile`. Missing or false `overflow-checks`: HIGH. Other deviations: WARN. A `[profile.*]` section in a non-root manifest is ignored by Cargo, so report `profile-ignored` (INFO). [Verified: Cargo behavior]
- Flag `soroban-sdk` with `testutils` in a contract crate's `[dependencies]`, including features inherited through `workspace = true`. Libraries are exempt. The rule assumes resolver 2 semantics. [Unverified: confirm against Cargo docs, task 0.12]
- Do not enforce target triple, size limit or SDK version. Stellar docs disagree with each other on them (`wasm32v1-none` versus `wasm32-unknown-unknown`; 64 KB versus 128 KB). [Verified: documentation inconsistency observed]

### 9.4 `stellar_seed` (P1)

**D-06: KEEP, owner-approved 2026-10-28 UTC (task 0.7, issue #24).** Retain the
planned offline detector for checksum-valid plaintext Stellar secret seeds in tracked
files. This is a scope decision, not an implementation: `strkey.py` and the detector
remain stubs until tasks 6.2 and 6.3.

Candidate regex `\bS[A-Z2-7]{55}\b`, applied only to collected text on lines at or
under `line_cap`. No assignment keyword or entropy threshold is required. For each
candidate:

1. Require exactly 56 canonical uppercase RFC4648 Base32 characters, without padding.
   Decode to exactly 35 bytes and require re-encoding to reproduce the candidate.
2. Require version byte `0x90` (`18 << 3`), followed by a 32-byte Ed25519 seed.
3. Compute CRC16-XMODEM over those first 33 bytes. Require it to equal the final
   2-byte checksum interpreted as little endian. Report only checksum-valid candidates.

**[Verified: source inspection, 2026-10-28 UTC]** Encoding references:

- [SEP-0023, specification](https://github.com/stellar/stellar-protocol/blob/62a67297ea14562ada30702d7e0f9d1cfbbfd2fa/ecosystem/sep-0023.md#specification):
  seed version, 32-byte payload, CRC polynomial, unpadded Base32 and canonical round trip.
- [`stellar/go`, `strkey/main.go`](https://github.com/stellar/go/blob/aab2ea4aca889ebebb11148a542e2165a0778f9a/strkey/main.go):
  `VersionByteSeed`, `Decode` and `Encode` confirm the version and little-endian
  checksum over version plus payload. Its
  [CRC helper](https://github.com/stellar/go/blob/aab2ea4aca889ebebb11148a542e2165a0778f9a/strkey/internal/crc16/main.go#L1-L13)
  specifies XMODEM (polynomial `0x1021`, initial value and final XOR zero, no reflection).
  One version byte + 32 payload bytes + 2 checksum bytes gives 35 bytes, or 56 Base32 characters.

**Tool overlap, verified by source inspection only at these revisions:**

| Tool and pinned source | Finding |
|---|---|
| Gitleaks [`config/gitleaks.toml`](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/config/gitleaks.toml) | 222 rules; no dedicated Stellar/StrKey checksum detector. `generic-api-key` may incidentally match a seed in suitable keyword/assignment context with entropy >= 3.5. It does not validate StrKey checksums or guarantee coverage of a bare seed. |
| TruffleHog [`pkg/detectors/privatekey/privatekey.go`](https://github.com/trufflesecurity/trufflehog/blob/0301dc36bd6762d2a20a8317ae00375eb5ba90a9/pkg/detectors/privatekey/privatekey.go#L39-L79) and [`pkg/engine/defaults/defaults.go`](https://github.com/trufflesecurity/trufflehog/blob/0301dc36bd6762d2a20a8317ae00375eb5ba90a9/pkg/engine/defaults/defaults.go#L1246) | No dedicated Stellar detector in the inspected revision. `privatekey` handles PEM-style private-key blocks, not plaintext StrKey seeds; the `generic.Scanner` registration is commented out. |

Neither tool was executed for this comparison. This is not a coverage benchmark or a
claim that either can never report a seed through another rule or custom configuration.
The owner retained the small, offline checksum-specific check rather than relying on
incidental generic matches; Airlock does not replace a general secret scanner.

**Limits and fixtures.** Valid test vectors also pass the checksum. It checks encoding
integrity, not whether a seed is funded, live, used on testnet or safe to publish; none
of those facts is inferable from the encoding. Findings remain suppressible with a
reason through the existing trusted-base, occurrence-aware mechanism, including deliberate
test vectors in tests or docs. No automatic testnet or test-directory exemption.

Scope is plaintext in tracked files, including tests and docs, subject to the collector's
read limits and skip findings. Split or concatenated strings, additional encodings,
hex seeds, mnemonics and git history are outside this detector's scope. Word-character
adjacency (including underscores) can prevent the candidate regex from matching;
checksum validation cannot recover a candidate the regex never found.

Tasks 6.2 and 6.3 must test reference-derived valid and invalid encodings, boundary
cases and suppression before release. Build seeds at test time from documented reference
bytes or fragments, never commit a complete live-looking seed or import reference code
at scan time. No network access, balance lookup or live-key verification during a scan.

### 9.5 `cargo_vectors` (P1)

`cargo_vectors` reads every tracked `Cargo.toml` as TOML data. It reports every `[patch.*]` override, Git dependencies in `dependencies`, `dev-dependencies`, `build-dependencies` and `workspace.dependencies`, and path dependencies in those tables that resolve outside the repository. Findings name the manifest table, dependency key and replacement source. In-repository path dependencies and registry-version dependencies are clean. A malformed manifest becomes `detector-error`; the detector never invokes Cargo or accesses the network. Until registry policy exists, intentional Git and patch sources require a reasoned suppression. This slice does not implement `.cargo/config.toml` runner/linker/wrapper checks, custom `build` scripts, `[replace]`, or `build.rs` capability checks.

### 9.6 `builtin_patterns`

Line rules ported from `malware_scan.py`: invisible Unicode, exfiltration endpoints, decode-and-eval, obfuscator identifiers, credential harvesting, blockchain C2 hosts, workflow secret dump, install-hook droppers, VS Code auto-run, `pull_request_target` checkout, `build.rs` network, native binaries. HIGH rules first, then WARN rules. Intentional changes from the old script: skips become findings, directory skips are gone and the inline `malware-scan: allow` marker is dropped.

Shipped as of task 3.6 (text-side slice) in `rules/builtin/builtin_patterns.toml`, four rules with
`detector = "pattern"` and no code detector module: `pat-decode-eval` (HIGH),
`pat-invisible-unicode` (HIGH), `pat-exfil-endpoint` (WARN), `pat-obfuscator-id` (WARN). Each names
`roles = ["source", "tooling-config", "editor-autorun", "other"]`, which is where the coverage claim
lives: the old script's miss was not a wrong pattern but a wrong scope, since its only in-repo
consumer was an allowlist of five config filenames (`PRD.md` 2.3 item 7, Appendix B case 7). Naming
the roles in the rule data means a reviewer reads the claim and the rule reference generator (5.2)
can publish it, instead of a detector hardcoding a path list.

Residuals, stated rather than hidden:

- `doc` appears on no rule here. Prose describes payloads, and this repository's own `PRD.md` quotes
  the Appendix B case 7 string, so a rule reading `doc` would report a finding on every scan of a
  security tool's documentation. A loader named `README.md` therefore keeps its invisible characters
  and its endpoints from these rules; it also keeps an extension nothing executes, and
  `cfg-long-line` and `nul-in-text` still read the role.
- The severity tiers are a false-positive budget (risk R-2), not a ranking of harm. The two HIGHs are
  shapes with no innocent reading in a file that is code; a tool fingerprint and a single endpoint
  mention are WARN because each has a common legitimate form (a committed obfuscated bundle, a
  webhook URL in a test) and each only becomes the attack in combination with something that runs it.
  Combination rules over these roles are task 3.7.
- Raw-text matching, no comment or string masking (ADR-013), and `line_cap` still applies: an
  attacker who pads a payload line past the cap trades `pat-*` for a `cfg-long-line` finding, which
  is HIGH inside `SENSITIVE_ROLES` and WARN elsewhere (`rules._cap_severity`). Padding therefore
  costs the exit-code gate nothing it hides from the report.
- `pat-exfil-endpoint` is matched case-sensitively. A `(?i)` flag measured about ten times slower on
  the ReDoS harness's own near-miss bait for the same alternation (1.5 ms against 15 ms for `[a-z]`
  repeated to the cap), which is a per-line cost multiplied by every line of every code file. Hosts
  in code are lowercase almost always, and a shouty uppercase host is an evasion of a WARN rule
  rather than a miss worth that multiplier. `pat-decode-eval` keeps `(?i)` because the identifiers it
  names are camelCase by convention (`decodeURIComponent`, `Buffer.from`).

Measured worst case per cap-length line on the shipped bait set (CPython 3.14 locally, fresh
interpreter per pattern; the suite's own gate is `tests/unit/test_redos.py` against 60 ms):
`pat-decode-eval` 8.5 ms, `pat-exfil-endpoint` 9.8 ms, `pat-obfuscator-id` 1.3 ms,
`pat-invisible-unicode` 1.0 ms, all on the harness's repeated `[a-z]` line. CI runs 3.11 and asserts
the same bound.

Ported since, as task 3.6's second slice, in its own rule file and its own detector, because three of
the shapes need two conditions at once: see 9.7.

Not yet ported from the list above: credential harvesting, blockchain C2 shapes, `build.rs` network
and the native-binary rules. The last two belong with the Cargo work in 6.4; credential harvesting
and blockchain C2 have no rule, fixture or decision behind them yet, and are not guessed at here.

### 9.7 `ci_surface`

Applies to the three roles added for it (`workflow`, `package-manifest`, `install-hook`) plus
`editor-autorun`, which since this slice also resolves `.vscode/settings.json`. Raw text, no masking
(ADR-013), and no line past `line_cap` reaches any matcher in the family, including this detector's
own. There is still no YAML parser (ADR-007), so every rule here is line- or file-scoped over text.

Three rules are engine patterns in `rules/builtin/ci_surface.toml`: `pat-privileged-trigger` (WARN,
which names `pull_request_target` as a fact, because that trigger is how a comment bot is built and
only the pairing is the attack), `pat-lifecycle-fetch` (WARN, a client verb or an install-from-URL
argument in a lifecycle script or a hook) and `pat-editor-command-path` (WARN, a settings key that
points the editor at an interpreter or a compiler directory). Three are decided in
`src/airlock/detectors/ci_surface.py`, because each holds two conditions and one of them is not a
word on the line:

1. `pat-secret-dump` (HIGH): `${{ secrets.* }}` on a line that also names a command able to display
   it (`echo`, `printf`, `print`, `cat`, `tee`, `xxd`, `base64`, `Write-Output`, `Add-Content`,
   `Out-File`), with `::add-mask::` carved out because that one echo is hygiene. A secret handed to a
   step through `env:` or `with:` is the negative fixture rather than a finding; that is how a
   workflow uses a credential, and reporting it would bury the shape under noise.
2. `pat-ptr-head-checkout` (HIGH): the privileged trigger, a head ref
   (`github.event.pull_request.head`, `refs/pull/N/head`, `refs/pull/N/merge`) and an
   `actions/checkout` step in one file. Three conditions, because every pair of them has an innocent
   reading: `pull_request` with a head checkout is reviewed code in a read-only context, and
   `pull_request_target` that leaves the default base ref is the safe form. The trigger half is read
   out of `pat-privileged-trigger`'s own pattern, so the WARN and the HIGH cannot drift apart on what
   a privileged trigger is.
3. `pat-lifecycle-exec` (HIGH): a line that both fetches and hands the result to a shell or
   interpreter, which covers `curl ... | bash`, `... && python`, `| Invoke-Expression`,
   `bash <(curl ...)` and an `eval` of a fetched string. The fetch half comes from
   `pat-lifecycle-fetch`'s pattern for the same reason as above. Package-manifest pairing stays
   on one line because each script is a separate value. On an `install-hook` entry only, the
   detector also checks a forward window of three physical lines, including the fetch line. The
   finding is on that fetch line and names the first matching execution line. Both lines must be
   at or under `line_cap`; each fetch produces at most one finding.

Each pairing is two linear searches rather than one regex, because the obvious single pattern for the
dropper, a downloader then `.*` then a shell, restarts its `.*` at every column. That is quadratic in
the line length, and a 20,000 character line is the input an attacker chooses.

`cfg-network` and `cfg-network-exec` already catch the fetch-decode-evaluate shape inside a build
config. These rules are the same shape in the three files that family does not claim, plus the two
CI-only shapes it cannot express: the trigger pairing and the secret dump.

Everything here is `suppressible = true`, following `cfg-process-spawn`, whose dropper tier is also
HIGH and also suppressible. The reasoning is that a maintainer may need to accept a known
fetch-and-run with a written reason instead of being locked out of their own repository. The
non-suppressible set stays what the owner named it, which is the shapes with no legitimate reading.

Residuals, stated rather than hidden:

- A secret passed in through `env:` and printed by a script the workflow does not name is invisible
  here, and so is an `env:` block on one line with `echo $TOKEN` on the next. A padding line past
  `line_cap` trades these matchers for `cfg-long-line`, which is HIGH in these roles, so padding buys
  no silence in the report even when it buys it in a rule.
- `workflow_run`, `issue_comment` and a fork's reusable-workflow `on:` are not in the trigger
  pattern. All three are real vectors; none is the reported shape, and `pat-privileged-trigger` is a
  WARN whose value is that a reviewer reads the handful of files it names. Widening it is a corpus
  question for 3.7 and 0.10.
- A lifecycle script that fetches through a helper file (`"postinstall": "node scripts/install.js"`,
  which then downloads) is only caught if that helper file trips the text-side family.
- `cfg-long-line` names none of the three new roles in its own `roles` list, and this slice does not
  edit a shipped rule. The cap account does not need it: `rules.cap_findings` runs on every entry that
  has text whatever its roles, and the extension fallback keeps the text-side family reading these
  files as `source` or `other`. `tests/unit/test_ci_surface.py` pins both behaviors instead of leaving
  them to the reading of a comment.

Measured worst case per cap-length line on the harness's bait set (CPython 3.14 locally, a fresh
interpreter per pattern, against the same 60 ms bound `tests/unit/test_redos.py` asserts):
`pat-lifecycle-fetch` 4.3 ms, `pat-editor-command-path` 1.6 ms, `pat-privileged-trigger` 1.2 ms, and
for the detector's own matchers, which that harness now times next to the rule data because a code
rule's regex is the same ReDoS surface as a pattern rule's: `_DISPLAY_VERB` 4.8 ms, `_EXEC_TARGET`
1.5 ms, `_HEAD_REF` 0.7 ms, `_CHECKOUT_STEP` 0.06 ms, `_SECRETS_INTERP` 0.05 ms.

### 9.8 `npm_registry`

The detector reads tracked `package-lock.json` files as JSON and inspects `resolved` values from
lockfile versions 2 and 3 (`packages`) or version 1 (`dependencies`, recursively). Each HTTP(S)
tarball URL whose parsed host is not exactly `registry.npmjs.org` produces one
`npm-registry-bypass` HIGH with the package path and host. `git+`, `file:`, `link:`, `workspace:`
and other non-HTTP(S) sources are outside this rule. A malformed JSON document becomes
`detector-error`, not a clean result. The URL is parsed locally; nothing is fetched. Private
registries are not configurable yet and need a fingerprint-keyed suppression with a reason.

### 9.9 Deferred designs

- `deploy_gate`: text heuristics over workflow files cannot see deploys hidden in scripts, reusable workflows or `make` targets, so it would give false assurance. Reconsider only if a real repo deploys to mainnet from CI.
- SEP-58 metadata presence check and `wasmparse`: the SEP is not final and Colibri already verifies builds. [Verified: Colibri exists; Unverified: SEP final status]
- Watch mode, org scan, history scan, parser-based JS: see `ROADMAP.md` Phase 9.

## 10. Distribution: the composite Action

Design sketch for task 4.1, not a shipped `action.yml`. Task 0.8 verified the launch prefix
and the scan cases below, not the composite Action's environment setup or full input matrix.

```yaml
# action.yml (sketch)
name: airlock
description: Supply-chain scan for Stellar and Soroban repositories
inputs:
  fail-on: { default: "high" }
  config:  { default: "airlock.toml" }
runs:
  using: composite
  steps:
    - shell: bash
      env:
        AIRLOCK_EVENT:   ${{ github.event_name }}
        AIRLOCK_BASE:    ${{ github.event.pull_request.base.sha }}
        AIRLOCK_BEFORE:  ${{ github.event.before }}
        AIRLOCK_FAIL_ON: ${{ inputs.fail-on }}
        AIRLOCK_CONFIG:  ${{ inputs.config }}
      run: |
        python3 -I -c 'import sys; sys.path.insert(0, sys.argv.pop(1)); from airlock.cli import main; raise SystemExit(main())' "$GITHUB_ACTION_PATH/src" scan \
          --event "$AIRLOCK_EVENT" --base "$AIRLOCK_BASE" \
          --before "$AIRLOCK_BEFORE" --fail-on "$AIRLOCK_FAIL_ON" \
          --config "$AIRLOCK_CONFIG" --format github
```

Notes:

- `python3 -I -c` excludes the current directory and user site directory from its import path and ignores `PYTHONPATH`, so the trusted module path is passed through `argv`. The scanner code comes from `GITHUB_ACTION_PATH`, never from the scanned checkout. [Verified 2026-10-28: task 0.8 evidence below]
- The tool never fetches. The consumer's `actions/checkout` needs `fetch-depth: 0`, or enough depth to include the base; otherwise exit 2.
- User-influenced values reach the script through `env:`, never by interpolation into the shell.
- Consumers use `permissions: contents: read` and the full commit SHA.
- Consumers should make the check a **required status check**. Without it, a PR that deletes the workflow step simply never runs the scan. [Unverified: how GitHub treats a required check whose job no longer exists; task 4.5 tests it]
- Review Action SHA bumps by hand and do not auto-merge them (B12).
- An installed copy carries its own rule data. `pyproject.toml` force-includes `rules/` at `airlock/rules` in the wheel and `cli.rules_root` prefers that copy, falling back to `rules/` two levels above the package directory, which is the checkout layout `$GITHUB_ACTION_PATH` uses. Without the bundled data an installed `airlock scan` cannot scan: it exits 2 on a missing `roles.toml` rather than reporting nothing, and 5.7 measured that shape before fixing it.

### Task 0.8: observed isolation evidence

[Verified 2026-10-28 UTC] The [immutable scratch workflow](https://github.com/wagmiiii/airlock-isolation-probe/blob/3c569b5948ead2552993771949c1da75170567dd/.github/workflows/isolation.yml)
passed in [real PR run 40706458871](https://github.com/wagmiiii/airlock-isolation-probe/actions/runs/40706458871)
(14:29:36 to 14:29:48 UTC) and [dispatch run 40706400064](https://github.com/wagmiiii/airlock-isolation-probe/actions/runs/40706400064)
(14:29:14 to 14:29:26 UTC), both attempt 1. [Probe PR #1](https://github.com/wagmiiii/airlock-isolation-probe/pull/1)
retains the full reproduction and captured output. Trusted Airlock was pinned to
`17079ac7ad830deb2b31e991a84f849ee3074959` in a separate `trusted-airlock` checkout.
`GITHUB_ACTION_PATH` was **manually set** to that checkout; automatic composite Action setup
remains unverified until 4.1.

The runner was `ubuntu-latest`, Ubuntu 24.04.5 LTS, image `ubuntu-24.04`, agent `2.338.0`,
with CPython `3.11.17` at `/opt/hostedtoolcache/Python/3.11.17/x64/bin/python3`.
The setup header reported image version `20261012.334.1`; runtime reported
`ImageVersion=20261023.334.3` and `ImageOS=ubuntu24`. These differ in the logs; neither is
silently substituted for the other.

Every scanner invocation used the exact `python3 -I -c 'import sys; sys.path.insert(0, sys.argv.pop(1)); from airlock.cli import main; raise SystemExit(main())' "$GITHUB_ACTION_PATH/src" scan`
prefix shown in the sketch. Full scans appended `--mode full --format console .`;
PR scans appended `--event "$PROBE_EVENT" --base "$PROBE_BASE" --format console .`, with
inputs supplied through environment variables. The workflow asserted that `PROBE_BASE` equalled
the real event's `pull_request.base.sha`, `3c569b5948ead2552993771949c1da75170567dd`.

Benign shadow packages were staged under both `airlock/` and `src/airlock/` in the scanned
checkout, with `src/sitecustomize.py` and `src/usercustomize.py` marker/sentinel probes.
`PYTHONPATH` pointed at that checkout and its `src` directory. A separate isolated diagnostic
resolved `airlock.__file__` and `airlock.cli.__file__` to `trusted-airlock/src/airlock/__init__.py`
and `trusted-airlock/src/airlock/cli.py`, respectively. It asserted `isolated=1`,
`ignore_environment=1`, `safe_path=True`, `no_user_site=1`, `ENABLE_USER_SITE=False`, no cwd or
`PYTHONPATH` entries in `sys.path`, and no loaded file-backed module under the scanned cwd.
All captured stdout/stderr lacked the shadow marker, and the sentinel was absent. No shadow
module was executed and no non-isolated control was run.

| Observed case | Exit | Meaning (section 8) |
|---|---|---|
| Full scan in PR / dispatch | 0 / 0 | Completed below threshold: 0 HIGH, 0 WARN, 2 INFO; 8 / 7 files scanned, nothing skipped |
| Real PR base, full history | 0 | Completed below threshold: 0 HIGH, 0 WARN, 0 INFO; 8 files scanned, nothing skipped |
| Same PR base, deliberately shallow checkout | 2 | Configuration/usage error, not a passing scan; stdout empty |

The shallow target had exactly one reachable commit and lacked the base before and after the
scan. Its stderr was `airlock: base 3c569b5948ea is not reachable in this checkout. The workflow needs actions/checkout with fetch-depth: 0, or a depth that reaches the base commit.`
The scanner did not fetch. Codes 1 (findings at threshold) and 3 (internal error) were not
exercised by these benign cases. Task 4.1 remains open, including the composite Action and its
`push` event coverage.

## 11. Self-protection of the Airlock repo

- Every Action pinned by hash; top-level `permissions: contents: read`; write only on the release job.
- Rulesets: no force pushes, no deletion, required status checks; `CODEOWNERS` on `src/`, `rules/`, `action.yml`, `scripts/` and `.github/`.
- Maintainer accounts use hardware-key 2FA and a protected recovery email. These controls matter more than any code here.
- Releases carry build provenance attestations; the README documents the verification command.
- The tool scans itself. There is no `SELF` skip. Fixtures that intentionally trigger rules are built at test time, not committed.
- Scorecard runs on the repo; target 8 or higher.
- `scripts/check_roadmap_touched.sh` runs as a required check (section 17).

## 12. Testing strategy

- **Unit tests** for every module.
- **Fixtures:** every rule has one positive and one negative fixture, enforced inside the pytest suite. The rule file names its builders, so the gate can ask every shipped rule for both halves and fail on a missing one (`tests/unit/test_fixtures.py`, task 2.12).
- **Synthetic only.** Trigger strings are assembled at test time from fragments (for example `'ev' + 'al('`), handed to the scanner as already-collected files (path, bytes, roles, hash) and run through the engine pass and the whole detector registry. The repository never stores a live-looking payload. Wasm fixtures are minimal generated byte strings (`\0asm\x01\0\0\0` plus a trivial section). A temporary git repository is used only where the git state itself is under test (trusted base, bypass cases), because there the collector has to run for real.
- **Bypass regression tests:** the seven cases in `PRD.md` Appendix B, plus any later discovered evasion, each asserting fail-closed.
- **ReDoS timing test:** each pattern runs against adversarial inputs (long runs of a single character, nested repeats, the pattern's own literal fragments repeated and left as a near miss) at the length `line_cap` allows, and must finish within the budget. The measurement runs in a child process with a wall-clock limit, so a pattern that backtracks fails the suite instead of hanging it, and a canary pattern is asserted to breach the same budget.
- **Trusted-base tests:** a pushed commit that edits policy and adds a payload; a force push; a new branch; an unresolvable base.
- **Parity test:** old `malware_scan.py` versus the ported rules on a shared corpus; no lost findings.
- **Golden outputs:** JSON (and SARIF once it exists).
- **Corpus gate:** a clean-state snapshot of the six repos (`tests/corpus/`) must yield zero HIGH findings.
- **Self-scan test:** the Airlock repo passes its own scan in CI.
- **Roadmap gate test:** the script fails a diff that omits `ROADMAP.md` and passes one that includes it.

## 13. Architecture decision records

| ID | Decision | Reason | Cost |
|---|---|---|---|
| ADR-001 | Python standard library only, 3.11 or newer | Smallest supply-chain surface; existing code is Python | No YAML parser; hand-written TOML writer; Python version floor |
| ADR-002 | One repository | Solo maintainer; no second tool has a reason to exist yet | Rules and code release together |
| ADR-003 | Trusted base for policy: PR base in `pr`, pre-push SHA in `push` | A change must not approve its own findings, including a credentialed push | Bootstrap friction; new-branch pushes are weaker |
| ADR-004 | Fail closed on skips, errors and unreadable input | A green result must mean something | More findings to triage at first |
| ADR-005 | No inline suppressions; fingerprint-keyed, occurrence-aware, with a reason (also for retained `stellar_seed`, D-06) | Inline markers are an attacker's bypass manual | Slightly slower suppression flow; valid seed test vectors are not automatically exempt |
| ADR-006 | Rules are data, detectors are code, no plugins | Loading external code defeats the trust model | Contributors add rules via PR |
| ADR-007 | No YAML parsing in v0.1 | Avoid a runtime dependency | Workflow-aware rules are deferred |
| ADR-008 | SARIF deferred to P1 | Needs an extra permission and upload step; step summary and annotations suffice at first | Less code-scanning integration at launch |
| ADR-009 | Composite Action pinned by SHA, no Docker image | A container adds an unpinned layer and a registry trust hop | Depends on the runner's Python |
| ADR-010 | Wasm identified by magic bytes, never by extension | `.wasm` was silently skipped by the old gate | None material |
| ADR-011 | Soroban expectations from policy, not constants | Stellar docs disagree on size limit, target and SDK version | Defaults need maintenance |
| ADR-012 | Detect capabilities, not signatures | PolinRider rotated fingerprints but kept its mechanism | Higher false-positive risk; tiers and tuning needed |
| ADR-013 | No comment or string masking in `config_role` | A lexer that mis-tracks state hands attackers a hiding place; configs rarely contain `eval(` anywhere | Rare false positives, handled by suppression |
| ADR-014 | No default directory skips | Tracked `vendor/` and `dist/` were a hiding place | Slower on repos that track vendored trees |
| ADR-015 | Occurrence-aware fingerprints | A duplicate of a suppressed line must not inherit the suppression | Suppressions can need reissue after edits |
| ADR-016 | Soroban rules apply to contract crates only | Test-support libraries legitimately enable `testutils` | Needs `crate-type` detection |
| ADR-017 | Roadmap gate as a required CI check | The roadmap rots unless a machine enforces it | Friction on tiny PRs |
| ADR-018 | Line cap instead of regex timeouts | Python `re` cannot be interrupted safely mid-match | Lines over the cap are inspected only by length and entropy |
| ADR-019 | SARIF uses `partialFingerprints["airlock/v1"]` (D-09, 2026-10-28) | Match the Airlock name before output consumers can depend on a key; the fingerprint algorithm is unchanged | No migration needed because SARIF has not shipped; reporter implementation stays deferred to task 7.6 |
| ADR-020 | npm lockfile findings trust only `registry.npmjs.org` by default | A fixed host check is auditable and avoids adding an unreviewed policy field | Private registry users need an exact, reasoned suppression until host policy is designed |
| ADR-021 | Split-line fetch/exec pairing is limited to install hooks and three physical lines | Hook files are interpreted line-by-line by the detector, while package scripts are independent values; an unbounded window invents relationships | Hooks with a more distant handoff remain outside this rule and need separate evidence |

## 14. Roadmap

All remaining work, with task IDs, dependencies and exit criteria: `ROADMAP.md`.

## 15. Open technical questions

1. Resolved (0.8): `python3 -I -c` with the explicit trusted `sys.path` insert worked on `ubuntu-latest`, CPython 3.11.17, on 2026-10-28. Section 10 records the workflow, trusted origins and exits 0/0/2 for full/PR/shallow scans. Composite Action integration remains task 4.1, not part of this verification.
2. What are the real `tail_max_len` and `tail_entropy` values on the six-repo corpus? (3.3)
3. Can GitHub pin a required status check to a trusted source, and what happens when the job is deleted? (0.13, 4.5)
4. Verified (0.9, 2026-10-30): GitHub keeps the first 10 annotations of each level per step, caps a step summary at 1 MiB without failing the step, and takes a gzip-compressed SARIF file up to 10 MB with 5,000 results kept per run. Section 6.6 separates the documented numbers from the observed ones and records the probe runs. `merge_group` base reachability was not measured and stays open under 4.1.
5. Exact SEP-58 metadata keys and Soroban metadata section names. (0.11)
6. Resolver-2 feature behavior for `testutils` inherited via the workspace. (0.12)
7. Should watch mode exist? (decision D-04)

## 16. Red-team review

This is design-review analysis. Nothing here has been run. Every item is a hypothesis that should become a test or a task. GitHub-specific claims were marked [Unverified] until checked; task 0.9 measured the reporting limits on 2026-10-30 (section 6.6) and 0.13 remains open.

### 16.1 Ranking

Likelihood and impact are rough judgments (H, M, L).

### 16.2 What would break

| ID | Scenario | Why it breaks | L / I | Resolution | Task |
|---|---|---|---|---|---|
| B1 | A credentialed push edits `airlock.toml` and adds a payload in one commit | `push` and `full` modes read policy from HEAD, so the push approves itself. This is the PolinRider scenario | H / H | Push mode reads policy from `github.event.before`; non-ancestor `before` yields `history-rewritten` | 2.7, 4.5 |
| B2 | The attacker deletes or edits the workflow step that runs Airlock | A push-triggered run uses the workflow from the pushed commit, so it is attacker-controlled. A scheduled run uses the default branch file, also editable | H / H | Required status check for PRs; maintainer-account hardening; an external watcher that clones from outside and checks ancestry is the only detector the attacker cannot edit. Decision D-04 | 0.13, 4.5, 9.1 |
| B3 | A minified 5 MB single-line file | Regex rules can take quadratic time or worse and hang CI | M / M | `line_cap`, `cfg-long-line`, adversarial timing test per pattern | 2.5, 2.12 |
| B4 | The `testutils` rule fires on a test-support library | `soroban-budget-assert` plausibly needs `testutils` as a normal dependency, so dogfooding would fail on your own repo [Unverified: Cargo.toml not inspected] | H / M | Apply only to contract crates; profile rule only at the workspace root | 6.1, 6.5 |
| B5 | A suppressed line is duplicated elsewhere in the same file | Line-free fingerprints suppress the copy too | M / H | Occurrence-aware fingerprints | 2.6 |
| B6 | A payload is committed under `vendor/`, `dist/` or `node_modules/` | The old script and the first draft of this design skip those paths | M / H | No default directory skips; bypass test 7 | 2.2, 3.9 |
| B7 | Runner has Python older than 3.11, no `git`, or git `safe.directory` errors | Every repo goes red with an opaque exit 3 and users disable the tool | M / M | Startup checks with plain messages, exit 2 | 2.3 |
| B8 | A flood of WARNs buries a HIGH | GitHub keeps the first 10 annotations of each level per step and drops a step summary above 1 MiB without failing the step (0.9, 6.6) | M / H | HIGH first, caps one slot under the budget, every HIGH in the summary | 2.9, 7.10, 7.13 |
| B9 | New Wasm fixture fails its own PR | Base-ref manifest does not yet list it | H / M | Documented two-step flow; revisit if adoption suffers | risk register |
| B10 | Suppression expiry turns CI red on a date | Users learn to bulk-extend | M / L | Optional `expires`, 30-day warning, only that finding returns | 2.8, 7.11 |
| B11 | Evidence text injects markdown or annotation syntax | Evidence is a line of attacker-controlled code | M / M | Fenced evidence with safe fence length; escaped annotations | 2.9 |
| B12 | Consumers auto-merge bot bumps of the Action SHA | A compromised Airlock release would propagate | L / H | Attested releases; document manual review of SHA bumps | 5.3 |
| B13 | UTF-16 config files trip `nul-in-text` | NULs appear in every other byte | L / L | BOM detection and decoding | 2.2, 7.3 |
| B14 | Policy schema changes between Action versions | Old policy files fail on new releases | M / L | `version` field; unknown keys WARN | 2.1, 2.7 |
| B15 | The force-push workflow template | It runs from the attacker's workflow, so it protects nothing against a credentialed push | M / L | Removed; `history-rewritten` covers the detectable case | 2.7 |

### 16.3 Edge cases missing from the first draft

| Area | Case | Decision |
|---|---|---|
| Git | Submodules (gitlinks) | INFO in v0.1; hardening P1 (7.2) |
| Git | LFS pointer files in place of Wasm | Report in v0.1 as unverifiable; manifest check by pointer hash P1 (7.1) |
| Git | Shallow clones, sparse checkout, missing base | Exit 2 with a message (2.3) |
| Git | Paths with spaces, quotes, newlines | Use `-z` throughout; test (2.2) |
| Git | Case-insensitive duplicate paths | Test; low priority (7.8) |
| Events | Fork PRs, `merge_group`, tag pushes, first commit, base equals head, base not an ancestor | Test matrix (7.9) |
| Files | Empty files, CRLF, BOM, UTF-16, non-UTF-8 | Handled in the collector (2.2, 7.3) |
| Files | Symlinks to paths outside the repo | Never followed (2.2) |
| Config role | `next.config.ts`, `vite.config.*`, `webpack.config.*`, `jest.config.*`, `svelte.config.js`, `astro.config.*`, `.eslintrc.*`, `.babelrc.*`, `prettier` and `commitlint` configs | P1 globs, each reviewed for false positives (7.4) |
| Config role | Hooks and lifecycle files run by tools: `.husky/*`, `.devcontainer/devcontainer.json`, composite `action.yml`, `Makefile`, `justfile` | Evaluate for P1 (7.5) |
| Config role | Legitimate configs that fetch or spawn at build time | Network alone is WARN; combination is HIGH (3.1) |
| Wasm | Wasm embedded as base64 in TS or Rust (`include_bytes!` is a path, base64 is a string), `.wasm.gz`, `.optimized.wasm` variants | `long-line`, archive and manifest rules cover part; document the gap (7.1) |
| Wasm | Same Wasm at several paths; rebuilt fixtures with new hashes | Hash-keyed manifest; rebuild friction accepted |
| Cargo | Dependency rename (`package = "soroban-sdk"`), target-specific dependency tables, legacy `.cargo/config` (no extension), nested workspaces, proc-macro crates running code at compile time | Handle rename and legacy name; proc-macros are undetectable, documented (6.1, 6.4) |
| Seeds | Testnet seeds in tests and docs; seeds split across lines, encoded or hex-encoded; mnemonic phrases; seeds in git history | Suppressible with reason; encoded forms and history are documented gaps (6.3) |
| Suppressions | Duplicate evidence lines; expiry; reissue after edits | Occurrence index; expiry warning (2.6, 2.8) |
| Reporting | Huge finding counts, SARIF size limits, summary size, annotation caps | Severity-first order, caps (2.9, 7.6, 7.10) |
| Platform | Windows runners, path separators, `core.quotepath`, locale | Test (7.8) |
| Time | Expiry compared in local time | Compare UTC dates only (2.8) |

### 16.4 What is overengineered

| ID | Item | Verdict | Reason |
|---|---|---|---|
| O1 | `jsmask.py` comment and string masking lexer | Cut | JavaScript lexing is hard (regex literals, nested templates). A bug hides code from the scanner. Configs rarely contain `eval(`, so raw text matching costs little |
| O2 | SARIF in v0.1 | Defer to P1 | Needs `security-events: write` and an upload step. Summary and annotations serve a solo maintainer |
| O3 | `init` command | Cut | A README snippet does the same job |
| O4 | `rules test` CLI command | Cut | The pytest suite enforces fixtures |
| O5 | `deploy_gate` | Defer | Heuristic over files, misses scripts and reusable workflows, and no in-scope repo deploys from CI |
| O6 | `wasmparse.py` and the SEP-58 metadata check | Defer | SEP not final; Colibri already verifies builds |
| O7 | Suppression `owner` field | Cut | Git history records authorship |
| O8 | `read_policy_from` and `roles.overrides` policy fields | Cut | The first is fixed by mode, the second has no user |
| O9 | A separate suppressions file | Merge | Three base-ref reads become two |
| O10 | JSON schema files | Cut | Validate in code; schemas can be generated later |
| O11 | Force-push workflow template | Cut | Attacker-controlled (B15) |
| O12 | `hypothesis` fuzzing | Cut | Only needed for the Wasm parser, which is deferred |
| O13 | Detector Protocol and registry object | Simplify | A list of functions is enough |
| O14 | Porting every builtin rule before shipping | Phase | HIGH rules first, WARN rules after (3.6, 3.7) |
| O15 | PyPI distribution, org scan, history scan, parser-based JS | Defer | Backlog, no design needed now |

Not overengineered, but under-built: an **external watcher** (D-04). It is the only design that survives a stolen credential, and it can start as one scheduled job in a separate repository that clones public repos, runs the scan and refuses any non-fast-forward update to the last seen SHA. [Likely] That claim stays a hypothesis until built.

### 16.5 Net effect

- P0 moves from 13 broad requirements to 15 narrower ones: SARIF, `init`, the `rules test` command and the SEP-58 check moved out; the trusted base, no-skips, ReDoS bound and roadmap gate moved in.
- Two design flaws are fixed (B1, B6). One open risk is explicit (B2).
- The first release needs fewer parts: no lexer, no SARIF, no WASM parser, no `init`.

## 17. Documentation and roadmap maintenance rule

`ROADMAP.md` must be updated on every contribution (code, rules, tests, docs, CI, configuration, dependency bumps, reverts), by humans and agents alike. The same pull request must tick, untick or add the affected tasks, add a changelog entry, and refresh the progress table and `Last updated` line. Enforcement is `scripts/check_roadmap_touched.sh` in CI plus a PR template checkbox (task 1.9); until then, reviewers enforce it. Changes to behavior described here must also update `PRD.md`, `ARCHITECTURE_ESSENTIALS.md` and `project_structure.md` in the same PR.
