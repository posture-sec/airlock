# PRD: Airlock

| | |
|---|---|
| Status | Draft v0.2 (red-team revision) |
| Date | 2026-10-27 |
| Owner | Ademola |
| Name | Airlock |
| Repository | https://github.com/posture-sec/airlock (public, Apache-2.0, default branch `main`) |
| Companion docs | `ARCHITECTURE.md`, `ARCHITECTURE_ESSENTIALS.md`, `ROADMAP.md`, `project_structure.md`, `AGENTS.md`, `CLAUDE.md` |

Conventions: **[Verified]** means checked against a source during research. **[Unverified]** means believed but not checked, or untested. Every Unverified item is listed again in section 12 so none of them silently becomes a requirement.

> **Roadmap rule (every contribution):** any change to this repository, by a human or an agent, must update `ROADMAP.md` in the same pull request: tick or add tasks, add a changelog entry, refresh the progress table and the `Last updated` line. See section 14.

---

## 1. Summary

Airlock is a command-line scanner and GitHub Action that audits Stellar and Soroban open-source repositories for supply-chain compromise and release-integrity gaps.

It has two layers:

1. A generic injection scanner aimed at the PolinRider class of attack: malicious loaders appended to build configuration files, editor auto-run tasks, and hidden payloads.
2. Soroban-aware rules that generic scanners do not have: release-profile hygiene, Wasm artifact integrity, Stellar secret-key leakage, and mainnet deploy gating.

It runs from a pinned, attested copy that lives outside the repository it audits, so a PR (or a stolen maintainer credential) cannot quietly edit the scanner.

## 2. Problem

### 2.1 The threat

PolinRider is a real, documented campaign against GitHub repositories. [Verified: OpenSourceMalware reports]

- Attackers gain access through account compromise or recovery abuse, then add obfuscated JavaScript to repositories that runs through developer tooling when a project is opened.
- The payload is fetched from accounts on TRON, Aptos and BSC, decrypted with XOR and executed with `eval()`.
- The loader is appended to the end of build config files such as `postcss.config.mjs`, `tailwind.config.js`, `eslint.config.mjs`, `next.config.mjs` and `babel.config.js`.
- Git history is rewritten with backdated force pushes, so the visible commit log cannot be trusted.
- The campaign farms the accounts of job-seeking developers, and its obfuscator fingerprints have already been rotated while the architecture stayed the same.
- Reported scale: 4,367 repositories across 2,152 owners as of July 9, 2026.

The author of this PRD has been told by peers that Drips Wave maintainers were affected. [Unverified: no public source found tying the campaign to Drips maintainers specifically]

### 2.2 What existing tools leave open

Scorecard reports were run on five repositories (Tollcraft: `soroban-budget-assert`, `soroban-cost-linter`; Accensa: `accensa-app`, `accensa-contracts`, `x402-facilitator-stellar`). [Verified: reports dated 2026-10-26]

- Scorecard findings are mostly generic hygiene: Token-Permissions is 0 on all five, Pinned-Dependencies ranges from 1 to 6.
- Branch-Protection errored on four of five (token limitation); the fifth scored 3 with no required approvers.
- Scorecard does not join its own findings. Example: `soroban-cost-linter` `nightly-bump.yml` has top-level `contents: write` and unpinned third-party actions in the same workflow.
- `accensa-contracts` has release v0.2.0 with no signature and no provenance, and no packaging workflow. The repo holds receipt anchoring and a refund vault.
- Committed `.wasm` fixtures (`exports_min.wasm`, `smart_account.wasm`) are flagged as generic binaries with no integrity record.
- The same two advisories (RUSTSEC-2026-0387, RUSTSEC-2024-0436) appear in all four Rust repos, with no reachability or ownership information.

### 2.3 What the current in-repo gate leaves open

Each of the five repos runs `.github/workflows/malware-scan.yml` with `.github/scripts/malware_scan.py`. It is good work (about eight detector types Scorecard lacks), but a review found these weaknesses. Verified 2026-10-27: items 1, 2, 3, 5, 6 and 7 were each executed as a commit in a scratch repository with the real script copied in, and all six exit 0, which means the job passes (`run: python3 -I .github/scripts/malware_scan.py`, no `continue-on-error`). Item 4 is a property of where the files live, not of a rule, so it is confirmed by reading the workflow: the scan step is checked out from the PR's own head, and the allowlist and the scanner are in the tree it reads. The harness is `scripts/bypass_probe.py` (`--script` pointing at the external copy), and the detailed observations are in Appendix B. Airlock's fail-closed regressions for the same shapes live in `tests/bypass/` (task 3.9), where cases 1 to 5 and 7 run and case 6 is a skip naming 6.4.

1. Wasm files are skipped silently because they begin with a NUL byte and `.wasm` is not in the binary extension list. **Confirmed**: `\0asm` puts a NUL in the first 4 KB, which the size/NUL test treats as binary noise and drops the file without a finding, and `.wasm` is absent from the extension list, so nothing else claims it either.
2. Any text file containing a NUL byte in its first 4 KB, or larger than 5 MB, is skipped silently. **Confirmed**: `// <NUL>` plus a decode-and-eval line yields zero findings, and `node --check` still accepts that file, so the NUL costs the scan and not the payload.
3. `.github/malware-scan-allow.txt` uses `fnmatch`, so a single `*` line can disable the scan; the inline `malware-scan: allow` marker exempts any line from any rule. **Confirmed for both halves**: a one-line `*` allowlist hides a `Buffer.from` decode-and-eval in `loader.js`, and the same payload with the marker in its own line is exempt with no rule change.
4. The scanner and its allowlist live inside the tree being scanned, so a PR or a credentialed attacker can edit them. **Confirmed by inspection** (see the note above): the step is checked out from the head under scan, and the script even excludes its own path from the scan, so a rewrite of the rule table is both possible and invisible.
5. The key PolinRider behavior (decode, then `eval`) scores only WARN unless it uses a literal `eval(atob(` style form. **Confirmed**: `eval(decrypted)` in `postcss.config.mjs` produces one WARN and zero HIGH, and only HIGH affects the exit code.
6. No rule for Cargo-specific execution vectors, and no rule for `.cargo/config.toml`. **Confirmed**: a `runner = ["sh", "-c", …]` build runner is not read by any rule and exits 0.
7. Tracked files under `node_modules/`, `target/`, `dist/`, `.next/` and `vendor/` are skipped entirely, so a payload committed in any of those directories is never inspected. **Confirmed**: the same decode-and-eval under `vendor/thing/` exits 0.

### 2.4 Why this needs to be Stellar-specific

The generic half competes with existing products (OpenSourceMalware, Socket, StepSecurity) and has no Stellar advantage. The Soroban half does: contract release profile, Wasm provenance, Stellar secret seeds, mainnet deploy gating and SEP-58 awareness are all checks nobody else runs against Stellar repos. [Unverified: no exhaustive search for existing Soroban-specific hygiene tooling was done; do a 30-minute GitHub search before committing]

## 3. Users

### 3.1 Primary: the Stellar open-source maintainer

- Solo developer or team of 2 to 5, building Soroban contracts, SDK tooling, facilitators or Next.js frontends.
- Participates in SCF, Drips Wave or similar grant and bounty programs, so contributors and reviewers inspect the repo.
- Repos mix Rust and JavaScript. No security staff.
- Wants: a one-time setup, no false-positive churn, evidence to show reviewers, and protection from the PolinRider pattern without becoming a security engineer.

Jobs to be done:

- "Tell me if my repo, or a PR to it, contains something that looks like a loader or hidden payload."
- "Tell me if a release artifact or committed Wasm cannot be traced to source."
- "Stop me from committing or deploying with a Stellar secret key in the wrong place."
- "Give me one badge or report I can show a grant reviewer."

### 3.2 Secondary

- **Program reviewers** (SCF, Drips Wave maintainers): read the scan report to judge a repo's hygiene.
- **Contributors**: see actionable findings on their pull requests.

### 3.3 Not for

Closed-source enterprise pipelines, non-Stellar chains, runtime or on-chain monitoring, and smart-contract logic auditing (Scout, Sunbeam, Komet and similar tools cover that).

## 4. Goals and non-goals

### Goals

- G1. Catch the PolinRider class of attack by structure, not by signature.
- G2. Make Wasm artifacts in Stellar repos traceable: listed, hashed, and (where available) carrying build metadata.
- G3. Provide Soroban-aware release and deploy checks that run with zero configuration.
- G4. Be hard for the audited repo (or an attacker holding its credentials) to switch off silently.
- G5. Be installable in under five minutes and quiet enough to leave on.

### Non-goals

- Contract logic or vulnerability analysis.
- Rebuilding or verifying Wasm reproducibly (Colibri, the Runtime Verification service and `stellar contract build --verifiable` are better-resourced; Airlock only checks presence and consistency of the evidence).
- Replacing Scorecard. Airlock complements it and does not duplicate its generic checks.
- Defending against an attacker with full admin control of the repository and its settings. No in-repo tool can; hardware-key 2FA, a protected recovery email and sandboxed handling of untrusted code do that work.
- Dependency vulnerability scanning (cargo-audit, cargo-deny and OSV-Scanner exist). Airlock may consume their output later.

## 5. Product principles

1. **Fail closed.** If the tool cannot inspect something, that is a finding. It never reports green because it looked away.
2. **Structure over signature.** Rules describe capabilities (a config file doing network I/O) rather than strings that attackers rotate.
3. **The scanner sits outside the scanned tree.** Pinned by commit SHA, attested at release, never executed from the PR checkout.
4. **Policy cannot approve itself.** In PR mode, suppressions and manifests come from the base ref.
5. **No inline escape hatches.** Suppressions are fingerprint-keyed, owned, and expiring.
6. **Explain every finding.** Each finding states the rule, the evidence and how to resolve it.
7. **Offline and dependency-free by default.** No network calls during a scan; no runtime dependencies in v0.1.
8. **Rules are data, detectors are code, third-party code never runs.**

## 6. Product requirements

Priority: **P0** ships in v0.1.0, **P1** in v0.2.0, **Later** is backlog (`ROADMAP.md`, Phase 9). The first draft had 13 P0 requirements. The red-team pass (section 13) cut or deferred several and added the ones that close real holes.

### 6.1 Functional requirements

| ID | Requirement | Priority | Acceptance criteria |
|---|---|---|---|
| FR-01 | Scan modes: `pr` (HIGH over the whole tree, WARN only on files changed vs base), `push` (same, against the pre-push SHA), `full` (local or manual) | P0 | Runs on `pull_request`, `push` and `workflow_dispatch` in the six repos |
| FR-02 | File roles by glob, plus content magic for Wasm and native binaries | P0 | A renamed `.wasm` still resolves to role `wasm` |
| FR-03 | `config_role` detector with tiered `cfg-*` rules (6.2) | P0 | All positive fixtures detected; zero HIGH on clean configs in the six repos |
| FR-04 | `wasm_manifest` detector with a hash-keyed manifest (6.2) | P0 | Unknown hash, hash mismatch, moved path and stale entry each reported; `.wasm` never silently skipped |
| FR-05 | Fail closed on anything not fully inspected: oversize, unreadable, NUL in text, non-UTF-8 in sensitive roles, lines over the cap, missing `git`, Python older than 3.11 | P0 | Each of the seven bypass tests in Appendix B fails closed; startup errors exit 2 with a plain message |
| FR-06 | Trusted base for policy and manifest: PR base in `pr` mode, `github.event.before` in `push` mode; an unreachable or non-ancestor `before` yields `history-rewritten` (HIGH) | P0 | A push that edits the policy and adds a payload in one commit is judged by the old policy |
| FR-07 | Suppressions inside `airlock.toml`: `rule`, `path`, `fingerprint`, `reason` required, `expires` optional; occurrence-aware fingerprints; some rules non-suppressible | P0 | A duplicated suppressed line is not suppressed; expiry warns 30 days ahead |
| FR-08 | Port builtin rules from `malware_scan.py` as data rules, HIGH rules first | P0 | Parity test: no lost findings on the shared corpus |
| FR-09 | Reporters: console, GitHub annotations, JSON, step summary; HIGH first, capped, evidence sanitized | P0 | A flood of WARNs cannot push a HIGH out of the output |
| FR-10 | Exit codes: 0 pass, 1 findings at or above `fail_on`, 2 config or usage error, 3 internal error | P0 | A detector exception yields a HIGH `detector-error` and exit 1 |
| FR-11 | Composite GitHub Action, pinned by SHA, read-only token, no secrets | P0 | Works under `permissions: contents: read` |
| FR-12 | `manifest add` and `manifest check` | P0 | Adding a fixture is one command |
| FR-13 | Every rule has a positive and a negative fixture, enforced by the pytest suite (no separate `rules test` command) | P0 | The suite fails when a rule lacks fixtures |
| FR-14 | ReDoS bound: lines over `line_cap` skip regex rules and raise non-suppressible `cfg-long-line`; every pattern passes an adversarial timing test | P0 | No scan exceeds the runtime target on a 5 MB single-line file |
| FR-15 | Roadmap gate: `scripts/check_roadmap_touched.sh`, PR template checkbox and a required CI check | P0 | A PR that changes any file but not `ROADMAP.md` fails |
| FR-16 | `soroban_profile`, contextual to contract crates | P1 | No false positive on a test-support library crate |
| FR-17 | `stellar_seed`: offline, checksum-valid plaintext Stellar seeds in tracked files (D-06: KEEP, owner-approved 2026-10-28 UTC) | P1 | Canonical 56-character seeds detected within collector and line limits; invalid checksum, version or length rejected. Valid test vectors also detected unless explicitly suppressed with a reason. No funding or live-use inference. Implementation remains tasks 6.2 and 6.3. |
| FR-18 | `cargo_vectors` | P1 | Fixtures pass |
| FR-19 | SARIF 2.1.0 output (deferred to task 7.6) | P1 | Validates against the schema; result count capped; uses `partialFingerprints["airlock/v1"]` (D-09, ADR-019), settled before shipping with no migration needed |
| FR-20 | Git LFS pointer and submodule handling | P1 | LFS-stored Wasm is checked against the manifest or reported |
| FR-21 | Extended config globs and vector roles (`vite`, `webpack`, `jest`, `.husky/*`, `devcontainer.json`, composite action files) | P1 | False-positive review on the six repos |
| FR-22 | Watch mode: scheduled scan from a separate trusted repository, with an ancestry check against the last seen SHA | Later (decision D-04) | See ARCHITECTURE.md 16.2, item B2 |
| FR-23 | Org scan and workflow-drift report | Later | |
| FR-24 | History scan of reflog and unreachable objects | Later | |
| FR-25 | Parser-based JavaScript analysis | Later | |
| FR-26 | SEP-58 metadata presence check | Later | After the SEP is final and keys are confirmed |
| FR-27 | `deploy_gate` | Later | Only if a real repo deploys to mainnet from CI |
| FR-28 | Release-provenance and workflow-combination rules | Later | |
| FR-29 | PyPI distribution | Later | |

### 6.2 Detector catalog

**`config_role`** (role `tooling-config`). Rules run on raw text. There is no comment or string masking, because a mis-tracking lexer would hand an attacker a way to hide code (see 16.4, O1).

| Rule | Capability | Severity |
|---|---|---|
| `cfg-dynamic-code` | `eval`, `Function`, `new Function`, `vm.runIn*` | HIGH, not suppressible |
| `cfg-network-exec` | network capability and (process spawn, dynamic code or `require()` of a non-literal) in the same file | HIGH |
| `cfg-network` | `fetch`, `http(s).request`, `WebSocket`, `net.connect`, URL literal, alone | WARN |
| `cfg-process-spawn` | `child_process` import: WARN; HIGH if the command is non-literal or contains `curl`, `wget`, `powershell`, `sh -c`, `base64`, `node -e` | tiered |
| `cfg-chain-endpoint` | RPC hosts for TRON, Aptos and BSC | HIGH |
| `cfg-appended-tail` | last non-empty line over `tail_max_len`, or a high-entropy blob near the end | HIGH |
| `cfg-long-line` | a line over `line_cap`: regex rules skipped for that line | HIGH in `tooling-config`, WARN elsewhere |
| `cfg-nul` | NUL byte in a text config (after UTF-16 BOM handling) | HIGH |

Network alone is WARN because some legitimate Next.js configs fetch at build time (for example for redirects). [Unverified: stated from general knowledge of Next.js; confirm on the real corpus]

**`wasm_manifest`**. Manifest entries are keyed by SHA-256 and list the paths that may hold that hash.

| Rule | Condition | Severity |
|---|---|---|
| `wasm-unlisted` | tracked file with `\0asm` magic whose hash is not in the manifest | HIGH |
| `wasm-hash-mismatch` | path is listed under hash A but the file hashes to B | HIGH |
| `wasm-path-moved` | hash is listed, path is not | WARN |
| `wasm-manifest-stale` | entry whose file no longer exists | WARN |
| `wasm-archive-skipped` | archive present, contents not inspected | WARN |

**`soroban_profile`** (P1). The release profile in the Stellar-ecosystem example sets `opt-level = "z"`, `overflow-checks = true`, `debug = 0`, `strip = "symbols"`, `debug-assertions = false`, `panic = "abort"`, `codegen-units = 1`, `lto = true`. [Verified: Stellar docs and a Chainlink Stellar tutorial] Applies only to contract crates (`crate-type` includes `cdylib`) and only to the workspace root manifest, because Cargo ignores profiles in non-root manifests. [Verified: Cargo behavior] Missing or false `overflow-checks` is HIGH, other deviations WARN. `testutils` under `[dependencies]` of a contract crate is HIGH. It is not flagged in library crates: `soroban-budget-assert` is a test-support library and plausibly needs `testutils` as a normal dependency. [Unverified: Cargo.toml not inspected]

**`stellar_seed`** (P1, planned). D-06 retains offline detection of checksum-valid plaintext Stellar seeds in tracked files, including tests and docs. Require canonical uppercase Base32, 56 characters with `S` prefix, 35 decoded bytes, version `0x90`, a 32-byte seed and a little-endian CRC16-XMODEM checksum over the first 33 bytes. [Verified: source inspection, 2026-10-28 UTC; pinned SEP-0023 and `stellar/go` references in `ARCHITECTURE.md` 9.4.] Checksum-valid test vectors are not exempt: validity says nothing about funding, live use or testnet use. Findings remain suppressible with a reason through the existing trusted-base, occurrence-aware mechanism. No assignment context or entropy threshold is required. Collector limits and `line_cap` still apply; word-character adjacency can prevent a regex match. Split strings, other encodings, hex seeds, mnemonics and history are outside this detector's scope. Reference-derived tests and implementation remain tasks 6.2 and 6.3; no network or live-key verification during a scan.

**`cargo_vectors`** (P1). `.cargo/config.toml` `runner`, `linker` or `rustc-wrapper` containing a shell; custom `build = "<path>"`; git dependencies without `rev`; `[patch]` or `[replace]` to git or path sources; `build.rs` network or shell capability.

**Deferred detectors:** `deploy_gate` (heuristic, no repo in scope deploys from CI), SEP-58 metadata presence (SEP not final), advisory triage (cargo-audit and cargo-deny own detection).

### 6.3 CLI

```
airlock scan     [path] [--mode pr|push|full] [--event <name>] [--base <sha>] [--before <sha>]
                    [--config <path>] [--wasm-manifest <path>]
                    [--fail-on info|warn|high] [--format console|json|github] [--output <path>]
                    [--rules-dir <path>] [--roles <path>]
airlock manifest add <path>… --origin built|vendored|generated --source <text>
                    [--build <text>] [--note <text>] [--repo <path>]
                    [--wasm-manifest <path>]
airlock manifest check [path] [--wasm-manifest <path>] [--config <path>]
                    [--rules-dir <path>] [--roles <path>] [--format …] [--output <path>]
```

`--event` is how the Action passes `github.event_name`, and it implies a mode: `pull_request` to `pr`, `push` to `push`, `workflow_dispatch` and `schedule` to `full`. An event that is not one of those four is a usage error rather than a default, because picking a trust model silently is the bypass B1 is about. Giving both `--event` and a contradicting `--mode` is also a usage error.

`--rules-dir` and `--roles` point at the rule data that shipped with the tool, which is what the Action does with `$GITHUB_ACTION_PATH`. They exist so a source checkout and a test can name a copy explicitly; a scanned repository's own `rules/` is never a valid argument, and `fail_on`, `--format` and the step summary are all this command writes.

`manifest add` (task 3.5) records artifacts by hash and writes the manifest with a hand-written canonical writer, because the standard library reads TOML and does not write it. It refuses with exit 2 rather than degrade: a file without Wasm magic (so a git LFS pointer is not recorded as an artifact), a target or manifest path outside the repository, an artifact over `max_file_bytes`, missing provenance (`--source` always, `--build` when `origin = "built"`), and a manifest whose entry region holds comments or unknown keys that a writer emitting from parsed data would lose. It stages and commits nothing: `wasm-manifest.toml` is a protected path, so the operator lands that diff in its own pull request before the one that adds the files (FR-06). `manifest check` is the scan pipeline with the report narrowed to the `wasm-` rules, so its exit code follows `fail_on` instead of a threshold of its own, and one set of artifact accounting answers the question in both commands.

No `init` command: the README carries a copy-paste workflow snippet. No `rules test` command: the pytest suite does that job.

### 6.4 Configuration files (user-owned, in the audited repo)

- `airlock.toml`: `version`, policy settings, Soroban expectations and suppressions.
- `wasm-manifest.toml`: Wasm inventory.

Field definitions are in `ARCHITECTURE.md` section 7.

## 7. Non-functional requirements

- **Determinism:** same inputs, same findings, same order (severity first, then path, line, rule).
- **Performance:** target under 30 seconds for the largest of the six repos on a standard GitHub runner. [Unverified: unmeasured target]
- **ReDoS bound:** a line past `line_cap` never reaches a regex, so the bound is per cap-length line: every pattern the scanner runs against attacker text must finish one 20 000-character adversarial line within 60 ms in the test suite. Measured (task 2.12): the rule-data patterns worst at about 10 ms, `config_role`'s dangerous-command test at about 20 ms, and 1 MB of adversarial text through the whole engine at about 440 ms. Each measurement runs in a child process, so a pattern that backtracks fails the suite instead of hanging it. [Measured 2026-10-27: one machine, one run per pattern]
- **Offline:** no network access during a scan, no telemetry.
- **Runtime dependencies:** none in v0.1 (Python standard library only; Python 3.11 or newer).
- **Tool supply chain:** the Airlock repository passes its own scan, pins every Action by hash, uses top-level read-only permissions, publishes release attestations and targets a Scorecard score of 8 or higher. [Target, unmeasured]
- **Noise budget:** zero HIGH findings on the clean state of the six repos at release.
- **Safe fixtures:** test samples are synthetic and assembled at test time so the repository contains no live payloads.
- **Roadmap currency:** `ROADMAP.md` reflects reality after every merged change (section 14).

## 8. Success metrics

| Metric | Target |
|---|---|
| Positive fixture detection | 100% |
| Bypass tests (Appendix B) failing closed | 7 of 7 |
| HIGH false positives on the six repos at release | 0 |
| Parity with `malware_scan.py` on the shared corpus | no lost findings |
| Install to first green scan | under 5 minutes |
| Scorecard score of the Airlock repo | 8 or higher |
| Merged PRs that left `ROADMAP.md` untouched | 0 |
| Adoption | the six own repos first; then external Stellar repos (number set after launch) |

## 9. Milestones

No calendar dates are promised. Phases, tasks and exit criteria live in `ROADMAP.md`.

- **v0.1.0:** Phases 0 to 5 (decisions, bootstrap, core, P0 detectors, Action and dogfood, release).
- **v0.2.0:** Phases 6 to 8 (Stellar detectors, hardening, release and community).
- **Backlog:** Phase 9, including the watch-mode decision.

## 10. Risks and mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Config-role false positives on legitimate configs | High | Capability tiers, corpus-tuned thresholds, fingerprint suppressions |
| Determined attacker evades regex heuristics | Certain over time | Goal is to catch mass-campaign variants and raise cost; parser analysis is Later |
| Attacker with push access removes or edits the workflow that runs the scanner | Certain | Required status check, base-ref policy, and (decision D-04) an external watcher; see ARCHITECTURE.md B2 |
| Push-mode policy read from HEAD lets a credentialed push approve itself | Was a design flaw | Fixed: push mode reads policy from `github.event.before` (FR-06) |
| Bootstrap friction: a new Wasm fixture fails until the manifest change merges | High | Documented two-step flow; revisit if adoption suffers |
| Narrow market (Stellar only) | Medium | Keep the generic layer valuable; track adoption honestly |
| Generic half duplicates existing products | Medium | Do not market the generic half as novel |
| Solo-maintainer burnout and rule rot | Medium | Small rule set, mandatory fixtures, no scope growth before v0.1.0 ships |
| Consumers auto-merge bot bumps of the pinned Action SHA | Medium | Document manual review of SHA bumps; releases are attested |
| SEP-58 and `--verifiable` change under us | Medium | No SEP-58 dependency in P0 or P1 |
| Docs inconsistencies (contract size limit, build target, SDK versions) | Certain | Never hardcode limits, targets or versions; read from policy |
| Name collision: other security products and libraries use the word "airlock" [Unverified] | Medium | Task 0.15 before the first release; the `posture-sec` namespace and the Stellar-specific description reduce confusion |
| The `posture-sec` org plan may lack some ruleset or org-level required-workflow features [Unverified] | Low | Task 0.16; fall back to repository rulesets and a required status check; strengthens the case for decision D-04 if gaps remain |

## 11. Open questions

1. Resolved 2026-10-27: name Airlock, repository `posture-sec/airlock` (decisions D-01, D-03). Because it sits outside the Tollcraft repositories, it likely needs its own Drips Wave application if you want Wave coverage. [Unverified]
2. Resolved 2026-10-27: Apache-2.0 (the `LICENSE` file already in the repository; decision D-02). The Tollcraft and Accensa repos mix MIT and Apache-2.0, so dogfooding crosses licenses, which is fine for scanning.
3. Resolved 2026-10-27 (task 0.4): all seven bypasses are real. Each case was run as a commit in a scratch repository against the real script and every one exits 0, which passes the job; `scripts/bypass_probe.py` reproduces it and Appendix B records what each case produced.
4. Resolved 2026-10-28 UTC (task 0.7, D-06): **KEEP**, approved by the owner. At the pinned revisions cited in `ARCHITECTURE.md` 9.4, Gitleaks has 222 rules and no dedicated Stellar/StrKey checksum detector; `generic-api-key` may incidentally match via keyword/assignment context and entropy >= 3.5. TruffleHog has no dedicated Stellar detector; `privatekey` handles PEM blocks and the generic detector registration is commented out. This is source inspection, not executed-tool coverage. Retain the offline checksum-valid plaintext tracked-file detector, not a general secret scanner; implementation stays in 6.2 and 6.3.
5. Where does stellar-cli store identities, and is there a keychain option? (not needed until a detector depends on it)
6. SEP-58 final status and metadata key names. (task 0.11)
7. Can a required status check be pinned to a trusted source, and which ruleset, required-check and required-workflow features does the `posture-sec` org plan provide? (tasks 0.13, 0.16) [Unverified: recalled from GitHub features, not checked]
8. Should watch mode be built? (D-04)
9. Does the name "Airlock" collide with an existing security product, PyPI package or trademark? (task 0.15)

## 12. Evidence and assumptions register

**Verified against sources**

- PolinRider mechanics, targeted files, history rewriting, scale and signature rotation (OpenSourceMalware reports).
- SEP-58 purpose; `stellar contract build --verifiable` was a draft PR in the result found; Colibri build verification exists; Runtime Verification is building a verification service.
- Soroban release profile and `testutils` placement per Stellar docs examples.
- Cargo ignores `[profile.*]` in non-root manifests.
- Scorecard results for five repos as of 2026-10-26.
- The existing script's `SKIP_DIRS` skips `node_modules/`, `target/`, `dist/`, `.next/` and `vendor/` (read from the pasted source).
- Stellar seed encoding and the source-level Gitleaks/TruffleHog comparison at pinned revisions, 2026-10-28 UTC (`ARCHITECTURE.md` 9.4). Neither tool was executed; valid test vectors pass the checksum too.
- GitHub's reporting and upload limits, from its documentation and from hosted probe runs, 2026-10-30 UTC (`ARCHITECTURE.md` 6.6). A step keeps the first 10 annotations of each level; a step summary above 1 MiB is dropped without failing the step or the job; SARIF upload takes a gzip-compressed file up to 10 MB and keeps the top 5,000 results of a run. `github.event.before` on a new branch, an ordinary push and a force push were read off three runs, including whether `actions/checkout` at its default depth can reach the base.

**Unverified or untested**

- Drips Wave maintainers specifically being hit.
- Whether any of the five repos carries a tracked `node_modules/`, `dist/` or `vendor/` directory today, which decides how much real exposure bypass 7 has.
- RUSTSEC-2026-0387 (not found in search); RUSTSEC-2024-0436 believed to be the unmaintained `paste` crate.
- `merge_group` events delivering a usable base. The reporting limits above are verified; this one needs a merge queue on a repository to observe, and 4.1 decides whether the event is supported at all.
- Aptos RPC hostnames, stellar-cli identity storage, SEP-58 key names.
- Executed Gitleaks/TruffleHog seed coverage and custom configurations; Airlock's planned seed implementation and reference-vector tests (6.2, 6.3).
- Performance, ReDoS and Scorecard targets; all effort sizing.

## 13. Red-team review (summary)

Three questions were put to this design. Full tables, with task IDs, are in `ARCHITECTURE.md` section 16.

**1. What would break?** The three that matter most:

- **B1.** In `push` mode the first draft read policy from HEAD, so a credentialed push could approve its own findings. That is the PolinRider scenario. Fixed (FR-06).
- **B2.** Whoever can push workflow files can remove the step that runs the scanner. A required status check helps for PRs; only a scanner outside the repo (watch mode) covers a stolen credential. Decision D-04.
- **B6.** Skipping `vendor/`, `dist/` and similar directories hides payloads committed there. Fixed: no default directory skips (FR-05).

**2. What edge cases are we missing?** Submodules, LFS pointers, UTF-16 and BOM files, shallow clones, `merge_group` and fork PRs, duplicated suppressed lines, test-support crates that legitimately enable `testutils`, vendored Wasm embedded as base64, `.husky` and `devcontainer` hooks, and output limits that could bury a HIGH finding. Each has a decision in ARCHITECTURE.md 16.3.

**3. What is overengineered?** The JavaScript comment and string masking lexer, SARIF in v0.1, the `init` command, a CLI `rules test`, `deploy_gate`, the SEP-58 parser, suppression `owner` fields, a separate suppressions file, JSON schema files, and the force-push workflow template. All cut or deferred (ARCHITECTURE.md 16.4).

Net effect: P0 requirements are narrower, two real holes are closed, and one open decision (watch mode) is now explicit.

## 14. Documentation and roadmap maintenance rule

`ROADMAP.md` must be updated on every contribution. This applies to code, rules, tests, docs, CI, configuration, dependency bumps and reverts, whether the author is a human or an agent. The same pull request must:

1. Tick, untick or add the affected tasks.
2. Add a changelog entry (date, change, task IDs).
3. Refresh the progress table and the `Last updated` line.

Enforcement: `scripts/check_roadmap_touched.sh` in CI plus a PR template checkbox (task 1.9). Until that task is done, reviewers enforce it by hand. If you change behavior described in this PRD, `ARCHITECTURE.md`, `ARCHITECTURE_ESSENTIALS.md` or `project_structure.md`, update them in the same PR.

---

## Appendix A: Scorecard and gate findings mapped to requirements

| Finding | Where | Requirement |
|---|---|---|
| Committed `.wasm` fixtures flagged as generic binaries | budget-assert, facilitator | FR-04 |
| Release v0.2.0 unsigned, no provenance, no packaging workflow | accensa-contracts | FR-28 (Later) |
| Write token plus unpinned third-party action in one workflow | cost-linter `nightly-bump.yml`, `publish.yml` | FR-28 (Later) |
| Unpinned download-and-run | cost-linter `Dockerfile:46-58`, facilitator `conformance-run.yml:73` | Leave to Scorecard and StepSecurity |
| Same RUSTSEC pair across four Rust repos | all Rust repos | Out of scope (advisory triage) |
| Identical template line numbers across repos | all five | FR-23 (Later) |
| Wasm and NUL-byte silent skips | `malware_scan.py` | FR-05 |
| Allowlist wildcard and inline marker | `malware_scan.py` | FR-07 |
| Scanner in the audited tree | `malware-scan.yml` | Principle 3, FR-06, FR-11 |
| Tracked `vendor/` and `dist/` directories skipped | `malware_scan.py` | FR-05 |

## Appendix B: Bypass test plan (run 2026-10-27 against the real script)

In a scratch repo with the current script copied in, commit each case and run the script. Exit code 0 where it should fail confirms the bypass.

`scripts/bypass_probe.py` does exactly this and is reproducible: it builds one temporary git
repository per case, commits a clean base and then the case, copies in the script passed with
`--script`, and runs it from the repository root with `-I`, which is how the workflow runs it. All
seven cases below ran on 2026-10-27 (Python 3.14, `main` at `Tollcraft/soroban-budget-assert`).

1. A `.wasm` file of any content. **Confirmed, 0 findings** — `\0asm` is a NUL within the first 4 KB, so the file is dropped by the binary/NUL test before any rule reads it, and `.wasm` is not in `BINARY_EXT`, so even the native-binary finding cannot reach it.
2. `printf '// \0\neval(x)\n' > next.config.mjs` (then run `node next.config.mjs` to confirm it still executes). **Confirmed, 0 findings** — `node --check` accepts the file, so the NUL costs the scan and not the payload. This is the shape that matters most: the skip is silent, so an unscanned file and a clean file look identical in the output.
3. A payload line ending in `// malware-scan: allow`, containing `eval(Buffer.from(a,'base64'))`. **Confirmed, 0 findings** — the marker is checked before the rule table, so any line can exempt itself from every rule with no path change.
4. An allowlist file containing a single `*`. **Confirmed, 0 findings** — `fnmatch` against one glob, so a two-byte file in `.github/malware-scan-allow.txt` disables the scan for the whole tree, and the allowlist itself is not scanned by anything.
5. `eval(decrypted)` inside `postcss.config.mjs`. **Confirmed, 0 HIGH** — one WARN `dynamic-eval`, and only HIGH affects the exit code. The literal `atob`/`Buffer.from` requirement is what makes the real PolinRider shape (decode first, then eval a variable) invisible to a gate that scores HIGH.
6. A `.cargo/config.toml` with a `runner` that invokes a shell command. **Confirmed, 0 findings** — no rule reads that file.
7. A file under `vendor/` (or `dist/`) containing `eval(Buffer.from(a,'base64'))`. **Confirmed, 0 findings** — `SKIP_DIRS` is matched against the path prefix before the file is opened.

Each becomes a permanent regression test in Airlock and must fail closed.

Status, task 3.9: cases 1 to 5 and 7 run as `tests/bypass/test_bypass_<n>_<slug>.py`, each asserting
the rule ids and severities rather than a bare exit code, and case 3 runs the payload with and
without the inline marker to prove the marker changes nothing. Case 6 is a skipped test naming task
6.4, because `.cargo/config.toml` has no role and `cargo_vectors` is not written yet; the skip is
the honest record and it turns into a normal test when 6.4 lands.
