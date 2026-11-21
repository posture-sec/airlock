# ARCHITECTURE_ESSENTIALS: Airlock

Status: v0.2 (red-team revision). Outline of decisions an agent must not violate. Full detail: `ARCHITECTURE.md` (section numbers in brackets). Scope: `PRD.md`. Work queue: `ROADMAP.md`. File locations: `project_structure.md`.

## 0. Roadmap rule (read first)

- `ROADMAP.md` must be updated in the same PR as every change: code, rules, tests, docs, CI, config, dependency bumps, reverts.
- Update means: tick, untick or add tasks; add a changelog entry; refresh the progress table; refresh `Last updated`.
- CI check: `scripts/check_roadmap_touched.sh` (task 1.9; until it exists, reviewers enforce by hand).
- If behavior changes, also update `PRD.md`, `ARCHITECTURE.md`, this file and `project_structure.md` in the same PR. [17]

## 1. What this is

- CLI plus composite GitHub Action that scans Stellar/Soroban repos for supply-chain compromise and release-integrity gaps.
- Two layers: generic injection scanner (PolinRider class) and Soroban-aware rules.
- The scanned repo is untrusted input.

## 2. Hard rules (never break)

- Never execute, import or `eval` scanned content. [1]
- Never run scanner code from the scanned checkout; it comes from the pinned Action path. [4, 10]
- Policy, suppressions and manifest come from a trusted base: PR base in `pr` mode, `github.event.before` in `push` mode. [6.5]
- Never read policy from HEAD in `pr` or `push` mode.
- A base config copy over `MAX_CONFIG_BYTES` is refused before decoding: `skipped-unreadable` (HIGH) and the shipped defaults apply. [6.5, 7.6]
- Never skip a file silently. Every skip is a finding. [8]
- No default directory skips (no `vendor/`, `dist/`, `node_modules/` exemptions). [6.1]
- Never exit 0 after a detector exception, invalid config, missing git, old Python or unresolvable base. [8]
- No inline suppression markers. Suppressions are fingerprint-keyed, occurrence-aware, with a reason. [7.3, 7.6]
- No network and no telemetry during `scan`. [1]
- No runtime dependencies in v0.1; standard library only. [2]
- No third-party detector plugins. Rules are data, detectors are in-tree code. [6.3]
- No comment or string masking in `config_role`; match raw text. [ADR-013]
- Regex only runs on lines at or under `line_cap`. Longer lines are findings, not regex input. [ADR-018]
- Soroban rules apply to contract crates only (`crate-type` has `cdylib`). [ADR-016]
- Never hardcode contract size limit, build target triple or SDK version; read from policy. [9.3]
- No rule without one positive and one negative fixture. [12]
- No `SELF` skip: the tool scans its own repo. [11]
- Never commit live-looking payloads; build trigger strings at test time. [12]
- Evidence text is attacker-controlled: never render it as raw markdown. [6.6]

## 3. Stack

- Python 3.11+, `tomllib`, `hashlib`, `subprocess` (fixed argv, never a shell), `re`, `json`.
- Build: `pyproject.toml`, `src/` layout, hatchling. Dev only: pytest, ruff, mypy. The wheel carries `rules/` inside the package, because a scanner with no rules cannot scan.
- Output v0.1: console, GitHub commands, JSON, step summary. SARIF is P1. [ADR-008]
- Distribution: composite Action, consumers pin the full commit SHA. PyPI is Later.
- No YAML parser. [ADR-007]

## 4. Pipeline

`Collector -> Role resolver -> Detectors -> Suppression filter -> Reporters -> exit code` [3]

- Collector: `git ls-files -z`, size, line and read limits, BOM-aware decoding, startup checks. [6.1]
- Roles: content magic first (`wasm`, `native-binary`), then globs, then extension fallback. [6.2]
- Detectors: plain functions `run(ctx) -> Iterable[Finding]`; a raise becomes `detector-error` (HIGH) and the findings it yielded beforehand are kept. [6.3]
- The engine pass in `runner.py` runs the `pattern` rules and the `line_cap` account for every file, so neither depends on a detector being registered. A `builtin:` rule may carry a pattern only its detector reads. [6.3, 6.4]
- Output order: severity descending, then path, line, rule_id. HIGH always first.

## 5. Data models (field lists) [7]

- `Severity`: INFO < WARN < HIGH. `Mode`: pr, push, full.
- `Finding`: rule_id, severity, path, line, roles, message, evidence, occurrence, fingerprint, suppressible, suppressed_by.
- Fingerprint: `sha256(rule_id \0 path \0 normalized_evidence \0 occurrence)`; no line number.
- `Rule` (TOML): id, title, roles, detector, severity, suppressible, rationale, pattern, tests.
- Suppression (in `airlock.toml`): rule, path, fingerprint, reason, optional expires. No owner, no globs.
- Policy keys: `version`, `[policy]` (fail_on, max_file_bytes, line_cap, tail_max_len, tail_entropy), `[soroban]`, `[[suppress]]`.
- Wasm manifest entry: sha256, paths[], origin (built|vendored|generated), source, build, note. Keyed by hash.
- `ScanReport`: tool_version, mode, repo_head, base, files_indexed, files_scanned, files_skipped, findings, suppressed, exit_code. Scanned plus skipped must equal indexed; `run_scan` raises when it does not, and a skip with a digest counts as skipped.
- User-owned files: `airlock.toml`, `wasm-manifest.toml`.

## 6. Exit codes and fail-closed findings [8]

- Exit: 0 pass, 1 findings at or above `fail_on`, 2 config or usage error, 3 internal error.
- Skip and state findings are never suppressible, even when a loaded rule declares otherwise. IDs: `skipped-oversize`, `skipped-unreadable`, `skipped-symlink`, `skipped-unmerged`, `submodule-present`, `nul-in-text`, `non-utf8-text`, `content-magic-role`, `cfg-long-line`, `detector-error`, `history-rewritten`, `no-trusted-base`, `policy-changed`, `policy-unknown-key`, `suppression-expiring`, `suppression-invalid`, `untrusted-policy-source`.

## 7. Detectors

| Detector | Rules | Priority |
|---|---|---|
| `config_role` | `cfg-dynamic-code`, `cfg-network-exec`, `cfg-network`, `cfg-process-spawn`, `cfg-chain-endpoint`, `cfg-appended-tail`, `cfg-long-line` | P0 |
| `wasm_manifest` | `wasm-unlisted`, `wasm-hash-mismatch`, `wasm-path-moved`, `wasm-manifest-stale`, `wasm-archive-skipped` | P0 |
| `builtin_patterns` | rule data, not a code detector: `pat-decode-eval`, `pat-invisible-unicode` (HIGH), `pat-exfil-endpoint`, `pat-obfuscator-id` (WARN) | P0 |
| `ci_surface` | `pat-secret-dump`, `pat-ptr-head-checkout`, `pat-lifecycle-exec` (HIGH, in code) and `pat-privileged-trigger`, `pat-lifecycle-fetch`, `pat-editor-command-path` (WARN, rule data) | P0 |
| `cargo_vectors` | `cargo-patch-override`, `cargo-git-dependency`, `cargo-path-escape` (remaining Cargo vectors are deferred) | P1 |
| `npm_registry` | `npm-registry-bypass` | P1 |
| `stellar_seed` | `stellar-seed` (HIGH, checksum-valid plaintext seeds only) | P1 |
| `soroban_profile` | release-profile keys, `testutils` placement (contract crates only) | P1 |
| `stellar_seed` | strkey `S...` seed with valid checksum; suppressible | P1 |

Key behaviors:

- `config_role` targets role `tooling-config` (postcss, tailwind, next, eslint, babel configs). Capabilities, not signatures. [9.1]
- `cfg-dynamic-code` is HIGH and not suppressible. Network or spawn alone is WARN; combined is HIGH.
- `wasm_manifest` identifies Wasm by magic `00 61 73 6D`, never by extension. [9.2]
- `pat-*` rules read every role that is code (`source`, `tooling-config`, `editor-autorun`, `other`) and not `doc`; the scope claim lives in each rule's `roles` list, so widening or narrowing it is a data change a reviewer sees. [9.6]
- The CI surface has roles of its own (`workflow`, `package-manifest`, `install-hook`, plus `editor-autorun` for `.vscode/settings.json`) and each of the three new ones is in `SENSITIVE_ROLES`, because something executes them with credentials attached. A pairing rule reads its own half out of the WARN rule's pattern rather than restating it, and a code rule's regex is bound by `line_cap` like any other. [9.7]
- The lifecycle fetch/exec pairing remains same-line for package scripts; install hooks may pair the fetch line with an execution line in a three-line inclusive forward window. Both lines obey `line_cap`, and one fetch yields at most one HIGH. npm lockfile URLs and Cargo manifests are parsed as data only; no package or object is fetched. [9.5, 9.7, 9.8]
- D-06: owner-approved KEEP (2026-10-28 UTC). Planned `stellar_seed` is offline, checksum-valid plaintext in tracked files; valid test vectors also match, with no funding or live-use inference. Explicit reasoned suppressions only; implementation remains 6.2/6.3. [9.4]

## 8. Trust model [4]

- Trust anchors: pinned Action commit SHA; the trusted base (PR base or pre-push SHA).
- Residual risk: whoever can push workflow files can remove the scan. A required status check covers PRs. Only an external watcher covers a stolen credential (decision D-04, backlog). Hardware-key 2FA and a protected recovery email are the real controls.

## 9. Action design [10]

- `python3 -I -c` with an explicit `sys.path` from `GITHUB_ACTION_PATH` (`-I` ignores `PYTHONPATH`).
- Inputs pass through `env:`, never interpolated into the shell.
- Caller supplies `fetch-depth: 0`; the tool never fetches.
- Caller uses `permissions: contents: read`, a full-SHA reference and a required status check.

## 10. Layout [5, project_structure.md]

```
src/airlock/{cli,model,collector,roles,rules,policy,fingerprint,runner}.py    (+ strkey.py in P1)
src/airlock/detectors/{config_role,wasm_manifest,ci_surface,builtin_patterns}.py  (+ P1 detectors)
src/airlock/report/{console,github,jsonout,summary}.py                        (+ sarif.py in P1)
rules/{roles.toml,builtin/*.toml}   scripts/   tests/{unit,fixtures,bypass,corpus,golden}/
action.yml   pyproject.toml   airlock.toml   wasm-manifest.toml
```

## 11. Testing must-haves [12]

- Positive and negative fixture per rule, enforced inside pytest.
- Seven bypass regression tests (PRD Appendix B), each failing closed.
- ReDoS timing test per pattern. Trusted-base tests (policy edit plus payload, force push, new branch).
- Parity test against `malware_scan.py`. Corpus gate: zero HIGH on clean state of the six repos.
- Self-scan passes in CI. Roadmap-gate script test.

## 12. Decisions (ADR one-liners) [13]

- 001 stdlib-only Python. 002 one repo. 003 trusted-base policy. 004 fail closed. 005 no inline suppressions.
- 006 rules are data, no plugins. 007 no YAML parser. 008 SARIF deferred. 009 composite Action, no Docker.
- 010 Wasm by magic. 011 Soroban expectations from policy. 012 capabilities over signatures.
- 013 no masking. 014 no directory skips. 015 occurrence-aware fingerprints. 016 contract crates only.
- 017 roadmap gate in CI. 018 line cap instead of regex timeouts.
- 019 SARIF key `partialFingerprints["airlock/v1"]` settled before shipping (D-09); no migration needed. Reporter still deferred to 7.6.

## 13. Cut or deferred (do not build without a roadmap decision) [16.4]

- Cut: JS lexer (`jsmask`), `init` command, `rules test` command, suppression `owner`, `roles.overrides`, `read_policy_from`, JSON schema files, force-push workflow template, `hypothesis` fuzzing.
- Deferred: SARIF (P1), `deploy_gate`, SEP-58 metadata check and `wasmparse`, watch mode, org scan, history scan, parser-based JS, PyPI.

## 14. Known unknowns (do not assume) [15]

- SEP-58 metadata key names and Soroban metadata section names.
- Composite Action integration (4.1) remains unverified. The exact `-I -c` launch with a trusted `sys.path` insert passed on `ubuntu-latest` / CPython 3.11.17 on 2026-10-28: trusted origins, no shadow execution, full/PR/shallow exits 0/0/2. The probe manually set `GITHUB_ACTION_PATH`; it did not ship an Action. Task 0.8 is resolved; evidence and runner details: [ARCHITECTURE.md section 10](ARCHITECTURE.md#task-08-observed-isolation-evidence).
- `tail_max_len` and `tail_entropy` values (placeholders until tuned on corpus).
- Executed seed coverage of Gitleaks/TruffleHog and custom configurations; source-only comparison is verified in 9.4, not a runtime benchmark.
- Resolver-2 feature behavior for `testutils` inheritance.
- Required-check behavior when a job is deleted (0.13); `merge_group` base reachability, which needs a merge queue to measure (4.1). GitHub's reporting limits are verified: 10 annotations of each level per step, 1 MiB per step summary with no effect on step status, 10 MB and 5,000 kept results per SARIF run. Numbers, sources and probe runs: [ARCHITECTURE.md 6.6](ARCHITECTURE.md#66-reporters) (0.9).

## 15. Definition of done for v0.1.0

- P0 requirements FR-01 to FR-15 met.
- All seven bypass tests fail closed; parity test green.
- Dogfooded on the six repos with zero HIGH false positives; five copy-pasted workflows replaced.
- Attested release; Airlock repo passes its own scan; `ROADMAP.md` current.
