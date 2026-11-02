---
slug: port-text-side-high-rules
title: Port the text-side HIGH rules so eval and exfiltration are visible outside five config files
labels: Stellar Wave, complexity: high, area: rules, enhancement
roadmap: 3.6
---

> **Repo context.** `airlock` is a Python 3.11 standard-library-only scanner: `src/airlock/` holds the pipeline (collector, then rules and detectors, then fingerprints and suppressions, then reporters) behind one CLI, and the rules themselves are data in `rules/builtin/*.toml`. The repository being scanned is untrusted input, so the hard rules in [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 are security properties rather than style. [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md) is the source of truth for what is built and what is only a docstring.

> 🟢 **Unblocked.** The engine, the role resolver and the fixture gate it needs are all shipped (2.4, 2.5, 2.12). This is the first of two slices of task 3.6; the second covers the CI surface and is a separate issue so the two can be reviewed apart.

## Problem

The twelve shipped rules cover less of a repository than the rule count suggests, because almost all
of them are scoped to five filenames. `cfg-dynamic-code`, `cfg-network`, `cfg-network-exec`,
`cfg-chain-endpoint`, `cfg-appended-tail`, `cfg-long-line` and `cfg-process-spawn` all declare
`roles = ["tooling-config"]`, and that role resolves from
[`rules/roles.toml`](https://github.com/posture-sec/airlock/blob/main/rules/roles.toml) through five
globs: `postcss.config.*`, `tailwind.config.*`, `next.config.*`, `eslint.config.*`,
`babel.config.*`. A file that is not one of those resolves to `source`, `doc`, `other`, `wasm`,
`native` or `archive`, and no pattern rule in the tree reads them.

The consequence is measurable against the bypass corpus. `PRD.md` Appendix B case 7 is
`eval(Buffer.from(a,'base64'))` in `vendor/`. The old script missed it because `SKIP_DIRS` matched the
prefix; Airlock does not skip the directory, opens the file, resolves its role to `source`, finds no
rule that applies to `source`, and reports clean. Same exit code, same verdict, different reason.
`ROADMAP.md` section 2 names this as the reason the bypass suite (3.9) cannot yet show all seven cases
failing closed.

Three of the four families this slice covers do not exist in any form:
[`ARCHITECTURE.md`](https://github.com/posture-sec/airlock/blob/main/ARCHITECTURE.md) 9.6 lists
invisible Unicode, exfiltration endpoints, decode-and-eval and obfuscator identifiers as the port list
for `builtin_patterns`, and
[`src/airlock/detectors/builtin_patterns.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/detectors/builtin_patterns.py)
is four lines of docstring. Invisible Unicode is the one with no analogue at all: a zero-width or
bidi-override character inside an identifier is invisible in a diff, defeats a grep for the payload
name, and is exactly why "match raw text with no masking" is a hard rule rather than a style choice.

## What to build

Four rule families, all of them data in a new `rules/builtin/builtin_patterns.toml`, all run by the
existing engine pass:

1. **Decode-and-eval beyond the config role.** The pattern `cfg-dynamic-code` already matches
   `eval(`; what is missing is coverage. Decide whether the right shape is the same pattern with a
   wider `roles` list, or a distinct rule for source files at a lower severity than for build tooling,
   since a legitimate `eval` in application code is far more common than one in a PostCSS config. That
   severity call is yours to make and must be argued in the pull request, because it decides how many
   false positives the tool ships with (risk R-2).
2. **Invisible Unicode.** Cover the zero-width set, the bidi overrides and the word-joiner variants,
   as characters that must not appear outside a comment or a string in code, and decide the
   suppression story: this is a finding where an owner will want an entry, so `suppressible` matters.
   Beware the interaction with `line_cap`: a rule that runs only on short lines can be evaded by
   padding, so say what the residual risk is.
3. **Exfiltration endpoints.** Known paste, webhook and tunnel endpoints as data. Keep this a separate
   rule from `cfg-network` rather than widening that pattern, because the two have different false
   positive profiles and different reasons to be suppressed.
4. **Obfuscator identifiers.** The `javascript-obfuscator` identifier shape, and the
   `_0x`-prefixed hex family. `ARCHITECTURE.md` 9.6 is explicit that obfuscator *fingerprints* rotate
   weekly while the mechanism stays, so prefer a shape that keys on the identifier grammar over a list
   of tool names.

Every rule needs its positive and negative fixture pair in
[`tests/fixtures/`](https://github.com/posture-sec/airlock/blob/main/tests/fixtures), assembled from
fragments at call time. The fixture gate from 2.12 fails a rule without both, and the ReDoS harness
times every new pattern automatically, so an expression with backtracking in it will be caught rather
than discovered in a run.

**Out of scope:** the CI-surface families (`workflow` secret dump, `pull_request_target` checkout,
install-hook droppers, VS Code auto-run outside `tasks.json`), which are the other slice; the WARN-tier
rules (3.7); the `build.rs` and native-binary families, which belong with the Cargo work in 6.4; and
any change to the twelve existing rules.

## Acceptance criteria

- [ ] Each of the four families has at least one rule in `rules/builtin/builtin_patterns.toml` with id, title, severity, roles, rationale and a fixture pair, and `python -m pytest tests/unit/test_fixtures.py` passes without being told about them by hand.
- [ ] Appendix B case 7 (`eval(Buffer.from(…))` under `vendor/`) now yields a finding whose severity affects the exit code, demonstrated by a test rather than asserted in prose.
- [ ] The role coverage each rule claims is stated in the rule's `roles` list, not enforced in detector code, so the reference generator and a reviewer can see it.
- [ ] `airlock scan --mode full .` still reports no HIGH findings on this repository, and if a new rule fires on a real file here, the false positive is discussed in the pull request rather than suppressed by the author.
- [ ] The ReDoS harness passes for every new pattern on cap-length adversarial input, with the measured worst-case time stated in the pull request.
- [ ] `ARCHITECTURE.md` 9.6 and the `ARCHITECTURE_ESSENTIALS.md` finding-id list match what shipped, and `ROADMAP.md` 3.6 records which half of its list this closes and which the CI-surface issue still owes.
- [ ] `rules/` is a protected path: the pull request needs owner review and must not weaken an existing rule to make a new one fit.
- [ ] `python -m pytest`, `ruff check .`, `ruff format --check .` and `mypy src` all pass.
- [ ] `ROADMAP.md` carries a changelog row with a UTC date, `Last updated` moved, and `python scripts/roadmap_progress.py --check` passing.
- [ ] PR description includes `Closes #{{issue:self}}`.

## Tech stack

- Runtime: Python 3.11, standard library only. [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 forbids adding a runtime dependency, and a scan never touches the network, so a helper library is not an option here.
- Data: a new file under [`rules/builtin`](https://github.com/posture-sec/airlock/blob/main/rules/builtin), leaving the seven `cfg-*` rules in [`rules/builtin/config_role.toml`](https://github.com/posture-sec/airlock/blob/main/rules/builtin/config_role.toml) as they are.
- Roles: [`rules/roles.toml`](https://github.com/posture-sec/airlock/blob/main/rules/roles.toml) decides which files a rule reaches, and today six of the seven `cfg-*` rules are `tooling-config` only. Widening a glob is a false-positive decision, not a formatting one, so show corpus evidence in the pull request.
- Fixtures: [`tests/fixtures`](https://github.com/posture-sec/airlock/blob/main/tests/fixtures) builders, one positive and one negative per rule. The suite fails without both, and [`src/airlock/detectors/builtin_patterns.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/detectors/builtin_patterns.py) is the detector these rules point at.
- Run before pushing: `python -m pytest tests/unit/test_fixtures.py tests/unit/test_redos.py` and `python -m airlock scan --mode full .`. State the worst ReDoS measurement you saw.

### **Contact & Support**
- [`SUPPORT.md`](https://github.com/posture-sec/airlock/blob/main/SUPPORT.md) — where to ask, the commands CI runs, and the rules that most often get a pull request rejected
- [`SECURITY.md`](https://github.com/posture-sec/airlock/blob/main/SECURITY.md) — private disclosure only; never open an issue about a bypass
