---
slug: port-ci-surface-high-rules
title: Port the workflow and install-hook HIGH rules and give workflow files a role
labels: Stellar Wave, complexity: high, area: rules, enhancement
roadmap: 3.6
---

> **Repo context.** `airlock` is a Python 3.11 standard-library-only scanner: `src/airlock/` holds the pipeline (collector, then rules and detectors, then fingerprints and suppressions, then reporters) behind one CLI, and the rules themselves are data in `rules/builtin/*.toml`. The repository being scanned is untrusted input, so the hard rules in [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 are security properties rather than style. [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md) is the source of truth for what is built and what is only a docstring.

> 🟢 **Unblocked.** It needs the shipped engine and role resolver only. It is the second of two slices of task 3.6; the other covers the text-side families and can proceed in parallel, since the two touch different rule files and different roles.

## Problem

Nothing in the shipped rule set reads a GitHub workflow file.
[`rules/roles.toml`](https://github.com/posture-sec/airlock/blob/main/rules/roles.toml) declares two
roles, `tooling-config` (five build-config globs) and `editor-autorun` (`.vscode/tasks.json`), and
`.github/workflows/*.yml` resolves to `doc` by extension fallback, which no pattern rule applies to.
So the four families `ARCHITECTURE.md` 9.6 lists for the CI surface are all absent:

- A workflow step that echoes a secret, or writes `${{ secrets.` into a log or a file.
- `pull_request_target` combined with a checkout of the pull request head, which is the combination
  that hands an outside contributor a write token and an executed payload.
- An install-hook dropper: a `package.json` `scripts.postinstall`, or a `.husky/` or `.githooks/`
  script that runs on `npm install` or on a developer's commit.
- Editor auto-run beyond `tasks.json`, where `.vscode/settings.json` can wire a command to save or
  open events.

The third one is the shape PolinRider used, and the fourth is the reason `editor-autorun` is a
sensitive role at all. Both are currently invisible to the tool built to catch them, and the reason
is coverage rather than judgement: `ARCHITECTURE.md` 9.6 already specifies these rules, and
[`src/airlock/detectors/builtin_patterns.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/detectors/builtin_patterns.py)
is a docstring.

Note that `pull_request_target` plus a head checkout is the class of weakness this repository's own
design document worries about in section 11, so the rule has a test corpus two steps away.

## What to build

1. **Give the files a role first.** Add the workflow, package-manifest and hook paths to
   `rules/roles.toml`, and decide which of them are `SENSITIVE_ROLES` in
   [`src/airlock/roles.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/roles.py),
   which is what makes an unreadable or over-cap file there HIGH rather than WARN. That list is a
   security decision with a false-positive cost, so state the reasoning. A new role name is
   automatically visible to the rule loader's unknown-role cross-check from 2.5, so a rule pointing at
   a typo fails rather than matching nothing.
2. **Write the four families as data** in a new `rules/builtin/` file, one rule per family at minimum,
   each with id, title, severity, roles, rationale and a fixture pair. `detector = "pattern"` is the
   right tier for the three that are single-line tests; the `pull_request_target` case needs to see
   two things in one file (the trigger *and* a head checkout), so it either becomes a code rule on the
   `builtin_patterns` detector, registered in `DETECTORS` and `DETECTOR_NAMES`, or is expressed as two
   WARN rules that a reviewer can read together. Choose one and say why.
3. **Mind the raw-text rule.** No comment or string masking in this layer, per `AGENTS.md` section 4,
   which means a YAML comment containing `eval(` is a match by design. The negative fixture is where
   you show you understood that: make it a near miss, the way `cfg-dynamic-code`'s negative is
   `evalOrder: "post"`.
4. **Check the self-scan honestly.** This repository has workflow files, so the new rules will run
   against them on every pull request. If a rule fires on `ci.yml` or `roadmap-check.yml`, that is
   either a true positive about this repo or a false positive to argue in the pull request. It is not
   something to suppress by the author, since only the owner writes `airlock.toml`.

**Out of scope:** the text-side families (invisible Unicode, decode-and-eval, exfiltration endpoints,
obfuscator identifiers), which are the other slice; the WARN tier of 3.7; `.cargo/config.toml` and
`build.rs` coverage, which belongs with `cargo_vectors` in 6.4; and any change to the twelve shipped
rules.

## Acceptance criteria

- [ ] `rules/roles.toml` names the new roles, and every rule's `roles` list resolves through the loader rather than matching nothing.
- [ ] Each of the four families has at least one rule with a positive and a negative fixture, and `python -m pytest tests/unit/test_fixtures.py` passes without the fixtures being registered by hand.
- [ ] A workflow that dumps a secret, and a `pull_request_target` workflow that checks out the PR head, each produce a finding whose severity affects the exit code, shown by a test rather than asserted.
- [ ] A `package.json` with a `postinstall` that fetches and executes is reported, and the negative fixture is a legitimate lifecycle script rather than an empty file.
- [ ] `airlock scan --mode full .` reports no HIGH findings on this repository, and any finding it does report on `ci.yml` is discussed in the pull request rather than suppressed.
- [ ] The ReDoS harness passes for every new pattern, with the worst measured time stated in the pull request.
- [ ] `ARCHITECTURE.md` 9.6, the section 8 fail-closed table and `ARCHITECTURE_ESSENTIALS.md` match what shipped, and `ROADMAP.md` 3.6 records which families this closes.
- [ ] `rules/` and `src/airlock/roles.py` are protected paths: owner review required, and no existing rule weakened to make a new one fit.
- [ ] `python -m pytest`, `ruff check .`, `ruff format --check .` and `mypy src` all pass.
- [ ] `ROADMAP.md` carries a changelog row with a UTC date, `Last updated` moved, and `python scripts/roadmap_progress.py --check` passing.
- [ ] PR description includes `Closes #{{issue:self}}`.

## Tech stack

- Runtime: Python 3.11, standard library only. [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 forbids adding a runtime dependency, and a scan never touches the network, so a helper library is not an option here.
- Roles first: [`rules/roles.toml`](https://github.com/posture-sec/airlock/blob/main/rules/roles.toml) and `SENSITIVE_ROLES` in [`src/airlock/roles.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/roles.py). A workflow file resolves to `doc` today, which is why no rule reads one.
- Rules: a new file under [`rules/builtin`](https://github.com/posture-sec/airlock/blob/main/rules/builtin), with fixtures in [`tests/fixtures`](https://github.com/posture-sec/airlock/blob/main/tests/fixtures). There is no YAML parser in this build and ADR-007 keeps it out of v0.1, so these are raw text patterns over lines, not parsed documents.
- Self-scan consequence: [`.github/workflows/ci.yml`](https://github.com/posture-sec/airlock/blob/main/.github/workflows/ci.yml) runs the scanner over this repository's own workflows, so a new rule fires here first. That is a true positive or a false positive to argue, not something to suppress yourself.
- Run before pushing: `python -m pytest tests/unit/test_fixtures.py tests/unit/test_redos.py` and `python -m airlock scan --mode full .`, and quote the self-scan output.

### **Contact & Support**
- [`SUPPORT.md`](https://github.com/posture-sec/airlock/blob/main/SUPPORT.md) — where to ask, the commands CI runs, and the rules that most often get a pull request rejected
- [`SECURITY.md`](https://github.com/posture-sec/airlock/blob/main/SECURITY.md) — private disclosure only; never open an issue about a bypass
