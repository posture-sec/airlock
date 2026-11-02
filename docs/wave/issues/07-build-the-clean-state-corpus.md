---
slug: build-the-clean-state-corpus
title: Build the clean-state corpus from the dogfood repositories under tests/corpus
labels: Stellar Wave, complexity: medium, area: tests, enhancement
roadmap: 0.10
---

> **Repo context.** `airlock` is a Python 3.11 standard-library-only scanner: `src/airlock/` holds the pipeline (collector, then rules and detectors, then fingerprints and suppressions, then reporters) behind one CLI, and the rules themselves are data in `rules/builtin/*.toml`. The repository being scanned is untrusted input, so the hard rules in [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 are security properties rather than style. [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md) is the source of truth for what is built and what is only a docstring.

> 🟢 **Unblocked.** It depends on nothing: the six repositories it snapshots are public, and the scanner that will read the snapshot is on `main`. Three open tasks name it as their dependency, so this is the queue's bottleneck.

## Problem

Airlock's rule thresholds are guesses. `airlock.toml` says so in its own comments:
`tail_max_len = 2000   # placeholder until tuned on the corpus (task 3.3)` and
`tail_entropy = 4.5    # placeholder until tuned on the corpus (task 3.3)`. The consequence is
already measured: `ROADMAP.md` 3.11 records that `cfg-network` costs about 63 ms per MB of
adversarial text against a 50 ms target, and nobody can say whether that matters on real
repositories, because there is no real-repository input in the tree.

Three rows are waiting on the same snapshot: 3.3 (threshold tuning), 3.8 (the parity harness that
proves the ported rules lose no findings against `malware_scan.py`), and 4.6 (the corpus gate in CI,
gate G4). `ROADMAP.md` section 4 names it as one of the two tasks that unblock the most.

[`tests/corpus/`](https://github.com/posture-sec/airlock/blob/main/tests/corpus) exists as a
directory with a `.gitkeep` in it and nothing else.

There is a hard part, and it is the reason this issue is Medium rather than a fetch script. The
`checks` job's last step runs `airlock scan --mode full .` over this repository and fails the build
on any HIGH finding. A clean-state snapshot of six real repositories is exactly the input likely to
produce a HIGH that is a false positive: a minified bundle trips `cfg-long-line` at HIGH, and a
legitimate Soroban RPC URL in a build config trips `cfg-chain-endpoint`. So the snapshot cannot just
be dropped in the tree, and it cannot be quietly excluded either, because "no default directory
skips" is a hard rule rather than a preference.

## What to build

1. **Collect the snapshot.** From the six repositories named in `ROADMAP.md` 4.4
   (`Tollcraft/soroban-budget-assert`, `soroban-cost-linter`, `accensa-app`, `accensa-contracts`,
   `x402-facilitator-stellar`, and `soroban-cost-profiler` if it is public by the time you get there),
   take the files the rules read: JS and TS tooling configs, editor task files, `.cargo/config.toml`,
   `Cargo.toml` and workspace manifests, workflow YAML, and any committed Wasm artifact or its git LFS
   pointer. Record for every file the source repository, the path and the full commit SHA, in a
   manifest that lives with the snapshot. Clean state only, from the default branch.
2. **Prove it is clean by inspection, not by assumption.** No secret, no token, no seed, and no
   live-looking payload reaches the tree. Where a source file contains one of those, leave it out and
   say so in the manifest rather than redacting it in place: a redacted file is no longer the input
   the thresholds are being tuned on.
3. **Decide how the snapshot meets the self-scan, and propose it before you build it.** The options
   are all defensible and one of them needs the owner: a separate CI job that scans the snapshot and
   compares against a committed expected-findings baseline, so the corpus gate has a home and the
   self-scan step keeps scanning only this repository's own source; or landing the snapshot with the
   false positives suppressed through `airlock.toml`, which only the owner may write and which bakes
   a guess into the policy file. State which you chose and why in the pull request. Do not solve it by
   adding a skip, an ignore list or a `continue-on-error`.
4. **Write the harness that reads it**, so 3.3 and 3.8 have something to run against: a documented
   way to scan the corpus and get findings per source file, and a golden record of what the twelve
   shipped rules report today. The golden file is the baseline the threshold tuning will be judged
   against, so it has to be reproducible rather than hand-written.

**Out of scope:** changing `tail_max_len`, `tail_entropy` or any pattern (that is 3.3, and it needs
this snapshot to exist first), implementing the parity harness (3.8), and wiring a required corpus
gate into CI (4.6). Copying whole repositories is also out: the corpus is the files the rules read,
not a mirror.

## Acceptance criteria

- [ ] `tests/corpus/` holds the snapshot plus a manifest naming, for every file, the source repository, its path there and the commit SHA it came from.
- [ ] A second person can reproduce the snapshot from the manifest alone, and the document says how.
- [ ] The corpus contains no secret, no seed and no live-looking payload, and the pull request states how that was checked rather than asserting it.
- [ ] A scan over the corpus is runnable through a documented command, and its current output is committed as a golden file that the suite reproduces byte-for-byte.
- [ ] `airlock scan --mode full .` still reports no HIGH findings, and the way that was achieved is stated explicitly in the pull request.
- [ ] Tasks 3.3, 3.8 and 4.6 read consistently with whatever the corpus now provides, and `ROADMAP.md` 0.10 is ticked with a changelog row, `Last updated` moved, and `python scripts/roadmap_progress.py --check` passing.
- [ ] `python -m pytest`, `ruff check .`, `ruff format --check .` and `mypy src` all pass.
- [ ] PR description includes `Closes #{{issue:self}}`.

## Tech stack

- Runtime: Python 3.11, standard library only. [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 forbids adding a runtime dependency, and a scan never touches the network, so a helper library is not an option here.
- Directory: [`tests/corpus`](https://github.com/posture-sec/airlock/blob/main/tests/corpus), which holds a `.gitkeep` today. Baselines go under [`tests/golden`](https://github.com/posture-sec/airlock/blob/main/tests/golden) if the issue's chosen design needs them.
- The collision to plan around: [`.github/workflows/ci.yml`](https://github.com/posture-sec/airlock/blob/main/.github/workflows/ci.yml) runs `airlock scan --mode full .` over the whole tree, so a real-world snapshot is scanned by the build that is supposed to stay green.
- Allowed resolutions are a separate corpus job with its own baseline, or owner-issued suppressions in [`airlock.toml`](https://github.com/posture-sec/airlock/blob/main/airlock.toml). A skip, a `.gitignore` entry or a default directory exclusion is not a resolution; those are the bypasses this project exists to close.
- No secrets and no live-looking payload in the corpus. Copy tooling configs, Cargo manifests and Wasm fixtures, and say which commit each came from.

### **Contact & Support**
- [`SUPPORT.md`](https://github.com/posture-sec/airlock/blob/main/SUPPORT.md) — where to ask, the commands CI runs, and the rules that most often get a pull request rejected
- [`SECURITY.md`](https://github.com/posture-sec/airlock/blob/main/SECURITY.md) — private disclosure only; never open an issue about a bypass
