---
slug: write-bypass-regression-tests
title: Turn the seven Appendix B cases into permanent bypass regressions
labels: Stellar Wave, complexity: medium, area: tests, type: test, blocked
roadmap: 3.9
---

> **Repo context.** `airlock` is a Python 3.11 standard-library-only scanner: `src/airlock/` holds the pipeline (collector, then rules and detectors, then fingerprints and suppressions, then reporters) behind one CLI, and the rules themselves are data in `rules/builtin/*.toml`. The repository being scanned is untrusted input, so the hard rules in [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 are security properties rather than style. [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md) is the source of truth for what is built and what is only a docstring.

> ⛔ **Blocked by #{{issue:port-text-side-high-rules}} and by task 6.4.** Two of the seven shapes stay invisible until rules exist for them: a payload under `vendor/` at role `source`, which none of the seven `cfg-*` rules reads, and a `.cargo/config.toml` `runner`, which has no role and no rule at all. **The other five are unblocked right now**, and they are the larger half of the work: cases 1 to 5 already fail closed on the twelve shipped rules, nothing locks that in, and a rule edit could reopen one of them silently. A pull request that lands the harness and those five cases is a complete contribution on its own.

## Problem

Task 0.4 proved the bypasses are real. It ran each of the seven shapes from `PRD.md` Appendix B as a
commit in a scratch repository against the actual `malware_scan.py`, and all seven exited 0, which
passes the job. That evidence lives in [`scripts/bypass_probe.py`](https://github.com/posture-sec/airlock/blob/main/scripts/bypass_probe.py)
and in the PRD, and it is evidence about *the other scanner*. [`tests/bypass/`](https://github.com/posture-sec/airlock/blob/main/tests/bypass)
is an empty directory with a `.gitkeep`, so nothing here says that Airlock still closes those shapes
after the next edit.

The harness is nearly there already. `bypass_probe.py` has the seven cases as data (`Case(num, name,
claim, files)`), builds each one with `build()` and `commit()`, and runs the scan with `scan()`. The
part it does not have is the second scanner: `build()` writes `malware_scan.py` into the scratch tree
and `scan()` runs it as `python3 -I .github/scripts/malware_scan.py`, which is the right thing for a
probe of an external script and the wrong thing for a regression of this package.

What the five closed cases do today, measured on this machine against the twelve shipped rules, in
`--mode full`, from a scratch git repository:

| Case | Shape | Result |
|---|---|---|
| 1 | `.wasm` of any content | `wasm-unlisted` HIGH, exit 1 |
| 2 | NUL byte then `eval(x)` in `next.config.mjs` | `nul-in-text` HIGH *and* `cfg-dynamic-code` HIGH, exit 1 |
| 3 | payload line ending in an inline allow marker | the marker is inert; `cfg-dynamic-code` HIGH on the config copy, exit 1 |
| 4 | allowlist file containing `*` | the file is ignored as data; the payload next to it is HIGH, exit 1 |
| 5 | `eval(decrypted)` in `postcss.config.mjs` | `cfg-dynamic-code` HIGH, exit 1 |
| 6 | `.cargo/config.toml` with a shell `runner` | 0 findings, exit 0 |
| 7 | `eval(Buffer.from(...))` under `vendor/` | 0 findings, exit 0 |

Case 2 is the one worth reading twice: the old script *lost* the file to its own binary test, so the
NUL cost the scan and not the payload. Here the NUL is itself a HIGH finding and the `eval` is
reported as well, which is the fail-closed behavior `ARCHITECTURE_ESSENTIALS.md` asks for. That
difference is a claim about this repository's behavior, it is currently only true by accident of
which rules exist, and gate G2 ("all seven bypass tests fail closed and run in CI") cannot be checked
honestly until it is a test.

## What to build

1. **Split the harness from the subject.** The case data and the repository builder in
   `bypass_probe.py` are already general; make the part that runs a scanner one step the caller
   supplies, so one set of seven shapes can be pointed at either the external script (which is what
   the probe is for, and what must keep working) or at this package's CLI. `build()` currently writes
   `malware_scan.py` into the tree even when the subject is a package, so the copied-script step
   belongs to the probe rather than to the shared builder.
2. **Write the five unblocked cases as tests** under `tests/bypass/`, one per Appendix B case, each
   asserting the finding *ids and severities* rather than just a non-zero exit. A test that only says
   "exit 1" would pass on an unrelated HIGH, which is exactly the wrong kind of green. Case 3's real
   assertion is the differential one: the same payload with and without the inline marker must
   produce the same findings, because Airlock has no inline marker to honour and never should.
3. **Keep the payloads built from fragments at test time.** `bypass_probe.py` already does this with
   `_join("ev", "al")`, and `AGENTS.md` section 4 requires it: no live-looking payload or real secret
   gets committed here. Reuse those constants rather than writing literal trigger strings into a new
   file.
4. **Use `--mode full` and say why.** `pr` and `push` modes need a trusted base, and a synthetic
   scratch repo has none, so full mode is the right trust model for a payload regression. State that
   in the test module docstring, because someone will otherwise "fix" it to exercise the Action's
   mode.
5. **Leave cases 6 and 7 as marked skips, with the reason in the test.** Do not write a test that
   asserts a bypass succeeds. A `pytest.skip("blocked by 6.4: .cargo/config.toml has no role")`, or a
   commented-out entry in a list that names the blocking task, is honest; a green check on a shape the
   tool cannot see is not. If instead you land the rules first, do it as the other issue and come
   back here.
6. **Correct the dependency line while you are in the roadmap.** [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md)
   gives 3.9 "Deps: 0.4, 3.1, 3.4", but section 2 of the same file explains that two of the seven
   cases are invisible until 3.6 lands. Add 3.6 (or the two slices of it) to that line so the graph
   matches the reasoning, and update the "six-rule set shipped today" phrasing, which is stale: the
   count is twelve.

**Out of scope:** the parity harness against the old script (3.8), the corpus (0.10), the two rule
slices themselves, any change to what the reporters print, and any new rule. Cases 6 and 7 are not in
scope for this issue's own pull request either; they are in scope for the issue that unblocks them.

## Acceptance criteria

- [ ] `tests/bypass/` has a test per Appendix B case, and each of cases 1 to 5 asserts the specific rule ids and severities listed above, not merely a non-zero exit code.
- [ ] Case 2 asserts both findings (the NUL *and* the dynamic-code HIGH), so a change that makes the NUL a skip fails this test.
- [ ] Case 3 is a differential test: identical findings with and without the inline marker text.
- [ ] No payload literal is committed; trigger strings are assembled from fragments at test time, as `AGENTS.md` section 4 requires.
- [ ] `scripts/bypass_probe.py` still reproduces the original result when pointed at the external script (`python3 scripts/bypass_probe.py --script <path>`), with its `--script` contract unchanged.
- [ ] Cases 6 and 7 are recorded as blocked, naming the task that closes them, and no test asserts that a bypass succeeds.
- [ ] `ROADMAP.md` 3.9's dependency line includes the rule task it actually waits on, and the stale rule-count sentence in section 2 is corrected.
- [ ] `python -m pytest`, `ruff check .`, `ruff format --check .`, `mypy src` and `python -m airlock scan --mode full .` all pass, including the new tests.
- [ ] `ROADMAP.md` carries a changelog row with a UTC date, `Last updated` moved, and `python scripts/roadmap_progress.py --check` passing.
- [ ] PR description includes `Closes #{{issue:self}}`.

## Tech stack

- Runtime: Python 3.11, standard library only. [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 forbids adding a runtime dependency, and a scan never touches the network, so a helper library is not an option here.
- Harness to split: [`scripts/bypass_probe.py`](https://github.com/posture-sec/airlock/blob/main/scripts/bypass_probe.py) already holds the seven cases as data (`CASES`, `build`, `commit`, `scan`), and its `--script` contract must keep working.
- Destination: [`tests/bypass`](https://github.com/posture-sec/airlock/blob/main/tests/bypass), which holds a `.gitkeep` today.
- Payloads are assembled from fragments at test time, the way the probe does it. Committing a live-looking payload fails [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 and will close the pull request.
- Run before pushing: `python -m pytest tests/bypass` and `python -m pytest tests/unit/test_collector.py`, since a bypass case that needs a real git tree is the one place the collector runs for real here.

### **Contact & Support**
- [`SUPPORT.md`](https://github.com/posture-sec/airlock/blob/main/SUPPORT.md) — where to ask, the commands CI runs, and the rules that most often get a pull request rejected
- [`SECURITY.md`](https://github.com/posture-sec/airlock/blob/main/SECURITY.md) — private disclosure only; never open an issue about a bypass
