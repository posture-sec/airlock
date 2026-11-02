---
slug: verify-isolated-python-launch
title: Confirm python3 -I with an explicit sys.path insert in a scratch workflow
labels: Stellar Wave, complexity: trivial, area: action, enhancement, good first issue
roadmap: 0.8
---

> **Repo context.** `airlock` is a Python 3.11 standard-library-only scanner: `src/airlock/` holds the pipeline (collector, then rules and detectors, then fingerprints and suppressions, then reporters) behind one CLI, and the rules themselves are data in `rules/builtin/*.toml`. The repository being scanned is untrusted input, so the hard rules in [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 are security properties rather than style. [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md) is the source of truth for what is built and what is only a docstring.

> 🟢 **Unblocked.** This is a one-hour verification task with no code change and no dependency on any other open issue. It is the single highest-leverage row in the tracker: task 4.1, the composite Action, lists it as a dependency.

## Problem

The design distributes Airlock as a composite GitHub Action that runs the scanner out of
`$GITHUB_ACTION_PATH`, the pinned copy of *this* repository, and never out of the checkout being
scanned. [`ARCHITECTURE.md`](https://github.com/posture-sec/airlock/blob/main/ARCHITECTURE.md)
section 10 sketches the launch as:

```
python3 -I -c 'import sys; sys.path.insert(0, sys.argv.pop(1)); from airlock.cli import main; raise SystemExit(main())' "$GITHUB_ACTION_PATH/src" scan ...
```

`-I` implies `-E` and `-P`: it ignores `PYTHONPATH`, the user site directory and the script's own
directory, which is why the path has to arrive through `argv`. Every part of that sentence is a
claim about CPython and Actions behaviour that nobody has executed on a runner. It is marked
`[Unverified: confirm with a scratch workflow, task 0.8]` in the design, and
[`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 10 tells a
contributor to stop when a task depends on an unverified item.

Until it is confirmed, 4.1 cannot be scoped honestly: if `-I` plus an `argv` path insert does not
work on `ubuntu-latest`, the Action needs a different launch (a `sitecustomize`-free wrapper file,
or installing the wheel into a throwaway virtualenv at run time), and that is an architecture
change rather than a detail inside `action.yml`.

## What to build

Run the sketch, not a paraphrase of it, on a standard GitHub runner and record what happened.

1. **Build the scratch repository.** A public repo with a `main` branch, plus a second copy of
   Airlock it can point at. The Action under test can be referenced with `uses: ./`-style local
   syntax or a `uses:` line pointing at an Airlock branch, whichever you can iterate on faster.
2. **Prove the isolation, not just the import.** A scan that prints findings proves the module
   loaded. It does not prove the loaded module came from `GITHUB_ACTION_PATH`. Make the checkout
   contain a *different* `src/airlock/` (one whose `cli.main` prints a marker string) and show the
   marker does not appear. That is the property the trust model rests on.
3. **Test the failure shapes** the design assumes away: a repository with no history (shallow
   checkout, so `--base` is unresolvable), and a `pull_request` event where
   `github.event.pull_request.base.sha` is present. Record the exit codes you see against the
   documented 0/1/2/3.
4. **Record the result.** Replace the `[Unverified]` marker in `ARCHITECTURE.md` 10 with the
   observed outcome and the runner date, tick task 0.8 in `ROADMAP.md`, and add the changelog row.
   If the answer is "it does not work", write what actually happened and what the alternative
   launch is; a refutation is a complete deliverable for this issue and is the more valuable one if
   it is true.

**Out of scope:** writing `action.yml` itself (that is 4.1 and a separate issue), and any change to
`src/airlock/`. If the only way to make the launch work touches the CLI, open an issue describing
it instead of landing the change here.

## Acceptance criteria

- [ ] `ARCHITECTURE.md` 10 no longer carries the `[Unverified]` marker for this claim, and states what was run, on which runner, on what date.
- [ ] A link to the scratch workflow run (a public Actions run URL) is in the pull request description, and the run shows a scan executing under `python3 -I`.
- [ ] The checkout-shadowing test is shown: a `src/airlock/` in the scanned repository that differs from the Action's copy, with the evidence that the Action's copy ran.
- [ ] Exit codes for a shallow checkout and for a `pull_request` event are recorded against the documented meanings.
- [ ] `ROADMAP.md` is updated in the same pull request: 0.8 ticked, a changelog row with a UTC date, `Last updated` moved, and `python scripts/roadmap_progress.py --check` passing.
- [ ] `python -m pytest`, `ruff check .`, `ruff format --check .` and `mypy src` all pass (they should be unaffected; a change to a doc is still gated by the suite).
- [ ] PR description includes `Closes #{{issue:self}}`.

## Tech stack

- Runtime: Python 3.11, standard library only. [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 forbids adding a runtime dependency, and a scan never touches the network, so a helper library is not an option here.
- Surface: a scratch repository and one throwaway workflow. Nothing in [`src/airlock`](https://github.com/posture-sec/airlock/blob/main/src/airlock) changes; the launch line imports [`src/airlock/cli.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/cli.py)'s `main` from `$GITHUB_ACTION_PATH/src`, and that import path is the thing under test.
- Design text being verified: [`ARCHITECTURE.md`](https://github.com/posture-sec/airlock/blob/main/ARCHITECTURE.md) section 10, which carries the `[Unverified]` marker this issue removes.
- Run before pushing: `python -m airlock scan --mode full .` locally, then read the runner's log for the module path the child process actually resolved.
- Evidence this issue asks for is a runner log and a shadowing test, not a green pytest run. Paste the log into the pull request.

### **Contact & Support**
- [`SUPPORT.md`](https://github.com/posture-sec/airlock/blob/main/SUPPORT.md) — where to ask, the commands CI runs, and the rules that most often get a pull request rejected
- [`SECURITY.md`](https://github.com/posture-sec/airlock/blob/main/SECURITY.md) — private disclosure only; never open an issue about a bypass
