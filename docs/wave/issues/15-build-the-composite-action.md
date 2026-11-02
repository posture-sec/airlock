---
slug: build-the-composite-action
title: Ship action.yml so a repository can add the scan in one line
labels: Stellar Wave, complexity: high, area: action, enhancement, blocked
roadmap: 4.1
---

> **Repo context.** `airlock` is a Python 3.11 standard-library-only scanner: `src/airlock/` holds the pipeline (collector, then rules and detectors, then fingerprints and suppressions, then reporters) behind one CLI, and the rules themselves are data in `rules/builtin/*.toml`. The repository being scanned is untrusted input, so the hard rules in [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 are security properties rather than style. [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md) is the source of truth for what is built and what is only a docstring.

> ⛔ **Blocked by #{{issue:verify-isolated-python-launch}}.** Task 0.8 has to run first, because the launch mechanism this Action depends on is marked `[Unverified: confirm with a scratch workflow, task 0.8]` in [`ARCHITECTURE.md`](https://github.com/posture-sec/airlock/blob/main/ARCHITECTURE.md) section 10, and it is the mechanism that keeps the hard rule "never run scanner code from the scanned checkout" true rather than merely intended. Build nothing on that line until 0.8 records that `python3 -I` plus an explicit `sys.path` insert loads the package from `GITHUB_ACTION_PATH` while a shadowing `src/airlock/` in the repository under scan is ignored. **If 0.8 refutes it**, this issue changes shape: the Action needs a different carrier for the code, which is an owner decision that earns its own row in the decision log, not something to improvise in a pull request.

## Problem

There is no `action.yml`. The repository has a working scanner, three output formats and a step
summary, a trusted-base policy model and a suite of 475 tests behind one console script, and no way
for any of the five Stellar repos to adopt it. Each of them today runs a copy-pasted
`.github/scripts/malware_scan.py`, which is the exact artifact this project exists to replace:
`PRD.md` 2.3 records that all seven of
that script's bypasses were run on 2026-10-27 and every one exits 0. The replacement cannot be
adopted, only described, until a consumer can write `uses: posture-sec/airlock@<full sha>` and get a
check.

The CLI half is already Action-shaped, which is why this is one file and its contract rather than
engine work:

- `--event` maps `pull_request`, `push`, `workflow_dispatch` and `schedule` onto the three trust
  models, and an event that is not in that table is a usage error rather than a guess, so a scan
  never silently gets the wrong policy source.
- `--format github` writes workflow annotations, HIGH first, with the 50/25/10 per-severity caps and
  a line saying how many were withheld.
- When `GITHUB_STEP_SUMMARY` is set, [`src/airlock/cli.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/cli.py)
  appends the summary render to it, on purpose separately from `--format`: the annotation stream is
  for the author and the summary is for the reviewer who must see every HIGH without opening a log.
- `rules_root()` already resolves the checkout layout the pinned Action uses (`rules/` two levels
  above `src/airlock`), so the code the Action runs can find its rule data without a flag.

What is missing is the invocation contract around all of that, and three decisions the sketch does
not settle.

## What to build

1. **`action.yml`, composite, matching the `ARCHITECTURE.md` section 10 sketch**: `using: composite`,
   one bash step, inputs for `fail-on`, `config` and the wasm manifest with the same defaults the CLI
   uses. User-influenced values reach the script through `env:`, never by interpolation into the shell
   command; the sketch's `AIRLOCK_*` block is the pattern and section 4 of `AGENTS.md` is the reason.
2. **Prove the invocation, do not eyeball it.** The launch line is subtle: `python3 -I` ignores
   `PYTHONPATH` and the script directory, so the package path arrives as `argv` and is popped inside
   the `-c` program. A typo there fails loudly on someone else's repository. Add a test that reads
   `action.yml`, extracts the `run:` block, and executes it against a scratch git repository with
   `GITHUB_ACTION_PATH` pointed at this checkout, asserting the exit code and that the findings are
   the ones the same tree produces through `python -m airlock scan`. Note that there is no YAML parser
   in the runtime and ADR-007 keeps it out of v0.1, so the extraction is a small targeted read of the
   file, not a parsed document: say which lines you take and why that is enough. Do not add a
   dependency to make the test easier.
3. **Settle the event surface.** `pull_request_target` and `merge_group` are not in `EVENT_MODES`, so
   an Action that accepts them gets exit 2. Choose what `action.yml` documents as supported events,
   and for `merge_group` say which trust model applies and why (its checkout is the merge commit, so
   the base is neither `pull_request`'s base SHA nor `push`'s `event.before`); that is a security
   decision, so write it in the file and in `ARCHITECTURE.md` 10 rather than only in the pull request.
   `pull_request_target` deserves an explicit sentence: it runs in the base context with a write
   token, which is the shape this tool's own rules (issue 13) will flag in other people's repos.
4. **Make the `fetch-depth` failure mode legible.** The tool never fetches, so a consumer who checks
   out with the default depth gives `pr` mode an unresolvable base. Confirm what the scan reports today
   and put the requirement where a consumer reads it: in `action.yml`'s `description` or inputs, since
   the caller's workflow is not in this repository.
5. **Run the three events for real.** 4.1's Done when is "it runs on a scratch repo for each event".
   That means a scratch repository on GitHub with this Action pinned by full SHA, one `pull_request`,
   one `push`, one `workflow_dispatch`, recording for each the event name, the mode the CLI resolved,
   the exit code and where policy was read from. `workflow_dispatch` maps to `full`, so it is the case
   that prints the `untrusted-policy-source` INFO; assert the mode reached, not only that the step ran.
6. **State what this repository does about its own scan.** `ci.yml` runs the console script, and it
   cannot reasonably switch to `uses: ./` on a pull request, because the pinned SHA it would use is the
   ref under review. Keep the self-scan on the console script and say so in `ARCHITECTURE.md` 11, so
   the choice is a documented position rather than an oversight.

**Out of scope:** the caller workflow snippet and usage docs (4.2), any release, tag or attestation
work (Phase 5), configuring required checks on this or any dogfooded repository (4.5, 1.3), SARIF
output (7.6), and any change to how the reporters format findings.

## Acceptance criteria

- [ ] `action.yml` exists, is `using: composite`, and passes the #{{issue:verify-isolated-python-launch}} launch mechanism on the runner's Python without reading `PYTHONPATH` or the scanned checkout for scanner code.
- [ ] A test executes the `run:` block from `action.yml` against a scratch repository and gets the same findings and exit code as `python -m airlock scan` on the same tree.
- [ ] No user-influenced or event-payload value is interpolated into a shell command; each arrives through `env:`.
- [ ] `pull_request`, `push` and `workflow_dispatch` each ran on a scratch repository on GitHub, with the event name, resolved mode, exit code and policy source recorded in the pull request.
- [ ] `merge_group` and `pull_request_target` have a documented position in `action.yml` and `ARCHITECTURE.md` 10, with the reasoning for the mode each gets.
- [ ] A shallow checkout in `pr` mode produces a non-zero exit and a finding that names the cause, demonstrated by a test rather than asserted.
- [ ] `ARCHITECTURE.md` 10 loses the `[Unverified]` marker only if 0.8 closed it; a new ADR or decision-log row records any choice the sketch did not make.
- [ ] No runtime dependency was added, no CI step was weakened, and the self-scan still reports zero HIGH findings on this repository.
- [ ] `python -m pytest`, `ruff check .`, `ruff format --check .`, `mypy src` and `python scripts/roadmap_progress.py --check` pass.
- [ ] `ROADMAP.md` records 4.1's state with a changelog row and a UTC date, `Last updated` moved, and the PR description includes `Closes #{{issue:self}}`.

## Tech stack

- Runtime: Python 3.11, standard library only. [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 forbids adding a runtime dependency, and a scan never touches the network, so a helper library is not an option here.
- New file: `action.yml`, composite, at the repository root. It is a protected path and listed in `.github/CODEOWNERS`.
- Code it calls: `main` in [`src/airlock/cli.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/cli.py), the `EVENT_MODES` table that maps an event name to a trust model, and `rules_root`, which already resolves the `$GITHUB_ACTION_PATH` layout.
- No `pip install` in the Action and no fetch: the scanner code comes from the pinned Action's own checkout, which is the whole point of the `-I` launch line and the reason this issue waits on the launch experiment.
- Design text to update in the same pull request: [`ARCHITECTURE.md`](https://github.com/posture-sec/airlock/blob/main/ARCHITECTURE.md) 10 and 11. Caller-side usage docs are task 4.2 and stay out of scope.

### **Contact & Support**
- [`SUPPORT.md`](https://github.com/posture-sec/airlock/blob/main/SUPPORT.md) — where to ask, the commands CI runs, and the rules that most often get a pull request rejected
- [`SECURITY.md`](https://github.com/posture-sec/airlock/blob/main/SECURITY.md) — private disclosure only; never open an issue about a bypass
