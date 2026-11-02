---
slug: test-path-handling-on-windows
title: Test path handling on a Windows runner and settle the reserved-device-name case
labels: Stellar Wave, complexity: medium, area: ci, type: test
roadmap: 7.8
---

> **Repo context.** `airlock` is a Python 3.11 standard-library-only scanner: `src/airlock/` holds the pipeline (collector, then rules and detectors, then fingerprints and suppressions, then reporters) behind one CLI, and the rules themselves are data in `rules/builtin/*.toml`. The repository being scanned is untrusted input, so the hard rules in [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 are security properties rather than style. [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md) is the source of truth for what is built and what is only a docstring.

> 🟢 **Unblocked.** The collector is shipped and green (2.2, 2.14), and `ubuntu-latest` CI already runs on every pull request, so adding a second runner is the only infrastructure this needs.

## Problem

Every test in the suite runs on Linux. The collector takes paths from `git ls-files -z --stage` and
turns them into strings with `os.fsdecode` at
[`src/airlock/collector.py:147`](https://github.com/posture-sec/airlock/blob/main/src/airlock/collector.py),
then opens them relative to the repository root, and
[`src/airlock/roles.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/roles.py)
implements a hand-written glob matcher that splits on `/`. All of that is correct on a
case-sensitive filesystem with no device namespace. None of it has been run anywhere else.
`ROADMAP.md` 7.8 exists for exactly this gap and is unticked.

The case worth the most attention is not the separator, since git emits forward slashes on every
platform. It is that Windows reserves a set of device names that are ordinary filenames
everywhere else: `NUL`, `CON`, `PRN`, `AUX`, `COM1` to `COM9`, `LPT1` to `LPT9`, each with any
extension and regardless of case. Git will happily track a file named `NUL` or `aux.js` on Linux and
macOS. On Windows, opening that relative path without the extended-length `\\?\` prefix resolves to
the device rather than the file, and the null device reads as zero bytes.

If that holds, a scan on a Windows runner reports a clean file it never read, which is the exact
shape this project was written against: `PRD.md` Appendix B case 7 is a payload under a directory the
old script skipped, and the hard rule in [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md)
section 4 is that nothing is skipped silently. It would also mean the collector's size and content
checks are being applied to an empty device.

Treat that as a hypothesis to confirm or refute on a real runner, not as a fact. This issue is
equally done if the answer is "it does not reproduce, here is the test that proves why not".

## What to build

1. **Get a Windows job running somewhere you can iterate**, either a workflow in your own fork or a
   `windows-latest` job added to `ci.yml` behind a decision the owner reviews. Prove the behaviour
   before proposing the permanent CI change.
2. **Test the three things 7.8 names**: separator handling (a tracked path with a backslash in its
   *filename*, which is legal on Linux), case-insensitive collision (a repository whose index holds
   both `postcss.config.MJS` and `postcss.config.mjs`, where the glob matcher's case behaviour and
   the read target are both in question), and the reserved device names.
3. **Handle what you find.** For reserved names the defensible shapes are: detect them and report a
   finding at a severity that affects the exit code, since the file cannot be trusted as read; or
   open with an extended-length absolute path so the read is of the real file. The first is a few
   lines and needs a fixture pair; the second is more correct and needs to be proven on a runner
   rather than reasoned about from here. Say which you chose and why.
4. **Keep the failure honest.** Whatever the fix, an unreadable or substituted path must produce a
   finding and a counted skip reason, in the pattern 2.14 established for unmerged paths.

**Out of scope:** making the whole suite pass on Windows if that requires changing the fixture
builders or the ReDoS timing harness (a timing budget is machine-dependent by nature); path handling
on filesystems other than NTFS; and any change to what the Linux job runs.

## Acceptance criteria

- [ ] Each of the three cases has a test that runs on the platform it is about, and the pull request states which platform each ran on.
- [ ] The reserved-device-name hypothesis is recorded as confirmed or refuted, with the observed output, not as an assumption.
- [ ] If confirmed: a tracked path that cannot be read as itself yields a named finding with a counted skip reason, and a positive and negative fixture for it exist so the fixture gate covers the new rule id.
- [ ] A repository whose index holds two paths differing only in case produces two findings that are not silently merged into one, or the reason it cannot is written into `ARCHITECTURE.md` 6.1.
- [ ] `ARCHITECTURE.md` 6.1 and the fail-closed table in section 8 match the shipped behaviour, and `ROADMAP.md` 7.8 is ticked with its evidence.
- [ ] `ROADMAP.md` carries a changelog row with a UTC date, `Last updated` moved, and `python scripts/roadmap_progress.py --check` passing.
- [ ] `python -m pytest`, `ruff check .`, `ruff format --check .` and `mypy src` all pass on Linux, and `airlock scan --mode full .` reports no HIGH findings.
- [ ] PR description includes `Closes #{{issue:self}}`.

## Tech stack

- Runtime: Python 3.11, standard library only. [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 forbids adding a runtime dependency, and a scan never touches the network, so a helper library is not an option here.
- Code: [`src/airlock/collector.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/collector.py), specifically the `os.fsdecode` call on the git index path, and the read that follows it.
- Tests: [`tests/unit/test_collector.py`](https://github.com/posture-sec/airlock/blob/main/tests/unit/test_collector.py) for the platform-independent cases, and a new job in [`.github/workflows/ci.yml`](https://github.com/posture-sec/airlock/blob/main/.github/workflows/ci.yml) on `windows-latest` for the ones that are not.
- The device-name hypothesis in the issue body has to be confirmed or refuted on a real runner, not argued from documentation. Either outcome is a result; record which.
- Expect no production change if the hypothesis is refuted. The deliverable is the test and the recorded answer.

### **Contact & Support**
- [`SUPPORT.md`](https://github.com/posture-sec/airlock/blob/main/SUPPORT.md) — where to ask, the commands CI runs, and the rules that most often get a pull request rejected
- [`SECURITY.md`](https://github.com/posture-sec/airlock/blob/main/SECURITY.md) — private disclosure only; never open an issue about a bypass
