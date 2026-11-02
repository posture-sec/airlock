---
slug: confirm-github-reporting-limits
title: Measure GitHub's annotation, step-summary and SARIF limits and write them into the design
labels: Stellar Wave, complexity: trivial, area: docs, documentation
roadmap: 0.9
---

> **Repo context.** `airlock` is a Python 3.11 standard-library-only scanner: `src/airlock/` holds the pipeline (collector, then rules and detectors, then fingerprints and suppressions, then reporters) behind one CLI, and the rules themselves are data in `rules/builtin/*.toml`. The repository being scanned is untrusted input, so the hard rules in [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 are security properties rather than style. [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md) is the source of truth for what is built and what is only a docstring.

> 🟢 **Unblocked.** This is a documentation and measurement task with no dependency on other open issues. Two shipped design decisions are waiting on it: the reporter caps, and the SARIF result cap that task 7.6 will need.

## Problem

Airlock's reporters assume GitHub truncates output, and the assumption is load-bearing.
[`src/airlock/report/github.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/report/github.py)
orders findings HIGH-first and cuts each severity at a constant, because "GitHub renders only a
fraction of the annotations attached to a check run, and which fraction is not documented well
enough to build on". The numbers it cuts at, 50 HIGH, 25 WARN and 10 INFO, are described in the
source as "deliberately conservative" guesses.

Three places say the same thing out loud: [`ARCHITECTURE.md`](https://github.com/posture-sec/airlock/blob/main/ARCHITECTURE.md)
6.6 carries `[Unverified: exact limits, task 0.9]`, section 15 item 4 asks the question, and the
bypass B8 row ("a flood of WARNs buries a HIGH") is mitigated by exactly these caps. A guess that
sits under a security mitigation is worse than the two outcomes it might be wrong about: if the real
limit is far above 50, Airlock is hiding findings it could have shown, and if it is below, the
"nothing dropped quietly" annotation naming the withheld count never reaches a reader either.

The same gap blocks 7.6 (SARIF output), which needs a result cap and a payload ceiling it does not
have yet.

## What to build

Answer the question with numbers and a date, then make the documents and the code agree.

1. **Read the primary sources.** GitHub's own documentation on workflow commands, check-run
   annotations and step summaries, plus the SARIF upload path in code scanning. Cite the page in
   the pull request, not a summary of it.
2. **Measure the boundary rather than trusting the prose**, where a measurement is cheap. A
   temporary workflow in your own fork that emits N annotations of each severity and a step summary
   of a known size is enough to see where output stops appearing, and it is the evidence the design
   currently lacks. State which numbers are documented and which you observed.
3. **Cover the rest of task 0.9's list** while you are in the same area: the size and result-count
   limits that apply to a SARIF upload, and the behaviour of `github.event.before` on a new branch
   and on a force push, which [`src/airlock/policy.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/policy.py)
   already reasons about, and whether `merge_group` events deliver a usable base.
4. **Write the result back.** Replace the `[Unverified: exact limits, task 0.9]` marker in
   `ARCHITECTURE.md` 6.6 with the numbers, mark section 15 item 4 answered, and either move the
   reporter constants to the measured values or state in the source comment why the conservative
   guess is still the right choice.

**Out of scope:** whether a required status check whose job has been deleted blocks a merge. That is
`ARCHITECTURE.md` 478, tasks 0.13 and 4.5, and it needs repository settings rather than a limit.
Do not raise the caps as a side effect of this issue without the measurement to justify it.

## Acceptance criteria

- [ ] `ARCHITECTURE.md` 6.6 states the measured or documented limits and no longer carries the `[Unverified]` marker for them.
- [ ] `ARCHITECTURE.md` 15 item 4 is marked answered, and `ROADMAP.md` 0.9 is ticked with the date.
- [ ] Each number is attributed to either a cited GitHub documentation page or an observed run, and the two are not mixed in the same sentence.
- [ ] `HIGH_ANNOTATIONS`, `WARN_ANNOTATIONS` and `INFO_ANNOTATIONS` are either changed to values the evidence supports, or their comment says why the current values stand.
- [ ] The SARIF limits 7.6 will need are recorded, so that task no longer has to guess.
- [ ] `ROADMAP.md` carries a changelog row with a UTC date, `Last updated` moved, and `python scripts/roadmap_progress.py --check` passes.
- [ ] `python -m pytest`, `ruff check .`, `ruff format --check .` and `mypy src` all pass.
- [ ] PR description includes `Closes #{{issue:self}}`.

## Tech stack

- Runtime: Python 3.11, standard library only. [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 forbids adding a runtime dependency, and a scan never touches the network, so a helper library is not an option here.
- Constants this measures: `HIGH_ANNOTATIONS`, `WARN_ANNOTATIONS` and `INFO_ANNOTATIONS` in [`src/airlock/report/github.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/report/github.py), and the truncation in [`src/airlock/report/summary.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/report/summary.py).
- Design text being corrected: [`ARCHITECTURE.md`](https://github.com/posture-sec/airlock/blob/main/ARCHITECTURE.md) 6.6 and 15, both of which carry `[Unverified: exact limits, task 0.9]`.
- Method: a workflow that emits a known number of annotations and a known-size summary, then the run's own output as the measurement. GitHub's documented limits and the observed behavior are two different columns; record both.
- Run before pushing: `python -m pytest tests/unit/test_report.py` and `python -m pytest tests/unit`, since a changed cap moves a test expectation.

### **Contact & Support**
- [`SUPPORT.md`](https://github.com/posture-sec/airlock/blob/main/SUPPORT.md) — where to ask, the commands CI runs, and the rules that most often get a pull request rejected
- [`SECURITY.md`](https://github.com/posture-sec/airlock/blob/main/SECURITY.md) — private disclosure only; never open an issue about a bypass
