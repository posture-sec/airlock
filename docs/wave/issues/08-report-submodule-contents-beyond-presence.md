---
slug: report-submodule-contents-beyond-presence
title: Make a submodule an actionable finding instead of an INFO note
labels: Stellar Wave, complexity: medium, area: engine, enhancement
roadmap: 7.2
---

> **Repo context.** `airlock` is a Python 3.11 standard-library-only scanner: `src/airlock/` holds the pipeline (collector, then rules and detectors, then fingerprints and suppressions, then reporters) behind one CLI, and the rules themselves are data in `rules/builtin/*.toml`. The repository being scanned is untrusted input, so the hard rules in [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 are security properties rather than style. [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md) is the source of truth for what is built and what is only a docstring.

> 🟢 **Unblocked.** The collector already records gitlinks, so this is a decision about what a scan says about them plus the code and fixtures for that decision. No other open issue is involved.

## Problem

A tracked submodule contributes nothing to a scan. In
[`src/airlock/collector.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/collector.py),
an index entry with mode `160000` yields one `submodule-present` finding at INFO and the path is
returned with `skip_reason = SKIP_SUBMODULE`, so no file beneath it is ever read. `git ls-files`
reports the gitlink and nothing inside it, which is correct git behaviour and means the entire
subtree is outside the scan.

The message asserts the mitigation: `"embedded repository: its contents are scanned by its own
pipeline, not here"`. That is a claim about a third party's CI, and the scanner has no way to know
whether it is true. The parent repository controls the gitlink: repointing it at a different URL, or
at a commit of the same URL that carries a payload, changes one line of `.gitmodules` plus a mode
`160000` index entry, and Airlock reports it as INFO in a run that still exits 0.

This is the same shape as the bypass the project was written against. `PRD.md` Appendix B case 7 is
a payload under `vendor/` that the old script never opened because `SKIP_DIRS` matched the path
prefix, and the whole point of the rewrite is that a file which was not looked at must not read as a
file that was clean. INFO is the quietest severity that exists, and a scanner-state finding cannot be
suppressed, so today there is no way for a maintainer to say "this repository must not have
submodules" and have a scan enforce it.

## What to build

1. **Decide the policy first, in the issue thread or the pull request description.** The candidates
   are: raise `submodule-present` to WARN by default and let a trusted policy setting raise it to
   HIGH; add a `submodules` key to the trusted policy that lists allowed URLs, with anything outside
   the list reported at HIGH; or treat every gitlink as HIGH and require an explicit allow to build
   at all. All three are defensible. The one that is not allowed is leaving it at INFO with an
   unverifiable claim in its message.
2. **Implement it in the collector and the policy model**, reading the allow list from the trusted
   base like every other policy input, never from HEAD. A gitlink records only a path and a commit,
   so the URL has to come from `.gitmodules`, which is itself a tracked file the scan already reads:
   cross-check the two directions, a gitlink with no `.gitmodules` entry and an entry whose path has
   no gitlink are both cases worth naming, and a URL outside the allow list is the one that decides
   the severity.
3. **Give the rule its fixtures.** Every rule needs a positive and a negative case assembled at test
   time, and the fixture gate from 2.12 fails without both. Build the gitlink the way
   `test_a_gitlink_yields_submodule_present` does today, against a real temporary repository rather
   than a mocked index.
4. **Update the documents the change touches**: the fail-closed table in `ARCHITECTURE.md` 8, which
   currently reads `| Submodule | submodule-present (INFO) |`, the collector section 6.1, and
   `ARCHITECTURE_ESSENTIALS.md` where the finding ids are listed.

**Out of scope:** scanning inside a submodule, which would mean fetching or requiring the consumer to
have initialised it, and either choice breaks a hard rule (no network during a scan; never trust
what the checkout handed you). Also out: history scanning of unreachable gitlinks, which is task 9.3.

## Acceptance criteria

- [ ] The chosen policy is stated in the pull request with the reasoning, and the shipped behaviour matches it.
- [ ] A gitlink with no `.gitmodules` entry, and an entry with no gitlink at that path, each produce their own finding rather than being covered by the presence finding.
- [ ] `submodule-present` is no longer INFO-only, or the allow-list setting exists and its absence is what makes a gitlink report at the raised severity.
- [ ] Positive and negative fixtures exist for every new rule id, and `tests/unit/test_fixtures.py` passes without being told about them by hand.
- [ ] A trusted-base test proves the allow list is read from the base commit, so a pull request cannot add a gitlink and authorise it in the same change.
- [ ] `ARCHITECTURE.md` 6.1 and 8, and the `ARCHITECTURE_ESSENTIALS.md` finding-id list, match the shipped severity, and any new id appears in `STATE_RULE_IDS` or the rule data as appropriate.
- [ ] `ROADMAP.md` is updated in the same pull request: 7.2 ticked, changelog row with a UTC date, `Last updated` moved, `python scripts/roadmap_progress.py --check` passing.
- [ ] `python -m pytest`, `ruff check .`, `ruff format --check .` and `mypy src` all pass, and `airlock scan --mode full .` reports no HIGH findings.
- [ ] PR description includes `Closes #{{issue:self}}`.

## Tech stack

- Runtime: Python 3.11, standard library only. [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 forbids adding a runtime dependency, and a scan never touches the network, so a helper library is not an option here.
- Code: [`src/airlock/collector.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/collector.py), which emits `submodule-present` and carries the `SKIP_SUBMODULE` reason, and {L('src/airlock/policy.py')} for the state-finding side.
- Existing test to extend: `test_a_gitlink_yields_submodule_present` in [`tests/unit/test_collector.py`](https://github.com/posture-sec/airlock/blob/main/tests/unit/test_collector.py).
- A gitlink records a mode, a path and a commit; the URL lives in `.gitmodules`, which is a separate read and may disagree with the index. Say which one a finding names.
- Protected path: [`src/airlock/collector.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/collector.py) is fail-closed machinery. A change there must not turn a skip into a silent pass, and needs owner review.

### **Contact & Support**
- [`SUPPORT.md`](https://github.com/posture-sec/airlock/blob/main/SUPPORT.md) — where to ask, the commands CI runs, and the rules that most often get a pull request rejected
- [`SECURITY.md`](https://github.com/posture-sec/airlock/blob/main/SECURITY.md) — private disclosure only; never open an issue about a bypass
