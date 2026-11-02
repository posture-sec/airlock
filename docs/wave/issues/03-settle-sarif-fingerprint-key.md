---
slug: settle-sarif-fingerprint-key
title: Settle the SARIF partialFingerprints key spelling after the rename
labels: Stellar Wave, complexity: trivial, area: docs, enhancement, good first issue
roadmap: 7.12
---

> **Repo context.** `airlock` is a Python 3.11 standard-library-only scanner: `src/airlock/` holds the pipeline (collector, then rules and detectors, then fingerprints and suppressions, then reporters) behind one CLI, and the rules themselves are data in `rules/builtin/*.toml`. The repository being scanned is untrusted input, so the hard rules in [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 are security properties rather than style. [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md) is the source of truth for what is built and what is only a docstring.

> 🟢 **Unblocked.** Its only dependency, the 1.12 rename sweep, merged on 2026-10-28. This is a bounded decision with a grep-verified target and no runtime code to change.

## Problem

The rename sweep replaced 37 stale working-name spellings across the four design documents but
left the SARIF fingerprint key undecided. This issue settles the SARIF row of
[`ARCHITECTURE.md`](https://github.com/posture-sec/airlock/blob/main/ARCHITECTURE.md) 6.6 on
`partialFingerprints["airlock/v1"]` (D-09).

The key is part of the planned output contract, not a cosmetic label. Settling it before SARIF
ships avoids having to migrate consumers of a released key. The fingerprint algorithm is unchanged.
[`src/airlock/report/sarif.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/report/sarif.py)
remains a docstring-only stub until task 7.6; this decision does not implement SARIF output.

## What to build

Record the settled spelling where the next reader will look, and leave a check behind so it
cannot silently revert.

1. **Use `airlock/v1`.** The package is `airlock`, the CLI is `airlock`, the policy file is
   `airlock.toml` and the planned Action environment prefix is `AIRLOCK_`. The key follows that
   name, and the `v1` suffix leaves room for a future fingerprint version. No migration is needed
   before SARIF ships.
2. **Apply it** in `ARCHITECTURE.md` 6.6 and in the `sarif.py` docstring as a settled decision,
   while keeping the reporter unimplemented.
3. **Record D-09** in the `ROADMAP.md` section 7 decision log. The id was free when checked for
   this issue. Sync the PRD, architecture ADR table and essentials with the decision.
4. **Make it checkable.** Follow `tests/unit/test_model.py`'s documented-constant pattern with
   tests that read the actual SARIF row in `ARCHITECTURE.md` 6.6 and the stub docstring. Changing
   only that row must fail even if the decided key still appears elsewhere in the document.

**Out of scope:** implementing the SARIF reporter. It stays a stub until 7.6, and this issue is done
when the name it will use is settled and documented.

## Acceptance criteria

- [ ] `git grep -n "repo[G]uard"` over the tracked tree returns only `ROADMAP.md` rows that record the rename history, and no design document or issue draft. The character class keeps this criterion from matching itself.
- [ ] `ARCHITECTURE.md` 6.6 names the decided key, and `sarif.py`'s docstring states it as settled rather than as an open question.
- [ ] A D-09 row exists in the `ROADMAP.md` decision log with the date and the spelling.
- [ ] The new tests fail when only the SARIF row or stub key changes, even if the decided key remains elsewhere, and pass otherwise.
- [ ] `ROADMAP.md` is updated in the same pull request: 7.12 ticked, a changelog row with a UTC date, `Last updated` moved, and `python scripts/roadmap_progress.py --check` passing.
- [ ] `python -m pytest`, `ruff check .`, `ruff format --check .` and `mypy src` all pass.
- [ ] PR description includes `Closes #{{issue:self}}`.

## Tech stack

- Runtime: Python 3.11, standard library only. [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 forbids adding a runtime dependency, and a scan never touches the network, so a helper library is not an option here.
- Where the spelling is specified: [`ARCHITECTURE.md`](https://github.com/posture-sec/airlock/blob/main/ARCHITECTURE.md) 6.6, in the `sarif (P1)` row of the reporter table.
- What it must agree with: [`src/airlock/fingerprint.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/fingerprint.py), which computes the digest, and the verbatim-assertion style already used in [`tests/unit/test_model.py`](https://github.com/posture-sec/airlock/blob/main/tests/unit/test_model.py).
- The deliverable is one decision plus tests that fail when the document and the stub drift again, and a decision-log row in [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md) section 7.
- Out of scope: writing `sarif.py`. SARIF output is 7.6 and stays deferred; this issue only settles the key that issue will use.

### **Contact & Support**
- [`SUPPORT.md`](https://github.com/posture-sec/airlock/blob/main/SUPPORT.md) — where to ask, the commands CI runs, and the rules that most often get a pull request rejected
- [`SECURITY.md`](https://github.com/posture-sec/airlock/blob/main/SECURITY.md) — private disclosure only; never open an issue about a bypass
