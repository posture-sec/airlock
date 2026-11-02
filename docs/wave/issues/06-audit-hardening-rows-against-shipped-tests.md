---
slug: audit-hardening-rows-against-shipped-tests
title: Audit the three Phase 7 hardening rows the Phase 2 work may already satisfy
labels: Stellar Wave, complexity: trivial, area: tests, type: test
roadmap: 7.3, 7.10, 7.11
---

> **Repo context.** `airlock` is a Python 3.11 standard-library-only scanner: `src/airlock/` holds the pipeline (collector, then rules and detectors, then fingerprints and suppressions, then reporters) behind one CLI, and the rules themselves are data in `rules/builtin/*.toml`. The repository being scanned is untrusted input, so the hard rules in [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 are security properties rather than style. [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md) is the source of truth for what is built and what is only a docstring.

> 🟢 **Unblocked.** All three rows depend only on 2.2, 2.8 and 2.9, which merged and are green in CI. This is a reading-and-recording task with one small test-writing tail.

## Problem

Phase 7 is written as the hardening pass that follows Phase 2, and for three rows the tests it asks
for appear to have already shipped:

- **7.3, encoding tests.** Its "Done when" is UTF-16 with BOM, non-UTF-8 and CRLF.
  [`tests/unit/test_collector.py`](https://github.com/posture-sec/airlock/blob/main/tests/unit/test_collector.py)
  already has `test_utf16_with_a_bom_does_not_trip_the_nul_rule`,
  `test_utf16_without_a_bom_is_still_reported`, `test_utf8_bom_is_stripped`,
  `test_undecodable_bytes_in_a_source_file_are_still_scanned` and
  `test_undecodable_bytes_elsewhere_are_a_warn_and_a_skip`. CRLF is the one with no collector-level
  case: the only `\r\n` assertions in the suite are about evidence truncation and forged
  annotations, not about how a CRLF file is read, numbered and matched.
- **7.10, output flooding.** `test_report.py` has `test_a_warn_flood_cannot_push_a_high_out_of_the_output`
  for annotations and `test_B8_a_warn_flood_keeps_every_high_visible` for the step summary.
- **7.11, suppression churn.** `test_suppression.py` has the expiry boundary
  (`test_the_warning_window_is_inclusive`, `test_an_entry_expiring_today_still_covers`) and the
  reindexing cases (`test_B5_a_second_copy_of_a_suppressed_line_is_reported`,
  `test_deleting_the_first_copy_returns_the_later_suppression`).

None of the three rows is ticked, so `ROADMAP.md` currently says Phase 7 is 0 of 12 while the tests
it describes are in the suite and running on every pull request. That is the failure mode the
roadmap rule exists to prevent, in the opposite direction from the usual one: an overstated backlog
is still a false statement about the repository, and it sends contributors at work that is done.

## What to build

1. **Read each row against its tests**, and decide on the evidence rather than on how the row is
   worded. For each of 7.3, 7.10 and 7.11 the answer is one of: tick it, tick it with the residual
   named in the row, or leave it open and say what is missing in one sentence.
2. **Write the CRLF cases** if 7.3's audit confirms the gap, which is the likely outcome: a tracked
   file whose lines end `\r\n` must be read, line-numbered and pattern-matched the same way, and a
   finding inside it must fingerprint identically to the LF form or differ for a stated reason. That
   second half matters because a fingerprint that changes when an editor flips line endings silently
   invalidates an owner's suppression.
3. **Record the audit** in the task lines themselves, the way 2.14 and 5.7 do it: what was checked,
   which test proves it, and what is still open. `ROADMAP.md` section 2's prose and the progress
   table follow from the boxes, so regenerate the table rather than editing it.
4. **Do not expand.** If the audit turns up a behavioural defect rather than a missing test, that is
   a new task with its own id in Phase 7, added here and fixed in its own pull request.

**Out of scope:** the other nine Phase 7 rows, and any change to `src/airlock/` that is not forced by
a defect the CRLF tests actually find.

## Acceptance criteria

- [ ] Each of 7.3, 7.10 and 7.11 ends the pull request either ticked with its evidence, or open with one sentence naming precisely what is missing.
- [ ] The CRLF collector cases exist and fail before the reading or numbering code is touched, if the audit found the gap; if it did not, the row says which test covers it.
- [ ] A fingerprint-parity assertion for LF against CRLF exists, or the reason it cannot hold is written into the task line.
- [ ] `python scripts/roadmap_progress.py --check` passes against the edited file, and the Phase 7 row in section 2 matches the boxes.
- [ ] No test was weakened, skipped or deleted to make this pass, and no row was ticked without running the suite.
- [ ] `python -m pytest`, `ruff check .`, `ruff format --check .` and `mypy src` all pass.
- [ ] PR description includes `Closes #{{issue:self}}`.

## Tech stack

- Runtime: Python 3.11, standard library only. [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 forbids adding a runtime dependency, and a scan never touches the network, so a helper library is not an option here.
- Rows under audit: 7.3, 7.10 and 7.11 in [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md).
- Tests to read first: [`tests/unit/test_collector.py`](https://github.com/posture-sec/airlock/blob/main/tests/unit/test_collector.py), [`tests/unit/test_suppression.py`](https://github.com/posture-sec/airlock/blob/main/tests/unit/test_suppression.py), [`tests/unit/test_report.py`](https://github.com/posture-sec/airlock/blob/main/tests/unit/test_report.py) and [`tests/unit/test_redos.py`](https://github.com/posture-sec/airlock/blob/main/tests/unit/test_redos.py). The issue body names the specific cases that look like they already cover each row.
- Deliverable is a verdict per row with the test name that proves it, and a new task only where the proof is missing. One gap is already known: CRLF handling at the collector.
- Run before pushing: `python -m pytest tests/unit` and read the failure list rather than the pass count, because a row that looks covered may be covered by a test that asserts something adjacent.

### **Contact & Support**
- [`SUPPORT.md`](https://github.com/posture-sec/airlock/blob/main/SUPPORT.md) — where to ask, the commands CI runs, and the rules that most often get a pull request rejected
- [`SECURITY.md`](https://github.com/posture-sec/airlock/blob/main/SECURITY.md) — private disclosure only; never open an issue about a bypass
