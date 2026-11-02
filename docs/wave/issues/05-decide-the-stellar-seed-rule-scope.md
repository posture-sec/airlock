---
slug: decide-the-stellar-seed-rule-scope
title: Check whether gitleaks and TruffleHog already detect Stellar secret seeds, and decide D-06
labels: Stellar Wave, complexity: trivial, area: detectors, documentation
roadmap: 0.7
---

> **Repo context.** `airlock` is a Python 3.11 standard-library-only scanner: `src/airlock/` holds the pipeline (collector, then rules and detectors, then fingerprints and suppressions, then reporters) behind one CLI, and the rules themselves are data in `rules/builtin/*.toml`. The repository being scanned is untrusted input, so the hard rules in [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 are security properties rather than style. [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md) is the source of truth for what is built and what is only a docstring.

> **Decision recorded locally, 2026-10-28 UTC: KEEP, approved by the owner.** Retain the offline checksum-valid plaintext tracked-file detector. Task 0.7 is complete; implementation remains 6.2 (`strkey.py`) and 6.3 (the detector). This corrects the repository draft only; it does not update or close the already-published issue #24.

## Problem

At filing, `ARCHITECTURE.md` 9.4 specified a Stellar secret-seed detector with byte
constants recalled from memory, and D-06 was Open. Task 0.7 asked whether existing
secret scanners made this work redundant before implementing it.

The source verification is now recorded in `ARCHITECTURE.md` 9.4 with pinned links:
canonical uppercase Base32, 56 characters, 35 decoded bytes, version `0x90`, 32 seed
bytes, and CRC16-XMODEM over the first 33 bytes stored as a 2-byte little-endian checksum.
At the inspected revisions, neither tool has a dedicated Stellar checksum detector;
Gitleaks's `generic-api-key` may incidentally overlap through assignment context and
entropy. This is source inspection only, not executed-tool coverage.

The owner approved **KEEP** on 2026-10-28 UTC, recorded in D-06. This unblocks the
scope dependency, not the implementation. A valid test vector also passes the checksum;
funding, live use and testnet use cannot be inferred from the encoding.

## What to build

1. **Check the two tools at the source.** Read the current gitleaks default rule set and TruffleHog's
   detectors in their repositories, not in a blog post. Report whether either matches a Stellar
   `S…` secret seed, with the rule id or file path and the commit you read. Note whether they decode
   and verify the checksum or only pattern-match. Checksum validation rejects malformed
   candidates, not valid test vectors. Adjacent-text coverage depends on candidate boundaries
   and context; a checksum cannot recover a candidate the pattern missed. Distinguish source
   inspection from an executed-tool coverage test.
2. **Verify the encoding details** you are reasoning about, from the reference implementation in
   `stellar-go` or the `strkey` specification, and record them. Do not correct one remembered
   constant with another.
3. **Record the owner-approved KEEP decision.** Fill in D-06 with the evidence and UTC date.
   Retain offline checksum-valid plaintext tracked-file detection, with explicit reasoned
   suppressions for deliberate test vectors and no claim about funding or live use.
4. **Adjust the queue.** Task 0.7 closes on the decision; 6.2 and 6.3 stay open for implementation
   and reference-derived fixtures. Keep `ARCHITECTURE.md` 9.4 and PRD FR-17 consistent with D-06.

**Out of scope:** implementing `strkey.py` or the detector. This issue ends at the decision.

## Acceptance criteria

- [ ] The pull request names the gitleaks and TruffleHog rules found, with file paths and the commit or version read, or states plainly that neither has one.
- [ ] The strkey byte details in `ARCHITECTURE.md` 9.4 are confirmed against a reference or corrected, and the `[Unverified]` marker there is gone or replaced with a citation.
- [ ] D-06 in the `ROADMAP.md` decision log reads Decided, with the date, the choice and the evidence.
- [ ] Tasks 6.2 and 6.3, and `PRD.md`'s corresponding FR row, are consistent with that decision.
- [ ] `ROADMAP.md` carries a changelog row with a UTC date, `Last updated` moved, and `python scripts/roadmap_progress.py --check` passing.
- [ ] `python -m pytest`, `ruff check .`, `ruff format --check .` and `mypy src` all pass.
- [ ] No live-looking seed is committed anywhere in the repository: test vectors are constructed from a documented reference, and a real-looking `S…` string in a fixture is a rejection.
- [ ] PR description includes `Closes #{{issue:self}}`.

## Tech stack

- Runtime: Python 3.11, standard library only. [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 forbids adding a runtime dependency, and a scan never touches the network, so a helper library is not an option here.
- Code today: [`src/airlock/detectors/stellar_seed.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/detectors/stellar_seed.py) and [`src/airlock/strkey.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/strkey.py) are stubs of a few lines each, registered as neither `DETECTORS` nor `DETECTOR_NAMES` in [`src/airlock/detectors/__init__.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/detectors/__init__.py).
- Design text: [`ARCHITECTURE.md`](https://github.com/posture-sec/airlock/blob/main/ARCHITECTURE.md) 9.4, now source-cited at pinned revisions, and the owner-approved KEEP decision D-06 in [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md).
- Recorded outcome: retain the planned rule, not a general secret scanner. Do not implement or delete either stub in this docs-only task.
- Do not commit a live-looking seed while testing the tools you compare. Build any probe key from fragments, per [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4.

### **Contact & Support**
- [`SUPPORT.md`](https://github.com/posture-sec/airlock/blob/main/SUPPORT.md) — where to ask, the commands CI runs, and the rules that most often get a pull request rejected
- [`SECURITY.md`](https://github.com/posture-sec/airlock/blob/main/SECURITY.md) — private disclosure only; never open an issue about a bypass
