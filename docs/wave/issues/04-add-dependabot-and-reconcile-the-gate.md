---
slug: add-dependabot-and-reconcile-the-gate
title: Enable Dependabot for Actions and pip, and settle how its pull requests pass the roadmap gate
labels: Stellar Wave, complexity: medium, area: ci, enhancement
roadmap: 1.6
---

> **Repo context.** `airlock` is a Python 3.11 standard-library-only scanner: `src/airlock/` holds the pipeline (collector, then rules and detectors, then fingerprints and suppressions, then reporters) behind one CLI, and the rules themselves are data in `rules/builtin/*.toml`. The repository being scanned is untrusted input, so the hard rules in [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 are security properties rather than style. [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md) is the source of truth for what is built and what is only a docstring.

> 🟢 **Unblocked.** CI exists and is green on `main`, which is the only dependency. The gate interaction described below needs an owner decision before the config can merge, and asking for that decision is part of this issue rather than a blocker to it.

## Problem

Two pinned things float. The Actions in [`ci.yml`](https://github.com/posture-sec/airlock/blob/main/.github/workflows/ci.yml)
and
[`roadmap-check.yml`](https://github.com/posture-sec/airlock/blob/main/.github/workflows/roadmap-check.yml)
are pinned to full commit SHAs with the reviewed tag in a comment, which is the right shape and
still a snapshot taken by hand on 2026-10-28. The dev tools are not pinned at all: the install step
is `python -m pip install --quiet . pytest ruff mypy`, so every CI run takes whatever is newest on
the day. `ROADMAP.md` 1.5 records that consequence in its own row: "Dev tool versions float until
Dependabot lands (1.6)."

There is no `.github/dependabot.yml`, so nothing lands.

The interesting half is what happens the first time Dependabot opens a pull request here.
[`scripts/check_roadmap_touched.sh`](https://github.com/posture-sec/airlock/blob/main/scripts/check_roadmap_touched.sh)
fails any diff that changes files but not `ROADMAP.md`, and decision D-07 in `ROADMAP.md` section 7
states that the gate has no exemptions, "including dependency bumps". Dependabot cannot edit
`ROADMAP.md`: it controls its own commit message and nothing else. So the config as written in
task 1.6 produces a stream of permanently red pull requests, which is worse than no config, because
a red check that is always red stops meaning anything. That is the part to solve here.

## What to build

1. **Write the config.** `.github/dependabot.yml` covering both ecosystems the repository actually
   uses: `github-actions` for the two pinned Actions, and `pip` for `pytest`, `ruff` and `mypy`.
   Group the pip entries and schedule weekly, which is what task 1.6 asks for and what D-07's note
   about limiting noise assumes. Note that a `pip` setup with no lockfile has to be scoped to the
   dev requirement list, since the runtime dependency count is zero by design.
2. **Settle the gate interaction, and propose rather than assume.** Two shapes are defensible:
   a human step that appends the changelog row to the Dependabot branch before merge (a small
   `scripts/` helper that writes the row and moves `Last updated`), or an exemption for pull requests
   whose author is the Dependabot bot, which contradicts D-07 and therefore needs the owner to
   change a recorded decision. Pick one, write the reasoning into the pull request, and update
   `ROADMAP.md` section 7 so the decision log and the config agree. Do not quietly add the exemption.
3. **Keep the SHA-pin rule honest.** Dependabot's Actions updates move the pin but cannot read a
   diff. The comment that names the tag each SHA was resolved from is the review aid
   [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 9 depends on, so
   the config should not strip it, and the workflow comment convention should be documented as
   something a bump PR has to preserve.
4. **Prove it before asking for a merge.** Open a throwaway branch in your own fork with the config,
   let Dependabot produce one pull request against it, and show whether the `roadmap` check passes.
   The evidence is the point: this issue is not done on the strength of a plausible YAML file.

**Out of scope:** bumping either Action SHA in this repository (a bump is its own pull request, read
the diff first per `AGENTS.md` 9), adding a lockfile or a runtime dependency (there are none, by
design), and changing what the `checks` job runs.

## Acceptance criteria

- [ ] `.github/dependabot.yml` declares both ecosystems, weekly grouping, and no runtime dependency additions.
- [ ] The chosen gate behaviour is implemented, and `ROADMAP.md` decision D-07 either still reads as it does today or has been amended with the date and the reason.
- [ ] A link to the fork pull request that exercised the config is in the description, with the observed `roadmap` check result.
- [ ] The `Last updated` and changelog convention for a dependency PR is written down where a contributor will find it, in [`CONTRIBUTING.md`](https://github.com/posture-sec/airlock/blob/main/CONTRIBUTING.md) or `AGENTS.md`.
- [ ] `ROADMAP.md` is updated in the same pull request: 1.6 ticked, a changelog row with a UTC date, `Last updated` moved, and `python scripts/roadmap_progress.py --check` passing.
- [ ] `python -m pytest`, `ruff check .`, `ruff format --check .` and `mypy src` all pass.
- [ ] `.github/` is a protected path, so the pull request needs owner review; do not merge it yourself.
- [ ] PR description includes `Closes #{{issue:self}}`.

## Tech stack

- Runtime: Python 3.11, standard library only. [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 forbids adding a runtime dependency, and a scan never touches the network, so a helper library is not an option here.
- Files: `.github/dependabot.yml` (new), [`scripts/check_roadmap_touched.sh`](https://github.com/posture-sec/airlock/blob/main/scripts/check_roadmap_touched.sh), [`tests/unit/test_roadmap_gate.py`](https://github.com/posture-sec/airlock/blob/main/tests/unit/test_roadmap_gate.py) and the D-07 row in [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md) section 7.
- The gate is a shell script with no exemptions today, and [`.github/workflows`](https://github.com/posture-sec/airlock/blob/main/.github/workflows) workflows are protected paths, so both halves of this need owner review.
- Real problem to solve first: a Dependabot pull request cannot edit `ROADMAP.md` without defeating the gate's purpose. Decide the exemption shape and write it down before writing the YAML.
- Run before pushing: `python -m pytest tests/unit/test_roadmap_gate.py` and `sh scripts/check_roadmap_touched.sh origin/main`.

### **Contact & Support**
- [`SUPPORT.md`](https://github.com/posture-sec/airlock/blob/main/SUPPORT.md) — where to ask, the commands CI runs, and the rules that most often get a pull request rejected
- [`SECURITY.md`](https://github.com/posture-sec/airlock/blob/main/SECURITY.md) — private disclosure only; never open an issue about a bypass
