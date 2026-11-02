# Wave application: the draft, and what it still needs

Nothing in this file has been submitted. It is the text and the checklist, so the decision is one
reading away rather than several.

## 1. The three facts that decide timing

- **Neither this repository nor its predecessor is on the approved-repository list.** The check on
  2026-10-28 ran against `airlock-sec/airlock` (842 repositories at that reading) and did not include
  it; the program page read 838 approved repositories with no active or upcoming wave on 2026-11-02,
  and `posture-sec/airlock` has never been submitted at its new path. The
  list is only readable from the Drips dashboard, so re-confirm it there immediately before
  submitting rather than trusting this line: an application that reads as a duplicate is worse than a
  late one.
- **A rejected repository cannot re-apply.** The route after a rejection is an appeal through the
  dashboard. That single rule is why this draft states what is not built.
- **Wave 10 ran 15 to 22 October 2026 and has closed.** The next submission is for the following
  cycle, which is also the cycle these fifteen issues would be live for. Budgets reset per Wave, and
  unresolved issues roll over, so issues published now are still counted later.

Decision **D-05** ("Pursue SCF or Drips Wave funding") is still `Open` in
[`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md) section 7, and task 8.4
owns it. This file prepares the Wave half of that choice; it does not make it.

## 2. What the form asks for, and what to write

### Project description (one paragraph, plain English)

> Airlock is a command-line scanner and GitHub Action that checks Stellar and Soroban open-source
> repositories for supply-chain compromise. The five repositories in this ecosystem run a
> copy-pasted scan script, and a review of that script found seven ways past it: a `.wasm` file of
> any content, a NUL byte in a text file, an inline allow-marker on a payload line, a two-byte
> allowlist that disables the scan for the whole tree, a decode-then-eval payload that only ever
> scores a warning, a Cargo runner with no rule reading it, and a skipped `vendor/` directory. All
> seven were run against the real script on 2026-10-27 and every one exited 0, which passes the
> job. Airlock closes those shapes by refusing to treat an unread file as a clean one: every skip is
> a finding, policy and the Wasm manifest are read from the trusted base rather than from the change
> under review, suppressions are fingerprint-keyed and carry a reason and an expiry, and the scan
> never returns success after an error. It is Python 3.11 with no runtime dependencies, so it adds
> nothing to the supply chain it is auditing.

### What is real today, and what is not

Say this plainly rather than letting a reviewer find it.

| Claim | Status |
|---|---|
| The scanner runs: 22 rules, 3 code detectors plus the pattern engine, three output formats plus a step summary, 664 tests, CI green on every pull request, and it scans this repository on every build | Built, and the CI runs are public |
| The seven bypasses are confirmed against the real script, with a reproducible harness | Done 2026-10-27; `scripts/bypass_probe.py` reproduces it |
| Five of the seven fail closed under Airlock today, measured | Now six. Cases 1 to 5 were measured on the `cfg-*` and `wasm-*` rules, and case 7 (a decode-and-eval payload under `vendor/`) was measured on 2026-10-30 against `python -m airlock scan --mode full` in a scratch repository: `1 HIGH · exit 1` from `pat-decode-eval`, which task 3.6's text-side slice added. Only case 6, a `.cargo/config.toml` shell `runner`, stays invisible until `cargo_vectors` (6.4). No bypass harness locks these in yet; that is task 3.9, issue 14 |
| A repository can install it as a GitHub Action | Not built. `action.yml` is task 4.1, issue 15 |
| It detects Stellar-specific compromise (Soroban size limits, SEP metadata, secret seeds) | Not built. D-06 is owner-approved KEEP as of 2026-10-28 UTC for offline checksum-valid plaintext tracked-file seeds; implementation remains 6.2/6.3. This does not add size-limit or SEP-metadata checks. |
| There is a release to pin | `v0.0.1` exists as a pre-release since 2026-11-02, described in its own notes as not a version to depend on. No signed artifact and no attestation, which are task 5.3, and `v0.1.0` is Phase 5 |
| Someone outside this repository uses it | No adoption evidence at all |

The last row is the weakest part of this application and the reason task 8.4 lists adoption evidence
as a dependency. The honest counter is that the program funds *maintainers with a plan*, and fifteen
scoped issues across four areas with a test-first contribution gate is the evidence available now.

### Supporting links

The standard submission asks for a live app URL, both repo URLs, on-chain verification links and a
demo video. Airlock has no app, no contracts and no deployment, so the equivalents are:

- Repository: `https://github.com/posture-sec/airlock`
- The bypass evidence: [`PRD.md`](https://github.com/posture-sec/airlock/blob/main/PRD.md)
  Appendix B, and [`scripts/bypass_probe.py`](https://github.com/posture-sec/airlock/blob/main/scripts/bypass_probe.py)
- The design: [`ARCHITECTURE_ESSENTIALS.md`](https://github.com/posture-sec/airlock/blob/main/ARCHITECTURE_ESSENTIALS.md)
  for the hard rules and [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md)
  for what exists versus what is planned
- A green CI run on `main`, citable by run id

**The demo is the gap worth closing before submitting.** The guide is right that a submission
without a working demo reads as unfinished; for a scanner the demo is a terminal recording, not a
URL. One that runs the same payload past the current script (exit 0, job green) and then past
Airlock (HIGH, exit 1) is the whole argument in ninety seconds, it can be produced locally with
`asciinema` or `script`, and it needs nothing built first. Do that before the form goes in.

### Planned issues description

> Fifteen issues, drawn from the open rows of the project roadmap rather than invented for the
> Wave, and each one grounded in a file and a line rather than in a plan. Five are Trivial, which is
> the tier this tracker is thinnest on and the only entry point into a codebase this specialized:
> confirming a runner launch mechanism, measuring GitHub's annotation limits against constants the
> code already uses, settling one fingerprint-key spelling left over from a rename, recording the
> Stellar seed scope decision (0.7, now owner-approved KEEP after source comparison, not tool execution),
> and auditing three hardening rows that shipped tests may already satisfy. Seven are Medium,
> including one real defect found while writing these: a rule id
> that is both scanner-state and a loaded rule makes a non-suppressible class of finding
> suppressible, reproduced on the shipped build. Three are High and they are the coverage that
> decides whether the tool catches the class it was built for: the text-side rules that reach
> outside five named config files, the workflow and install-hook rules for the CI surface, and the
> composite Action that lets a repository adopt it in one line.
>
> Every issue names its acceptance criteria, the commands CI runs, and what is out of scope. Two
> carry a blocked banner with the specific issue they wait on. The contribution gate is that a pull
> request must update the roadmap in the same change, so the tracker and the project cannot drift.

## 3. Points against the caps

The batch totals **2,150 pre-multiplier points**: 5 Trivial at 100, 7 Medium at 150, 3 High at 200.
The caps observed in a previous Wave were 25,000 per repository and 75,000 per organization, so this
batch is roughly 9% of the per-repo ceiling. `posture-sec` now hosts a second program repository,
`guage`, whose own backlog would draw on the same per-org pool, so the org-side arithmetic has to be
read from the dashboard with both repositories in view rather than planned against this number.

The headroom is deliberate. The remaining open roadmap rows that would make good issues (the corpus,
the parity harness, the Stellar detectors, the false-positive review) are either blocked on 0.10 or
too large to scope honestly as one unit, and an issue added to fill a budget is the failure mode the
program's own guidance warns about.

## 4. Before the form goes in

- [ ] Re-confirm on the dashboard that `posture-sec/airlock` is not already approved, and that it has
      not been applied for before. A second application for one repository reads as spam.
- [ ] Record the real per-repo and per-org caps for the coming Wave.
- [ ] Apply the `Stellar Wave` label and the complexity and area labels
      (`docs/wave/settings.md` section 3), so the issues exist as GitHub issues the moment approval
      lands.
- [ ] Produce the two-scan demo recording and host it somewhere the form can link.
- [ ] Decide D-05. If the answer is SCF rather than Wave, this file is still useful: the same
      fifteen issues and the same honest status table are what an SCF application asks for.
- [ ] Have the owner, not an agent, submit it. The form asks questions about account ownership and
      payout that an agent should not answer on someone's behalf.
