# Wave readiness: repository settings

Everything in this file is a setting on `posture-sec/airlock`, not a code change. Sections 2, 3, 4 and
5 were applied on 2026-11-02 as part of the move (task 1.15) and read back; the Drips application in
section 1 step 4 and the issue publication in step 5 are not applied, in that file's own order. Each
command is written so the owner can run it, or approve an agent running it, one section at a time.

| Applied 2026-11-02 | Result read back |
|---|---|
| Topics | the twelve listed, set as a full replacement |
| Labels | `Stellar Wave`, three `complexity: *`, seven `area: *`, `type: test`, `blocked`, plus the stock set: 23 in total |
| Ruleset | `protect main`, id 26360459, enforcement active, requiring the `checks` and `roadmap` contexts from integration 15368, strict, merge and squash allowed, and holding only `deletion`, `non_fast_forward`, `pull_request` and `required_status_checks` (see the note below) |
| Pages | `build_type: workflow`; run 3 of `pages.yml` deployed `main`, and `https://posture-sec.github.io/airlock/` answers 200 with the new URLs on every page and in `sitemap.xml` (run 1 failed, before Pages was enabled) |
| Release | `v0.0.1` as a pre-release on `main`, with notes that name the unbuilt Action, Stellar detectors and SARIF |

Two readings that the plan did not predict:

- **On the free plan, a private repository can have neither a ruleset nor Pages.** `POST /repos/.../rulesets`
  answers 403, "Upgrade to GitHub Pro or make this repository public to enable this feature", and
  `POST /repos/.../pages` answers 422, "Your current plan does not support GitHub Pages for this
  repository". Both succeeded the moment the repository was public. This is the live half of the answer
  task 0.16 asks for, and it means the controls have to be applied last rather than first.
- **The ruleset key in section 4 is spelled wrong and its approver count does not work here.** The
  `pull_request` rule takes `required_approving_review_count`, not `required_approver_count`, and a
  count of 1 on a one-maintainer repository blocks every pull request, because GitHub does not let an
  author approve their own. The applied ruleset therefore sets it to 0 and turns
  `require_code_owner_review` off and keeps thread resolution and strict status checks. `guage`
  records the same acceptance under its D-14.
- **An `update` rule blocks the merge it is meant to guard.** With `creation` and `update` in the
  ruleset and no bypass actor, merging a pull request is an update of a protected ref:
  `PUT /pulls/2/merge` answered 405, "Repository rule violations found: Cannot update this protected
  ref", while both required contexts were green. The applied ruleset therefore keeps only `deletion`,
  `non_fast_forward`, `pull_request` and `required_status_checks`, which is the exact shape
  `posture-sec/guage` runs, and pull request #2 merged under it. Direct pushes to `main` are still
  refused: the rule that refuses them is `pull_request`, not `update`, which is the point task 1.3
  observes.

Verified against the live repository on 2026-10-28 with read-only calls. That reading was taken at
`airlock-sec/airlock`, the repository before the 2026-11-02 move (task 1.15), so it describes the
pre-move state; the commands below are written for `posture-sec/airlock`:

| Checked | Result |
|---|---|
| Topics | none (`"topics": []`) |
| Labels | the ten stock GitHub labels only; no `Stellar Wave`, no `complexity: *`, no `area: *` |
| Rulesets | `[]`, and the endpoint answers, so repository rulesets are available on this plan |
| Branch protection on `main` | `Branch not protected` (404) |
| Releases | none |
| Tags | none |
| Description | present: "command-line scanner and GitHub Action that audits Stellar and Soroban open-source repositories for supply-chain compromise and release-integrity gaps." |

The ruleset endpoint returning `[]` rather than a permissions error is the useful one: it means the
plan supports repository rulesets, which is the open half of task 0.13 and 0.16. That is an inference
from an API response and not a plan confirmation, so 0.16 still needs the org's own answer.

## 1. Order of operations

The order matters because of one mechanic: on a repository Drips has not approved, the `Stellar
Wave` label is removed automatically. So labels and issues can be created any time, but they score
nothing until approval lands, and an issue published before approval looks live to a contributor while
being invisible to the program.

1. Topics and labels (harmless, needed by everything after).
2. Branch protection naming the two checks that already run (section 4). This is the one piece of
   Phase 10 hygiene that is not cosmetic: it is what makes a red gate mean something.
3. A `v0.0.1` pre-release tag (section 5).
4. The Drips application (see `application.md`), and wait for the decision. A rejected repository
   cannot re-apply, so this step goes last on purpose.
5. Only after approval: publish the fifteen issues with `sh scripts/create_wave_issues.sh --apply`,
   then confirm on the Drips dashboard that the points counted.

`scripts/create_wave_issues.sh` refuses to create anything while the repository has no `Stellar Wave`
label, which is step 1's check as well as a guard against running step 5 out of order.

## 2. Topics

```
gh api -X PUT repos/posture-sec/airlock/topics -f names[]=supply-chain -f names[]=security \
  -f names[]=wasm -f names[]=soroban -f names[]=stellar -f names[]=github-actions \
  -f names[]=scanner -f names[]=python -f names[]=devsecops -f names[]=smart-contracts \
  -f names[]=dependency-audit -f names[]=ci
```

Chosen for what a Stellar maintainer would search for, not for volume. `python3`, `cli` and
`linter` were left out: they are true and they are noise. The list is twelve, which is under GitHub's
cap, and the endpoint is a full replacement, so re-running it with a different list overwrites rather
than appends.

## 3. Labels

`Stellar Wave` must be created by hand or by the bot; the exact spelling matters, since it is the
string Drips matches.

```
gh label create "Stellar Wave" --repo posture-sec/airlock \
  --color "5319E7" --description "In the Stellar Wave builder program"

gh label create "complexity: trivial" --repo posture-sec/airlock --color "C2E0C6" \
  --description "100 points: one bounded change with obvious acceptance criteria"
gh label create "complexity: medium"  --repo posture-sec/airlock --color "FBC2D7" \
  --description "150 points: standard change touching several parts of the codebase"
gh label create "complexity: high"    --repo posture-sec/airlock --color "D4C5F9" \
  --description "200 points: complex engineering or a security-critical surface"

gh label create "area: engine"    --repo posture-sec/airlock --color "0E8A16" --description "collector, runner, fingerprint, suppression, reporters"
gh label create "area: rules"     --repo posture-sec/airlock --color "0E8A16" --description "rules/*.toml and the detectors that read them"
gh label create "area: detectors" --repo posture-sec/airlock --color "0E8A16" --description "a detector's scope, its fixtures or its rule data decision"
gh label create "area: action"    --repo posture-sec/airlock --color "0E8A16" --description "action.yml and the runner's execution environment"
gh label create "area: ci"        --repo posture-sec/airlock --color "0E8A16" --description ".github/workflows and scripts/"
gh label create "area: docs"      --repo posture-sec/airlock --color "0E8A16" --description "README and the design documents"
gh label create "area: tests"     --repo posture-sec/airlock --color "0E8A16" --description "tests/ layout, fixtures, corpus, harnesses"

gh label create "type: test" --repo posture-sec/airlock --color "F9D0C4" \
  --description "Work whose deliverable is test coverage rather than behavior"
gh label create "blocked"    --repo posture-sec/airlock --color "E9969A" \
  --description "Cannot be completed until another issue or task lands"
```

`bug`, `documentation`, `enhancement` and `good first issue` already exist as stock labels and are
reused as they are. No `area: security` label: every area here is security, so the label would carry
no information.

## 4. Branch protection

The check names below are the real ones, read from the two workflows rather than guessed:
`.github/workflows/ci.yml` has job `checks`, and `.github/workflows/roadmap-check.yml` has job
`roadmap`. Both were confirmed as check-run names on the live repository: pull request #18's head
commit carries exactly `checks` and `roadmap`, both reported by the `github-actions` app, whose
integration ID is `15368`. A required check whose name does not match a job that runs is worse than
no required check, because it blocks every pull request forever, and because the mismatch reads as
"the gate is configured" when it is not.

```json
{
  "name": "protect-main",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [
    { "type": "creation" },
    { "type": "update" },
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "pull_request",
      "parameters": {
        "required_approver_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "authorized_actor_names": ["bolabeatz"],
        "required_review_teams": [],
        "dismissal_restrictions": []
      } },
    { "type": "required_status_checks",
      "parameters": {
        "required_status_checks": [
          { "context": "checks", "integration_id": 15368 },
          { "context": "roadmap", "integration_id": 15368 }
        ],
        "strict_required_status_checks_policy": true
      } }
  ]
}
```

Run it as:

```
gh api -X POST repos/posture-sec/airlock/rulesets --input ruleset.json
```

Three notes on choices in that document:

- **`strict_required_status_checks_policy: true`** means a pull request must be up to date with
  `main` before it can merge, so a green gate cannot be stale against the branch it would land on.
- **`required_status_checks` never runs a check; it only requires one.** A contributor who deletes
  the workflow file does not get a green light, they get a pull request that can never merge, which
  is the behavior `PRD.md` wants and task 4.5 tests. It also means a new required job must exist
  before it is listed here, not after.
- **`integration_id: 15368`** is the GitHub Actions app. Without it the context string is ambiguous
  against checks from other apps.
- **`authorized_actor_names` lists the account that owns this repository.** `posture-sec` has one
  member, `bolabeatz`, with the `admin` role, on the free plan, and org-wide two-factor authentication
  not required; all four read from the API on 2026-11-02. The pre-move org had a single owner on an
  account that has since been suspended, which is what task 1.15 records. If a second maintainer is
  added, that list is a security boundary and belongs in the same pull request as the change, not in a
  settings edit nobody reviewed. Task 1.2 (account hardening) is the precondition for trusting it.

This closes the file-editable half of task 1.3. `.github/CODEOWNERS` already exists and lists the
protected paths, which is why `require_code_owner_review` is `true` above: the file has no effect
until a ruleset asks for it, so turning it on is what makes the twelve entries mean something. With
one owner it changes nothing in practice today, and it changes everything the moment a second
account joins, which is the point of configuring it now rather than remembering later. Task 1.2
(account hardening) and 0.16 (what the org plan actually allows) stay open, and 0.16 is the reason
to check whether `authorized_actor_names` and the bypass list are the right shape before trusting
this file.

## 5. A release tag

The guide asks for a version tag. `ROADMAP.md` 5.5 gates `v0.1.0` behind Phases 0 to 5 and a review
of gates G1 to G10, and the repository is at 36% of that, so cutting `v0.1.0` today would be a claim
this file contradicts two sections later.

`pyproject.toml` and `airlock.__version__` both already read `0.0.1`, so the honest tag is `v0.0.1`
as a pre-release, described as what it is:

```
gh release create v0.0.1 --prerelease --title "v0.0.1 (pre-release)" --notes-file /tmp/notes.md
```

Draft notes:

> Pre-release, not a version to depend on. `v0.1.0` is gated on Phases 0 to 5 of
> [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md), and three of the four
> things a consumer would want are not built: the composite Action (`action.yml`, task 4.1), the
> Stellar-specific detectors (Phase 6) and SARIF output (7.6).
>
> What does work, from a source checkout on Python 3.11 or newer:
>
> ```
> python -m pip install .
> python -m airlock scan --mode full .
> ```
>
> Twenty-two rules across four rule files, three detectors, three report formats (`console`, `github`,
> `json`) plus a step summary written when `GITHUB_STEP_SUMMARY` is set, fingerprint-keyed
> suppressions with expiry, a Wasm manifest with
> `airlock manifest add` and `check`, and fail-closed skips. Exit 0 only when nothing reached the
> threshold.
>
> There is no signed artifact and no build provenance at this tag: task 5.3 adds those, and 5.5 is
> the first release that carries them. Pin a commit SHA, not this tag, if you are reading the code
> rather than installing it.

No contract addresses belong in the body: Airlock deploys nothing, which is the one item in the
builder guide's Phase 10 list that does not transfer to this repository.

## 6. What is deliberately not here

- **The `Stellar Wave` label applied to anything before approval.** It would be stripped, and the
  strip is silent.
- **A docs site** (guide Phase 11). `PRD.md`, `ARCHITECTURE.md`, `ARCHITECTURE_ESSENTIALS.md`,
  `project_structure.md` and this roadmap already describe the design five ways, and task 5.2 is
  going to generate a rule reference from the rule data. A sixth hand-written copy would be a sixth
  thing to keep true. Revisit after 5.2.
- **`contrib.rocks` in the README.** The image would render one avatar. Add it when the first
  external contributor lands, which is the point of the whole exercise.
- **Auto-merge, or a bot that merges Wave pull requests.** `AGENTS.md` section 9 forbids it, and a
  scanner that reviews its own reviewer is the failure mode this tool exists to catch.
- **Dependabot** (1.6). It is issue 04 in this batch on purpose: the roadmap gate has no exemptions
  and decision D-07 says it must not gain any silently, so enabling Dependabot before that question
  is settled produces permanently red bot pull requests.
