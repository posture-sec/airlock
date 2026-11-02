<div align="center">

# Airlock

**Supply-chain scanning for Stellar and Soroban repositories**

[![CI](https://github.com/posture-sec/airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/posture-sec/airlock/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![Runtime dependencies](https://img.shields.io/badge/runtime%20dependencies-0-green)](pyproject.toml)

Airlock reads a repository's tracked files and reports the shapes that have actually been used to
compromise open-source Stellar projects: payloads appended to JS and TS build tooling configs,
editor tasks that run on folder open, and Wasm artifacts that do not match the build they claim.
It is a scanner for a specific attack class, not a general-purpose antivirus.

[Documentation site](https://posture-sec.github.io/airlock/) · [Quick start](#quick-start) ·
[What it checks](#what-it-checks) · [Trust model](#trust-model) · [Limits](#limits) ·
[Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

</div>

## Status

**Building.** The engine works and this repository scans itself on every pull request. The
installer does not exist yet.

| | |
|---|---|
| Works today | `airlock scan` in console, GitHub-annotation and JSON output, plus a step summary; `airlock manifest add` and `manifest check`; 22 rules across three code detectors and the pattern engine; 664 tests in CI |
| Not built yet | the composite GitHub Action (`action.yml`), the Soroban-side detectors, the build-script and native-binary rules, SARIF output |
| Usable now | as a CLI, from a checkout or an installed wheel, on any git repository |

There is no `uses: posture-sec/airlock@…` line to copy into a workflow, and no package index
release. Do not treat a scan from this build as complete coverage: a clean report means nothing
matched the twenty-two rules that ship, which is a narrower claim than "no compromise found". Track
what exists in [ROADMAP.md](ROADMAP.md) and read the design in
[ARCHITECTURE.md](ARCHITECTURE.md).

## Why this exists

Five public Soroban repositories shipped the same copy-pasted scan step, and a review of that step
found seven ways to commit anything you like past it. All seven were run against the real script on
2026-10-27 and every one of them exits 0, which the workflow reads as a pass. The shapes include a
`.wasm` file dropped before any rule sees it, a payload line that exempts itself with a comment,
and `eval(decrypted)` in a build config scoring one WARN where only HIGH affects the exit code.
The measurements are in [PRD.md](PRD.md) Appendix B.

Airlock is the rewrite those campaigns should have had: fail closed on everything it did not look
at, judge a change by the policy that existed before the change, and treat rules as data.

## What it checks

Three code detectors are registered, and the rule data lives in [`rules/builtin/`](rules/builtin):
one file per family, plus the engine's own line-matching path for `detector = "pattern"` rules.

**`config_role`** targets the tooling configs a Soroban frontend ships (`postcss.config.*`,
`tailwind.config.*`, `next.config.*`, `eslint.config.*`, `babel.config.*`) and editor auto-run
tasks. It looks for capabilities rather than signatures, and it reads raw text with no comment or
string masking.

| Rule | Severity | Shape |
|---|---|---|
| `cfg-dynamic-code` | HIGH | `eval`, `new Function`, `vm.runIn*` in a build config |
| `cfg-network-exec` | HIGH | a fetch or download whose result is executed |
| `cfg-chain-endpoint` | HIGH | a chain or wallet RPC endpoint reached from tooling |
| `cfg-appended-tail` | HIGH | a high-entropy run appended past the config's real content |
| `cfg-long-line` | HIGH | a line over the cap, where the regexes deliberately do not run |
| `cfg-network` | WARN | network capability with no execution alongside it |
| `cfg-process-spawn` | WARN | a build step that spawns a process |

**`wasm_manifest`** checks every committed `.wasm` against a hash-keyed manifest, so an artifact
that was not built from the reviewed source is named.

| Rule | Severity | Shape |
|---|---|---|
| `wasm-unlisted` | HIGH | an artifact with no manifest entry, including a git LFS pointer wearing a `.wasm` name |
| `wasm-hash-mismatch` | HIGH | an artifact whose bytes are not the bytes the manifest recorded |
| `wasm-path-moved` | WARN | a known hash at a path the manifest does not list |
| `wasm-manifest-stale` | WARN | an entry whose file is gone |
| `wasm-archive-skipped` | WARN | an artifact inside an archive, which the scanner does not open |

**`builtin_patterns`** is rule data rather than a code detector: the text-side shapes the old
script matched, run line by line over every role that is code, so a payload in a `.py` file, in an
extensionless file or under `vendor/` is read instead of waved past. Prose is out of scope by the
`roles` lists, not by a skip.

| Rule | Severity | Shape |
|---|---|---|
| `pat-decode-eval` | HIGH | a decoder feeding `eval`, `Function`, `setTimeout` or a similar evaluator |
| `pat-invisible-unicode` | HIGH | a zero-width or direction-flipping character inside code |
| `pat-exfil-endpoint` | WARN | a paste site, webhook, tunnel or out-of-band callback host in code |
| `pat-obfuscator-id` | WARN | the `_0x` plus hex identifier grammar an obfuscator emits |

**`ci_surface`** covers the places a repository hands control to someone else: workflow triggers,
package lifecycle scripts under `package.json`, install hooks under `.husky/` and `.githooks/`, and
editor auto-run settings. Whole-file shapes belong to the engine's pattern path, and the pairings
that need two lines judged together (a secret read and displayed, a privileged checkout of a
contributor's head, a fetched script handed to a shell) are code, because one regex for those is
quadratic on a line of repeated `curl` at the cap.

| Rule | Severity | Shape |
|---|---|---|
| `pat-secret-dump` | HIGH | a workflow that interpolates `secrets.*` into a command that prints or writes it |
| `pat-ptr-head-checkout` | HIGH | `pull_request_target` plus a checkout pinned to the contributor's head ref |
| `pat-lifecycle-exec` | HIGH | a `package.json` script or install hook that fetches and then executes the result |
| `pat-privileged-trigger` | WARN | a workflow triggered by `pull_request_target`, where the head is reachable |
| `pat-lifecycle-fetch` | WARN | a package or install hook that downloads something, with no execution seen |
| `pat-editor-command-path` | WARN | an editor setting that names an executable to run on open |

A file in one of those roles is treated as executed with credentials attached, so a line past
`line_cap` in it is HIGH rather than demoted to WARN. Every rule in the family is suppressible,
following `cfg-process-spawn`, and none of them judge a string with masking.

The collector adds the state findings on top: `nul-in-text`, `non-utf8-text`, `skipped-oversize`,
`skipped-unreadable`, `skipped-symlink`, `skipped-unmerged`, `submodule-present`. Every one of them
is a finding, because a file that was not read must not look the same as a file that was clean.

The Stellar-side detectors (`soroban_profile`, `stellar_seed`, `cargo_vectors`) are designed in
[ARCHITECTURE.md](ARCHITECTURE.md) 9 and not implemented: those modules carry docstrings and no
code. Of the rules ported from the old script, the text-side shapes and the CI-surface families
above ship now; the `build.rs` and native-binary families wait on the Cargo work. What the
CI-surface rules do not see (a secret read in one line and echoed in another, `workflow_run` and
`issue_comment` triggers, a fetch hidden in a helper script) is listed in
[ARCHITECTURE.md](ARCHITECTURE.md) 9.7.

## What it does not do

It does not execute, import or evaluate scanned content, and it never runs scanner code out of the
checkout under scan. It does not fetch: a scan makes no network calls and sends no telemetry. It
does not skip directories by default, and there is no inline suppression marker to hide a line
with. It is not an antivirus, not a dependency-advisory tool, and not a replacement for a code
review.

## Trust model

The rule that the whole design rests on: **a change cannot relax the rules it is judged by.**

| Mode | Policy, suppressions and Wasm manifest come from | Use for |
|---|---|---|
| `pr` | the pull request's base commit | gating a contribution |
| `push` | `github.event.before`, the commit the push started at | gating a merge to a default branch |
| `full` | the working tree, announced with an `untrusted-policy-source` INFO | a local look at your own repository |

A base that cannot be resolved is exit 2, not a scan against HEAD. A force push yields
`history-rewritten`. A policy edited inside the change yields `policy-changed` and the base copy is
what runs. Suppressions are fingerprint-keyed and occurrence-aware, carry a required reason, expire
within 30 days at the latest, and cannot cover a scanner-state finding at all.

## Quick start

Python 3.11 or newer, standard library only.

```bash
git clone https://github.com/posture-sec/airlock.git
cd airlock
python3 -m venv .venv && . .venv/bin/activate
pip install .
```

Scan the repository you are standing in:

```bash
airlock scan --mode full
```

`--mode full` reads policy from the working tree and says so in the report. The trust models a
review actually depends on are `--event pull_request --base <sha>` and `--event push --before
<sha>`, and both need history, so a checkout has to run with `fetch-depth: 0`.

If the repository commits Wasm artifacts, record each one and then verify the tree:

```bash
airlock manifest add target/*/*.wasm \
  --origin built --source contracts/counter \
  --build "cargo build --release --target wasm32-unknown-unknown"
airlock manifest check
```

`add` writes `wasm-manifest.toml` and stages nothing. Land that diff on its own before the pull
request that adds the files, which is the flow the trusted base assumes. `check` gates on the
artifacts that are present: an unlisted or swapped one fails, a stale entry is named and does not.

Run from a checkout without installing, if you prefer:

```bash
PYTHONPATH=src python3 -m airlock scan --mode full
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | nothing at or above `--fail-on` (default `high`) |
| 1 | a finding at or above the threshold |
| 2 | usage or configuration error, including an unresolvable base and a missing `git` |
| 3 | internal error |

A scan that could not run never reports success.

## The Action shape is planned, not usable

`action.yml` is task 4.1 and does not exist. The intended consumer snippet, once it does:

```yaml
- uses: posture-sec/airlock@<full commit sha>   # pin the SHA, not a tag
  with:
    mode: pr
```

Pin the full commit SHA and read the diff before bumping it. Make the check a required status
check: without that, a pull request that deletes the scan step simply never runs it.

## Documentation

| Document | What it answers |
|---|---|
| [Documentation site](https://posture-sec.github.io/airlock/) | overview, usage, the rule reference and the trust model, rendered from the rules that ship |
| [`PRD.md`](PRD.md) | requirements, the seven bypass measurements in Appendix B, open questions |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | components, data models, the fail-closed table, ADRs, red-team review |
| [`ARCHITECTURE_ESSENTIALS.md`](ARCHITECTURE_ESSENTIALS.md) | the hard rules, in one screen |
| [`ROADMAP.md`](ROADMAP.md) | every remaining task, the gates, the changelog |
| [`project_structure.md`](project_structure.md) | where files go and which way imports point |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | how a change lands here |
| [`SECURITY.md`](SECURITY.md) | how to report a vulnerability in Airlock itself |
| [`SUPPORT.md`](SUPPORT.md) | where to ask for help, and the commands to run before you do |

## Contributing

Read [`AGENTS.md`](AGENTS.md) if you are working with a coding agent; humans are held to the same
bar. The short version: find your task in [`ROADMAP.md`](ROADMAP.md), write the failing test first,
make the smallest change that passes, and update `ROADMAP.md` in the same pull request. CI enforces
that last rule with a check named `roadmap`.

One rule earns more care than the rest. Airlock's job is to make a claim about a repository, so a
contribution that weakens a check, a test or a skip is not a smaller change than one that adds a
feature. Protected paths are listed in [`CONTRIBUTING.md`](CONTRIBUTING.md) and need owner review.

Contributor-sized work is filed in the [issue tracker](https://github.com/posture-sec/airlock/issues)
and names the roadmap task it closes; [`ROADMAP.md`](ROADMAP.md) stays the full queue and the source
of truth.

## Community and support

- Ask a question or report a false positive through [GitHub Issues](https://github.com/posture-sec/airlock/issues).
- Report a vulnerability privately, per [`SECURITY.md`](SECURITY.md).
- [`SUPPORT.md`](SUPPORT.md) carries the channels, the commands CI runs, and the house rules that
  most often get a pull request rejected.

## Maintainers

| Maintainer | Role | Contact |
|---|---|---|
| [posture-sec](https://github.com/posture-sec) owners | project owner, reviews protected paths | open an issue, or a private advisory per [`SECURITY.md`](SECURITY.md) |

A personal handle and a chat link go here once they are the ones the project will actually answer.
Until then the issue tracker is the supported channel.

Thanks to everyone who has contributed:

<a href="https://github.com/posture-sec/airlock/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=posture-sec/airlock" alt="Airlock contributors" />
</a>

## License

Apache-2.0. See [`LICENSE`](LICENSE).

Nothing is released yet, so no commit before the first attested tag carries a security guarantee.
Until then `main` is the only channel, and the honest description of a clean scan from it is
"nothing matched the rules that ship today".
