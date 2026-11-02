---
slug: close-the-state-rule-suppression-hole
title: Stop a loaded rule from making a scanner-state finding suppressible
labels: Stellar Wave, complexity: medium, area: engine, bug
roadmap: 2.15
---

> **Repo context.** `airlock` is a Python 3.11 standard-library-only scanner: `src/airlock/` holds the pipeline (collector, then rules and detectors, then fingerprints and suppressions, then reporters) behind one CLI, and the rules themselves are data in `rules/builtin/*.toml`. The repository being scanned is untrusted input, so the hard rules in [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 are security properties rather than style. [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md) is the source of truth for what is built and what is only a docstring.

> 🟢 **Unblocked.** The defect is in shipped code on `main`, it reproduces with the CLI as installed, and the fix is local to one function plus the tests around it.

## Problem

Scanner-state findings are not suppressible. That is a hard rule, not a default: `ARCHITECTURE.md`
7.6 says "the same holds for an entry naming ... a scanner-state rule id", and 2.8's design note
explains why a state finding is different from an ordinary one. Its content is "the scanner did not
look", and a policy that can silence it can turn an unscanned file into a clean report.

The check is in
[`src/airlock/policy.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/policy.py),
in `_entry_problem`, and it is nested inside the branch that only runs when the rule is *not* loaded:

```python
rule = by_rule.get(entry.rule)
if rule is None:
    if entry.rule in STATE_RULE_IDS:
        return "scanner-state findings cannot be suppressed"
    return "no rule with that id is loaded in this build"
if not rule.suppressible:
    return f"rule {entry.rule} is not suppressible"
```

For fifteen of the sixteen ids in `STATE_RULE_IDS` that is fine, because none of them appears in the
rule data and so `rule is None` is reached. `cfg-long-line` is the sixteenth. It is a real pattern
rule declared in
[`rules/builtin/config_role.toml`](https://github.com/posture-sec/airlock/blob/main/rules/builtin/config_role.toml)
with `suppressible = true`, because it was written as a rule before it was also made a state finding.
So a `[[suppress]]` entry naming `cfg-long-line` takes the second branch, is declared valid, and
applies.

Observed on `main` with the CLI as installed, against a scratch repository holding a 30,013-character
line in `postcss.config.mjs` and the entry above:

```
airlock: 1 HIGH · 0 WARN · 2 INFO, 1 suppressed · 1 file(s) scanned, nothing skipped
```

The `cfg-long-line` finding is gone and no `suppression-invalid` is raised. That finding is the only
account the scan gives for a line the regexes deliberately refused to run on, so suppressing it is
exactly the "unscanned file reads as clean" outcome the rule exists to stop. The JSON report makes it
worse in the quiet direction: the finding carries `"suppressible": true`, which is what tells a
maintainer that writing the entry was allowed in the first place.

The existing test does not catch it. `test_an_entry_naming_a_state_rule_is_high` uses
`history-rewritten`, which is never a loaded rule, so it exercises the `rule is None` branch and
passes for a reason that does not generalise.

Be precise about the blast radius when you describe this in the pull request: in `pr` and `push` mode
the policy comes from the trusted base, so an outside contributor cannot write this entry, and the
`[[suppress]]` block has to carry a matching fingerprint and path to cover anything. This is a
maintainer able to silence a coverage finding without being told, not a remote bypass. It is still the
rule it breaks.

## What to build

1. **Write the failing test first**, in the shape the suite already uses: an entry naming a
   scanner-state id that *is* present in the loaded rule set, asserted to yield `suppression-invalid`
   at HIGH and to cover nothing. Confirm it fails for the right reason before touching the function.
2. **Decide which of the two sources is wrong, and fix that one.** Either the state check runs before
   the loaded-rule lookup, or `cfg-long-line` stops being declared `suppressible = true` in the rule
   data, or both. The narrowest correct change is the ordering in `_entry_problem`, because a rule
   file that disagrees with `STATE_RULE_IDS` will be written again by whoever ports the next rule. The
   durable change is a check that the two cannot disagree: `tests/unit/test_model.py` already asserts
   the documented finding-id list verbatim against `STATE_RULE_IDS`, and this is the same class of
   drift.
3. **Say what the report should claim.** A `cfg-long-line` finding currently reaches the reporters
   with `suppressible=True`. If the answer is that it is not suppressible, the flag on the finding
   should agree with the policy that refuses it, so a maintainer reading JSON is not invited to write
   an entry that comes back as HIGH.
4. **Keep the fail-closed direction.** The fix must not make any currently-suppressible rule
   unsuppressible as a side effect, and must not turn a state finding suppressible in any case.

**Out of scope:** changing what `cfg-long-line` reports or at what severity, changing `line_cap`, and
any redesign of the suppression format. If you conclude the right fix is to remove `cfg-long-line`
from `STATE_RULE_IDS` instead, argue it in the pull request first rather than landing it: that id is
in the list for the same reason `skipped-oversize` is.

## Acceptance criteria

- [ ] A new test suppresses `cfg-long-line` through a loaded rule and asserts `suppression-invalid` at HIGH with the finding still reported; it fails before the fix and passes after.
- [ ] Every id in `STATE_RULE_IDS` refuses a suppression entry, whether or not a rule file declares it, demonstrated by a test that iterates the set rather than one that names a convenient member.
- [ ] The rule data and `STATE_RULE_IDS` cannot disagree unnoticed: either the fixture gate or a unit test fails when a state id is declared `suppressible = true`.
- [ ] The `suppressible` flag the reporters render for a state finding matches the policy's answer.
- [ ] `ARCHITECTURE.md` 7.6 and the `ARCHITECTURE_ESSENTIALS.md` finding-id list still describe the shipped behaviour, and `ROADMAP.md` records the task as closed with the observed before and after output.
- [ ] `python -m pytest`, `ruff check .`, `ruff format --check .` and `mypy src` all pass, and `airlock scan --mode full .` reports no HIGH findings.
- [ ] `src/airlock/policy.py` and `rules/` are protected paths: the pull request needs owner review, and no existing check may be loosened to make the fix fit.
- [ ] PR description includes `Closes #{{issue:self}}`.

## Tech stack

- Runtime: Python 3.11, standard library only. [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 forbids adding a runtime dependency, and a scan never touches the network, so a helper library is not an option here.
- Code: `_entry_problem` in [`src/airlock/policy.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/policy.py), and `STATE_RULE_IDS` in the same module. The fix is an ordering change, not a new mechanism.
- Tests: [`tests/unit/test_suppression.py`](https://github.com/posture-sec/airlock/blob/main/tests/unit/test_suppression.py) carries the existing suppression cases; the new one needs an id that is in both sets, which `cfg-long-line` is.
- Run the reproduction in the issue body before changing anything, against this checkout (`PYTHONPATH=src python3 -m airlock scan --mode full <scratch-repo>`), so the test you write is the one that fails first.
- Protected path: [`src/airlock/policy.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/policy.py) is the trusted-base module and needs owner review. Do not weaken the non-suppressible list to make a test pass.

### **Contact & Support**
- [`SUPPORT.md`](https://github.com/posture-sec/airlock/blob/main/SUPPORT.md) — where to ask, the commands CI runs, and the rules that most often get a pull request rejected
- [`SECURITY.md`](https://github.com/posture-sec/airlock/blob/main/SECURITY.md) — private disclosure only; never open an issue about a bypass
