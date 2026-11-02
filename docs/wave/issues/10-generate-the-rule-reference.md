---
slug: generate-the-rule-reference
title: Generate the rule reference from rules/*.toml instead of maintaining it by hand
labels: Stellar Wave, complexity: medium, area: docs, enhancement
roadmap: 5.2
---

> **Repo context.** `airlock` is a Python 3.11 standard-library-only scanner: `src/airlock/` holds the pipeline (collector, then rules and detectors, then fingerprints and suppressions, then reporters) behind one CLI, and the rules themselves are data in `rules/builtin/*.toml`. The repository being scanned is untrusted input, so the hard rules in [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 are security properties rather than style. [`ROADMAP.md`](https://github.com/posture-sec/airlock/blob/main/ROADMAP.md) is the source of truth for what is built and what is only a docstring.

> 🟢 **Unblocked.** The rule data it reads is shipped and stable. Task 5.2 lists 3.7 as a dependency because that is when the rule count roughly triples, and the generator does not care: it emits whatever the files hold, so it can land now and 3.7 will simply add rows.

## Problem

Every rule already carries its own documentation. A rule in
[`rules/builtin/config_role.toml`](https://github.com/posture-sec/airlock/blob/main/rules/builtin/config_role.toml)
has `id`, `title`, `roles`, `detector`, `severity`, `suppressible`, `rationale`, an optional
`pattern`, and `tests = { positive = …, negative = … }` naming the fixture pair that proves it fires.
The `rationale` fields are the design argument for the rule, written by whoever ported it:
"Build configs are evaluated at install and build time. Evaluating a string there is how this class
of attack turns a dependency install into remote code execution."

None of that reaches a reader who is not already in the TOML file. A maintainer deciding whether to
suppress a finding needs the severity, the rationale and whether the rule is suppressible at all; a
contributor adding a rule needs to see the shape the eleven others follow. Today the only prose is
the summary table in [`README.md`](https://github.com/posture-sec/airlock/blob/main/README.md), which
lists twelve rules by id and severity and will drift the moment a rule is added, since nothing checks
it. `ROADMAP.md` 5.2 asks for the generated reference and gate G7 ("the documents agree with the
code") is not checkable while that is true by convention.

## What to build

1. **Write the generator** as a script under [`scripts/`](https://github.com/posture-sec/airlock/blob/main/scripts),
   standard library only, loading the rule files through the same loader the scanner uses
   ([`src/airlock/rules.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/rules.py))
   rather than re-parsing them, so a rule the scanner refuses to load cannot appear in the docs.
2. **Emit one document** covering every rule: id, title, severity, whether it is suppressible, the
   roles it applies to, which detector runs it, the rationale, and the fixture names that cover it.
   Group by detector family, and state the count in the header so a missing family is visible.
3. **Make it a check, not just a command.** `--check` mode regenerates and fails if the committed
   output differs, in the same shape as
   [`scripts/roadmap_progress.py`](https://github.com/posture-sec/airlock/blob/main/scripts/roadmap_progress.py)
   already uses for the progress table, and add it to the `checks` job. A rule added without a
   documentation regeneration then fails CI, which is the only way the reference stays true.
4. **Point the README at it.** Replace the hand-written summary tables with a link plus whatever
   short framing the landing page needs, so there is one authoritative list rather than two that can
   disagree.

**Out of scope:** porting the rules 3.6 and 3.7 still owe (the generator must work for rules that do
not exist yet, and that is the whole point of generating), prose beyond what the rule files already
carry, and a documentation site. Do not write rationales for other people's rules; if one is thin,
say so in the pull request instead of inventing a justification.

## Acceptance criteria

- [ ] The generated reference lists every rule in `rules/builtin/` with id, title, severity, suppressibility, roles, detector, rationale and fixture names, and the counts in its header match the files.
- [ ] `python scripts/<the generator you added>.py --check` fails when a rule file changes and the committed document does not, and passes on a clean tree.
- [ ] The check runs in `.github/workflows/ci.yml` and its absence is not possible to merge unnoticed.
- [ ] A unit test asserts the generator's output for at least one rule with a `pattern` and one without, so the two shapes cannot silently diverge.
- [ ] `README.md` no longer maintains a second copy of the rule list, and links to the generated document instead.
- [ ] `ROADMAP.md` is updated in the same pull request: 5.2 ticked or annotated with what 3.7 still owes, a changelog row with a UTC date, `Last updated` moved, and `python scripts/roadmap_progress.py --check` passing.
- [ ] `python -m pytest`, `ruff check .`, `ruff format --check .` and `mypy src` all pass, and `airlock scan --mode full .` reports no HIGH findings.
- [ ] `scripts/` is a protected path, so the pull request needs owner review.
- [ ] PR description includes `Closes #{{issue:self}}`.

## Tech stack

- Runtime: Python 3.11, standard library only. [`AGENTS.md`](https://github.com/posture-sec/airlock/blob/main/AGENTS.md) section 4 forbids adding a runtime dependency, and a scan never touches the network, so a helper library is not an option here.
- Parser to reuse, not rewrite: [`src/airlock/rules.py`](https://github.com/posture-sec/airlock/blob/main/src/airlock/rules.py) already loads and validates every field, and [`rules/builtin`](https://github.com/posture-sec/airlock/blob/main/rules/builtin) is the data.
- Shape to copy for the staleness check: the `--check` mode of [`scripts/roadmap_progress.py`](https://github.com/posture-sec/airlock/blob/main/scripts/roadmap_progress.py), which regenerates a derived block and fails when the committed one disagrees.
- Output target: a generated document that [`README.md`](https://github.com/posture-sec/airlock/blob/main/README.md) links, so the README stops carrying a hand-copied table that can drift.
- Run before pushing: `python -m pytest tests/unit/test_rule_data.py` and `python -m airlock scan --mode full .`, since a generated file in the tree is a file the self-scan reads.

### **Contact & Support**
- [`SUPPORT.md`](https://github.com/posture-sec/airlock/blob/main/SUPPORT.md) — where to ask, the commands CI runs, and the rules that most often get a pull request rejected
- [`SECURITY.md`](https://github.com/posture-sec/airlock/blob/main/SECURITY.md) — private disclosure only; never open an issue about a bypass
