#!/usr/bin/env python3
"""Generate the documentation site's derived blocks from the shipped rule data (task 8.6).

`site/` is static and uploaded as-is, so nothing here builds HTML from scratch. It replaces two
marked blocks in place: the rule reference in `site/rules.html` and the counts readout in
`site/index.html`. Both come from `rules/builtin/*.toml`, and `site/data/rules.json` carries the
same data for anything that wants to read it without parsing HTML.

`--check` writes nothing and exits 1 when a copy is stale. The Pages workflow and the unit suite
both run it, so a rule that lands without a regenerated page fails before the site can describe a
rule set that no longer exists.

An unregistered rule file is an error rather than a silent omission: a family this script does not
know about would otherwise vanish from the published reference without anybody noticing.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

RULES_START = "<!-- RULES:START -->"
RULES_END = "<!-- RULES:END -->"
TELEMETRY_START = "<!-- TELEMETRY:START -->"
TELEMETRY_END = "<!-- TELEMETRY:END -->"

SEVERITIES = frozenset({"high", "warn", "info"})
SEVERITY_ORDER = ("high", "warn", "info")


@dataclass(frozen=True, slots=True)
class Family:
    """One rule file, and the order it appears in on the page."""

    name: str
    label: str


FAMILIES: tuple[Family, ...] = (
    Family("builtin_patterns", "Pattern engine"),
    Family("config_role", "Build tooling"),
    Family("ci_surface", "CI surface"),
    Family("cargo_vectors", "Cargo dependencies"),
    Family("native_binary", "Native binaries"),
    Family("npm_registry", "npm registry"),
    Family("stellar_seed", "Stellar keys"),
    Family("submodules", "Submodule integrity"),
    Family("wasm_manifest", "Artifact integrity"),
)


@dataclass(frozen=True, slots=True)
class RuleData:
    """The columns the reference publishes for one rule."""

    id: str
    title: str
    severity: str
    family: str
    detector: str
    roles: tuple[str, ...]
    suppressible: bool
    rationale: str


def fail(message: str) -> None:
    print(f"build_site: {message}", file=sys.stderr)
    raise SystemExit(2)


def _text(entry: dict[str, object], key: str, context: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        fail(f"{context}: {key} must be a non-empty string")
    return value


def load_rules(root: Path) -> tuple[RuleData, ...]:
    """Read every rule family, refusing data the published page could not describe."""
    rules_dir = root / "rules" / "builtin"
    if not rules_dir.is_dir():
        fail(f"no rule directory at {rules_dir}")

    registered = {family.name for family in FAMILIES}
    present = {path.stem for path in rules_dir.glob("*.toml")}
    unknown = sorted(present - registered)
    if unknown:
        fail("unregistered rule file(s): " + ", ".join(unknown) + "; add them to FAMILIES")
    missing = sorted(registered - present)
    if missing:
        fail("missing rule file(s): " + ", ".join(missing))

    rules: list[RuleData] = []
    seen: set[str] = set()
    for family in FAMILIES:
        path = rules_dir / f"{family.name}.toml"
        try:
            document = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            fail(f"{path}: {exc}")
        entries = document.get("rule")
        if not isinstance(entries, list) or not entries:
            fail(f"{path}: [[rule]] must hold at least one table")

        for number, entry in enumerate(entries, start=1):
            context = f"{path}: rule #{number}"
            if not isinstance(entry, dict):
                fail(f"{context}: expected a table")
            rule_id = _text(entry, "id", context)
            context = f"{path}: {rule_id}"
            if rule_id in seen:
                fail(f"{context}: duplicate rule id")
            seen.add(rule_id)

            title = _text(entry, "title", context)
            rationale = _text(entry, "rationale", context)
            detector = _text(entry, "detector", context)
            severity = _text(entry, "severity", context)
            if severity not in SEVERITIES:
                fail(f"{context}: severity {severity!r} is not one of {sorted(SEVERITIES)}")

            roles = entry.get("roles")
            if (
                not isinstance(roles, list)
                or not roles
                or not all(isinstance(role, str) and role for role in roles)
            ):
                fail(f"{context}: roles must be a non-empty list of names")

            suppressible = entry.get("suppressible")
            if not isinstance(suppressible, bool):
                fail(f"{context}: suppressible must be true or false")

            tests = entry.get("tests")
            if (
                not isinstance(tests, dict)
                or not isinstance(tests.get("positive"), str)
                or not isinstance(tests.get("negative"), str)
            ):
                fail(f"{context}: tests must name a positive and a negative fixture")

            rules.append(
                RuleData(
                    id=rule_id,
                    title=title,
                    severity=severity,
                    family=family.name,
                    detector=detector,
                    roles=tuple(roles),
                    suppressible=suppressible,
                    rationale=rationale,
                )
            )
    return tuple(rules)


def engine_name(detector: str) -> str:
    """Where the decision is made, in words a reader can act on."""
    if detector == "pattern":
        return "pattern engine"
    if detector.startswith("builtin:"):
        return f"{detector.split(':', 1)[1]} (code)"
    return f"{detector} (code)"


def _article(rule: RuleData) -> list[str]:
    esc = html.escape
    supp = "yes" if rule.suppressible else "no"
    return [
        f'<article class="rule" id="{esc(rule.id)}" data-severity="{rule.severity}"',
        f'  data-family="{rule.family}">',
        '  <div class="rule-top">',
        f'    <h3 class="rule-id">{esc(rule.id)}</h3>',
        f'    <span class="sev sev--{rule.severity}">{rule.severity.upper()}</span>',
        "  </div>",
        f'  <p class="rule-title">{esc(rule.title)}</p>',
        f'  <p class="rule-why">{esc(rule.rationale)}</p>',
        '  <p class="rule-meta">',
        f"    <span>Detector <b>{esc(engine_name(rule.detector))}</b></span>",
        f"    <span>Roles <b>{esc(', '.join(rule.roles))}</b></span>",
        f"    <span>Suppressible <b>{supp}</b></span>",
        "  </p>",
        "</article>",
    ]


def _tally(group: list[RuleData]) -> str:
    counts = Counter(rule.severity for rule in group)
    parts = [f"{len(group)} RULES"]
    for severity in SEVERITY_ORDER:
        if counts[severity]:
            parts.append(f"{counts[severity]} {severity.upper()}")
    return " / ".join(parts)


def render_rules(rules: tuple[RuleData, ...]) -> str:
    lines: list[str] = []
    for index, family in enumerate(FAMILIES, start=1):
        group = [rule for rule in rules if rule.family == family.name]
        label = html.escape(family.label)
        lines.extend(
            [
                f'<section class="family" id="family-{family.name}" data-family="{family.name}">',
                f'  <h3 class="family-head"><span><b>[ {index:02d} ] {label}</b> / '
                f"{family.name}</span><span>{_tally(group)}</span></h3>",
                '  <div class="rule-list-inner">',
            ]
        )
        for rule in group:
            lines.extend("    " + line for line in _article(rule))
        lines.extend(["  </div>", "</section>"])
    return "\n".join(lines)


def render_telemetry(rules: tuple[RuleData, ...]) -> str:
    counts = Counter(rule.severity for rule in rules)
    code_detectors = {rule.detector for rule in rules if rule.detector.startswith("builtin:")}
    cells = (
        ("Rules", str(len(rules))),
        ("High / warn", f"{counts['high']} / {counts['warn']}"),
        ("Code detectors", f"{len(code_detectors):02d}"),
        ("Runtime dependencies", "00"),
        ("Python", "3.11+"),
        ("License", "APACHE-2.0"),
    )
    return "\n".join(
        f'<div class="tel"><span class="tel-k">{html.escape(key)}</span>'
        f'<span class="tel-v">{html.escape(value)}</span></div>'
        for key, value in cells
    )


def render_json(rules: tuple[RuleData, ...]) -> str:
    counts = Counter(rule.severity for rule in rules)
    by_severity = {severity: counts[severity] for severity in SEVERITY_ORDER}
    payload = {
        "source": "rules/builtin",
        "counts": by_severity | {"total": len(rules)},
        "rules": [
            {
                "id": rule.id,
                "title": rule.title,
                "severity": rule.severity,
                "family": rule.family,
                "detector": rule.detector,
                "roles": list(rule.roles),
                "suppressible": rule.suppressible,
                "rationale": rule.rationale,
            }
            for rule in rules
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=True) + "\n"


def _replace(text: str, start: str, end: str, body: str, label: str) -> str:
    if text.count(start) != 1 or text.count(end) != 1:
        fail(f"{label}: expected exactly one {start} and one {end}")
    head, _, rest = text.partition(start)
    _, _, tail = rest.partition(end)
    return f"{head}{start}\n{body}\n{end}{tail}"


def build(root: Path) -> tuple[dict[Path, str], int]:
    rules = load_rules(root)
    site = root / "site"
    rules_html = site / "rules.html"
    index_html = site / "index.html"
    json_path = site / "data" / "rules.json"

    for path in (rules_html, index_html):
        if not path.is_file():
            fail(f"no page at {path}")

    outputs = {
        rules_html: _replace(
            rules_html.read_text(encoding="utf-8"),
            RULES_START,
            RULES_END,
            render_rules(rules),
            "site/rules.html",
        ),
        index_html: _replace(
            index_html.read_text(encoding="utf-8"),
            TELEMETRY_START,
            TELEMETRY_END,
            render_telemetry(rules),
            "site/index.html",
        ),
        json_path: render_json(rules),
    }
    return outputs, len(rules)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if the committed site disagrees with the rule data",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="repository root to read and write (default: this checkout)",
    )
    args = parser.parse_args(argv)
    root: Path = args.root.resolve()

    outputs, total = build(root)
    if args.check:
        stale = []
        for path, expected in outputs.items():
            label = path.relative_to(root).as_posix()
            if not path.is_file():
                stale.append(f"{label} is missing")
            elif path.read_text(encoding="utf-8") != expected:
                stale.append(f"{label} is stale")
        if stale:
            for line in stale:
                print(f"build_site: {line}", file=sys.stderr)
            print("build_site: run scripts/build_site.py and commit the result", file=sys.stderr)
            return 1
        return 0

    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    print(f"build_site: wrote {len(outputs)} files for {total} rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
