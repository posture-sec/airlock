"""Synthetic rule fixtures and the harness that scans them (`ARCHITECTURE.md` 12, task 2.12).

Each rule names its fixture builder in its own data file (`tests = { positive = ..., negative =
... }`), so the suite can ask every shipped rule for both halves and fail when one is missing
(`PRD.md` FR-13). Trigger text is assembled from fragments at test time and handed to the scanner
as collected files (path, bytes, roles, hash), so this repository never commits a live-looking
payload (`project_structure.md` 6).

The caps here are smaller than the shipped policy defaults on purpose: a fixture should be long
because the rule says so, not because it is the size of a real minified bundle.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from airlock.detectors import DETECTOR_NAMES
from airlock.model import (
    EMPTY_MANIFEST,
    FileEntry,
    Manifest,
    Policy,
    Rule,
    ScanContext,
)
from airlock.roles import known_roles, resolve_roles
from airlock.rules import load_role_globs, load_rules
from airlock.runner import scan

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The line length a fixture has to clear to trip `cfg-long-line`.
LINE_CAP = 90
#: The length a last line may reach before `cfg-appended-tail` calls it a payload.
TAIL_MAX_LEN = 60
TAIL_ENTROPY = 4.5

#: `roles_from_magic` looks for a tar header at offset 257, so that many bytes decide a role.
HEAD_BYTES = 262


@dataclass(frozen=True, slots=True)
class File:
    """One file of a fixture. `raw` is for content the collector would not decode."""

    path: str
    text: str | None = None
    raw: bytes | None = None
    skip_reason: str | None = None

    def __post_init__(self) -> None:
        if self.skip_reason is not None:
            if self.text is not None or self.raw is not None:
                raise ValueError(f"fixture file {self.path} cannot carry content when skipped")
        elif (self.text is None) == (self.raw is None):
            raise ValueError(f"fixture file {self.path} must give exactly one of text and raw")

    def content(self) -> bytes:
        return self.raw if self.raw is not None else (self.text or "").encode()


@dataclass(frozen=True, slots=True)
class Case:
    """One side of a fixture: a repository as the collector would have handed it over."""

    files: tuple[File, ...] = ()
    manifest: Manifest = EMPTY_MANIFEST


@dataclass(frozen=True, slots=True)
class Fixture:
    """A rule's positive case must trigger it and its negative case must not.

    A half left `None` is a gap the coverage gate reports, so a builder written for one side
    cannot pass as finished (`PRD.md` FR-13).
    """

    positive: Case | None = None
    negative: Case | None = None


Builder = Callable[[], Fixture]


def assemble(*fragments: str) -> str:
    """Put a trigger string together at call time, so no committed file holds the whole form.

    `AGENTS.md` 4 forbids a live-looking payload in this repository, and the `builtin_patterns`
    rules read every `.py` file here as role `source`, so a test constant that spells `eval` and a
    decoder as a call is a finding against the scanner's own tree. Builders use it for the same
    reason the fixture halves do: the assembled form exists only while a test is running.
    """
    return "".join(fragments)


def builders() -> Mapping[str, Builder]:
    """Every builder the suite knows, by the name a rule file uses."""
    from . import (
        builtin_patterns,
        cargo_vectors_patch,
        ci_surface,
        ci_surface_hook_window,
        config_role,
        jwt_shape,
        native_binary_artifact,
        npm_lockfile_registry,
        stellar_seed,
        submodule_url_drift,
        wasm_manifest,
    )

    return {
        **builtin_patterns.BUILDERS,
        **cargo_vectors_patch.BUILDERS,
        **ci_surface.BUILDERS,
        **ci_surface_hook_window.BUILDERS,
        **config_role.BUILDERS,
        **submodule_url_drift.BUILDERS,
        **jwt_shape.BUILDERS,
        **native_binary_artifact.BUILDERS,
        **npm_lockfile_registry.BUILDERS,
        **stellar_seed.BUILDERS,
        **wasm_manifest.BUILDERS,
    }


def shipped_rules() -> tuple[Rule, ...]:
    """The rule data the scanner loads, so the gate checks the real rules."""
    role_globs = load_role_globs(REPO_ROOT / "rules" / "roles.toml")
    return load_rules(
        REPO_ROOT / "rules" / "builtin",
        known_detectors=DETECTOR_NAMES,
        known_roles=sorted(known_roles(role_globs)),
    )


def fixture_gap(rules: Iterable[Rule], known: Mapping[str, Builder]) -> list[str]:
    """One line per rule the suite cannot prove. Empty means every rule has both halves.

    `tests/unit/test_fixtures.py` asserts this is empty, and tests it against a rule with one half
    missing, so the gate is shown to bite rather than assumed to.
    """
    gaps: list[str] = []
    for rule in rules:
        for kind, name in (("positive", rule.tests.positive), ("negative", rule.tests.negative)):
            builder = known.get(name)
            if builder is None:
                gaps.append(f"{rule.id}: no {kind} fixture builder named {name}")
                continue
            if getattr(builder(), kind) is None:
                gaps.append(f"{rule.id}: builder {name} declares no {kind} case")
    return gaps


def orphaned_builders(rules: Iterable[Rule], known: Mapping[str, Builder]) -> list[str]:
    """Builder names no shipped rule asks for: rot from a rule that was renamed or dropped."""
    referenced = {name for rule in rules for name in (rule.tests.positive, rule.tests.negative)}
    return sorted(set(known) - referenced)


def digest(data: bytes) -> str:
    """The hash a manifest entry would carry for these bytes."""
    return hashlib.sha256(data).hexdigest()


def entry_for(file: File, role_globs: Mapping[str, tuple[str, ...]]) -> FileEntry:
    """A collector-shaped entry: role by content and path, whole-file hash, text only for text."""
    data = file.content()
    return FileEntry(
        path=file.path,
        sha256=None if file.skip_reason is not None else digest(data),
        roles=resolve_roles(file.path, data[:HEAD_BYTES], role_globs),
        text=file.text,
        skip_reason=file.skip_reason,
    )


def context(case: Case) -> ScanContext:
    """The scan context a fixture is run under: the caps above, the shipped rules and policy."""
    role_globs = load_role_globs(REPO_ROOT / "rules" / "roles.toml")
    return ScanContext(
        entries=tuple(entry_for(file, role_globs) for file in case.files),
        policy=Policy(line_cap=LINE_CAP, tail_max_len=TAIL_MAX_LEN, tail_entropy=TAIL_ENTROPY),
        manifest=case.manifest,
        rules=shipped_rules(),
    )


def fired(case: Case) -> set[str]:
    """Every rule id a fixture triggers, through the engine pass and the whole registry."""
    return {finding.rule_id for finding in scan(context(case))}
