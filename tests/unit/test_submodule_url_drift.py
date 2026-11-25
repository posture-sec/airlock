"""Regression coverage for tracked submodule URL drift."""

from __future__ import annotations

from pathlib import Path

from airlock import detectors, roles
from airlock.detectors import submodules
from airlock.model import EMPTY_MANIFEST, FileEntry, Policy, ScanContext
from airlock.rules import load_role_globs, load_rules

ROOT = Path(__file__).resolve().parents[2]
RULE_GLOBS = load_role_globs(ROOT / "rules" / "roles.toml")
RULES = load_rules(
    ROOT / "rules" / "builtin",
    known_detectors=detectors.DETECTOR_NAMES,
    known_roles=sorted(roles.known_roles(RULE_GLOBS)),
)


def _run(url: str | None) -> list[object]:
    lines = '[submodule "dep"]\npath = "vendor/dep"\n'
    if url is not None:
        lines += f'url = "{url}"\n'
    entries = (
        FileEntry(".gitmodules", "a" * 64, ("other",), lines),
        FileEntry("vendor/dep", None, (), None, "submodule"),
    )
    context = ScanContext(entries, Policy(), EMPTY_MANIFEST, RULES)
    return list(submodules.run(context))


def test_canonical_and_relative_urls_are_clean() -> None:
    assert _run("https://github.com/owner/dep.git") == []
    assert _run("../dep.git") == []


def test_mirror_and_missing_urls_warn() -> None:
    assert len(_run("https://mirror.invalid/dep.git")) == 1
    assert len(_run(None)) == 1
