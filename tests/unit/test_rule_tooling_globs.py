"""Regression coverage for config filenames loaded by build and test tools."""

from __future__ import annotations

from pathlib import Path

from tests.fixtures import fired
from tests.fixtures.tooling_globs_extra import tooling_globs_extra

from airlock.roles import resolve_roles
from airlock.rules import load_role_globs

ROOT = Path(__file__).resolve().parents[2]


def test_vite_webpack_and_jest_configs_resolve_to_tooling_config() -> None:
    globs = load_role_globs(ROOT / "rules" / "roles.toml")
    for path in ("vite.config.ts", "packages/webpack.config.js", "tests/jest.config.js"):
        assert "tooling-config" in resolve_roles(path, b"", globs)


def test_extra_tooling_configs_expose_capability_rules() -> None:
    fixture = tooling_globs_extra()
    assert fixture.positive is not None
    assert fixture.negative is not None
    assert "cfg-network" in fired(fixture.positive)
    assert "cfg-network" not in fired(fixture.negative)
