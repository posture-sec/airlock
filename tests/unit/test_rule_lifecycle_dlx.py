"""Regression coverage for one-shot package runners."""

from __future__ import annotations

from tests.fixtures import fired
from tests.fixtures.lifecycle_dlx import lifecycle_dlx


def test_remote_one_shot_runners_fire_the_fetch_rule() -> None:
    fixture = lifecycle_dlx()
    assert fixture.positive is not None
    assert "pat-lifecycle-fetch" in fired(fixture.positive)


def test_bare_one_shot_package_names_stay_clean() -> None:
    fixture = lifecycle_dlx()
    assert fixture.negative is not None
    assert "pat-lifecycle-fetch" not in fired(fixture.negative)
