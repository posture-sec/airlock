"""Evidence truncation budget tests for step summary (issue #68).

Tests that evidence truncation counts the ellipsis marker inside SUMMARY_EVIDENCE_CHARS,
covering boundaries 199, 200, 201 chars, None, total length bounds, and backtick fences.
"""

from __future__ import annotations

import pytest

from airlock.report import summary


def test_truncated_none_returns_empty_string() -> None:
    res = summary.truncated(None)
    assert res == ""
    assert len(res) <= summary.SUMMARY_EVIDENCE_CHARS


def test_boundary_199_characters_returned_unchanged() -> None:
    raw = "a" * 199
    res = summary.truncated(raw)
    assert res == raw
    assert len(res) == 199


def test_boundary_200_characters_returned_unchanged() -> None:
    raw = "b" * 200
    res = summary.truncated(raw)
    assert res == raw
    assert len(res) == 200
    assert not res.endswith(" ...")


def test_boundary_201_characters_is_shorter_than_input_and_within_budget() -> None:
    raw = "c" * 201
    res = summary.truncated(raw)
    assert len(res) < 201
    assert len(res) <= summary.SUMMARY_EVIDENCE_CHARS
    assert len(res) == 200
    assert res.endswith(" ...")
    assert res == "c" * 196 + " ..."


@pytest.mark.parametrize("length", [0, 1, 50, 100, 199, 200, 201, 202, 250, 500, 5000])
def test_truncated_never_exceeds_budget(length: int) -> None:
    raw = "x" * length
    res = summary.truncated(raw)
    assert len(res) <= summary.SUMMARY_EVIDENCE_CHARS


def test_exactly_200_backticks_preserves_fence_safety() -> None:
    backticks = "`" * 200
    res = summary.truncated(backticks)
    assert res == backticks
    assert len(res) == 200

    fence = summary.fence_for([res])
    # The fence must be strictly longer than any backtick run in the excerpt
    assert len(fence) == 201
    assert len(fence) > 200
    assert fence == "`" * 201


def test_201_backticks_truncates_within_budget_and_fence_closes() -> None:
    backticks = "`" * 201
    res = summary.truncated(backticks)
    assert len(res) == 200
    assert res.endswith(" ...")

    fence = summary.fence_for([res])
    assert len(fence) == 197
    assert len(fence) > 196
    assert fence == "`" * 197
