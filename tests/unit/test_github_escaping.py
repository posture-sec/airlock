"""GitHub property and data escaping order tests (issue #65).

Pins the exact output bytes across all five property characters (%, CR, LF, :, ,)
and all three data characters (%, CR, LF), ensuring % is escaped first so literal
sequences like %0A and %25 are never confused with encoded ones.
"""

from __future__ import annotations

import pytest

from airlock.report.github import escape_data, escape_property


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("%", "%25"),
        ("\r", "%0D"),
        ("\n", "%0A"),
        (":", "%3A"),
        (",", "%2C"),
        ("%0A", "%250A"),
        ("%25", "%2525"),
        ("100%:\r,\n", "100%25%3A%0D%2C%0A"),
        ("% \r \n : , %0A %25", "%25 %0D %0A %3A %2C %250A %2525"),
    ],
)
def test_escape_property_exact_bytes(raw: str, expected: str) -> None:
    assert escape_property(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("%", "%25"),
        ("\r", "%0D"),
        ("\n", "%0A"),
        (":", ":"),
        (",", ","),
        ("%0A", "%250A"),
        ("%25", "%2525"),
        ("100%:\r,\n", "100%25:%0D,%0A"),
        ("% \r \n : , %0A %25", "%25 %0D %0A : , %250A %2525"),
    ],
)
def test_escape_data_exact_bytes(raw: str, expected: str) -> None:
    assert escape_data(raw) == expected


def test_real_newline_and_literal_percent_zero_a_produce_distinct_bytes_in_property() -> None:
    # A real newline becomes %0A; a literal %0A becomes %250A.
    # If substitutions swapped order (newline before percent), real newline would become %250A.
    real_nl = escape_property("\n")
    literal_seq = escape_property("%0A")

    assert real_nl == "%0A"
    assert literal_seq == "%250A"
    assert real_nl != literal_seq

    combined = "path/with\nnewline/and%0Aliteral"
    assert escape_property(combined) == "path/with%0Anewline/and%250Aliteral"


def test_real_newline_and_literal_percent_zero_a_produce_distinct_bytes_in_data() -> None:
    real_nl = escape_data("\n")
    literal_seq = escape_data("%0A")

    assert real_nl == "%0A"
    assert literal_seq == "%250A"
    assert real_nl != literal_seq

    combined = "message with\nnewline and %0A literal"
    assert escape_data(combined) == "message with%0Anewline and %250A literal"
