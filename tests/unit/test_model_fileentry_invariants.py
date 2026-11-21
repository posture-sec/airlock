"""`FileEntry`'s three states are mutually exclusive (#21).

The collector produces read entries, hashed-but-not-decoded entries and skipped entries. The
model used to accept every combination of `sha256`, `text` and `skip_reason`, so a skipped entry
carrying text could make a detector scan bytes the report said were never read. These tests pin
the matrix, one case per accepted state and per rejected combination.
"""

from __future__ import annotations

import pytest

from airlock.model import FileEntry

DIGEST = "a" * 64


def entry(**fields: object) -> FileEntry:
    return FileEntry(path="app.py", **fields)  # type: ignore[arg-type]


class TestAcceptedStates:
    def test_a_read_entry_carries_a_digest_and_its_text(self) -> None:
        built = entry(sha256=DIGEST, roles=("source",), text="value = 1\n")

        assert built.text == "value = 1\n"
        assert built.skip_reason is None

    def test_a_hashed_but_undecoded_entry_carries_only_a_digest(self) -> None:
        built = entry(sha256=DIGEST, roles=("native-binary",))

        assert built.text is None
        assert built.skip_reason is None

    def test_a_skipped_entry_carries_only_a_reason(self) -> None:
        built = entry(sha256=None, roles=("source",), skip_reason="oversize")

        assert built.text is None
        assert built.skip_reason == "oversize"


class TestRejectedCombinations:
    def test_text_with_a_skip_reason_is_rejected(self) -> None:
        with pytest.raises(ValueError) as error:
            entry(sha256=DIGEST, roles=("source",), text="x", skip_reason="oversize")

        message = str(error.value)
        assert "app.py" in message
        assert "cannot carry text" in message
        assert "oversize" in message

    def test_text_without_a_digest_is_rejected(self) -> None:
        with pytest.raises(ValueError) as error:
            entry(sha256=None, roles=("source",), text="x")

        assert "app.py" in str(error.value)
        assert "text requires a sha256" in str(error.value)

    def test_a_skip_reason_with_a_digest_is_rejected(self) -> None:
        with pytest.raises(ValueError) as error:
            entry(sha256=DIGEST, roles=("source",), skip_reason="oversize")

        message = str(error.value)
        assert "app.py" in message
        assert "cannot carry a sha256" in message

    def test_neither_a_digest_nor_a_skip_reason_is_rejected(self) -> None:
        with pytest.raises(ValueError) as error:
            entry(sha256=None, roles=("source",))

        assert "app.py" in str(error.value)
        assert "neither text, a sha256 digest nor a skip_reason" in str(error.value)
