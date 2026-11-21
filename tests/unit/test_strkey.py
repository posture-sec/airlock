"""The strkey seed decoder against vectors built at test time (#26).

No complete 56-character seed appears in this file. Every candidate is encoded here from a
32-byte body assembled from fragments, so the checksum, version and length cases are exercised
without committing anything that looks like a live seed (`AGENTS.md` 4).
"""

from __future__ import annotations

import base64

from airlock.strkey import SEED_VERSION, crc16_xmodem, decode_seed

#: The 32-byte body. Assembled from two fragments so no seed literal sits in the file.
SEED = bytes.fromhex("00" * 16) + bytes(range(16))


def encode(seed: bytes = SEED, version: int = SEED_VERSION) -> str:
    """Build a canonical uppercase unpadded Base32 candidate with a valid checksum."""
    body = bytes([version]) + seed
    return base64.b32encode(body + crc16_xmodem(body).to_bytes(2, "little")).decode("ascii")


def flip_last(candidate: str) -> str:
    """Change one character, which lands in the checksum bytes."""
    replacement = "B" if candidate[-1] != "B" else "C"
    return candidate[:-1] + replacement


class TestValidVector:
    def test_a_valid_vector_decodes_to_the_32_byte_seed(self) -> None:
        decoded = decode_seed(encode())

        assert decoded is not None
        assert len(decoded) == 32
        assert decoded == SEED

    def test_the_version_byte_is_0x90(self) -> None:
        raw = base64.b32decode(encode())

        assert raw[0] == 0x90
        assert SEED_VERSION == 0x90


class TestRejections:
    def test_a_flipped_checksum_character_returns_none(self) -> None:
        assert decode_seed(flip_last(encode())) is None

    def test_version_0x91_returns_none(self) -> None:
        assert decode_seed(encode(version=0x91)) is None

    def test_a_55_character_candidate_returns_none(self) -> None:
        assert decode_seed(encode()[:-1]) is None

    def test_lowercase_input_returns_none(self) -> None:
        assert decode_seed(encode().lower()) is None

    def test_a_non_base32_character_returns_none(self) -> None:
        candidate = encode()
        assert decode_seed(candidate[:20] + "1" + candidate[21:]) is None

    def test_a_56_character_literal_that_does_not_checksum_returns_none(self) -> None:
        assert decode_seed("S" + "A" * 55) is None
