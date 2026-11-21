"""The fingerprint payload is self-delimiting (issue #19, `ARCHITECTURE.md` 7.3)."""

from __future__ import annotations

import hashlib

from tests.fixtures import assemble

from airlock.fingerprint import _payload, fingerprint

_PAYLOAD = f"{assemble('ev', 'al')}({assemble('Buf', 'fer.from')}(p, 'base64'))"
NUL_FREE = ("cfg-dynamic-code", "postcss.config.mjs", _PAYLOAD, 0)
# The digest the published `\0` join produced before the length-prefixed branch existed.
PINNED = "sha256:3e1c980869ae432c985b851e1dd4be15a76c3cd3511f302298623bd4bc54c170"


class TestNulFreePayload:
    def test_a_nul_free_quadruple_keeps_todays_digest(self) -> None:
        assert fingerprint(*NUL_FREE) == PINNED

    def test_a_normal_payload_has_exactly_three_separators(self) -> None:
        assert _payload(*NUL_FREE).count(b"\x00") == 3

    def test_a_nul_free_payload_matches_the_old_join_byte_for_byte(self) -> None:
        fields = tuple(str(field) for field in NUL_FREE)
        assert _payload(*NUL_FREE) == "\0".join(fields).encode()


class TestNulEvidence:
    def test_evidence_split_at_a_nul_is_a_different_digest(self) -> None:
        # Under the old join both spellings produced the same payload:
        # rule \0 path \0 a \0 b \0 occurrence.
        left = fingerprint("cfg-dynamic-code", "a.js", "a\x00b", 0)
        right = fingerprint("cfg-dynamic-code", "a\x00b", "a", 0)
        assert left != right

    def test_a_nul_payload_is_length_prefixed_behind_the_marker(self) -> None:
        payload = _payload("cfg-dynamic-code", "a.js", "a\x00b", 0)
        assert payload.startswith(b"\x00")
        # Four 8-byte lengths, then the field bytes.
        assert len(payload) == 1 + 4 * 8 + len("cfg-dynamic-code") + len("a.js") + 3 + 1

    def test_the_digest_is_sha256_of_the_payload(self) -> None:
        assert fingerprint("r", "p", "a\x00b", 3) == (
            "sha256:" + hashlib.sha256(_payload("r", "p", "a\x00b", 3)).hexdigest()
        )
