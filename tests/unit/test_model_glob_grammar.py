"""One glob grammar for the matcher and the suppression validator (issue #22)."""

from __future__ import annotations

import pytest

from airlock.model import Suppression

FINGERPRINT = "sha256:" + "0" * 64


def suppression(path: str) -> Suppression:
    return Suppression(
        rule="cfg-dynamic-code",
        path=path,
        fingerprint=FINGERPRINT,
        reason="reviewed by the owner",
    )


class TestSuppressionPathGrammar:
    def test_a_literal_bracketed_path_loads(self) -> None:
        entry = suppression("app/[id].tsx")
        assert entry.path == "app/[id].tsx"

    @pytest.mark.parametrize("path", ["app/*.tsx", "app/?.tsx", "a*/b.tsx"])
    def test_wildcards_are_still_refused(self, path: str) -> None:
        with pytest.raises(ValueError, match="exact path"):
            suppression(path)

    def test_other_validation_is_unchanged(self) -> None:
        with pytest.raises(ValueError, match="repo-relative"):
            suppression("../outside.tsx")
        with pytest.raises(ValueError, match="reason"):
            Suppression(rule="cfg-dynamic-code", path="a.tsx", fingerprint=FINGERPRINT, reason=" ")
