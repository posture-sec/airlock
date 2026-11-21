"""Fixture pair distinctness enforcement (issue #84)."""

from __future__ import annotations

import difflib

from tests.fixtures import Case, builders, shipped_rules

from airlock.model import Manifest

# Floor is the smallest token-diff distance among today's non-exempt shipped
# fixture pairs. With whitespace-tokenized case blobs (file paths, normalized
# text/raw hex, and manifest entries), the closest legitimate pairs are
# `npm_lockfile_registry` and `stellar_seed` at distance 1, so every reviewed
# non-exempt pair must differ by at least this much.
DISTINCTNESS_FLOOR = 1

# Reviewed exemptions keyed by builder name. Each reason must name the real
# builder and explain why that builder cannot yet meet the floor without
# changing fixture semantics covered by its rule tests.
DISTINCTNESS_EXEMPTIONS: dict[str, str] = {}


def _normalize_text(text: str) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in normalized.split("\n"))


def _case_blob(case: Case) -> str:
    parts: list[str] = []
    for file in case.files:
        parts.append(f"PATH:{file.path}")
        if file.text is not None:
            parts.append("TEXT:")
            parts.append(_normalize_text(file.text))
        else:
            parts.append("RAW:")
            parts.append(file.content().hex())

    manifest: Manifest = case.manifest
    parts.append(f"MANIFEST_VERSION:{manifest.version}")
    for entry in sorted(manifest.entries, key=lambda item: (item.sha256, item.paths)):
        parts.append("ENTRY:")
        parts.append(entry.sha256)
        parts.append("PATHS:" + ",".join(sorted(entry.paths)))
        parts.append(f"ORIGIN:{entry.origin}")
        parts.append(f"SOURCE:{entry.source}")
        parts.append(f"BUILD:{entry.build}")
        parts.append(f"NOTE:{entry.note}")
    return "\n".join(parts) + "\n"


def _token_diff(left: str, right: str) -> int:
    matcher = difflib.SequenceMatcher(a=left.split(), b=right.split(), autojunk=False)
    diff = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag != "equal":
            diff += max(i2 - i1, j2 - j1)
    return diff


def _distinctness_failures() -> list[str]:
    known = builders()
    failures: list[str] = []
    for rule in shipped_rules():
        builder_name = rule.tests.positive
        # Each shipped rule names the same builder for both halves.
        builder = known[builder_name]
        fixture = builder()
        assert fixture.positive is not None and fixture.negative is not None

        positive_blob = _case_blob(fixture.positive)
        negative_blob = _case_blob(fixture.negative)
        if positive_blob == negative_blob:
            failures.append(f"{builder_name}: positive and negative cases are identical")
            continue

        diff = _token_diff(positive_blob, negative_blob)
        reason = DISTINCTNESS_EXEMPTIONS.get(builder_name)
        if reason is not None:
            if not reason.strip():
                failures.append(f"{builder_name}: exemption reason must be non-empty")
            elif builder_name not in reason:
                failures.append(
                    f"{builder_name}: exemption reason must name the real builder ({reason!r})"
                )
            continue

        if diff < DISTINCTNESS_FLOOR:
            failures.append(
                f"{builder_name}: token diff {diff} is below floor {DISTINCTNESS_FLOOR}"
            )
    return failures


def test_fixture_pairs_are_distinct_and_reviewed() -> None:
    assert _distinctness_failures() == []


def test_identical_halves_are_rejected() -> None:
    from tests.fixtures import File, Fixture

    def identical_builder() -> Fixture:
        case = Case(files=(File("same.txt", text="same\n"),))
        return Fixture(positive=case, negative=case)

    class _Rule:
        class _Tests:
            positive = "identical_builder"
            negative = "identical_builder"

        tests = _Tests()

    def fake_builders() -> dict[str, object]:
        return {"identical_builder": identical_builder}

    def fake_shipped_rules() -> tuple[object, ...]:
        return (_Rule(),)

    original_builders = globals()["builders"]
    original_shipped_rules = globals()["shipped_rules"]
    try:
        globals()["builders"] = fake_builders
        globals()["shipped_rules"] = fake_shipped_rules
        failures = _distinctness_failures()
    finally:
        globals()["builders"] = original_builders
        globals()["shipped_rules"] = original_shipped_rules

    assert failures == ["identical_builder: positive and negative cases are identical"]
