"""Issue #31: the detector registry and the rule data must describe the same detectors.

`DETECTORS` is a literal tuple of functions and `DETECTOR_NAMES` is a separate frozenset the rule
loader cross-checks every `builtin:<name>` pointer against. Nothing asserted the two halves agree,
and each disagreement is silent in a different way: a function in `DETECTORS` without its name
breaks every rule that names it, a name with no rule is a detector that never runs, and a rule
file that loses its last pointer leaves a detector with no fixture and no coverage while the
suite stays green, because the fixture gate iterates rules and cannot see a detector with none.

`parity_problems` is the whole check, written over its three inputs so the two mutated cases can
call it with the defect in place instead of asserting that the real tree happens to be fine.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from tests.fixtures import shipped_rules

from airlock.detectors import DETECTOR_NAMES, DETECTORS, Detector
from airlock.model import Rule

BUILTIN = "builtin:"


def detector_name(detector: Detector) -> str:
    """The bare name a rule file points at: the detector function's own module stem."""
    return detector.__module__.rsplit(".", 1)[-1]


def pointers(rules: Iterable[Rule]) -> set[str]:
    """Every bare name a `builtin:` pointer in the rule data resolves to."""
    return {
        rule.detector.removeprefix(BUILTIN) for rule in rules if rule.detector.startswith(BUILTIN)
    }


def parity_problems(
    detectors: tuple[Detector, ...],
    names: frozenset[str],
    rules: Iterable[Rule],
) -> list[str]:
    """Every way the three collections disagree, as one line each. Empty means parity."""
    problems: list[str] = []
    derived = [detector_name(detector) for detector in detectors]
    if len(derived) != len(names):
        problems.append(
            f"DETECTORS holds {len(derived)} function(s) and DETECTOR_NAMES {len(names)}, so one"
            " collection names a detector the other does not"
        )
    duplicates = sorted({name for name in derived if derived.count(name) > 1})
    if duplicates:
        problems.append(f"two detectors resolve to the same name: {', '.join(duplicates)}")

    rule_set = tuple(rules)
    pointed = pointers(rule_set)
    for name in sorted(set(derived) - set(names)):
        problems.append(
            f"detector {name} is registered in DETECTORS but missing from DETECTOR_NAMES"
        )
    for name in sorted(set(names) - set(derived)):
        problems.append(f"detector {name} is in DETECTOR_NAMES but has no function in DETECTORS")
    for name in sorted(set(names) - pointed):
        problems.append(f"detector {name} owns no rule, so it runs for nothing")
    for name in sorted(pointed - set(names)):
        problems.append(
            f"rule data points at builtin:{name}, which is not a registered detector name"
        )
    if not problems and pointed != set(names):
        problems.append(f"rule pointers {sorted(pointed)} do not equal {sorted(names)}")
    return problems


def shipped() -> tuple[Rule, ...]:
    return shipped_rules()


class TestTheRegistryMatchesTheRuleData:
    def test_the_two_collections_have_equal_size(self) -> None:
        assert len(DETECTORS) == len(DETECTOR_NAMES)

    def test_detector_names_are_distinct(self) -> None:
        derived = [detector_name(detector) for detector in DETECTORS]
        assert len(derived) == len(set(derived)), derived

    def test_every_registered_name_is_the_one_its_module_is_called(self) -> None:
        assert {detector_name(detector) for detector in DETECTORS} == set(DETECTOR_NAMES)

    def test_the_rule_pointers_are_exactly_the_registered_names(self) -> None:
        assert pointers(shipped()) == set(DETECTOR_NAMES)

    def test_every_detector_owns_at_least_one_rule(self) -> None:
        assert sorted(set(DETECTOR_NAMES) - pointers(shipped())) == []

    def test_the_real_tree_has_no_parity_problem(self) -> None:
        assert parity_problems(DETECTORS, DETECTOR_NAMES, shipped()) == []


class TestTheCheckBites:
    def test_a_pointer_no_detector_answers_is_reported(self) -> None:
        rule = shipped()[0]
        problems = parity_problems(
            DETECTORS, DETECTOR_NAMES, (*shipped(), replace(rule, detector=f"{BUILTIN}nope"))
        )
        assert problems == [
            "rule data points at builtin:nope, which is not a registered detector name"
        ]

    def test_a_name_with_no_function_behind_it_is_reported(self) -> None:
        problems = parity_problems(DETECTORS, DETECTOR_NAMES - {"wasm_manifest"}, shipped())
        assert (
            "detector wasm_manifest is registered in DETECTORS but missing from DETECTOR_NAMES"
            in problems
        )
