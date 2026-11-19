"""Issue #97 / Task 9.28: assert test counts in README and badge agree.

Checks that:
1. README.md metrics block: "**X passing**"
2. README.md prose table row: "X tests in CI"
3. site/data/badge-tests.json: "X passed"
All agree on the exact same integer count.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
README_PATH = REPO_ROOT / "README.md"
BADGE_TESTS_PATH = REPO_ROOT / "site" / "data" / "badge-tests.json"


def get_metrics_test_count() -> int:
    readme_text = README_PATH.read_text(encoding="utf-8")
    m = re.search(r"\|\s*Test Suite\s*\|\s*\*\*(\d+)\s+passing\*\*", readme_text)
    assert m is not None, "Test Suite count not found in README.md metrics block"
    return int(m.group(1))


def get_prose_test_count() -> int:
    readme_text = README_PATH.read_text(encoding="utf-8")
    m = re.search(r"(\d+)\s+tests in CI", readme_text)
    assert m is not None, "Prose 'X tests in CI' count not found in README.md"
    return int(m.group(1))


def get_badge_test_count() -> int:
    badge_data = json.loads(BADGE_TESTS_PATH.read_text(encoding="utf-8"))
    msg = badge_data.get("message", "")
    m = re.search(r"(\d+)\s+passed", msg)
    assert m is not None, f"Passed count not found in badge message: {msg}"
    return int(m.group(1))


def test_readme_and_badge_test_counts_agree() -> None:
    """The metrics block, prose count, and badge-tests.json must agree on one integer."""
    metrics_count = get_metrics_test_count()
    prose_count = get_prose_test_count()
    badge_count = get_badge_test_count()

    assert metrics_count == prose_count == badge_count, (
        f"Disagreement: metrics={metrics_count}, prose={prose_count}, badge={badge_count}"
    )
