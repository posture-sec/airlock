"""Issue #28 / Task 9.26: reconcile cfg-long-line severity docs with engine behavior.

The engine caps cfg-long-line severity to WARN outside sensitive roles (like tooling-config).
The README must accurately document this dual severity.
"""

from __future__ import annotations

from pathlib import Path

from airlock.model import Severity
from airlock.rules import SENSITIVE_ROLES, _cap_severity

REPO_ROOT = Path(__file__).resolve().parents[2]
README_PATH = REPO_ROOT / "README.md"


def test_cap_severity_engine_behavior() -> None:
    """_cap_severity keeps HIGH for sensitive roles and demotes to WARN elsewhere."""
    assert "tooling-config" in SENSITIVE_ROLES
    assert "source" not in SENSITIVE_ROLES

    # Build config / sensitive role keeps authored HIGH
    assert _cap_severity(Severity.HIGH, ["tooling-config"]) is Severity.HIGH
    assert _cap_severity(Severity.HIGH, ["editor-autorun"]) is Severity.HIGH

    # Source or general role demotes to WARN
    assert _cap_severity(Severity.HIGH, ["source"]) is Severity.WARN
    assert _cap_severity(Severity.HIGH, ["other"]) is Severity.WARN
    assert _cap_severity(Severity.HIGH, []) is Severity.WARN

    # Authored WARN stays WARN
    assert _cap_severity(Severity.WARN, ["source"]) is Severity.WARN


def test_readme_documents_long_line_demotion() -> None:
    """The README cfg-long-line row states HIGH in a build config, WARN elsewhere."""
    readme_text = README_PATH.read_text(encoding="utf-8")

    # Find the cfg-long-line row in README.md
    long_line_row = None
    for line in readme_text.splitlines():
        if "| `cfg-long-line` |" in line:
            long_line_row = line
            break

    assert long_line_row is not None, "cfg-long-line row not found in README.md"

    # The row must state both HIGH in a build config and WARN elsewhere
    assert "HIGH in a build config, WARN elsewhere" in long_line_row, (
        f"cfg-long-line row does not document demotion: {long_line_row}"
    )
