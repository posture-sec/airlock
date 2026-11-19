"""Issue #56 / Task 9.27: ensure docs list only defined cfg-* rules and omit cfg-nul.

ARCHITECTURE_ESSENTIALS.md and PRD.md previously had a phantom rule id `cfg-nul`.
The collector reports NUL bytes as `nul-in-text` (state finding), not as a config_role rule.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ARCH_ESSENTIALS_PATH = REPO_ROOT / "ARCHITECTURE_ESSENTIALS.md"
PRD_PATH = REPO_ROOT / "PRD.md"
CONFIG_ROLE_TOML_PATH = REPO_ROOT / "rules" / "builtin" / "config_role.toml"


def _shipped_cfg_rules() -> set[str]:
    data = tomllib.loads(CONFIG_ROLE_TOML_PATH.read_text(encoding="utf-8"))
    return {rule["id"] for rule in data.get("rule", [])}


def test_architecture_essentials_cfg_rules_match_shipped() -> None:
    """ARCHITECTURE_ESSENTIALS.md config_role row matches shipped cfg-* rules and drops cfg-nul."""
    content = ARCH_ESSENTIALS_PATH.read_text(encoding="utf-8")
    shipped = _shipped_cfg_rules()

    # Find the config_role row in Section 7 Detectors
    match = re.search(r"\|\s*`config_role`\s*\|\s*([^|]+)\s*\|", content)
    assert match is not None, "config_role row not found in ARCHITECTURE_ESSENTIALS.md"

    rules_cell = match.group(1)
    found_ids = set(re.findall(r"`(cfg-[a-z0-9-]+)`", rules_cell))

    assert "cfg-nul" not in found_ids, (
        "cfg-nul phantom rule still present in ARCHITECTURE_ESSENTIALS.md"
    )
    assert found_ids == shipped, f"Rules mismatch: {found_ids} != {shipped}"


def test_prd_detector_catalog_cfg_rules_match_shipped() -> None:
    """PRD.md detector catalog matches shipped cfg-* rules and mentions nul-in-text."""
    content = PRD_PATH.read_text(encoding="utf-8")
    shipped = _shipped_cfg_rules()

    # Extract the config_role table from PRD Section 6.2
    catalog_match = re.search(
        r"\*\*`config_role`\*\*.*?\n(\|.*?\n\n)",
        content,
        re.DOTALL,
    )
    assert catalog_match is not None, "config_role table not found in PRD.md"

    table_text = catalog_match.group(1)
    found_ids = set(re.findall(r"`(cfg-[a-z0-9-]+)`", table_text))

    assert "cfg-nul" not in found_ids, "cfg-nul phantom rule still present in PRD.md table"
    assert found_ids == shipped, f"Rules mismatch in PRD table: {found_ids} != {shipped}"

    # Must mention nul-in-text as the collector state finding
    assert "nul-in-text" in content, "nul-in-text state finding not mentioned in PRD.md"
