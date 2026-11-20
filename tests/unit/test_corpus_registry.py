"""Corpus registry enforcement (issue #83)."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_ROOT = REPO_ROOT / "tests" / "corpus"
REGISTRY_PATH = CORPUS_ROOT / "registry.toml"
RULES_ROOT = REPO_ROOT / "rules" / "builtin"

COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_KEYS = {"name", "commit", "source_url", "licence", "rules_expected"}


def shipped_rule_ids() -> set[str]:
    ids: set[str] = set()
    for path in RULES_ROOT.glob("*.toml"):
        with path.open("rb") as handle:
            data = tomllib.load(handle)
        for rule in data.get("rules", []):
            rule_id = rule.get("id")
            if isinstance(rule_id, str):
                ids.add(rule_id)
    return ids


def corpus_directories(corpus_root: Path) -> set[str]:
    if not corpus_root.exists():
        return set()
    return {
        path.name
        for path in corpus_root.iterdir()
        if path.is_dir() and not path.name.startswith(".")
    }


def load_registry(registry_path: Path) -> list[dict[str, object]]:
    with registry_path.open("rb") as handle:
        data = tomllib.load(handle)
    snapshots = data.get("snapshots")
    if not isinstance(snapshots, list):
        raise ValueError("registry must define snapshots as a list")
    for item in snapshots:
        if not isinstance(item, dict):
            raise ValueError("each snapshot entry must be a table")
    return snapshots


def validate_corpus_registry(
    corpus_root: Path, registry_path: Path, known_rule_ids: set[str]
) -> list[str]:
    errors: list[str] = []
    snapshots = load_registry(registry_path)
    entries_by_name: dict[str, dict[str, object]] = {}

    for index, entry in enumerate(snapshots):
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            errors.append(f"snapshots[{index}]: name must be a non-empty string")
            continue
        if name in entries_by_name:
            errors.append(f"snapshot {name!r}: duplicate registry entry")
            continue
        entries_by_name[name] = entry

        missing = sorted(REQUIRED_KEYS - set(entry))
        if missing:
            errors.append(f"snapshot {name!r}: missing keys {', '.join(missing)}")

        commit = entry.get("commit")
        if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
            errors.append(f"snapshot {name!r}: commit must be 40 lowercase hex characters")

        licence = entry.get("licence")
        if not isinstance(licence, str) or not licence.strip():
            errors.append(f"snapshot {name!r}: licence must be non-empty")

        source_url = entry.get("source_url")
        if not isinstance(source_url, str) or not source_url.strip():
            errors.append(f"snapshot {name!r}: source_url must be non-empty")

        rules_expected = entry.get("rules_expected")
        if not isinstance(rules_expected, list) or not rules_expected:
            errors.append(f"snapshot {name!r}: rules_expected must be a non-empty array")
        else:
            for rule_id in rules_expected:
                if not isinstance(rule_id, str) or not rule_id:
                    errors.append(
                        f"snapshot {name!r}: rules_expected entries must be non-empty strings"
                    )
                elif rule_id not in known_rule_ids:
                    errors.append(f"snapshot {name!r}: unknown rule id {rule_id!r}")

        if not (corpus_root / name).is_dir():
            errors.append(f"snapshot {name!r}: entry has no matching directory")

    for directory in sorted(corpus_directories(corpus_root) - set(entries_by_name)):
        errors.append(f"corpus directory {directory!r}: not listed in registry")

    return errors


def test_corpus_registry_current_state_is_valid() -> None:
    assert validate_corpus_registry(CORPUS_ROOT, REGISTRY_PATH, shipped_rule_ids()) == []


def test_corpus_registry_rejects_unlisted_directory(tmp_path: Path) -> None:
    corpus_root = tmp_path / "corpus"
    corpus_root.mkdir()
    (corpus_root / "scratch").mkdir()
    registry_path = corpus_root / "registry.toml"
    registry_path.write_text("snapshots = []\n", encoding="utf-8")

    errors = validate_corpus_registry(corpus_root, registry_path, set())

    assert "corpus directory 'scratch': not listed in registry" in errors


def test_corpus_registry_accepts_directory_when_listed(tmp_path: Path) -> None:
    corpus_root = tmp_path / "corpus"
    corpus_root.mkdir()
    (corpus_root / "listed").mkdir()
    registry_path = corpus_root / "registry.toml"
    registry_path.write_text(
        """
[[snapshots]]
name = "listed"
commit = "0123456789abcdef0123456789abcdef01234567"
source_url = "https://example.invalid/repo"
licence = "MIT"
rules_expected = ["stellar-seed"]
""".lstrip(),
        encoding="utf-8",
    )

    errors = validate_corpus_registry(corpus_root, registry_path, {"stellar-seed"})

    assert errors == []


def test_corpus_registry_rejects_entry_without_directory(tmp_path: Path) -> None:
    corpus_root = tmp_path / "corpus"
    corpus_root.mkdir()
    registry_path = corpus_root / "registry.toml"
    registry_path.write_text(
        """
[[snapshots]]
name = "missing"
commit = "0123456789abcdef0123456789abcdef01234567"
source_url = "https://example.invalid/repo"
licence = "MIT"
rules_expected = ["stellar-seed"]
""".lstrip(),
        encoding="utf-8",
    )

    errors = validate_corpus_registry(corpus_root, registry_path, {"stellar-seed"})

    assert "snapshot 'missing': entry has no matching directory" in errors


@pytest.mark.parametrize(
    "commit",
    ["0123456789abcdef0123456789abcdef0123456", "0123456789ABCDEF0123456789abcdef01234567"],
)
def test_corpus_registry_rejects_non_40_hex_commit(tmp_path: Path, commit: str) -> None:
    corpus_root = tmp_path / "corpus"
    corpus_root.mkdir()
    (corpus_root / "sample").mkdir()
    registry_path = corpus_root / "registry.toml"
    registry_path.write_text(
        f"""
[[snapshots]]
name = "sample"
commit = "{commit}"
source_url = "https://example.invalid/repo"
licence = "MIT"
rules_expected = ["stellar-seed"]
""".lstrip(),
        encoding="utf-8",
    )

    errors = validate_corpus_registry(corpus_root, registry_path, {"stellar-seed"})

    assert "snapshot 'sample': commit must be 40 lowercase hex characters" in errors


def test_corpus_registry_rejects_empty_licence(tmp_path: Path) -> None:
    corpus_root = tmp_path / "corpus"
    corpus_root.mkdir()
    (corpus_root / "sample").mkdir()
    registry_path = corpus_root / "registry.toml"
    registry_path.write_text(
        """
[[snapshots]]
name = "sample"
commit = "0123456789abcdef0123456789abcdef01234567"
source_url = "https://example.invalid/repo"
licence = "   "
rules_expected = ["stellar-seed"]
""".lstrip(),
        encoding="utf-8",
    )

    errors = validate_corpus_registry(corpus_root, registry_path, {"stellar-seed"})

    assert "snapshot 'sample': licence must be non-empty" in errors


def test_corpus_registry_rejects_unknown_rule_id(tmp_path: Path) -> None:
    corpus_root = tmp_path / "corpus"
    corpus_root.mkdir()
    (corpus_root / "sample").mkdir()
    registry_path = corpus_root / "registry.toml"
    registry_path.write_text(
        """
[[snapshots]]
name = "sample"
commit = "0123456789abcdef0123456789abcdef01234567"
source_url = "https://example.invalid/repo"
licence = "MIT"
rules_expected = ["not-a-real-rule"]
""".lstrip(),
        encoding="utf-8",
    )

    errors = validate_corpus_registry(corpus_root, registry_path, {"stellar-seed"})

    assert "snapshot 'sample': unknown rule id 'not-a-real-rule'" in errors
