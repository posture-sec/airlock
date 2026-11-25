"""Check tracked submodule URLs against the repository's canonical host.

The submodule contents are deliberately out of scope: fetching or importing them would violate
the scanner's offline and trusted-code boundaries. The URL in `.gitmodules` is still actionable
metadata, and a gitlink without a matching URL is not an auditable dependency.
"""

from __future__ import annotations

import json
import tomllib
from collections.abc import Mapping
from urllib.parse import urlsplit

from ..fingerprint import PendingFinding
from ..model import FileEntry, Rule, ScanContext
from ..rules import finding_for

RULE_ID = "submodule-url-drift"
CANONICAL_HOSTS = frozenset({"github.com"})
GITLINK_SKIP_REASON = "submodule"


def _rule(ctx: ScanContext) -> Rule:
    for rule in ctx.rules:
        if rule.id == RULE_ID:
            return rule
    raise ValueError(f"submodules cannot run without the {RULE_ID} rule loaded")


def _gitmodules(entries: tuple[FileEntry, ...]) -> Mapping[str, Mapping[str, object]]:
    source = next((entry for entry in entries if entry.path == ".gitmodules"), None)
    if source is None or source.text is None:
        return {}
    # Git's section header is INI-shaped (`[submodule "name"]`), while the values are the
    # simple key/value subset accepted by TOML. Normalize only that header so tomllib remains the
    # parser and malformed content still raises a detector error.
    normalized: list[str] = []
    for line in source.text.splitlines():
        header = line.strip()
        if header.startswith('[submodule "') and header.endswith('"]'):
            name = header[len('[submodule "') : -2]
            normalized.append(f"[submodule.{json.dumps(name)}]")
        else:
            normalized.append(line)
    parsed = tomllib.loads("\n".join(normalized))
    submodules = parsed.get("submodule", {})
    if not isinstance(submodules, dict):
        raise ValueError(".gitmodules submodule table is not a table")
    result: dict[str, Mapping[str, object]] = {}
    for values in submodules.values():
        if not isinstance(values, dict):
            raise ValueError(".gitmodules submodule entry is not a table")
        path = values.get("path")
        if not isinstance(path, str) or not path:
            continue
        result[path] = values
    return result


def _host(url: str) -> str | None:
    if url.startswith(("../", "./")) or url in {"..", "."}:
        return "github.com"
    if url.startswith("git@") and ":" in url:
        return url[4:].split(":", 1)[0].lower()
    parsed = urlsplit(url)
    return parsed.hostname.lower() if parsed.hostname else None


def _finding(rule: Rule, entry: FileEntry, message: str, evidence: str) -> PendingFinding:
    return finding_for(rule, entry, 0, evidence=evidence, message=message)


def run(ctx: ScanContext) -> tuple[PendingFinding, ...]:
    """Report each gitlink whose tracked URL is missing or off the canonical host."""
    rule = _rule(ctx)
    urls = _gitmodules(ctx.entries)
    findings: list[PendingFinding] = []
    for entry in ctx.entries:
        if entry.skip_reason != GITLINK_SKIP_REASON:
            continue
        values = urls.get(entry.path)
        url = values.get("url") if values is not None else None
        if not isinstance(url, str) or not url:
            findings.append(
                _finding(
                    rule,
                    entry,
                    f"{entry.path} is a gitlink with no URL in .gitmodules",
                    "missing-url",
                )
            )
            continue
        host = _host(url)
        if host not in CANONICAL_HOSTS:
            findings.append(
                _finding(
                    rule,
                    entry,
                    f"{entry.path} points to non-canonical submodule host {host or 'unknown'}",
                    url,
                )
            )
    return tuple(findings)
