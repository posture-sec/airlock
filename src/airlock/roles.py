"""Role resolution: content magic, then globs from `rules/roles.toml`, then extension fallback.

Task 2.4 (`ARCHITECTURE.md` 6.2). Magic comes first on purpose: renaming `contract.wasm` to
`contract.bin` must not change how the file is treated, and an extension list is not a
security boundary.

The glob matcher is written here instead of using `fnmatch`, because `fnmatch` lets a lone
`*` cross directory separators. That single behavior is how the old in-repo allowlist could
be turned off with one `*` line (PRD 2.3 item 3). Here `*` never crosses `/` and `**` does.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from pathlib import PurePosixPath

WASM_MAGIC = b"\x00asm"
WASM_ROLE = "wasm"
NATIVE_ROLE = "native-binary"
ARCHIVE_ROLE = "archive"
SOURCE_ROLE = "source"
DOC_ROLE = "doc"
OTHER_ROLE = "other"

#: Roles defined by `rules/roles.toml` rather than by content or extension. The detectors that
#: own a role name it here, so a rename in the data file fails a test instead of silencing a
#: detector.
TOOLING_CONFIG_ROLE = "tooling-config"
EDITOR_AUTORUN_ROLE = "editor-autorun"
WORKFLOW_ROLE = "workflow"
PACKAGE_MANIFEST_ROLE = "package-manifest"
INSTALL_HOOK_ROLE = "install-hook"

# Mach-O appears in both endiannesses and as a fat archive. PE files also start with MZ, but
# that two-byte check lives in `_is_pe`: two ASCII bytes are a legal start for a text file, so
# the prefix alone cannot decide the file is a binary.
_NATIVE_PREFIXES: tuple[bytes, ...] = (
    b"\x7fELF",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xfe\xed\xfa\xca",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
)

_ARCHIVE_PREFIXES: tuple[bytes, ...] = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ",
    b"\x04\x22\x4d\x18",
    b"Rar!\x1a\x07",
    b"7z\xbc\xaf\x27\x1c",
)

_TAR_MAGIC_AT_257 = b"ustar"

#: A PE file is recognised from header bytes already read. `MZ` alone is not enough: it would
#: let whoever commits a file remove it from every text rule by choosing its first two characters.
_MZ_PREFIX = b"MZ"
_DOS_HEADER_BYTES = 64
_E_LFANEW_OFFSET = 0x3C
_PE_SIGNATURE = b"PE\x00\x00"

#: Roles where a file the scanner could not fully read is a HIGH finding, not a WARN
#: (`ARCHITECTURE.md` 8). Hiding a payload in a build config is the attack this tool exists
#: for, so an incomplete read of one of these is treated as the payload it might conceal.
#:
#: The three CI surface roles join on the same test, which is whether something executes the file
#: with credentials attached: a workflow runs in the repository's own GitHub App context with a
#: write token, a package manifest's lifecycle scripts run on every `npm install`, and a hook runs
#: on every commit a developer makes. The false-positive cost of the decision is bounded, because
#: this only changes the severity of a file the scanner could not read in full, which is already a
#: finding either way. A `.vscode/settings.json` is sensitive through `editor-autorun`.
SENSITIVE_ROLES = frozenset(
    {
        TOOLING_CONFIG_ROLE,
        EDITOR_AUTORUN_ROLE,
        WORKFLOW_ROLE,
        PACKAGE_MANIFEST_ROLE,
        INSTALL_HOOK_ROLE,
    }
)

#: Every role name the resolver can produce before `roles.toml` globs are added.
BUILTIN_ROLES = frozenset({WASM_ROLE, NATIVE_ROLE, ARCHIVE_ROLE, SOURCE_ROLE, DOC_ROLE, OTHER_ROLE})

SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".js",
        ".mjs",
        ".cjs",
        ".jsx",
        ".ts",
        ".tsx",
        ".rs",
        ".go",
        ".java",
        ".rb",
        ".php",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".hpp",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".bat",
        ".cmd",
        ".toml",
        ".json",
        ".jsonc",
        ".yaml",
        ".yml",
        ".sql",
        ".css",
        ".scss",
        ".html",
        ".vue",
        ".svelte",
        ".mk",
        ".cmake",
    }
)

DOC_SUFFIXES = frozenset({".md", ".markdown", ".txt", ".rst", ".adoc", ".cfg", ".ini"})


def _is_pe(head: bytes) -> bool:
    """True when the DOS header points at a PE signature inside the buffer.

    Only header bytes are read: the `e_lfanew` offset is bounds-checked against the buffer, so
    no length taken from the file is ever followed into it. A truncated MZ file fails this check
    and falls through to the role globs and extension, where it is scanned as text.
    """
    if len(head) < _DOS_HEADER_BYTES:
        return False
    offset = int.from_bytes(head[_E_LFANEW_OFFSET : _E_LFANEW_OFFSET + 4], "little")
    return head[offset : offset + len(_PE_SIGNATURE)] == _PE_SIGNATURE


def roles_from_magic(head: bytes) -> tuple[str, ...]:
    """Content-magic roles, applied whatever the extension claims (FR-02)."""
    if head.startswith(WASM_MAGIC):
        return (WASM_ROLE,)
    if head.startswith(_MZ_PREFIX):
        return (NATIVE_ROLE,) if _is_pe(head) else ()
    if head.startswith(_NATIVE_PREFIXES):
        return (NATIVE_ROLE,)
    if head.startswith(_ARCHIVE_PREFIXES) or (
        len(head) >= 262 and head[257:262] == _TAR_MAGIC_AT_257
    ):
        return (ARCHIVE_ROLE,)
    return ()


def _segment_pattern(segment: str) -> re.Pattern[str]:
    """Compile one path segment: `*` stays inside the segment, `?` matches one character.

    There is no local cache here: `re.compile` already memoizes, and a module-level dict
    would be the mutable state the code conventions forbid.
    """
    parts: list[str] = []
    for char in segment:
        if char == "*":
            parts.append("[^/]*")
        elif char == "?":
            parts.append("[^/]")
        else:
            parts.append(re.escape(char))
    return re.compile("\\A" + "".join(parts) + "\\Z")


def match_glob(pattern: str, path: str) -> bool:
    """Match a repo-relative path against one roles.toml pattern."""
    return _match_segments(pattern.split("/"), path.split("/"))


def _match_segments(pattern: list[str], path: list[str]) -> bool:
    if not pattern:
        return not path
    head = pattern[0]
    rest = pattern[1:]
    if head == "**":
        if not rest:
            return True
        return any(_match_segments(rest, path[start:]) for start in range(len(path) + 1))
    if not path:
        return False
    if not _segment_pattern(head).match(path[0]):
        return False
    return _match_segments(rest, path[1:])


def known_roles(role_globs: Iterable[str]) -> frozenset[str]:
    """Every role name a rule may legally reference.

    A rule naming a role no resolver can produce is a typo that would silence it forever, so
    the rule loader cross-checks against this set (`ARCHITECTURE.md` 6.4).
    """
    return BUILTIN_ROLES | frozenset(role_globs)


def fallback_role(path: str) -> str:
    """Extension fallback, the last step of resolution order."""
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in SOURCE_SUFFIXES:
        return SOURCE_ROLE
    if suffix in DOC_SUFFIXES:
        return DOC_ROLE
    return OTHER_ROLE


def resolve_roles(
    path: str,
    head: bytes,
    role_globs: Mapping[str, tuple[str, ...]],
) -> tuple[str, ...]:
    """Every role that applies, in a stable order.

    A binary magic role means the file is not decoded text, so the extension fallback is
    deliberately not added for it: a Mach-O binary called `payload.rs` is `native-binary`,
    not a source file to run text rules over.
    """
    magic = roles_from_magic(head)
    if magic:
        return magic
    roles = [role for role, globs in sorted(role_globs.items()) if _any_glob(globs, path)]
    roles.append(fallback_role(path))
    return tuple(dict.fromkeys(roles))


def _any_glob(globs: tuple[str, ...], path: str) -> bool:
    return any(match_glob(pattern, path) for pattern in globs)
