"""Role resolution tests (task 2.4)."""

from __future__ import annotations

import pytest

from airlock.roles import (
    ARCHIVE_ROLE,
    DOC_ROLE,
    NATIVE_ROLE,
    OTHER_ROLE,
    SOURCE_ROLE,
    WASM_ROLE,
    fallback_role,
    match_glob,
    resolve_roles,
    roles_from_magic,
)

WASM_HEAD = b"\x00asm\x01\x00\x00\x00"
ROLE_GLOBS = {
    "editor-autorun": ("**/.vscode/tasks.json",),
    "tooling-config": (
        "**/postcss.config.*",
        "**/tailwind.config.*",
        "**/next.config.*",
        "**/eslint.config.*",
        "**/babel.config.*",
    ),
}


def _pe_head(lfanew: int = 0x40) -> bytes:
    """A minimal PE head: `MZ`, `e_lfanew` at 0x3C and the signature it points at."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = lfanew.to_bytes(4, "little")
    return bytes(dos) + b"\x00" * (lfanew - len(dos)) + b"PE\x00\x00"


class TestMagic:
    def test_wasm_magic_wins_over_the_extension(self) -> None:
        assert roles_from_magic(WASM_HEAD) == (WASM_ROLE,)

    @pytest.mark.parametrize(
        "head",
        [
            b"\x7fELF\x02\x01\x01",
            _pe_head(),
            b"\xca\xfe\xba\xbe",
            b"\xcf\xfa\xed\xfe",
        ],
    )
    def test_native_binaries(self, head: bytes) -> None:
        assert roles_from_magic(head) == (NATIVE_ROLE,)

    @pytest.mark.parametrize("head", [b"PK\x03\x04mock", b"\x1f\x8b\x08\x00", b"BZh9mock"])
    def test_archives(self, head: bytes) -> None:
        assert roles_from_magic(head) == (ARCHIVE_ROLE,)

    def test_tar_is_found_at_offset_257_not_at_the_start(self) -> None:
        head = b"\0" * 257 + b"ustar\x00" + b"\0" * 5
        assert roles_from_magic(head) == (ARCHIVE_ROLE,)

    def test_short_text_has_no_magic_role(self) -> None:
        assert roles_from_magic(b"export default {}") == ()

    def test_a_truncated_header_does_not_match_tar(self) -> None:
        assert roles_from_magic(b"ustar") == ()


class TestGlob:
    def test_a_lone_star_cannot_cross_a_directory(self) -> None:
        # This is the exact hole the old allowlist fell through: one `*` line matched
        # everything once fnmatch was allowed to cross `/`.
        assert not match_glob("*", "src/index.ts")
        assert not match_glob("*.js", "src/a.js")
        assert match_glob("*.js", "a.js")

    def test_double_star_spans_directories(self) -> None:
        assert match_glob("**/postcss.config.*", "postcss.config.mjs")
        assert match_glob("**/postcss.config.*", "apps/web/postcss.config.js")
        assert match_glob("**/*.js", "a.js")
        assert match_glob("**/*.js", "deep/nested/path/file.js")

    def test_double_star_alone_covers_the_tree_below_it(self) -> None:
        assert match_glob("**", "a")
        assert match_glob("vendor/**", "vendor/a/b/c.js")
        assert not match_glob("vendor/**", "vendored/a.js")

    def test_dots_are_literal_not_wildcards(self) -> None:
        assert not match_glob("**/postcss.config.*", "postcssXconfigYmjs")

    def test_question_mark_matches_one_character_in_a_segment(self) -> None:
        assert match_glob("a?c.js", "abc.js")
        assert not match_glob("a?c.js", "ac.js")
        assert not match_glob("a?c.js", "a/c.js")

    def test_a_pattern_needs_every_segment(self) -> None:
        assert match_glob("**/.vscode/tasks.json", "repo/.vscode/tasks.json")
        assert not match_glob("**/.vscode/tasks.json", "repo/tasks.json")

    def test_brackets_in_a_path_are_literal(self) -> None:
        assert match_glob("**/[id].tsx", "app/[id]/page.tsx") is False
        assert match_glob("**/page.tsx", "app/[id]/page.tsx")


class TestFallback:
    @pytest.mark.parametrize(
        "path,role",
        [
            ("src/main.py", SOURCE_ROLE),
            ("Cargo.toml", SOURCE_ROLE),
            ("README.md", DOC_ROLE),
            ("notes.txt", DOC_ROLE),
            ("data/thing.wasm.bak", OTHER_ROLE),
            ("Makefile", OTHER_ROLE),
        ],
    )
    def test_extension_fallback(self, path: str, role: str) -> None:
        assert fallback_role(path) == role

    def test_fallback_is_case_insensitive(self) -> None:
        assert fallback_role("SCRIPT.PY") == SOURCE_ROLE


class TestResolve:
    def test_a_config_file_gets_both_its_role_and_source(self) -> None:
        # Ordered most specific first: glob roles, then the extension fallback.
        assert resolve_roles("postcss.config.mjs", b"export default {}", ROLE_GLOBS) == (
            "tooling-config",
            "source",
        )

    def test_binary_magic_stops_the_text_fallback(self) -> None:
        assert resolve_roles("payload.rs", WASM_HEAD, ROLE_GLOBS) == (WASM_ROLE,)

    def test_editor_autorun_role_resolves(self) -> None:
        assert "editor-autorun" in resolve_roles(".vscode/tasks.json", b"{}", ROLE_GLOBS)

    def test_a_plain_source_file_gets_only_the_fallback(self) -> None:
        assert resolve_roles("src/app.py", b"x = 1", ROLE_GLOBS) == (SOURCE_ROLE,)

    def test_order_is_stable_across_calls(self) -> None:
        first = resolve_roles("next.config.js", b"export default {}", ROLE_GLOBS)
        second = resolve_roles("next.config.js", b"export default {}", ROLE_GLOBS)
        assert first == second
