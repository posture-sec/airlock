"""Console renderer C0 control-character escaping (issue #61, task 9.32).

Properties asserted:

1. ``flatten`` escapes every character below 0x20 and 0x7f as ``\\xNN``.
2. CR, LF and CRLF still become a single space (pre-existing contract).
3. A path containing ``\\x1b[2K`` (erase-line sequence) renders with no raw ESC byte.
4. A message containing ``\\x07`` (BEL) renders with no raw BEL byte.
5. The line count still equals findings plus one summary line after escaping.
6. The test fails before the change (the old ``flatten`` only collapses line breaks).
"""

from __future__ import annotations

from airlock.model import EXIT_FINDINGS, Finding, Mode, ScanReport, Severity
from airlock.report import console

DIGEST = "sha256:" + "a" * 64


def _finding(
    path: str = "src/index.js",
    message: str = "remote code execution capability",
    line: int = 1,
) -> Finding:
    return Finding(
        rule_id="cfg-dynamic-code",
        severity=Severity.HIGH,
        path=path,
        line=line,
        roles=("source",),
        message=message,
        evidence=None,
        occurrence=0,
        fingerprint=DIGEST,
        suppressible=True,
    )


def _report(*findings: Finding) -> ScanReport:
    return ScanReport(
        tool_version="0.1.0",
        mode=Mode.PR,
        repo_head="b" * 40,
        base="c" * 40,
        files_indexed=4,
        files_scanned=4,
        files_skipped={},
        findings=findings,
        exit_code=EXIT_FINDINGS if findings else 0,
    )


class TestFlattenControlChars:
    def test_esc_byte_is_escaped_to_visible_notation(self) -> None:
        result = console.flatten("\x1b[2K")
        assert "\x1b" not in result
        assert "\\x1b" in result

    def test_bel_byte_is_escaped(self) -> None:
        result = console.flatten("\x07")
        assert "\x07" not in result
        assert "\\x07" in result

    def test_del_byte_0x7f_is_escaped(self) -> None:
        result = console.flatten("\x7f")
        assert "\x7f" not in result
        assert "\\x7f" in result

    def test_lf_still_becomes_space(self) -> None:
        assert console.flatten("a\nb") == "a b"

    def test_cr_still_becomes_space(self) -> None:
        assert console.flatten("a\rb") == "a b"

    def test_crlf_still_becomes_one_space(self) -> None:
        assert console.flatten("a\r\nb") == "a b"

    def test_all_c0_bytes_below_0x20_are_escaped(self) -> None:
        """Every byte from 0x00 to 0x1f except 0x0a and 0x0d is escaped, not deleted."""
        for code in range(0x00, 0x20):
            if code in (0x0A, 0x0D):
                continue  # LF and CR collapse to space; tested above.
            ch = chr(code)
            result = console.flatten(ch)
            assert ch not in result, f"byte 0x{code:02x} reached the output unescaped"
            assert f"\\x{code:02x}" in result, f"byte 0x{code:02x} was not escaped as \\x{code:02x}"

    def test_printable_ascii_passes_through_unchanged(self) -> None:
        text = "hello world / path.js:42 cfg-dynamic-code"
        assert console.flatten(text) == text

    def test_no_replacement_inserts_a_newline(self) -> None:
        """flatten must return exactly one line regardless of input (issue #61 rule)."""
        # Input has ESC, BEL, NUL and CRLF — none must produce a newline in output.
        result = console.flatten("\x1b[2K\x07\x00\r\nstill here")
        assert "\n" not in result


class TestRenderWithControlChars:
    def test_path_with_erase_sequence_still_gives_one_finding_line(self) -> None:
        """A path containing ESC[2K must not erase the terminal line above it."""
        # The path contains the two-character erase-line CSI sequence.
        evil_path = "src/\x1b[2Klegit.js"
        text = console.render(_report(_finding(path=evil_path)))
        lines = text.rstrip("\n").split("\n")
        # 1 finding line + 1 summary line.
        assert len(lines) == 2

    def test_path_with_erase_sequence_contains_no_raw_esc(self) -> None:
        evil_path = "src/\x1b[2Klegit.js"
        text = console.render(_report(_finding(path=evil_path)))
        assert "\x1b" not in text

    def test_message_with_bel_contains_no_raw_bel(self) -> None:
        text = console.render(_report(_finding(message="bad\x07message")))
        assert "\x07" not in text

    def test_message_with_bel_still_gives_one_finding_line(self) -> None:
        text = console.render(_report(_finding(message="bad\x07message")))
        lines = text.rstrip("\n").split("\n")
        assert len(lines) == 2

    def test_existing_newline_contract_still_holds(self) -> None:
        """Regression: a newline in a path must not split a finding (pre-existing)."""
        text = console.render(_report(_finding(path="a\nb.js")))
        assert len(text.rstrip("\n").split("\n")) == 2
        assert "a b.js" in text

    def test_existing_cr_contract_still_holds(self) -> None:
        """Regression: a CR-LF in a message must not forge a second line."""
        text = console.render(_report(_finding(message="x\r\nairlock: forged summary")))
        assert len(text.rstrip("\n").split("\n")) == 2
        assert text.rstrip("\n").split("\n")[-1].startswith("airlock: 1 HIGH")
