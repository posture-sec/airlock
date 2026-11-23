"""Localized-text cases for `pat-invisible-unicode` (issue #32).

The rule is about a character that hides an identifier from a reviewer, so the fixture that
matters is the opposite: a character that carries meaning. Persian, Arabic, Urdu and Hindi spell
ordinary words with the zero-width non-joiner (U+200C), so a single localized string in a `.ts`
file used to be a HIGH finding and could fail a `fail_on = "high"` scan.

The characters are written as code points rather than literals, for the reason this repository
never commits a live-looking payload: the fixture is about the byte, and a raw one in this file
would be invisible to the reviewer reading the builder.

`tests/unit/test_rule_unicode_locale.py` drives these through the same scanner the fixture gate
uses, because the point is the severity a `scan` reports, not the tuple this module returns.
"""

from __future__ import annotations

from . import Case, File

#: The zero-width non-joiner, which is orthography in several writing systems.
ZWNJ = chr(0x200C)

#: The characters the rule still has to report after U+200C leaves the class.
ZWSP = chr(0x200B)
RTO = chr(0x202E)

#: A Persian word pair joined by ZWNJ, as a Persian keyboard produces it. `می` + ZWNJ + `کند`.
PERSIAN_DOES = "می" + ZWNJ + "کند"

#: A Devanagari conjunct deliberately not ligated: `क्` + ZWNJ + `ष`.
HINDI_CONJUNCT = "क्" + ZWNJ + "ष"

#: The localized string sits in a source file, the role a localization table ships in.
LOCALE_PATH = "src/lib/locale.ts"


def _source(*lines: str) -> Case:
    return Case(files=(File(LOCALE_PATH, text="\n".join(lines) + "\n"),))


def persian_negative() -> Case:
    """A Persian UI string with the ZWNJ its spelling requires; must not be a finding."""
    return _source(
        "export const labels = {",
        f'  saves: "ذخیره {PERSIAN_DOES}",',
        f'  loading: "{PERSIAN_DOES} بارگذاری",',
        "};",
    )


def hindi_negative() -> Case:
    """A Hindi string where the ZWNJ blocks a conjunct ligature; must not be a finding."""
    return _source(
        "export const word = {",
        f'  strict: "{HINDI_CONJUNCT}",',
        "};",
    )


def bidi_override_positive() -> Case:
    """U+202E reverses the visible order of what follows, so the shown name is not the real one."""
    return _source(f'const report = "invoice{RTO}exe.txt";')


def zero_width_space_positive() -> Case:
    """U+200B splits a name in the bytes while the rendered line reads as one word."""
    return _source(f"const pay{ZWSP}load = decode(input);")
