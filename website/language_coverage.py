"""Lightweight script coverage checks shared by the API and optional model."""

from __future__ import annotations

import unicodedata


MIN_HAN_CHARS_FOR_LIMITED_COVERAGE = 12
_HAN_IDEOGRAPH_NAMES = ("CJK UNIFIED IDEOGRAPH-", "CJK COMPATIBILITY IDEOGRAPH-")
# Python 3.12 ships Unicode 15.0 names. Unicode 17.0 defines these newer Han
# blocks, so check their ranges even when unicodedata.name() cannot name them.
# https://www.unicode.org/versions/Unicode17.0.0/core-spec/chapter-18/
_NEWER_HAN_BLOCKS = ((0x2EBF0, 0x2EE5F), (0x323B0, 0x3347F))


def _is_han_ideograph(character: str) -> bool:
    codepoint = ord(character)
    return codepoint >= 0x3400 and (
        any(start <= codepoint <= end for start, end in _NEWER_HAN_BLOCKS)
        or unicodedata.name(character, "").startswith(_HAN_IDEOGRAPH_NAMES)
    )


def has_substantial_han_text(text: str) -> bool:
    """Recognize named Han ideographs, including supplementary-plane extensions."""
    count = 0
    for character in text:
        if _is_han_ideograph(character):
            count += 1
            if count >= MIN_HAN_CHARS_FOR_LIMITED_COVERAGE:
                return True
    return False


def non_latin_script_segments(text: str, min_letters: int) -> list[str]:
    """Return substantive same-script passages, not scattered foreign names.

    Han and Kana share a group so a normal Japanese phrase stays together.
    Latin letters and script changes separate passages. This is a
    conservative feature-coverage check, not language identification.
    """
    segments = []
    current = []
    current_script = None
    letter_count = 0

    def finish_segment():
        if letter_count >= min_letters:
            segments.append("".join(current).strip())

    for character in text:
        name = unicodedata.name(character, "")
        if _is_han_ideograph(character) or name.startswith(("HIRAGANA ", "KATAKANA ")):
            script = "cjk"
        elif unicodedata.category(character).startswith("L"):
            script = "latin" if name.startswith("LATIN ") else name.split(" ", 1)[0]
        else:
            script = None

        if script == "latin" or (
            script and current_script and script != current_script
        ):
            finish_segment()
            current = []
            current_script = None
            letter_count = 0
        if script and script != "latin":
            current_script = script
            current.append(character)
            letter_count += 1
        elif script is None and current_script and current[-1] != " ":
            # Numbers, URLs and symbols must never provide fitted features
            # on behalf of a language passage the model cannot represent.
            current.append(" ")

    finish_segment()
    return segments
