"""Lightweight script coverage checks shared by the API and optional model."""

from __future__ import annotations

import unicodedata


MIN_HAN_CHARS_FOR_LIMITED_COVERAGE = 12
_HAN_IDEOGRAPH_NAMES = ("CJK UNIFIED IDEOGRAPH-", "CJK COMPATIBILITY IDEOGRAPH-")
# Python 3.12 ships Unicode 15.0 names. Unicode 17.0 defines these newer Han
# blocks, so check their ranges even when unicodedata.name() cannot name them.
# https://www.unicode.org/versions/Unicode17.0.0/core-spec/chapter-18/
_NEWER_HAN_BLOCKS = ((0x2EBF0, 0x2EE5F), (0x323B0, 0x3347F))


def has_substantial_han_text(text: str) -> bool:
    """Recognize named Han ideographs, including supplementary-plane extensions."""
    count = 0
    for character in text:
        codepoint = ord(character)
        if codepoint < 0x3400:
            continue
        if (any(start <= codepoint <= end for start, end in _NEWER_HAN_BLOCKS)
                or unicodedata.name(character, "").startswith(_HAN_IDEOGRAPH_NAMES)):
            count += 1
            if count >= MIN_HAN_CHARS_FOR_LIMITED_COVERAGE:
                return True
    return False
