from __future__ import annotations

import unicodedata

ALLOWED_TEXT_CONTROL_CHARS = frozenset({"\t", "\n", "\r"})


DISALLOWED_TEXT_CATEGORIES = frozenset({"Cc", "Cf"})


def disallowed_text_character_message(field_name: str, text: str) -> str | None:
    """Return a clear error for Unicode controls that can hide prompt content."""

    for index, character in enumerate(text):
        category = unicodedata.category(character)
        if category not in DISALLOWED_TEXT_CATEGORIES:
            continue
        if character in ALLOWED_TEXT_CONTROL_CHARS:
            continue
        if character == "\x00":
            return f"{field_name} contains a NUL byte at position {index}."
        return (
            f"{field_name} contains a disallowed control character "
            f"{_character_label(character, category)} at position {index}."
        )
    return None


def _character_label(character: str, category: str) -> str:
    codepoint = f"U+{ord(character):04X}"
    name = unicodedata.name(character, "UNKNOWN")
    return f"{codepoint} ({name}, category {category})"
