"""Constant markers written into redacted or truncated fields.

These strings are what the dashboard displays in place of a redacted
value. They are documented so users know what they are seeing.
"""

from __future__ import annotations

REDACTED = "[REDACTED]"
"""Standard marker for a field whose value was redacted by the
engine because its key or value matched a configured pattern."""

REDACTED_COMPILE_ERROR = "[REDACTED:compile_error]"
"""Marker for a field that the engine failed closed on because a
user-supplied redaction pattern could not be compiled. Safer than
leaking the real value."""

REDACTED_TRUNCATED = "[REDACTED:truncated]"
"""Marker for a field that was first truncated (due to size) and
then additionally redacted."""


def truncation_suffix(remaining_bytes: int) -> str:
    """Return the suffix appended to a truncated string.

    Example: if a 12000-byte field is cut to 8192 bytes, the result
    is the first 8192 bytes plus ``truncation_suffix(3808)``.
    """
    return f"[...{remaining_bytes} more bytes truncated]"


__all__ = [
    "REDACTED",
    "REDACTED_COMPILE_ERROR",
    "REDACTED_TRUNCATED",
    "truncation_suffix",
]
