"""Strict numeric cron fields for native adapters with permissive parsers."""

from __future__ import annotations

import re


def numeric_cron_field(value: str, minimum: int, maximum: int, *, wrap: bool = False) -> list[int]:
    """Expand a numeric field, refusing silently ignored tokens and zero steps."""
    selected: set[int] = set()
    for part in value.split(","):
        match = re.fullmatch(r"(\*|\d+(?:-\d+)?)(?:/(\d+))?", part)
        if match is None:
            raise ValueError("cron fields require numeric values, ranges, lists or steps")
        base, raw_step = match.groups()
        step = int(raw_step or 1)
        if step <= 0:
            raise ValueError("cron step must be positive")
        if base == "*":
            left, right = minimum, maximum
        elif "-" in base:
            a, b = base.split("-", 1)
            left, right = int(a), int(b)
        else:
            if raw_step is not None:
                raise ValueError("cron steps require * or a range")
            left = right = int(base)
        if not minimum <= left <= maximum or not minimum <= right <= maximum:
            raise ValueError("cron value is outside the native field range")
        if left > right:
            if not wrap:
                raise ValueError("reversed cron ranges are unsupported by this scheduler")
            values = [*range(left, maximum + 1), *range(minimum, right + 1)]
        else:
            values = list(range(left, right + 1))
        selected.update(values[::step])
    return sorted(selected)
