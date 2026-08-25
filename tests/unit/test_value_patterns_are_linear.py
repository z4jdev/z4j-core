"""Value redaction must stay linear in the size of what it scans.

This runs inside the user's application, on task arguments. The email pattern
began with an unanchored character class, so on a payload with no ``@`` the
engine retried the ``+`` from every position, each attempt scanning to the end
before failing. Quadratic: a 64 KB argument, an entirely ordinary size for a
JSON blob or a document, took about fourteen seconds to reject, in their worker,
per value.

A leading lookbehind fixes it without changing a single match, because an email
cannot begin mid-token. Both properties are asserted here: the matches, so the
optimisation cannot quietly narrow what gets redacted, and the scaling, so it
cannot regress.
"""

from __future__ import annotations

import re
import time

import pytest
from z4j_core.redaction.patterns import DEFAULT_VALUE_PATTERNS


def _combined() -> re.Pattern[str]:
    """The alternation the engine actually searches with."""
    return re.compile("|".join(f"(?:{p})" for p in DEFAULT_VALUE_PATTERNS), re.IGNORECASE)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("contact a.b+c@example.co.uk now", ["a.b+c@example.co.uk"]),
        ("user@sub.domain.org,other@x.io", ["user@sub.domain.org", "other@x.io"]),
        ("UPPER@EXAMPLE.COM", ["UPPER@EXAMPLE.COM"]),
        ("trailing.dot@example.com.", ["trailing.dot@example.com"]),
        ("no email here", []),
        ("notanemail@", []),
        ("@nope.com", []),
    ],
)
def test_the_anchor_changed_no_match(text: str, expected: list[str]) -> None:
    """An email cannot start mid-token, so the lookbehind is free."""
    email = next(p for p in DEFAULT_VALUE_PATTERNS if p.startswith("(?<![A-Za-z0-9._%+"))
    assert [m.group(0) for m in re.finditer(email, text, re.IGNORECASE)] == expected


def test_a_large_value_with_nothing_to_match_rejects_in_linear_time() -> None:
    """Doubling the input must roughly double the cost, not quadruple it.

    Measured as a ratio rather than an absolute, so a slow or loaded machine
    does not make this flaky. Quadratic shows as roughly 4x per doubling and
    would fail comfortably; linear sits near 2x.
    """
    combined = _combined()

    def scan(size: int) -> float:
        """Best of three, so a scheduling hiccup does not decide the verdict."""
        payload = "A" * size
        timings = []
        for _ in range(3):
            started = time.perf_counter()
            combined.search(payload)
            timings.append(time.perf_counter() - started)
        return min(timings)

    small = scan(16_000)
    large = scan(64_000)
    if small <= 0:  # pragma: no cover - clock resolution on a very fast machine
        pytest.skip("timer resolution too coarse to measure")

    # Four times the input. Linear predicts about 4x; quadratic predicts 16x.
    ratio = large / small
    assert ratio < 8, (
        f"scanning 64k took {ratio:.1f}x the time of 16k. Linear is about 4x; "
        f"this looks quadratic, which means an unanchored repetition is "
        f"retrying from every position in the user's worker."
    )


def test_the_email_pattern_still_carries_its_anchor() -> None:
    """The specific fix, so a tidy-up that drops it is caught by name."""
    email = next(p for p in DEFAULT_VALUE_PATTERNS if p.startswith("(?<![A-Za-z0-9._%+"))
    assert email.startswith("(?<!"), (
        "the email pattern lost its leading lookbehind; without it, matching "
        "is unchanged but failing becomes quadratic"
    )
