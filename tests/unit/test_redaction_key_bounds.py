"""Key matching is bounded: a length cap and a construction-time cost probe.

``Z4J_REDACTION_EXTRA_KEY_PATTERNS`` accepted ``(a+)+$`` and the engine ran
every key pattern on the uncapped key string, so one 27-character key in one
frame stalled a brain worker for two seconds, doubling with every further
character. Two bounds close it: no pattern runs on a key over the cap (the
value is scrubbed instead), and every extra pattern is timed against
adversarial keys at construction and refused when it backtracks.

Each cap is asserted with a negative and a positive control around the exact
boundary, using a pattern object that raises if it is ever consulted, so the
test can only pass because the engine stopped before the pattern.
"""

from __future__ import annotations

import re
import time

import pytest
from z4j_core.errors import RedactionConfigError
from z4j_core.redaction import REDACTED, RedactionConfig, RedactionEngine
from z4j_core.redaction.engine import (
    MAX_EXTRA_PATTERN_KEY_LENGTH,
    MAX_REDACTION_KEY_LENGTH,
)
from z4j_core.redaction.patterns import (
    DEFAULT_KEY_PATTERNS,
    PATTERN_PROBE_SINGLE_LIMIT_SECONDS,
    PATTERN_PROBE_TOTAL_LIMIT_SECONDS,
    _probe_alphabet,
    probe_key_pattern,
)

CATASTROPHIC = r"(a+)+$"
POLYNOMIAL_BLOWUP = r"^(\w+_)*ssn$"
BENIGN = r"^customer_.*_token$"

#: The whole refusal has to land inside the arithmetic of the limits: at most
#: the total budget, plus the one probe that trips the single-key limit (for a
#: cost that doubles per character, under twice that limit), measured twice.
#: Measured at about 70 ms here against the 2.1 s the single key cost before.
REFUSAL_BUDGET_SECONDS = 0.5


class _PatternThatMustNotRun:
    """Stands in for a compiled pattern; proves the engine never reached it."""

    pattern = "<must not run>"

    def fullmatch(self, key: str) -> None:
        raise AssertionError(f"a key pattern ran on a {len(key)}-character key")


class TestGlobalKeyCap:
    def test_a_key_over_the_cap_is_scrubbed_without_running_any_pattern(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        engine = RedactionEngine(RedactionConfig(extra_key_patterns=("customer_secret",)))
        monkeypatch.setattr(engine, "_default_key_patterns", [_PatternThatMustNotRun()])
        monkeypatch.setattr(engine, "_extra_key_patterns", [_PatternThatMustNotRun()])
        key = "password_" + "x" * (300 - len("password_"))
        assert len(key) == 300

        assert engine.scrub({key: "hunter2"}) == {key: REDACTED}

    def test_a_key_at_the_cap_still_runs_the_patterns(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Positive control: the boundary is exactly where it is documented."""
        engine = RedactionEngine()
        monkeypatch.setattr(engine, "_default_key_patterns", [_PatternThatMustNotRun()])
        key = "x" * MAX_REDACTION_KEY_LENGTH

        with pytest.raises(AssertionError, match=f"{MAX_REDACTION_KEY_LENGTH}-character"):
            engine.key_matches(key)

    def test_a_long_key_with_defaults_only_is_treated_as_sensitive(self) -> None:
        engine = RedactionEngine()
        over = "x" * (MAX_REDACTION_KEY_LENGTH + 1)
        at = "x" * MAX_REDACTION_KEY_LENGTH

        assert engine.scrub({over: "v", at: "v"}) == {over: REDACTED, at: "v"}


class TestExtraPatternKeyCap:
    def test_a_key_over_the_extra_cap_is_scrubbed_without_running_the_extras(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        engine = RedactionEngine(RedactionConfig(extra_key_patterns=("customer_secret",)))
        monkeypatch.setattr(engine, "_extra_key_patterns", [_PatternThatMustNotRun()])
        over = "x" * (MAX_EXTRA_PATTERN_KEY_LENGTH + 1)

        assert engine.scrub({over: "v"}) == {over: REDACTED}

    def test_a_key_at_the_extra_cap_still_runs_the_extras(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        engine = RedactionEngine(RedactionConfig(extra_key_patterns=("customer_secret",)))
        monkeypatch.setattr(engine, "_extra_key_patterns", [_PatternThatMustNotRun()])

        with pytest.raises(AssertionError, match=f"{MAX_EXTRA_PATTERN_KEY_LENGTH}-character"):
            engine.key_matches("x" * MAX_EXTRA_PATTERN_KEY_LENGTH)

    def test_the_extra_cap_does_not_apply_without_extra_patterns(self) -> None:
        """The built-in patterns keep their behaviour on a long ordinary key."""
        over = "x" * (MAX_EXTRA_PATTERN_KEY_LENGTH + 1)

        assert RedactionEngine().scrub({over: "v"}) == {over: "v"}

    def test_a_catastrophic_pattern_past_the_probe_is_bounded_by_the_cap(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Installed behind the probe's back, the pattern still never sees a long key.

        Below the extra cap the probe is the sole bound (``key_matches``
        says so), which is why the engine refuses the pattern at
        construction; this shows the cap holds for what the probe cannot.
        """
        engine = RedactionEngine(RedactionConfig(extra_key_patterns=("customer_secret",)))
        monkeypatch.setattr(
            engine, "_extra_key_patterns", [re.compile(CATASTROPHIC, re.IGNORECASE)]
        )
        key = "a" * MAX_EXTRA_PATTERN_KEY_LENGTH + "!"

        started = time.perf_counter()
        result = engine.scrub({key: "v"})
        elapsed = time.perf_counter() - started

        assert result == {key: REDACTED}
        assert elapsed < 0.05


class TestConstructionProbe:
    @pytest.mark.parametrize("pattern", [CATASTROPHIC, POLYNOMIAL_BLOWUP])
    def test_a_catastrophic_extra_pattern_is_refused_inside_the_budget(self, pattern: str) -> None:
        started = time.perf_counter()
        with pytest.raises(RedactionConfigError) as excinfo:
            RedactionEngine(RedactionConfig(extra_key_patterns=(pattern,)))
        elapsed = time.perf_counter() - started

        message = str(excinfo.value)
        assert message.startswith("catastrophic key pattern: ")
        assert repr(pattern) in message
        assert "20 ms" in message
        assert "100 ms" in message
        assert excinfo.value.details["source"] == "extra_key_patterns"
        assert excinfo.value.details["index"] == 0
        assert excinfo.value.details["pattern"] == pattern
        assert elapsed < REFUSAL_BUDGET_SECONDS, f"refusal took {elapsed * 1000:.0f} ms"

    def test_the_refusal_names_the_index_of_the_offending_pattern(self) -> None:
        with pytest.raises(RedactionConfigError) as excinfo:
            RedactionEngine(RedactionConfig(extra_key_patterns=(BENIGN, CATASTROPHIC)))

        assert excinfo.value.details["index"] == 1

    def test_a_benign_extra_pattern_is_accepted_and_matches(self) -> None:
        engine = RedactionEngine(RedactionConfig(extra_key_patterns=(BENIGN,)))

        assert engine.scrub({"customer_billing_token": "x", "customer_billing_tokens": "y"}) == {
            "customer_billing_token": REDACTED,
            "customer_billing_tokens": "y",
        }

    def test_every_built_in_key_pattern_passes_the_probe(self) -> None:
        """The defaults are what every engine starts with; none may ever trip it."""
        for pattern in DEFAULT_KEY_PATTERNS:
            assert probe_key_pattern(re.compile(pattern, re.IGNORECASE)) is None, pattern

    def test_the_probe_alphabet_covers_escapes_and_literals(self) -> None:
        alphabet = _probe_alphabet(POLYNOMIAL_BLOWUP)

        assert alphabet[0] == "a"
        assert "_" in alphabet, "the \\w escape maps to the separator that makes it blow up"
        assert {"s", "n"} <= set(alphabet)
        assert not {"^", "(", "\\", "+", ")", "*", "$"} & set(alphabet)

    def test_the_limits_are_the_documented_ones(self) -> None:
        assert PATTERN_PROBE_SINGLE_LIMIT_SECONDS == 0.020
        assert PATTERN_PROBE_TOTAL_LIMIT_SECONDS == 0.100
        assert MAX_REDACTION_KEY_LENGTH == 256
        assert MAX_EXTRA_PATTERN_KEY_LENGTH == 64
