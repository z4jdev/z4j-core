"""The redaction engine.

Walks arbitrary JSON-like Python data and replaces any value whose
key or content matches a configured pattern with the standard
:data:`REDACTED` marker. Fail-closed on invalid patterns.

Usage::

    engine = RedactionEngine()
    safe = engine.scrub({"user_id": 42, "password": "hunter2"})
    # safe == {"user_id": 42, "password": "[REDACTED]"}

The engine is pure and has no dependencies beyond stdlib and its own
package. It is exercised by the z4j-core unit tests at 100 %
line + branch coverage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from z4j_core.errors import RedactionConfigError
from z4j_core.redaction.markers import (
    REDACTED,
    truncation_suffix,
)
from z4j_core.redaction.patterns import (
    DEFAULT_KEY_PATTERNS,
    DEFAULT_VALUE_PATTERNS,
    compile_key_patterns,
    compile_value_patterns,
)


@dataclass(frozen=True)
class RedactionConfig:
    """Immutable configuration for a :class:`RedactionEngine`.

    Attributes:
        extra_key_patterns: Additional key-name regexes to check in
                            addition to the defaults.
        extra_value_patterns: Additional value regexes to check in
                              addition to the defaults.
        default_patterns_enabled: If False, the built-in patterns are
                                  skipped. This is an intentional
                                  footgun - only set this if you know
                                  what you are doing.
        max_value_bytes: Any stringified value longer than this many
                         bytes is truncated with a visible marker.
                         Default 8192 bytes.
    """

    extra_key_patterns: tuple[str, ...] = ()
    extra_value_patterns: tuple[str, ...] = ()
    default_patterns_enabled: bool = True
    max_value_bytes: int = 8192


class RedactionEngine:
    """Redacts and truncates JSON-like data.

    The engine is constructed once at agent startup. Compiled patterns
    are held for the process lifetime. A configuration error during
    construction results in :class:`RedactionConfigError` - startup
    fails fast rather than silently disabling a misconfigured pattern.

    Thread safety: ``scrub`` is read-only and safe to call concurrently
    from multiple threads once the engine is constructed.
    """

    MAX_DEPTH = 64

    def __init__(self, config: RedactionConfig | None = None) -> None:
        self.config = config or RedactionConfig()
        self._key_patterns = self._build_key_patterns()
        self._value_patterns = self._build_value_patterns()
        # Combined-alternation regex across every value pattern, so
        # scrub does ONE re.search per string instead of N separate
        # searches. Negligible for small inputs, meaningful savings
        # on large tracebacks / task payloads (R3 finding M17).
        # Individual ``self._value_patterns`` is retained for
        # ``value_matches()`` callers that want per-pattern
        # attribution and for tests.
        if self._value_patterns:
            self._value_regex: re.Pattern[str] | None = re.compile(
                "|".join(f"(?:{p.pattern})" for p in self._value_patterns),
                re.IGNORECASE,
            )
        else:
            self._value_regex = None

    # ------------------------------------------------------------------
    # Pattern compilation - fail-closed on bad input
    # ------------------------------------------------------------------

    def _build_key_patterns(self) -> list[re.Pattern[str]]:
        defaults = DEFAULT_KEY_PATTERNS if self.config.default_patterns_enabled else ()
        try:
            return compile_key_patterns(defaults + tuple(self.config.extra_key_patterns))
        except re.error as exc:
            raise RedactionConfigError(
                f"invalid key pattern: {exc}",
                details={"source": "extra_key_patterns", "error": str(exc)},
            ) from exc

    def _build_value_patterns(self) -> list[re.Pattern[str]]:
        defaults = DEFAULT_VALUE_PATTERNS if self.config.default_patterns_enabled else ()
        try:
            return compile_value_patterns(
                defaults + tuple(self.config.extra_value_patterns),
            )
        except re.error as exc:
            raise RedactionConfigError(
                f"invalid value pattern: {exc}",
                details={"source": "extra_value_patterns", "error": str(exc)},
            ) from exc

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scrub(self, data: object) -> object:
        """Return a scrubbed copy of ``data``.

        The input is NOT mutated. The output is a new structure where
        every match has been replaced with the redaction marker.

        Supported inputs:

        - dicts (recursively)
        - lists and tuples (recursively; tuples become lists in the
          output - JSON has no concept of a tuple)
        - strings (value-pattern check + truncation)
        - primitives (int, float, bool, None) pass through unchanged
        - anything else is converted to ``str(...)`` and then scrubbed

        Cycle-safe: a container that references itself (or any
        ancestor) is replaced with the redaction marker rather than
        recursing forever. The recursion depth is also bounded by
        :attr:`MAX_DEPTH`.
        """
        return self._scrub(data, inside_redacted_key=False, seen=set(), depth=0)

    def key_matches(self, key: str) -> bool:
        """True if ``key`` matches any key-name pattern.

        Exposed for testing and for use by the per-task ``z4j_meta``
        helper, which composes its own list of "always redact" keys
        on top of the engine's defaults.
        """
        return any(p.fullmatch(key) for p in self._key_patterns)

    def value_matches(self, value: str) -> bool:
        """True if ``value`` matches any value pattern.

        Uses one ``re.search`` over the combined alternation of
        every value pattern (R3 finding M17) - single pass instead
        of N separate searches. Falls back to the per-pattern list
        when the combined regex is empty (all patterns disabled).
        """
        if self._value_regex is not None:
            return self._value_regex.search(value) is not None
        return any(p.search(value) for p in self._value_patterns)

    # ------------------------------------------------------------------
    # Internal recursion
    # ------------------------------------------------------------------

    def _scrub(
        self,
        data: object,
        *,
        inside_redacted_key: bool,
        seen: set[int],
        depth: int,
    ) -> object:
        if depth >= self.MAX_DEPTH:
            return REDACTED
        if isinstance(data, dict):
            container_id = id(data)
            if container_id in seen:
                return REDACTED
            seen.add(container_id)
            try:
                return self._scrub_dict(
                    data,
                    inside_redacted_key=inside_redacted_key,
                    seen=seen,
                    depth=depth + 1,
                )
            finally:
                seen.discard(container_id)
        if isinstance(data, (list, tuple)):
            container_id = id(data)
            if container_id in seen:
                return REDACTED
            seen.add(container_id)
            try:
                return [
                    self._scrub(
                        item,
                        inside_redacted_key=inside_redacted_key,
                        seen=seen,
                        depth=depth + 1,
                    )
                    for item in data
                ]
            finally:
                seen.discard(container_id)
        if isinstance(data, str):
            return self._scrub_scalar(data, inside_redacted_key=inside_redacted_key)
        if isinstance(data, (int, float, bool)) or data is None:
            # Primitives still need the "inside redacted key" check -
            # a password like {"password": 12345} should also be redacted.
            if inside_redacted_key:
                return REDACTED
            return data
        # Anything else: coerce to string and scrub.
        return self._scrub_scalar(str(data), inside_redacted_key=inside_redacted_key)

    def _scrub_dict(
        self,
        data: dict[object, object],
        *,
        inside_redacted_key: bool,
        seen: set[int],
        depth: int,
    ) -> dict[str, object]:
        # Preserves key order.
        result: dict[str, object] = {}
        for raw_key, value in data.items():
            key_str = str(raw_key)
            # Scrub the KEY itself for value-pattern matches before
            # using it. A user putting a secret as a dict key
            # (uncommon but real - e.g. `{stripe_token_value: 1}`
            # in some SDK adapters) would otherwise persist the
            # secret-shaped key verbatim (R3 finding H9). Key-name
            # patterns intentionally don't apply to themselves.
            scrubbed_key = self._scrub_scalar(
                key_str, inside_redacted_key=False,
            )
            key_hit = inside_redacted_key or self.key_matches(key_str)
            result[scrubbed_key] = self._scrub(
                value,
                inside_redacted_key=key_hit,
                seen=seen,
                depth=depth,
            )
        return result

    def _scrub_scalar(self, value: str, *, inside_redacted_key: bool) -> str:
        # Fast path: a UTF-8 character is at most 4 bytes, so if the
        # string is short enough we can skip the encode entirely.
        max_bytes = self.config.max_value_bytes
        if len(value) * 4 > max_bytes:
            raw_bytes = value.encode("utf-8", errors="replace")
            if len(raw_bytes) > max_bytes:
                cut = raw_bytes[:max_bytes].decode("utf-8", errors="replace")
                remaining = len(raw_bytes) - max_bytes
                value = cut + truncation_suffix(remaining)

        # Then redaction.
        if inside_redacted_key or self.value_matches(value):
            return REDACTED
        return value


__all__ = ["RedactionConfig", "RedactionEngine"]
