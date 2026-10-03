"""Default redaction patterns.

These are the built-in patterns every :class:`RedactionEngine` starts
with unless ``default_patterns_enabled`` is explicitly set to False.
Users can add extra patterns via configuration (see ``docs/ADAPTER.md §8.1``).
Individual built-ins cannot be subtracted, but configuration can explicitly
disable the complete default set.

All patterns are case-insensitive. Key patterns match against dict
keys; when a key matches, the whole value is replaced regardless of
its content. Value patterns match against stringified values; when
a value matches, the value is replaced.

Only full matches count for key patterns - a key named ``"password"``
matches, but ``"last_password_reset"`` does not. This is deliberate
to avoid over-redaction that hides useful context.

Key matching is bounded in two ways, because the engine runs these
patterns on every key of every payload, agent-side in the user's worker
and brain-side on the event loop, and the keys arrive from the network:

* No pattern runs on a key longer than :data:`MAX_REDACTION_KEY_LENGTH`,
  and an operator-supplied extra pattern runs only on keys up to
  :data:`MAX_EXTRA_PATTERN_KEY_LENGTH`. A key past the cap that applies
  is treated as sensitive, so its value is scrubbed: fail closed, never
  an unbounded regex over attacker-sized input.
* Every extra key pattern is timed at construction by
  :func:`probe_key_pattern` against adversarial keys up to the extra cap,
  and refused when a single key exceeds
  :data:`PATTERN_PROBE_SINGLE_LIMIT_SECONDS` or the probe set exceeds
  :data:`PATTERN_PROBE_TOTAL_LIMIT_SECONDS`. ``(a+)+$`` doubles its cost
  with every character and took two seconds on a 27-character key; the
  probe refuses it in well under a tenth of a second. Below the extra cap
  this probe is the only bound on a pattern's cost, which is why it runs
  in the engine and not just in one caller's configuration layer.

See ``docs/SECURITY.md §5.3`` for the complete specification.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterator

#: Longest key any key-name pattern runs against. A longer key is treated as
#: sensitive without running a pattern: the value behind it is scrubbed.
MAX_REDACTION_KEY_LENGTH = 256

#: Longest key an operator-supplied extra key pattern runs against. Real
#: identifiers and header names sit far below it; the probe at construction
#: covers exactly this range, so the worst per-key cost it measured is the
#: worst per-key cost the engine can pay. When extra patterns are configured,
#: a longer key is treated as sensitive, like one over the global cap.
MAX_EXTRA_PATTERN_KEY_LENGTH = 64

#: A single probe key taking longer than this refuses the pattern.
PATTERN_PROBE_SINGLE_LIMIT_SECONDS = 0.020

#: All probe keys together taking longer than this refuses the pattern.
PATTERN_PROBE_TOTAL_LIMIT_SECONDS = 0.100

# ---------------------------------------------------------------------------
# Key-name patterns.
#
# Compiled as full-match regexes with IGNORECASE. The engine applies
# them with ``re.fullmatch``.
# ---------------------------------------------------------------------------

DEFAULT_KEY_PATTERNS: tuple[str, ...] = (
    # Passwords
    r"password",
    r"password_confirmation",
    r"password_hash",
    r"passwd",
    r"pwd",
    r"old_password",
    r"new_password",
    # Secrets. The ``[_]?`` makes the separator optional so camelCase
    # keys (``clientSecret``, ``hmacSecret``) are caught as well as
    # snake_case -- key matching is fullmatch + IGNORECASE, so this
    # covers both spellings without over-matching longer keys.
    r"secret",
    r"secrets",
    r"client[_]?secret",
    r"webhook[_]?secret",
    r"hmac[_]?secret",
    # Tokens. Underscore-optional catches accessToken / refreshToken /
    # etc. that the snake_case-only patterns missed (audit M-4).
    r"token",
    r"access[_]?token",
    r"refresh[_]?token",
    r"id[_]?token",
    r"api[_]?token",
    r"bearer[_]?token",
    r"session[_]?token",
    # API keys
    r"api_?key",
    r"apikey",
    r"x-api-key",
    r"x_api_key",
    # Authorization and cookies
    r"authorization",
    r"auth",
    r"credentials",
    r"cookie",
    r"set-cookie",
    r"set_cookie",
    # Personal / sensitive identifiers
    r"ssn",
    r"social_security(_number)?",
    r"credit_card(_number)?",
    r"card_number",
    r"cvv",
    r"cvc",
)


# ---------------------------------------------------------------------------
# Value patterns.
#
# Compiled with IGNORECASE. Applied with ``re.search`` against the
# stringified value. A single hit redacts the entire value.
# ---------------------------------------------------------------------------

DEFAULT_VALUE_PATTERNS: tuple[str, ...] = (
    # JWT (three dot-separated base64 segments with the "eyJ" prefix)
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    # Authorization header value
    r"Bearer\s+[A-Za-z0-9._-]{16,}",
    # Common API key prefixes - Stripe, Slack, GitHub, Postmark, ...
    r"sk_(live|test)_[A-Za-z0-9]{24,}",
    r"pk_(live|test)_[A-Za-z0-9]{24,}",
    r"whsec_[A-Za-z0-9]{24,}",
    r"rk_(live|test)_[A-Za-z0-9]{24,}",
    r"xoxb-[0-9A-Za-z-]{10,}",
    r"xoxp-[0-9A-Za-z-]{10,}",
    r"xoxa-[0-9A-Za-z-]{10,}",
    r"ghp_[A-Za-z0-9]{36}",
    r"gho_[A-Za-z0-9]{36}",
    r"ghs_[A-Za-z0-9]{36}",
    # GitHub fine-grained PAT
    r"github_pat_[A-Za-z0-9_]{82,}",
    # AWS access key IDs (long-lived + STS short-lived)
    r"AKIA[0-9A-Z]{16}",
    r"ASIA[0-9A-Z]{16}",
    # Slack incoming webhook URL (operators routinely log the
    # whole URL in error paths)
    r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    # Google Cloud / Firebase API key
    r"AIza[0-9A-Za-z_-]{35}",
    # Twilio account-token shape
    r"\bSK[0-9a-f]{32}\b",
    # SendGrid API key
    r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    # Postgres / MySQL / MongoDB / Redis URIs with embedded creds
    # (extremely common in OperationalError tracebacks)
    r"(?:postgres|postgresql|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps)://[^:\s]+:[^@\s]+@[^\s/]+",
    # PEM private key - match the BEGIN line; truncation in the
    # engine ensures we don't try to scan a massive blob.
    r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED|PRIVATE) (?:PRIVATE )?KEY-----",
    # Email addresses - redacted by default since they are PII for
    # most Python apps. Users who need to see them can use
    # ``keep_kwargs=["email"]`` on specific tasks.
    #
    # The leading lookbehind is load-bearing for SPEED, not for matching. An
    # email cannot begin mid-token, so it changes no result; what it changes is
    # the cost of failing. Without it the engine retried the ``+`` from every
    # position in the string, each attempt scanning to the end before failing
    # on the missing ``@``, which is quadratic: a 64 KB task argument with no
    # ``@`` in it took 14 seconds to reject, inside the user's own worker.
    # With it, a position whose predecessor is already in the class cannot
    # start a match, so the same payload rejects in about a millisecond.
    r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    # US SSN (XXX-XX-XXXX)
    r"\b\d{3}-\d{2}-\d{4}\b",
)


def compile_key_patterns(patterns: tuple[str, ...]) -> list[re.Pattern[str]]:
    """Compile key-name patterns with IGNORECASE.

    Raised compilation errors are propagated - the caller is
    responsible for translating them into
    :class:`z4j_core.errors.RedactionConfigError`.
    """
    return [re.compile(p, re.IGNORECASE) for p in patterns]


def compile_value_patterns(patterns: tuple[str, ...]) -> list[re.Pattern[str]]:
    """Compile value patterns with IGNORECASE.

    Same error-propagation contract as :func:`compile_key_patterns`.
    """
    return [re.compile(p, re.IGNORECASE) for p in patterns]


# ---------------------------------------------------------------------------
# Construction-time cost probe for extra key patterns.
#
# Python's ``re`` is a backtracking engine with no step limit or timeout,
# so the only way to keep a user-supplied pattern off the critical path is
# to measure it before it is installed. The probe keys grow one character
# at a time from 8 to 32, then in steps to the extra cap, so a pattern
# whose cost doubles per character trips the single-key limit at the
# first length past it (a 20 ms probe can at most become a 40 ms one)
# rather than jumping from a cheap probe to a multi-second one.
# ---------------------------------------------------------------------------

_PROBE_LENGTHS: tuple[int, ...] = (*range(8, 33), 40, 48, 56, MAX_EXTRA_PATTERN_KEY_LENGTH)
_PROBE_ALPHABET_MAX = 12
_PROBE_TERMINATORS = "!~\x00"
_REGEX_METACHARACTERS = frozenset("\\^$.|?*+()[]{}")


def _probe_alphabet(pattern: str) -> tuple[str, ...]:
    """The characters the pattern mentions, plus ``a``, non-letters first.

    Escapes map to a representative member (``\\w`` to ``_``, ``\\d`` to
    ``0``, ``\\s`` to a space, ``\\.`` to the literal dot); metacharacters
    are skipped. ``a`` always leads, then the separators and digits, then
    the letters, capped so a long literal pattern does not inflate the
    probe set: the characters a nested quantifier repeats are the
    separators and the class members, not the tail of a literal word.
    """
    seen: dict[str, None] = {"a": None}
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            escaped = pattern[index + 1]
            index += 2
            if escaped in "dD":
                seen.setdefault("0", None)
            elif escaped in "wW":
                seen.setdefault("_", None)
            elif escaped in "sS":
                seen.setdefault(" ", None)
            elif not escaped.isalnum():
                seen.setdefault(escaped, None)
            continue
        index += 1
        if char in _REGEX_METACHARACTERS or char.isspace():
            continue
        seen.setdefault(char.lower(), None)
    ordered = sorted(seen, key=lambda c: (c != "a", c.isalpha()))
    return tuple(ordered[:_PROBE_ALPHABET_MAX])


def _probe_keys(alphabet: tuple[str, ...], length: int) -> Iterator[str]:
    """Adversarial keys of exactly ``length`` characters.

    Each alphabet character repeated, and the alphabet cycled, always
    ending in a character the pattern does not mention so an anchored
    pattern has to fail at the end and backtrack through everything
    before it.
    """
    terminator = next(t for t in _PROBE_TERMINATORS if t not in alphabet)
    body = length - 1
    for char in alphabet:
        yield char * body + terminator
    if len(alphabet) > 1:
        cycle = "".join(alphabet)
        yield (cycle * (body // len(cycle) + 1))[:body] + terminator


def _time_fullmatch(compiled: re.Pattern[str], key: str) -> float:
    started = time.perf_counter()
    compiled.fullmatch(key)
    return time.perf_counter() - started


def probe_key_pattern(compiled: re.Pattern[str]) -> str | None:
    """Time a key pattern against adversarial keys; describe why it is refused.

    Returns ``None`` when every probe key stays inside both limits, which
    is the case for every built-in pattern and for ordinary anchored
    patterns such as ``^customer_.*_token$``. Otherwise returns one
    readable sentence naming the pattern, the probe that tripped and both
    limits, for the caller to prefix with its own context (the engine
    names the config field, the brain's settings name the index).

    A measurement over the single-key limit is taken a second time before
    it counts, so a scheduler stall during one probe is not mistaken for a
    catastrophic pattern; a genuinely catastrophic probe repeats its cost.
    """
    single_ms = PATTERN_PROBE_SINGLE_LIMIT_SECONDS * 1000
    total_ms = PATTERN_PROBE_TOTAL_LIMIT_SECONDS * 1000
    alphabet = _probe_alphabet(compiled.pattern)
    total = 0.0
    for length in _PROBE_LENGTHS:
        for key in _probe_keys(alphabet, length):
            elapsed = _time_fullmatch(compiled, key)
            if elapsed > PATTERN_PROBE_SINGLE_LIMIT_SECONDS:
                elapsed = _time_fullmatch(compiled, key)
            total += elapsed
            if elapsed > PATTERN_PROBE_SINGLE_LIMIT_SECONDS:
                return (
                    f"{compiled.pattern!r} backtracks catastrophically: a {length}-character "
                    f"key took {elapsed * 1000:.0f} ms to match, over the {single_ms:.0f} ms "
                    f"limit per key (the limit across all probe keys is {total_ms:.0f} ms)"
                )
            if total > PATTERN_PROBE_TOTAL_LIMIT_SECONDS:
                return (
                    f"{compiled.pattern!r} is too slow to match: the probe keys up to "
                    f"{length} characters took {total * 1000:.0f} ms together, over the "
                    f"{total_ms:.0f} ms limit across all probe keys (the limit per key is "
                    f"{single_ms:.0f} ms)"
                )
    return None


__all__ = [
    "DEFAULT_KEY_PATTERNS",
    "DEFAULT_VALUE_PATTERNS",
    "MAX_EXTRA_PATTERN_KEY_LENGTH",
    "MAX_REDACTION_KEY_LENGTH",
    "PATTERN_PROBE_SINGLE_LIMIT_SECONDS",
    "PATTERN_PROBE_TOTAL_LIMIT_SECONDS",
    "compile_key_patterns",
    "compile_value_patterns",
    "probe_key_pattern",
]
