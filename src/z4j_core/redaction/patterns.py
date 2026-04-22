"""Default redaction patterns.

These are the built-in patterns every :class:`RedactionEngine` starts
with unless ``default_patterns_enabled`` is explicitly set to False.
Users can add extra patterns via configuration (see ``docs/ADAPTER.md §8.1``),
but cannot remove entries from these lists.

All patterns are case-insensitive. Key patterns match against dict
keys; when a key matches, the whole value is replaced regardless of
its content. Value patterns match against stringified values; when
a value matches, the value is replaced.

Only full matches count for key patterns - a key named ``"password"``
matches, but ``"last_password_reset"`` does not. This is deliberate
to avoid over-redaction that hides useful context.

See ``docs/SECURITY.md §5.3`` for the complete specification.
"""

from __future__ import annotations

import re

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
    # Secrets
    r"secret",
    r"secrets",
    r"client_secret",
    r"webhook_secret",
    # Tokens
    r"token",
    r"access_token",
    r"refresh_token",
    r"id_token",
    r"api_token",
    r"bearer_token",
    r"session_token",
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
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
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


__all__ = [
    "DEFAULT_KEY_PATTERNS",
    "DEFAULT_VALUE_PATTERNS",
    "compile_key_patterns",
    "compile_value_patterns",
]
