"""M-4: camelCase token keys + hmac_secret must redact.

The default key patterns are fullmatch + IGNORECASE, so snake_case
``access_token`` was covered but camelCase ``accessToken`` /
``refreshToken`` and ``hmac_secret`` slipped through. The token/secret
patterns are now underscore-optional so both spellings match without
over-redacting longer keys.
"""

from __future__ import annotations

from z4j_core.redaction import RedactionConfig, RedactionEngine
from z4j_core.redaction.markers import REDACTED


def _engine() -> RedactionEngine:
    return RedactionEngine(
        RedactionConfig(
            extra_key_patterns=(),
            extra_value_patterns=(),
            default_patterns_enabled=True,
            max_value_bytes=8192,
        ),
    )


def test_camelcase_and_hmac_secret_keys_redact() -> None:
    scrubbed = _engine().scrub(
        {
            "accessToken": "abc123",
            "refreshToken": "def456",
            "hmacSecret": "s3cr3t",
            "hmac_secret": "s3cr3t2",
            "clientSecret": "cs",
            # snake_case regression guard (was already covered)
            "access_token": "snake",
        },
    )
    for key in (
        "accessToken",
        "refreshToken",
        "hmacSecret",
        "hmac_secret",
        "clientSecret",
        "access_token",
    ):
        assert scrubbed[key] == REDACTED, f"{key} should be redacted"


def test_fullmatch_still_avoids_overredaction() -> None:
    scrubbed = _engine().scrub(
        {
            # Longer keys that merely CONTAIN a token/secret word must NOT
            # be redacted by the fullmatch key patterns.
            "access_token_expiry_seconds": 3600,
            "last_password_reset_at": "2026-01-01",
        },
    )
    assert scrubbed["access_token_expiry_seconds"] == 3600
    assert scrubbed["last_password_reset_at"] == "2026-01-01"
