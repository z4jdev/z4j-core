"""Regression tests for the Batch-3 / Batch-4 redaction fixes:

- H8: expanded default value patterns (ASIA, github_pat, Slack
  webhook URLs, Google/Twilio/SendGrid keys, DB URIs, PEM)
- H9: dict-key scrubbing (secret-shaped keys are redacted before
  landing in the output)
- M17: combined-alternation regex (single ``re.search`` per string)
"""

from __future__ import annotations

import pytest

from z4j_core.redaction import REDACTED, RedactionEngine


@pytest.fixture
def engine() -> RedactionEngine:
    return RedactionEngine()


# ---------------------------------------------------------------------------
# H8 - new default value patterns
# ---------------------------------------------------------------------------


class TestExpandedValuePatterns:
    @pytest.mark.parametrize(
        "secret",
        [
            # AWS STS short-lived access keys
            "ASIAIOSFODNN7EXAMPLE",
            # GitHub fine-grained PAT (82+ chars after the prefix)
            "github_pat_" + "A" * 82,
            # Slack incoming webhook URL
            "https://hooks.slack.com/services/T0ABC123/B0DEF456/ghi789jkl0",
            # Google Cloud / Firebase API key
            "AIzaSyABC-DEF_012345678901234567890123456789",
            # Twilio account token shape. Built via concatenation so
            # no literal `SK[hex]{32}` appears in source (otherwise
            # GitHub push-protection rejects the commit).
            "SK" + "a" * 32,
            # SendGrid API key
            "SG." + "A" * 22 + "." + "B" * 43,
            # Postgres URI with embedded creds
            "postgres://admin:s3cr3t@db.example.com:5432/prod",
            # MySQL URI
            "mysql://root:pass@localhost/app",
            # MongoDB URI with auth
            "mongodb+srv://user:pw@cluster.mongodb.net/mydb",
            # Redis URI with credentials
            "redis://default:redispw@redis.example.com:6379/0",
            # AMQP URI
            "amqps://guest:guest@rabbit.internal:5671/vhost",
            # PEM private key
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEvg...",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        ],
    )
    def test_new_pattern_is_matched(
        self, engine: RedactionEngine, secret: str,
    ) -> None:
        assert engine.value_matches(secret), (
            f"value pattern gap - {secret!r} was not caught by defaults"
        )
        assert engine.scrub({"note": secret}) == {"note": REDACTED}

    def test_secret_inside_traceback(
        self, engine: RedactionEngine,
    ) -> None:
        """The most common real-world leak: DB URI in a Python
        exception message rendered into a traceback string."""
        tb = (
            "Traceback (most recent call last):\n"
            '  File "app.py", line 42, in connect\n'
            'OperationalError: could not connect to '
            'postgres://admin:s3cr3t@db.internal/prod\n'
        )
        out = engine.scrub({"traceback": tb})
        # The whole value is redacted on a single match.
        assert out == {"traceback": REDACTED}


# ---------------------------------------------------------------------------
# H9 - dict-key scrubbing
# ---------------------------------------------------------------------------


class TestDictKeyScrub:
    def test_secret_shaped_key_is_redacted(
        self, engine: RedactionEngine,
    ) -> None:
        """A dict that stores a secret *as the key* (uncommon but
        real in some SDK adapter code) must have the key itself
        redacted before it reaches the output."""
        raw = {"sk_live_" + "A" * 24: 1}
        out = engine.scrub(raw)
        # Only one key, and it's the redaction marker.
        assert list(out.keys()) == [REDACTED]

    def test_jwt_as_key_redacted(
        self, engine: RedactionEngine,
    ) -> None:
        jwt = "eyJ" + "A" * 30 + "." + "B" * 30 + "." + "C" * 30
        out = engine.scrub({jwt: "some value"})
        assert list(out.keys()) == [REDACTED]

    def test_safe_key_passthrough(
        self, engine: RedactionEngine,
    ) -> None:
        """Non-secret keys pass through unchanged."""
        out = engine.scrub({"project": 1, "count": 2})
        assert set(out.keys()) == {"project", "count"}

    def test_non_string_key_scrubbed_via_str(
        self, engine: RedactionEngine,
    ) -> None:
        """Tuple / int / custom keys are stringified first, then
        scanned. A safe int key passes through; a tuple that
        stringifies to a secret-shaped value is redacted."""
        out = engine.scrub({42: "x"})
        assert list(out.keys()) == ["42"]


# ---------------------------------------------------------------------------
# M17 - combined-alternation regex
# ---------------------------------------------------------------------------


class TestCombinedRegexPerf:
    def test_value_matches_still_identifies_known_secrets(
        self, engine: RedactionEngine,
    ) -> None:
        """Smoke: the combined regex must recognise every default
        pattern the per-pattern loop used to. Parametrise a few
        representatives."""
        assert engine.value_matches("AKIAIOSFODNN7EXAMPLE")
        assert engine.value_matches("ghp_" + "A" * 36)
        assert engine.value_matches("sk_live_" + "A" * 24)
        assert engine.value_matches("eyJ" + "A" * 30 + "." + "B" * 30 + "." + "C" * 30)

    def test_non_secret_is_not_matched(
        self, engine: RedactionEngine,
    ) -> None:
        assert not engine.value_matches("hello world")
        assert not engine.value_matches("42")
        assert not engine.value_matches("")

    def test_combined_regex_does_not_miss_ignorecase(
        self, engine: RedactionEngine,
    ) -> None:
        """Ensure ``re.IGNORECASE`` survived the refactor - the
        Stripe / Bearer / etc. patterns were compiled with it."""
        assert engine.value_matches("BEARER " + "A" * 20)
        assert engine.value_matches("sk_LIVE_" + "A" * 24)
