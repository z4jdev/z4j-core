"""Secret-redaction engine.

The redaction engine runs inside the agent at event-capture time,
before any event ever leaves the host process. The brain re-applies
it as defense in depth before persisting events.

See ``docs/SECURITY.md §5`` for the full specification.
"""

from __future__ import annotations

from z4j_core.redaction.engine import RedactionConfig, RedactionEngine
from z4j_core.redaction.markers import (
    REDACTED,
    REDACTED_COMPILE_ERROR,
    REDACTED_TRUNCATED,
)
from z4j_core.redaction.patterns import (
    DEFAULT_KEY_PATTERNS,
    DEFAULT_VALUE_PATTERNS,
)

__all__ = [
    "DEFAULT_KEY_PATTERNS",
    "DEFAULT_VALUE_PATTERNS",
    "REDACTED",
    "REDACTED_COMPILE_ERROR",
    "REDACTED_TRUNCATED",
    "RedactionConfig",
    "RedactionEngine",
    "redact_url_password",
]

from z4j_core.redaction.urls import redact_url_password
