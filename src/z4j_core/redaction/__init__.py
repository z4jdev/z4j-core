"""Secret-redaction engine.

The redaction engine runs inside the agent at event-capture time,
before any event ever leaves the host process. The brain re-applies
it as defense in depth before persisting events.

See ``docs/SECURITY.md §5`` for the full specification and
``docs/CLAUDE.md §2.3`` for the non-negotiable rules.
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
]
