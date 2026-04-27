"""Wire-protocol version negotiation.

Agents advertise the protocol version they were built against in
their ``hello`` frame. The brain checks the advertised version
against the set of versions it supports and either acks the
connection or refuses it with a :class:`ProtocolError`.

Rules (see ``docs/API.md §7``):

- Additive changes (new message types, new fields) do not bump the
  version - they are backward compatible.
- Removing fields, changing field semantics, or changing framing
  bumps the version.
- The brain supports the latest N versions (target N=3).
- Backward compatibility within a major version is a hard requirement.

This module holds the list of supported versions and the
compatibility check. It is the only place this policy is encoded.
"""

from __future__ import annotations

from z4j_core.errors import ProtocolError

MIN_SUPPORTED_PROTOCOL: str = "2"
"""The oldest wire-protocol version this build of the brain still
understands. v1 (payload-only HMAC on brain→agent commands, nothing
signed the other way) is not supported on the wire any more - the
pre-release adversarial audit surfaced several attacks that the
envelope-HMAC + replay-guard design closes, and we are rebasing on
the new floor before the first public release rather than carrying
a compat shim nobody will ever need."""

CURRENT_PROTOCOL: str = "2"
"""The latest wire-protocol version this build produces."""

SUPPORTED_PROTOCOLS: tuple[str, ...] = ("2",)
"""The full set of wire-protocol versions this build accepts.
Ordered oldest → newest."""


def check_compatibility(advertised: str) -> None:
    """Raise :class:`ProtocolError` if the peer's version is unsupported.

    Args:
        advertised: The ``protocol_version`` value the peer sent in
                    its ``hello`` frame.

    Raises:
        ProtocolError: If ``advertised`` is not in
                       :data:`SUPPORTED_PROTOCOLS`. Includes both
                       versions in ``details`` so operators can see
                       which side needs to upgrade.
    """
    if advertised not in SUPPORTED_PROTOCOLS:
        raise ProtocolError(
            f"unsupported protocol version {advertised!r}; "
            f"this build supports {list(SUPPORTED_PROTOCOLS)}",
            details={
                "advertised": advertised,
                "supported": list(SUPPORTED_PROTOCOLS),
                "current": CURRENT_PROTOCOL,
                "minimum": MIN_SUPPORTED_PROTOCOL,
            },
        )


__all__ = [
    "CURRENT_PROTOCOL",
    "MIN_SUPPORTED_PROTOCOL",
    "SUPPORTED_PROTOCOLS",
    "check_compatibility",
]
