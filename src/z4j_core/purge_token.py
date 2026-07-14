"""Keyed confirmation token for the destructive ``purge_queue`` command.

The token binds a purge command to ``(queue_name, observed_depth)`` under
a **keyed HMAC-SHA256** using the agent's per-project secret -- the same
32 bytes that sign protocol frames (``derive_project_secret`` on the
brain; ``Z4J_HMAC_SECRET`` decoded on the agent). Both the issuer (the
brain, server-side) and the enforcing agent compute it from that shared
secret, so a party that can merely *observe* the queue depth (any VIEWER,
via telemetry) cannot forge a valid token, and a captured command cannot
be refreshed to match the current depth after a replay -- only a holder
of the project secret can produce one.

A pre-1.7 UNKEYED variant (bare SHA-256 of the same payload) exists for a
rolling-upgrade grace window, but it is a depth-observer forgery vector
(any VIEWER who can read the queue depth can compute it), so it is
**rejected by default**: ``verify_purge_confirm_token`` only accepts it
when the caller passes ``accept_legacy=True``, which the agent gates
behind an explicit opt-in env flag (``Z4J_ACCEPT_LEGACY_PURGE_TOKEN``,
default off). An operator doing a rolling upgrade from a pre-keyed issuer
turns it on temporarily; otherwise only the keyed HMAC is accepted.
"""

from __future__ import annotations

import hashlib
import hmac
import os

#: Env flag an operator sets on the AGENT to re-enable acceptance of the
#: pre-1.7 unkeyed purge token during a rolling upgrade from a pre-keyed
#: issuer. Default off (secure): the unkeyed token is depth-observer
#: forgeable.
_LEGACY_ENV = "Z4J_ACCEPT_LEGACY_PURGE_TOKEN"
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def accept_legacy_from_env() -> bool:
    """Whether the agent should accept the legacy unkeyed purge token, read
    from ``Z4J_ACCEPT_LEGACY_PURGE_TOKEN`` (default off). Shared by every
    engine adapter so the opt-in is uniform."""
    return os.environ.get(_LEGACY_ENV, "").strip().lower() in _TRUTHY


def _payload(queue_name: str, queue_depth: int) -> bytes:
    return f"purge|{queue_name}|{queue_depth}".encode()


def compute_purge_confirm_token(
    *,
    secret: bytes | str,
    queue_name: str,
    queue_depth: int,
) -> str:
    """Keyed HMAC-SHA256 confirm token (hex).

    ``secret`` is the raw per-project secret bytes -- on the brain,
    ``derive_project_secret(master, project_id)``; on the agent, the
    result of ``decode_agent_hmac_secret(Z4J_HMAC_SECRET)``. A ``str``
    secret is UTF-8 encoded (accepted for convenience, but callers should
    pass the raw bytes so both sides key identically).
    """
    key = secret.encode() if isinstance(secret, str) else secret
    return hmac.new(key, _payload(queue_name, queue_depth), hashlib.sha256).hexdigest()


def legacy_purge_confirm_token(*, queue_name: str, queue_depth: int) -> str:
    """The pre-1.7 UNKEYED token (bare SHA-256).

    Accepted by the agent only during the migration grace window so a new
    agent stays compatible with an old issuer. Do NOT use for new issuers.
    """
    return hashlib.sha256(_payload(queue_name, queue_depth)).hexdigest()


def verify_purge_confirm_token(
    *,
    provided: str,
    queue_name: str,
    queue_depth: int,
    secret: bytes | str | None = None,
    accept_legacy: bool = False,
) -> tuple[bool, bool]:
    """Verify a caller-supplied purge confirm token.

    Returns ``(accepted, used_legacy)``:

    - ``accepted`` -- the token matched the keyed HMAC (preferred) or, only
      when ``accept_legacy`` is True, the legacy unkeyed token.
    - ``used_legacy`` -- the match was against the legacy unkeyed token,
      so the caller should WARN and nudge an issuer upgrade.

    ``accept_legacy`` defaults to False: the unkeyed token is forgeable by
    anyone who can observe the queue depth, so it is rejected unless an
    operator has explicitly opted into the rolling-upgrade grace window.
    All comparisons are constant-time (``hmac.compare_digest``). When
    ``secret`` is None (agent could not resolve its ``Z4J_HMAC_SECRET``)
    and ``accept_legacy`` is False, nothing can match.
    """
    if not provided:
        return (False, False)
    if secret:
        expected = compute_purge_confirm_token(
            secret=secret,
            queue_name=queue_name,
            queue_depth=queue_depth,
        )
        if hmac.compare_digest(expected, provided):
            return (True, False)
    if not accept_legacy:
        return (False, False)
    legacy = legacy_purge_confirm_token(
        queue_name=queue_name,
        queue_depth=queue_depth,
    )
    if hmac.compare_digest(legacy, provided):
        return (True, True)
    return (False, False)


__all__ = [
    "accept_legacy_from_env",
    "compute_purge_confirm_token",
    "legacy_purge_confirm_token",
    "verify_purge_confirm_token",
]
