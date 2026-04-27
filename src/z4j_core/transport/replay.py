"""Replay + freshness guard for protocol v2 frames.

Every authenticated frame on a WebSocket carries a ``(ts, nonce,
seq)`` triple in its signed envelope. The :class:`ReplayGuard`
below enforces the three invariants the signature alone cannot:

1. **Freshness**: ``|local_now - frame.ts|`` must be within the
   configured skew window. Too old => captured and replayed by an
   attacker; too new => clock tampered with.
2. **Monotonic seq**: within a session, frame ``seq`` must be
   strictly greater than the last-seen seq for that direction.
   Closes the "replay within the skew window" hole.
3. **Unique nonce**: each nonce is remembered for slightly longer
   than the skew window. Belt-and-braces for the case of two
   legitimately-different frames sharing the same wall-clock
   tick (rare but possible under batching).

Per-session instance; cheap to construct. Intended for use by the
brain (one instance per agent WebSocket) and by the agent (one
instance tracking inbound brain→agent frames).
"""

from __future__ import annotations

import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any

from z4j_core.errors import SignatureError
from z4j_core.transport.hmac import (
    MAX_FRAME_TS_SKEW_SECONDS,
    MAX_NONCE_TRACK_SECONDS,
    MIN_SEQ,
)


class ReplayGuard:
    """Per-session replay + freshness enforcer.

    Tracks the last-seen seq and a bounded sliding window of
    recently-seen nonces. Thread-unsafe; callers that share one
    instance across threads must serialise with their own lock
    (the typical frame router runs single-threaded per connection
    so no lock is needed).
    """

    __slots__ = (
        "_direction",
        "_last_seq",
        "_max_nonce_entries",
        "_nonce_ttl_seconds",
        "_nonce_window",
        "_skew_seconds",
    )

    def __init__(
        self,
        *,
        direction: str = "inbound",
        skew_seconds: int = MAX_FRAME_TS_SKEW_SECONDS,
        nonce_window_seconds: int = MAX_NONCE_TRACK_SECONDS,
        max_nonce_entries: int = 4096,
    ) -> None:
        self._direction = direction
        self._skew_seconds = int(skew_seconds)
        self._last_seq: int = 0
        #: nonce -> monotonic insertion time (seconds, ``time.monotonic``)
        self._nonce_window: OrderedDict[str, float] = OrderedDict()
        self._max_nonce_entries = int(max_nonce_entries)
        # ``nonce_window_seconds`` is stored implicitly via the
        # eviction floor in :meth:`_evict_old_nonces`.
        self._nonce_ttl_seconds = int(nonce_window_seconds)

    def check(self, envelope: dict[str, Any]) -> None:
        """Enforce freshness, seq-monotonicity, and nonce uniqueness.

        Raises :class:`SignatureError` on any violation. The caller
        should log + close the session + increment a security
        counter; a surviving violation means the peer is replaying,
        desynchronised, or compromised.
        """
        seq = envelope.get("seq")
        ts_raw = envelope.get("ts")
        nonce = envelope.get("nonce")

        if not isinstance(seq, int) or seq < MIN_SEQ:
            raise SignatureError("frame envelope missing valid seq")
        if not isinstance(nonce, str) or not nonce:
            raise SignatureError("frame envelope missing nonce")
        if ts_raw is None:
            raise SignatureError("frame envelope missing ts")

        # Freshness.
        ts_dt = _parse_iso(ts_raw)
        now = datetime.now(timezone.utc)
        skew = abs((now - ts_dt).total_seconds())
        if skew > self._skew_seconds:
            raise SignatureError(
                f"frame ts skew {skew:.1f}s exceeds limit "
                f"{self._skew_seconds}s ({self._direction})",
            )

        # Monotonic seq.
        if seq <= self._last_seq:
            raise SignatureError(
                f"frame seq {seq} not strictly greater than "
                f"last-seen {self._last_seq} ({self._direction})",
            )

        # Unique nonce within the sliding window.
        self._evict_old_nonces()
        if nonce in self._nonce_window:
            raise SignatureError(
                f"frame nonce replay detected ({self._direction})",
            )

        # Commit: accept this frame.
        self._last_seq = seq
        self._nonce_window[nonce] = time.monotonic()
        # Enforce hard cap too (defense against a pathological
        # burst faster than TTL can evict).
        while len(self._nonce_window) > self._max_nonce_entries:
            self._nonce_window.popitem(last=False)

    @property
    def last_seq(self) -> int:
        return self._last_seq

    def _evict_old_nonces(self) -> None:
        cutoff = time.monotonic() - self._nonce_ttl_seconds
        # OrderedDict insertion order matches time order (monotonic
        # clock always advances) so we can pop from the front.
        while self._nonce_window:
            oldest_nonce, inserted_at = next(iter(self._nonce_window.items()))
            if inserted_at >= cutoff:
                return
            self._nonce_window.popitem(last=False)


def _parse_iso(raw: Any) -> datetime:
    """Parse an ISO 8601 timestamp, coercing naive→UTC."""
    if isinstance(raw, datetime):
        dt = raw
    elif isinstance(raw, str):
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as exc:
            raise SignatureError("frame ts is not a valid ISO 8601 string") from exc
    else:
        raise SignatureError("frame ts must be an ISO 8601 string")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


__all__ = ["ReplayGuard"]
