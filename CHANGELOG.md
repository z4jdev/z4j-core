# Changelog

## 1.11.0 (2026-09-10)

* Add the optional `telemetry_loss` field (`TelemetryLossPayload`) to
  heartbeat and agent-status payloads. It carries a buffer identifier, a
  runtime identifier and bounded cumulative counters: capacity-evicted and
  content-rejected frames, lost event records, command results, other and
  unclassified frames, and per-adapter event loss. A frame without the field
  parses with `telemetry_loss=None`, which means the sender does not report
  loss accounting, not that nothing was lost.
* `FrameVerifier` now rejects a signed heartbeat or agent-status frame whose
  `telemetry_loss` fails validation (for example a negative, boolean or
  out-of-range counter, an over-long identifier, or more than 32 adapters)
  with `ProtocolError("invalid telemetry loss counters")`. The check runs
  after HMAC verification and before the replay guard, so a rejected frame
  does not consume its sequence number or nonce.
* Broaden the Pydantic requirement from `pydantic[email]>=2.13.3` to
  `>=2.9.2` on Python below 3.14 and `>=2.12` on Python 3.14+, and
  `typing-extensions` from `>=4.15.0` to `>=4.12.2`, so host applications are
  not forced onto the newest releases. Validation, redaction and protocol
  tests run at these minimums.
* Align runtime version metadata and sibling dependency floors with the coordinated 1.11.0 release.

## 1.10.0 (2026-08-28)

* Carried with the coordinated fleet release. No behaviour changed.

## 1.9.1 (2026-08-27)

* Carried with the coordinated fleet release. No protocol or policy change.

## 1.9.0 (2026-08-25)

* Added `AgentIncompatibleError` and widened the audit model so a 1.9 agent and a 1.9 brain agree on what an incompatible peer is.
* Tightened a queue-engine protocol signature.
* Authenticated command results accept only `success` or `failed`; `timeout`
  remains brain-owned, including the signed-frame fast path.

## 1.8.0 (2026-07-23)

* Added the versioned per-adapter retry-contract capability used to bind retry authority to an executing session rather than sticky agent metadata.
* Hardened the predictable `/tmp` buffer fallback (CWE-377) and now create the z4j home tree `0700` so fresh installs stop warning about world-readable state.
* Part of the coordinated 1.8.0 fleet release (unified fleet version, green lint/format/import-boundary gate).

## 1.7.0 (2026-07-11)

* Purge confirmation tokens are now a keyed HMAC over the queue name and depth, derived from the project secret and verified server-side (the pre-1.7 unkeyed token is rejected by default; set `Z4J_ACCEPT_LEGACY_PURGE_TOKEN=1` on agents temporarily during a rolling upgrade from an older brain).
* Dependency floors raised to match the shipped generated stubs.
* Python 3.11 is now the minimum supported version (3.10 dropped).
* Part of the coordinated 1.7.0 fleet release (unified fleet version, green lint/format/import-boundary gate).

## 1.4.0 (2026-05-02)

Initial 1.4.0 release: shared SDK used by every agent. Pure-Python, no framework imports.
