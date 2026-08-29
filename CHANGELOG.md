# Changelog

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
