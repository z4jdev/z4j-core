# Changelog

## 1.7.0 (2026-07-11)

* Purge confirmation tokens are now a keyed HMAC over the queue name and depth, derived from the project secret and verified server-side (the pre-1.7 unkeyed token is rejected by default; set `Z4J_ACCEPT_LEGACY_PURGE_TOKEN=1` on agents temporarily during a rolling upgrade from an older brain).
* Dependency floors raised to match the shipped generated stubs.
* Python 3.11 is now the minimum supported version (3.10 dropped).
* Part of the coordinated 1.7.0 fleet release (unified fleet version, green lint/format/import-boundary gate).

## 1.4.0 (2026-05-02)

Initial 1.4.0 release: shared SDK used by every agent. Pure-Python, no framework imports.
