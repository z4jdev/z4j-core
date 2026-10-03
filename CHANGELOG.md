# Changelog

## 1.12.0 (2026-10-03)

* Add `QueueEngine.list_dead_letters(queue, limit, cursor)`, the read side
  of `requeue_dead_letter`. It returns a `DeadLetterPage` of
  `DeadLetterEntry` rows (task id, task name, queue, `failed_at`, a
  redacted error excerpt of at most `DEAD_LETTER_EXCERPT_MAX_CHARS` (512)
  characters, attempts), newest first, with an opaque `next_cursor` and an
  optional `total`. A page carries at most `DLQ_LIST_MAX_LIMIT` (200)
  entries so it stays far under the frame cap; `DLQ_LIST_DEFAULT_LIMIT` is
  100. An implementation must only read: it never consumes, acks or
  reorders what it lists and never deserialises an untrusted broker payload.
  `redact_error_excerpt` is exported for adapters.
* Add the capability token `list_dead_letters` and `Action.LIST_DEAD_LETTERS`
  to the policy engine. An adapter advertises the token only when it
  implements the method; an engine with no dead-letter store keeps it absent
  and raises `AdapterError` from the method.
* Add the command action `dlq.list`, whose `command_result.result` is the
  serialised page.
* Add `ProjectRole.AUDITOR` (`"auditor"`), between viewer and operator:
  everything a viewer may do plus the audit trail (list, export and verify
  it, and read the audit forwarder's status). It holds no command, schedule,
  membership, agent-token or project authority, so the people who review the
  record are not the people who make it. Authority order is
  `viewer < auditor < operator < admin`.
* Rebuild `z4j_core.policy.engine` as the single role vocabulary the brain
  enforces, built from the brain's real gates. `ROLE_ORDER` serves the
  `min_role` floors through `role_satisfies(held, required)` and
  `role_rank`; `ACTIONS_BY_ROLE` buckets every action under the tier that
  owns it and `ROLES_SATISFYING_TIER` names the held roles each tier admits,
  answered by `action_allowed(held, action)` and `action_required_role`. The
  audit tier is granted to auditor and admin only; operator outranks auditor
  for floors but does not inherit audit actions. All of these are exported
  from `z4j_core.policy`. `PolicyEngine.can` decides on the membership it is
  handed; the brain synthesises its instance-admin membership before asking.
* Add the actions the brain gates and the table lacked: `READ_COMMANDS`,
  `READ_AUTOMATION_RULES`, `READ_NOTIFICATION_CHANNELS`,
  `MANAGE_OWN_SAVED_VIEWS`, `MANAGE_OWN_SUBSCRIPTIONS` (viewer);
  `EXPORT_AUDIT`, `VERIFY_AUDIT`, `READ_AUDIT_FORWARDER_STATUS` (auditor,
  beside `READ_AUDIT`, which moves out of the viewer set); `RESIZE_POOL`,
  `MANAGE_CONSUMERS`, `SET_RATE_LIMIT`, `PAUSE_SCHEDULE`, `RESUME_SCHEDULE`,
  `RESOLVE_SCHEDULE_EVIDENCE`, `MANAGE_AUTOMATION_RULES` (operator);
  `DELETE_TASKS`, `SYNC_SCHEDULES`, `SET_LEGACY_FIRE_GRANT`,
  `MANAGE_DESTRUCTIVE_AUTOMATION_RULES`, `UPDATE_AUTOMATION_SETTINGS`,
  `MANAGE_NOTIFICATION_CHANNELS`, `READ_MEMBERS` (admin).
* Remove `Action.UPDATE_RETENTION`; nothing gated it.
* The README and `SECURITY.md` describe the vocabulary ownership: the table
  is defined once here, the brain's persistence-aware engine resolves
  memberships and answers HTTP, and a contract test in the z4j repository
  holds the two to the same answers for every (role, action) pair.
* Extra redaction key patterns are probed at construction and refused when
  they backtrack catastrophically; keys over 256 characters are treated as
  sensitive without running a pattern, and extra patterns run only on keys up
  to 64 characters.

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
