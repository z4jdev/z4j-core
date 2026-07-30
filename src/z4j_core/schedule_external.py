"""Canonical wire contract for sequenced external schedule projections."""

from __future__ import annotations

import hashlib
import json
import math
from datetime import UTC, datetime
from typing import Any

EXTERNAL_SCHEDULE_PROTOCOL_VERSION = 1
EXTERNAL_SCHEDULE_STABLE_SNAPSHOT_CAPABILITY = "external_schedule_stable_snapshot_v1"
EXTERNAL_SCHEDULE_RUNTIME_FEATURE = "external_schedule_protocol_v1"


class ExternalScheduleProtocolError(ValueError):
    """An external schedule projection is malformed or non-canonical."""


def _json_value(value: Any, *, path: str) -> Any:
    if value is None or isinstance(value, (bool, str, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ExternalScheduleProtocolError(
                f"{path} contains a non-finite number",
            )
        return value
    if isinstance(value, list | tuple):
        return [_json_value(item, path=f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key in sorted(value):
            if not isinstance(key, str):
                raise ExternalScheduleProtocolError(
                    f"{path} contains a non-string key",
                )
            result[key] = _json_value(
                value[key],
                path=f"{path}.{key}",
            )
        return result
    raise ExternalScheduleProtocolError(
        f"{path} contains unsupported {type(value).__name__}",
    )


def _json_object(
    value: dict[str, Any],
    *,
    path: str,
) -> dict[str, Any]:
    normalized = _json_value(value, path=path)
    if not isinstance(normalized, dict):
        raise ExternalScheduleProtocolError(
            f"{path} is not a JSON object",
        )
    return normalized


def canonical_external_json(value: dict[str, Any]) -> bytes:
    """Return the closed, cross-runtime canonical external encoding."""

    normalized = _json_value(value, path="$")
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def external_schedule_source_scope(owner: str) -> str:
    """Return the canonical v1 whole-owner source scope."""

    if not owner or owner == "z4j-scheduler":
        raise ExternalScheduleProtocolError(
            "external owner is missing or reserved",
        )
    return canonical_external_json(
        {
            "kind": "scheduler-owner",
            "owner": owner,
            "version": 1,
        },
    ).decode("utf-8")


def _timestamp(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise ExternalScheduleProtocolError(
                f"{field} is not an ISO-8601 timestamp",
            ) from exc
    if parsed.tzinfo is None:
        raise ExternalScheduleProtocolError(
            f"{field} must include an offset",
        )
    return parsed.astimezone(UTC).isoformat(timespec="microseconds")


def normalize_external_schedule(
    raw: dict[str, Any],
    *,
    owner: str,
) -> dict[str, Any]:
    """Normalize one source row into the exact projection vocabulary."""

    if not owner or owner == "z4j-scheduler":
        raise ExternalScheduleProtocolError(
            "external owner is missing or reserved",
        )
    inner_owner = str(raw.get("scheduler") or owner)
    if inner_owner != owner:
        raise ExternalScheduleProtocolError(
            "inner schedule owner differs from stream owner",
        )
    name = str(raw.get("name") or "").strip()
    task_name = str(raw.get("task_name") or "").strip()
    if not name or not task_name:
        raise ExternalScheduleProtocolError(
            "external schedule name and task_name are required",
        )
    source_key = str(
        raw.get("source_key") or raw.get("external_source_key") or raw.get("external_id") or name,
    ).strip()
    if not source_key:
        raise ExternalScheduleProtocolError(
            "external source key is empty",
        )
    args = raw.get("args", [])
    kwargs = raw.get("kwargs", {})
    if not isinstance(args, list) or not isinstance(kwargs, dict):
        raise ExternalScheduleProtocolError(
            "external schedule args/kwargs have wrong types",
        )
    total_runs = int(raw.get("total_runs", 0))
    if total_runs < 0:
        raise ExternalScheduleProtocolError(
            "external schedule total_runs is negative",
        )
    normalized = {
        "source_key": source_key,
        "engine": str(raw.get("engine") or owner.split("-", 1)[0] or owner),
        "scheduler": owner,
        "name": name,
        "task_name": task_name,
        "kind": str(raw.get("kind") or "interval"),
        "expression": str(raw.get("expression") or ""),
        "timezone": str(raw.get("timezone") or "UTC"),
        "queue": (str(raw["queue"]) if raw.get("queue") is not None else None),
        "priority": str(raw.get("priority") or "normal"),
        "args": args,
        "kwargs": kwargs,
        "is_enabled": bool(raw.get("is_enabled", True)),
        "last_run_at": _timestamp(
            raw.get("last_run_at"),
            field="last_run_at",
        ),
        "next_run_at": _timestamp(
            raw.get("next_run_at"),
            field="next_run_at",
        ),
        "total_runs": total_runs,
        "external_id": (str(raw["external_id"]) if raw.get("external_id") is not None else None),
        "catch_up": str(raw.get("catch_up") or "skip"),
        "source": str(raw.get("source") or "agent"),
        "source_hash": (str(raw["source_hash"]) if raw.get("source_hash") is not None else None),
    }
    return _json_object(normalized, path="$.schedule")


def external_projection_body(
    *,
    stream_id: str,
    epoch_uuid: str,
    epoch_number: int,
    sequence: int,
    kind: str,
    owner: str,
    source_scope: str,
    adapter_instance_id: str,
    schedules: list[dict[str, Any]],
    deleted_source_keys: list[str] | None = None,
    complete: bool,
    stable_source: bool,
    operation_id: str | None = None,
) -> dict[str, Any]:
    """Build the exact digest-bearing projection body."""

    if epoch_number <= 0 or sequence <= 0:
        raise ExternalScheduleProtocolError(
            "external epoch and sequence must be positive",
        )
    if kind not in {"snapshot", "created", "updated", "deleted", "control"}:
        raise ExternalScheduleProtocolError(
            f"unsupported external projection kind {kind!r}",
        )
    if not adapter_instance_id:
        raise ExternalScheduleProtocolError(
            "adapter instance id is required",
        )
    normalized_rows = [normalize_external_schedule(row, owner=owner) for row in schedules]
    normalized_rows.sort(key=lambda row: row["source_key"])
    source_keys = [str(row["source_key"]) for row in normalized_rows]
    if len(source_keys) != len(set(source_keys)):
        raise ExternalScheduleProtocolError(
            "projection repeats an external source key",
        )
    deleted = sorted(
        {str(value).strip() for value in (deleted_source_keys or []) if str(value).strip()},
    )
    if set(source_keys) & set(deleted):
        raise ExternalScheduleProtocolError(
            "projection both upserts and deletes one source key",
        )
    body = {
        "protocol_version": EXTERNAL_SCHEDULE_PROTOCOL_VERSION,
        "stream_id": str(stream_id),
        "epoch_uuid": str(epoch_uuid),
        "epoch_number": int(epoch_number),
        "sequence": int(sequence),
        "kind": kind,
        "owner": owner,
        "source_scope": source_scope,
        "adapter_instance_id": adapter_instance_id,
        "complete": bool(complete),
        "stable_source": bool(stable_source),
        "operation_id": operation_id,
        "schedules": normalized_rows,
        "deleted_source_keys": deleted,
    }
    return _json_object(body, path="$")


def external_projection_digest(body: dict[str, Any]) -> str:
    """Digest one canonical projection body."""

    return hashlib.sha256(canonical_external_json(body)).hexdigest()


def external_control_result_matches_desired(
    desired: dict[str, Any],
    observed: dict[str, Any],
) -> bool:
    """Match one native set-to-state result against its complete intent.

    ``next_run_at`` is a runtime-owned cursor.  Some schedulers necessarily
    clear it while paused and recompute it while resumed, so a successful
    enable/disable cannot promise the value captured before the operation.
    Every other normalized field remains exact, including source identity,
    configuration, counters, and the requested ``is_enabled`` state.
    """

    if desired.keys() != observed.keys():
        return False
    return all(desired[key] == observed[key] for key in desired if key != "next_run_at")


def external_snapshot_frame_body(
    *,
    stream_id: str,
    epoch_uuid: str,
    epoch_number: int,
    sequence: int,
    owner: str,
    source_scope: str,
    adapter_instance_id: str,
    snapshot_id: str,
    frame_kind: str,
    frame_index: int,
    frame_count: int,
    row_count: int,
    snapshot_digest: str,
    stable_source: bool,
    schedules: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build one canonical frame of a stable external snapshot.

    Row frames are indexed ``0..frame_count-1``.  The required terminal frame
    uses ``frame_index == frame_count`` and carries no rows.  Every frame binds
    the terminal row count and full projection digest, so mixing two snapshots
    or changing a frame after staging is detectable before reconciliation.
    """

    if epoch_number <= 0 or sequence <= 0:
        raise ExternalScheduleProtocolError(
            "external epoch and sequence must be positive",
        )
    if not adapter_instance_id or not snapshot_id:
        raise ExternalScheduleProtocolError(
            "external snapshot authority and identity are required",
        )
    if frame_count < 0 or row_count < 0 or frame_index < 0 or frame_index > frame_count:
        raise ExternalScheduleProtocolError(
            "external snapshot frame bounds are invalid",
        )
    if len(snapshot_digest) != 64 or any(
        character not in "0123456789abcdef" for character in snapshot_digest
    ):
        raise ExternalScheduleProtocolError(
            "external snapshot digest is invalid",
        )
    normalized_rows = [normalize_external_schedule(row, owner=owner) for row in schedules]
    normalized_rows.sort(key=lambda row: row["source_key"])
    source_keys = [str(row["source_key"]) for row in normalized_rows]
    if len(source_keys) != len(set(source_keys)):
        raise ExternalScheduleProtocolError(
            "snapshot frame repeats an external source key",
        )
    if frame_kind == "rows":
        if frame_count == 0 or frame_index >= frame_count or not normalized_rows:
            raise ExternalScheduleProtocolError(
                "external snapshot row frame is empty or out of bounds",
            )
    elif frame_kind == "terminal":
        if frame_index != frame_count or normalized_rows:
            raise ExternalScheduleProtocolError(
                "external snapshot terminal frame is malformed",
            )
    else:
        raise ExternalScheduleProtocolError(
            f"unsupported external snapshot frame kind {frame_kind!r}",
        )
    return _json_object(
        {
            "protocol_version": EXTERNAL_SCHEDULE_PROTOCOL_VERSION,
            "stream_id": str(stream_id),
            "epoch_uuid": str(epoch_uuid),
            "epoch_number": int(epoch_number),
            "sequence": int(sequence),
            "owner": owner,
            "source_scope": source_scope,
            "adapter_instance_id": adapter_instance_id,
            "snapshot_id": snapshot_id,
            "frame_kind": frame_kind,
            "frame_index": int(frame_index),
            "frame_count": int(frame_count),
            "row_count": int(row_count),
            "snapshot_digest": snapshot_digest,
            "stable_source": bool(stable_source),
            "schedules": normalized_rows,
        },
        path="$",
    )


def external_snapshot_frame_digest(body: dict[str, Any]) -> str:
    """Digest one canonical external stable-snapshot frame."""

    return hashlib.sha256(canonical_external_json(body)).hexdigest()


__all__ = [
    "EXTERNAL_SCHEDULE_PROTOCOL_VERSION",
    "EXTERNAL_SCHEDULE_RUNTIME_FEATURE",
    "EXTERNAL_SCHEDULE_STABLE_SNAPSHOT_CAPABILITY",
    "ExternalScheduleProtocolError",
    "canonical_external_json",
    "external_control_result_matches_desired",
    "external_projection_body",
    "external_projection_digest",
    "external_schedule_source_scope",
    "external_snapshot_frame_body",
    "external_snapshot_frame_digest",
    "normalize_external_schedule",
]
