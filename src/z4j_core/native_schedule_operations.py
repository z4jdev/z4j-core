"""Common direct adapter operations routed through native compare-and-set."""

from __future__ import annotations

from typing import Any

from z4j_core.models import CommandResult, Schedule
from z4j_core.models.schedule import refuse_unimplemented_overlap
from z4j_core.schedule_external import normalize_external_schedule


async def direct_native_mutation(
    adapter: Any,
    operation: str,
    schedule_id: str | None = None,
    spec: Schedule | None = None,
    *,
    enabled: bool | None = None,
) -> Schedule | CommandResult:
    """Use the same validated mutation path for direct and remote callers."""
    if spec is not None:
        refuse_unimplemented_overlap(getattr(spec, "overlap_policy", None))
        if spec.catch_up != "skip":
            raise ValueError("native schedules do not implement z4j catch-up policies")
    current = await adapter.get_schedule(schedule_id) if schedule_id else None
    if operation != "create" and current is None:
        if operation == "delete":
            return CommandResult(status="success", result={"noop": True})
        raise ValueError("native schedule not found")
    expected = (
        normalize_external_schedule(current.model_dump(mode="json"), owner=adapter.name)
        if current
        else None
    )
    definition = (
        {
            key: value
            for key, value in spec.model_dump(mode="json").items()
            if key
            in {
                "name",
                "task_name",
                "kind",
                "expression",
                "timezone",
                "queue",
                "args",
                "kwargs",
                "is_enabled",
            }
        }
        if spec
        else {}
    )
    if enabled is not None:
        definition["is_enabled"] = enabled
    result = await adapter.apply_external_mutation(
        operation=operation,
        schedule_id=current.external_id if current else None,
        expected=expected,
        definition=definition,
    )
    if spec is not None and isinstance(result, Schedule):
        return result
    return CommandResult(status="success", result={"schedule_id": schedule_id})
