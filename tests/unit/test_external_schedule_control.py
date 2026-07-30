"""Closed comparison rules for external scheduler set-to-state results."""

from __future__ import annotations

from z4j_core.schedule_external import (
    external_control_result_matches_desired,
    normalize_external_schedule,
)


def _projection() -> dict[str, object]:
    return normalize_external_schedule(
        {
            "source_key": "nightly",
            "engine": "apscheduler",
            "scheduler": "apscheduler",
            "name": "nightly",
            "task_name": "jobs.nightly",
            "kind": "interval",
            "expression": "60",
            "timezone": "UTC",
            "args": [],
            "kwargs": {},
            "is_enabled": False,
            "next_run_at": "2026-07-25T18:30:00+00:00",
        },
        owner="apscheduler",
    )


def test_control_result_allows_only_the_runtime_owned_next_run_cursor() -> None:
    desired = _projection()
    observed = dict(desired)
    observed["next_run_at"] = None

    assert external_control_result_matches_desired(desired, observed)

    observed["expression"] = "120"
    assert not external_control_result_matches_desired(desired, observed)


def test_control_result_requires_the_complete_closed_projection() -> None:
    desired = _projection()
    observed = dict(desired)
    observed.pop("source_hash")

    assert not external_control_result_matches_desired(desired, observed)
