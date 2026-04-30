"""celery-beat syntax compatibility (1.2.2+).

Translates ``CELERY_BEAT_SCHEDULE`` entries into the z4j scheduler
shape that ``z4j-brain``'s ``ScheduleCreateIn`` accepts. This is
the engine behind the framework adapters' declarative reconcilers
(z4j-django, z4j-flask, z4j-fastapi) when the operator opts into
reading ``CELERY_BEAT_SCHEDULE`` from their settings.

Supported celery-beat schedule shapes:

- ``celery.schedules.crontab(...)``  -> ``("cron", "<5-field cron string>")``
- ``celery.schedules.solar(event, lat, lon)`` -> ``("solar", "<event>:<lat>:<lon>")``
- ``datetime.timedelta(seconds=N)``  -> ``("interval", str(N))``
- ``int`` / ``float`` (interpreted as seconds) -> ``("interval", str(int(N)))``
- bare cron string (``"0 9 * * *"``) -> ``("cron", str)``

Intentionally NOT supported in 1.2.2 (raise ``UnsupportedScheduleError``
with a clear message; operator can convert manually):

- ``celery.schedules.schedule`` with relative=True
- crontab(``day_of_year`` / nth-weekday extensions)
- timedelta with non-integer seconds at sub-second precision
- ``expires`` / ``args`` / ``kwargs`` field validation - these are
  passed through to z4j without translation since they share
  semantics across both schedulers

The parser is *defensive*: missing celery → falls back to duck
typing (the ``crontab`` and ``solar`` types may exist as objects
with the same attribute names even if celery isn't importable).
This lets framework adapters call this code without forcing
celery as a hard dependency.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import logging
from typing import Any

logger = logging.getLogger("z4j.core.celerybeat_compat")


class UnsupportedScheduleError(ValueError):
    """The given celery-beat schedule shape isn't representable in z4j.

    Carries the schedule that triggered the failure so adapters can
    log it with operator-actionable context.
    """

    def __init__(self, message: str, *, source: object) -> None:
        super().__init__(message)
        self.source = source


@dataclasses.dataclass(frozen=True, slots=True)
class ScheduleSpec:
    """Translation result: one z4j schedule.

    Mirrors ``z4j_brain.api.schedules.ScheduleCreateIn`` for the
    fields the parser produces. Adapters add the per-deployment
    fields (``engine``, ``queue``, ``scheduler``) before POSTing.
    """

    name: str
    task_name: str
    kind: str  # "cron" | "interval" | "solar" | "one_shot"
    expression: str
    args: list[Any] = dataclasses.field(default_factory=list)
    kwargs: dict[str, Any] = dataclasses.field(default_factory=dict)
    queue: str | None = None
    timezone: str = "UTC"


# ---------------------------------------------------------------------------
# Helpers - duck typing first, real-import second
# ---------------------------------------------------------------------------


def _is_celery_crontab(obj: object) -> bool:
    """Return True if ``obj`` walks like a celery crontab.

    We don't import celery; we look for the attributes celery's
    crontab carries: ``minute``, ``hour``, ``day_of_week``,
    ``day_of_month``, ``month_of_year``. Any object with all five
    AND those attributes parseable as the celery shape qualifies.
    """
    return (
        hasattr(obj, "minute")
        and hasattr(obj, "hour")
        and hasattr(obj, "day_of_week")
        and hasattr(obj, "day_of_month")
        and hasattr(obj, "month_of_year")
        # rule out the stdlib datetime (which has hour + minute too)
        and not isinstance(obj, _dt.time)
    )


def _is_celery_solar(obj: object) -> bool:
    """Return True if ``obj`` walks like a celery solar schedule.

    celery's solar carries ``event``, ``lat``, ``lon`` (sometimes
    spelled ``latitude`` / ``longitude``).
    """
    return (
        hasattr(obj, "event")
        and (hasattr(obj, "lat") or hasattr(obj, "latitude"))
        and (hasattr(obj, "lon") or hasattr(obj, "longitude"))
    )


def _crontab_field_to_str(value: object) -> str:
    """Convert one of celery's crontab field types to a cron string segment.

    celery represents wildcard / set / range internally as ``set`` /
    ``str`` / ``crontab_parser.parse_*`` objects depending on the
    input. The simplest route: rely on ``str()`` which celery's
    fields all implement to round-trip back to crontab syntax.
    """
    if value is None:
        return "*"
    if isinstance(value, str):
        return value
    if isinstance(value, set):
        # Celery normalizes sets internally; iterating in numeric
        # sort order gives a stable representation.
        try:
            sorted_vals = sorted(value)
        except TypeError:
            sorted_vals = list(value)
        if not sorted_vals:
            return "*"
        return ",".join(str(v) for v in sorted_vals)
    return str(value)


def _coerce_crontab_to_string(crontab: object) -> str:
    """Build a 5-field cron string from a celery crontab-shaped object.

    Order: ``minute hour day_of_month month_of_year day_of_week``.
    """
    minute = _crontab_field_to_str(getattr(crontab, "minute", None))
    hour = _crontab_field_to_str(getattr(crontab, "hour", None))
    day_of_month = _crontab_field_to_str(getattr(crontab, "day_of_month", None))
    month_of_year = _crontab_field_to_str(getattr(crontab, "month_of_year", None))
    day_of_week = _crontab_field_to_str(getattr(crontab, "day_of_week", None))
    # Treat empty sets as wildcard (celery's default for unspecified fields)
    fields = [
        f if f else "*" for f in (
            minute, hour, day_of_month, month_of_year, day_of_week,
        )
    ]
    return " ".join(fields)


def _coerce_solar_to_string(solar: object) -> str:
    """Build z4j's ``"event:lat:lon"`` solar expression."""
    event = getattr(solar, "event", None)
    if not event:
        raise UnsupportedScheduleError(
            "solar schedule missing event attribute", source=solar,
        )
    lat = getattr(solar, "lat", None) or getattr(solar, "latitude", None)
    lon = getattr(solar, "lon", None) or getattr(solar, "longitude", None)
    if lat is None or lon is None:
        raise UnsupportedScheduleError(
            "solar schedule missing lat/lon attributes", source=solar,
        )
    return f"{event}:{lat}:{lon}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_celery_beat_schedule(schedule: object) -> tuple[str, str]:
    """Translate one celery-beat ``schedule`` value to ``(kind, expression)``.

    The single ``schedule`` field of a celery-beat entry can be any of:

    - ``crontab(...)``  -> ("cron", "<5 fields>")
    - ``solar(...)``    -> ("solar", "event:lat:lon")
    - ``timedelta``     -> ("interval", "<seconds>")
    - ``float`` / ``int`` (seconds) -> ("interval", "<seconds>")
    - bare cron string  -> ("cron", str)

    Raises ``UnsupportedScheduleError`` for shapes z4j 1.2.2 can't
    represent (e.g., relative schedules, expires-bearing schedules).
    """
    # bare cron string ("0 9 * * *")
    if isinstance(schedule, str):
        # Best-effort validation: cron strings have 5 or 6 space-separated
        # fields. Anything else is more likely a typo than a valid value.
        parts = schedule.strip().split()
        if 5 <= len(parts) <= 6:
            return ("cron", schedule.strip())
        raise UnsupportedScheduleError(
            f"unrecognised schedule string: {schedule!r}; "
            f"expected 5- or 6-field cron expression",
            source=schedule,
        )

    # crontab object (celery or duck-typed equivalent)
    if _is_celery_crontab(schedule):
        return ("cron", _coerce_crontab_to_string(schedule))

    # solar object
    if _is_celery_solar(schedule):
        return ("solar", _coerce_solar_to_string(schedule))

    # timedelta -> interval seconds
    if isinstance(schedule, _dt.timedelta):
        seconds = int(schedule.total_seconds())
        if seconds <= 0:
            raise UnsupportedScheduleError(
                f"interval must be positive: {schedule!r}",
                source=schedule,
            )
        return ("interval", str(seconds))

    # numeric (int / float) interpreted as seconds
    if isinstance(schedule, (int, float)) and not isinstance(schedule, bool):
        seconds = int(schedule)
        if seconds <= 0:
            raise UnsupportedScheduleError(
                f"interval must be positive: {schedule!r}",
                source=schedule,
            )
        return ("interval", str(seconds))

    raise UnsupportedScheduleError(
        f"unsupported schedule type {type(schedule).__name__}: {schedule!r}; "
        f"supported: crontab, solar, timedelta, int/float seconds, or "
        f"5/6-field cron string",
        source=schedule,
    )


def parse_celery_beat_entries(
    entries: dict[str, dict[str, Any]],
) -> list[ScheduleSpec]:
    """Translate a full ``CELERY_BEAT_SCHEDULE`` dict into z4j ScheduleSpecs.

    The shape celery-beat expects::

        CELERY_BEAT_SCHEDULE = {
            "name": {
                "task": "myapp.tasks.foo",
                "schedule": <crontab|timedelta|float|str|solar>,
                "args": [...],         # optional
                "kwargs": {...},       # optional
                "options": {           # optional, partial support
                    "queue": "default",
                    # expires: NOT supported in 1.2.2 - logged + dropped
                },
            },
            ...
        }

    Returns a list of :class:`ScheduleSpec` ready for the framework
    adapter to fill in the deployment-specific fields (``engine``,
    ``scheduler``) and POST to the brain.

    Errors per entry are collected into a per-name ``UnsupportedScheduleError``
    which the caller can format into operator-friendly output. The
    function does NOT raise; it returns successfully-translated specs
    and logs warnings for the rest. Adapters that want stricter
    behaviour can wrap with their own validator.
    """
    specs: list[ScheduleSpec] = []
    for name, entry in entries.items():
        if not isinstance(entry, dict):
            logger.warning(
                "z4j celery-beat compat: entry %r is not a dict, skipping",
                name,
            )
            continue
        task = entry.get("task")
        if not task:
            logger.warning(
                "z4j celery-beat compat: entry %r missing 'task', skipping",
                name,
            )
            continue
        sched = entry.get("schedule")
        if sched is None:
            logger.warning(
                "z4j celery-beat compat: entry %r missing 'schedule', skipping",
                name,
            )
            continue
        try:
            kind, expression = parse_celery_beat_schedule(sched)
        except UnsupportedScheduleError as exc:
            logger.warning(
                "z4j celery-beat compat: entry %r unsupported: %s",
                name, exc,
            )
            continue

        # Optional fields - celery-beat puts these in the top-level
        # entry dict; some shops nest them under ``options``.
        args = entry.get("args") or []
        kwargs = entry.get("kwargs") or {}
        options = entry.get("options") or {}
        queue = options.get("queue") or entry.get("queue")
        if "expires" in options or "expires" in entry:
            logger.warning(
                "z4j celery-beat compat: entry %r uses 'expires' which "
                "1.2.2 does not honour; the field is dropped. The schedule "
                "still fires; the resulting task simply won't auto-expire. "
                "If this matters, set the per-task expiry on the task "
                "itself or open a feature request.",
                name,
            )

        specs.append(
            ScheduleSpec(
                name=name,
                task_name=str(task),
                kind=kind,
                expression=expression,
                args=list(args) if args else [],
                kwargs=dict(kwargs) if kwargs else {},
                queue=queue,
            ),
        )

    return specs


__all__ = [
    "ScheduleSpec",
    "UnsupportedScheduleError",
    "parse_celery_beat_entries",
    "parse_celery_beat_schedule",
]
