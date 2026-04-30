"""Tests for the celery-beat syntax compatibility parser (1.2.2+).

Validates that ``CELERY_BEAT_SCHEDULE`` entries translate to the
z4j scheduler shape correctly, AND that unsupported shapes raise
the documented error rather than silently producing wrong output.

The tests use duck-typed stand-ins for celery's ``crontab`` and
``solar`` so the test suite doesn't require celery as a dep.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

import pytest

from z4j_core.celerybeat_compat import (
    ScheduleSpec,
    UnsupportedScheduleError,
    parse_celery_beat_entries,
    parse_celery_beat_schedule,
)


# ---------------------------------------------------------------------------
# Stand-ins for celery types (no celery import needed)
# ---------------------------------------------------------------------------


@dataclass
class FakeCrontab:
    """Duck-typed stand-in for ``celery.schedules.crontab``."""

    minute: object = "*"
    hour: object = "*"
    day_of_week: object = "*"
    day_of_month: object = "*"
    month_of_year: object = "*"


@dataclass
class FakeSolar:
    """Duck-typed stand-in for ``celery.schedules.solar``."""

    event: str = "sunrise"
    lat: float = 40.7128
    lon: float = -74.0060


# ---------------------------------------------------------------------------
# parse_celery_beat_schedule - single-value translator
# ---------------------------------------------------------------------------


class TestParseCronString:
    def test_5_field_cron_passes_through(self) -> None:
        kind, expr = parse_celery_beat_schedule("0 9 * * *")
        assert kind == "cron"
        assert expr == "0 9 * * *"

    def test_6_field_cron_passes_through(self) -> None:
        # Some cron flavours allow seconds as the 6th field.
        kind, expr = parse_celery_beat_schedule("0 0 9 * * *")
        assert kind == "cron"
        assert expr == "0 0 9 * * *"

    def test_invalid_cron_string_raises(self) -> None:
        with pytest.raises(UnsupportedScheduleError):
            parse_celery_beat_schedule("not-a-cron")
        with pytest.raises(UnsupportedScheduleError):
            parse_celery_beat_schedule("0 9 *")  # 3 fields


class TestParseCrontab:
    def test_default_wildcards(self) -> None:
        kind, expr = parse_celery_beat_schedule(FakeCrontab())
        assert kind == "cron"
        assert expr == "* * * * *"

    def test_explicit_fields(self) -> None:
        kind, expr = parse_celery_beat_schedule(
            FakeCrontab(minute=0, hour=9),
        )
        assert kind == "cron"
        assert expr == "0 9 * * *"

    def test_field_set_normalized(self) -> None:
        # celery internally stores sets like {0, 30} for minute
        kind, expr = parse_celery_beat_schedule(
            FakeCrontab(minute={0, 30}, hour=9),
        )
        assert kind == "cron"
        assert expr == "0,30 9 * * *"


class TestParseSolar:
    def test_solar_lat_lon(self) -> None:
        kind, expr = parse_celery_beat_schedule(FakeSolar())
        assert kind == "solar"
        assert expr == "sunrise:40.7128:-74.006"

    def test_solar_latitude_longitude_alt_attrs(self) -> None:
        @dataclass
        class FakeSolarAlt:
            event: str = "sunset"
            latitude: float = 51.5
            longitude: float = -0.12

        kind, expr = parse_celery_beat_schedule(FakeSolarAlt())
        assert kind == "solar"
        assert expr == "sunset:51.5:-0.12"

    def test_solar_missing_event_raises(self) -> None:
        @dataclass
        class FakeSolarBad:
            event: str = ""
            lat: float = 0.0
            lon: float = 0.0

        with pytest.raises(UnsupportedScheduleError):
            parse_celery_beat_schedule(FakeSolarBad())


class TestParseTimedelta:
    def test_seconds(self) -> None:
        kind, expr = parse_celery_beat_schedule(dt.timedelta(seconds=30))
        assert kind == "interval"
        assert expr == "30"

    def test_minutes(self) -> None:
        kind, expr = parse_celery_beat_schedule(dt.timedelta(minutes=5))
        assert kind == "interval"
        assert expr == "300"

    def test_hours(self) -> None:
        kind, expr = parse_celery_beat_schedule(dt.timedelta(hours=1))
        assert kind == "interval"
        assert expr == "3600"

    def test_zero_or_negative_raises(self) -> None:
        with pytest.raises(UnsupportedScheduleError):
            parse_celery_beat_schedule(dt.timedelta(seconds=0))
        with pytest.raises(UnsupportedScheduleError):
            parse_celery_beat_schedule(dt.timedelta(seconds=-1))


class TestParseNumeric:
    def test_int_seconds(self) -> None:
        kind, expr = parse_celery_beat_schedule(60)
        assert kind == "interval"
        assert expr == "60"

    def test_float_seconds_truncated(self) -> None:
        kind, expr = parse_celery_beat_schedule(30.5)
        assert kind == "interval"
        assert expr == "30"

    def test_zero_raises(self) -> None:
        with pytest.raises(UnsupportedScheduleError):
            parse_celery_beat_schedule(0)

    def test_negative_raises(self) -> None:
        with pytest.raises(UnsupportedScheduleError):
            parse_celery_beat_schedule(-30)

    def test_bool_rejected_not_treated_as_int(self) -> None:
        # bool is a subclass of int in Python; we don't want
        # ``schedule=True`` to be accepted as "1 second."
        with pytest.raises(UnsupportedScheduleError):
            parse_celery_beat_schedule(True)


class TestParseUnsupported:
    def test_dict_raises(self) -> None:
        with pytest.raises(UnsupportedScheduleError) as exc:
            parse_celery_beat_schedule({"foo": "bar"})
        assert "dict" in str(exc.value)

    def test_none_raises(self) -> None:
        with pytest.raises(UnsupportedScheduleError):
            parse_celery_beat_schedule(None)


# ---------------------------------------------------------------------------
# parse_celery_beat_entries - full dict translator
# ---------------------------------------------------------------------------


class TestParseEntries:
    def test_typical_celery_beat_dict(self) -> None:
        entries = {
            "send-daily": {
                "task": "myapp.tasks.send_digest",
                "schedule": FakeCrontab(minute=0, hour=9),
                "args": [],
                "kwargs": {"date": "today"},
            },
            "every-30s": {
                "task": "myapp.tasks.heartbeat",
                "schedule": dt.timedelta(seconds=30),
            },
        }
        specs = parse_celery_beat_entries(entries)
        assert len(specs) == 2
        by_name = {s.name: s for s in specs}
        assert by_name["send-daily"].kind == "cron"
        assert by_name["send-daily"].expression == "0 9 * * *"
        assert by_name["send-daily"].kwargs == {"date": "today"}
        assert by_name["every-30s"].kind == "interval"
        assert by_name["every-30s"].expression == "30"

    def test_options_queue_extracted(self) -> None:
        entries = {
            "with-queue": {
                "task": "myapp.tasks.priority",
                "schedule": dt.timedelta(seconds=60),
                "options": {"queue": "high-priority"},
            },
        }
        specs = parse_celery_beat_entries(entries)
        assert len(specs) == 1
        assert specs[0].queue == "high-priority"

    def test_top_level_queue_also_extracted(self) -> None:
        entries = {
            "with-queue": {
                "task": "myapp.tasks.priority",
                "schedule": dt.timedelta(seconds=60),
                "queue": "high-priority",
            },
        }
        specs = parse_celery_beat_entries(entries)
        assert specs[0].queue == "high-priority"

    def test_entry_missing_task_skipped(self) -> None:
        entries = {
            "broken": {
                "schedule": dt.timedelta(seconds=30),
            },
        }
        specs = parse_celery_beat_entries(entries)
        assert specs == []

    def test_entry_missing_schedule_skipped(self) -> None:
        entries = {
            "broken": {
                "task": "myapp.tasks.foo",
            },
        }
        specs = parse_celery_beat_entries(entries)
        assert specs == []

    def test_entry_with_unsupported_schedule_skipped(self) -> None:
        # Successful entries still come through.
        entries = {
            "ok": {
                "task": "myapp.tasks.foo",
                "schedule": dt.timedelta(seconds=30),
            },
            "bad": {
                "task": "myapp.tasks.bar",
                "schedule": "not-a-cron",
            },
        }
        specs = parse_celery_beat_entries(entries)
        assert len(specs) == 1
        assert specs[0].name == "ok"

    def test_expires_warns_but_does_not_skip(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        entries = {
            "with-expires": {
                "task": "myapp.tasks.foo",
                "schedule": dt.timedelta(seconds=30),
                "options": {"expires": 60.0},
            },
        }
        specs = parse_celery_beat_entries(entries)
        assert len(specs) == 1
        # warning logged
        assert any(
            "expires" in r.message and "with-expires" in r.message
            for r in caplog.records
        )

    def test_returns_schedule_spec_instances(self) -> None:
        entries = {
            "x": {
                "task": "myapp.tasks.x",
                "schedule": dt.timedelta(seconds=30),
            },
        }
        specs = parse_celery_beat_entries(entries)
        assert len(specs) == 1
        assert isinstance(specs[0], ScheduleSpec)
        # Defaults
        assert specs[0].timezone == "UTC"
        assert specs[0].args == []
        assert specs[0].kwargs == {}
        assert specs[0].queue is None
