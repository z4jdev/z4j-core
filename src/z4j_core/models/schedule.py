"""Schedule domain model.

A :class:`Schedule` is a periodic or one-shot trigger that fires a
task at configured times. In Celery terms: a row in
``django_celery_beat.PeriodicTask`` or an entry in
``celery_app.conf.beat_schedule``.

z4j-owned schedules can be created and controlled through the dashboard.
Externally owned schedules may instead be observed or require an explicit
activation ceremony, and each adapter advertises which operations it supports.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import (
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
)

from z4j_core.models._base import Z4JModel


class ScheduleKind(StrEnum):
    """How a schedule's firing times are defined.

    - ``cron`` - standard five-field cron expression (or six-field
      with seconds, if the adapter supports it).
    - ``interval`` - repeat at the duration encoded by the expression.
    - ``solar`` - tied to an astronomical event (sunrise, sunset, ...).
    - ``clocked`` - fire once at a specific timestamp.
    """

    CRON = "cron"
    INTERVAL = "interval"
    SOLAR = "solar"
    CLOCKED = "clocked"


class CatchUpPolicy(StrEnum):
    """How z4j-scheduler treats a schedule whose fire was missed.

    Matches the ``catch_up`` column on brain's ``schedules`` table
    and the policy applied by the pending-fires replay worker.

    - ``skip`` - the missed fire is dropped; only the next on-time
      fire runs. The safest default and what every importer
      defaults to.
    - ``fire_one_missed`` - one catch-up fire is issued for the
      most recently missed slot, then on-time firing resumes.
      Useful for daily reports where you want yesterday's report
      run after a brief outage but don't want to flood the queue.
    - ``fire_all_missed`` - every missed slot inside the catch-up
      window is fired in sequence. Use with care: a 12-hour outage
      on a per-minute schedule produces 720 fires.
    """

    SKIP = "skip"
    FIRE_ONE_MISSED = "fire_one_missed"
    FIRE_ALL_MISSED = "fire_all_missed"


class OverlapPolicy(StrEnum):
    """What to do when a schedule comes due while its last run is still going.

    **Only ``allow`` is implemented. ``skip`` and ``queue`` are declared here
    for a future release and are refused if you set them.**

    That refusal is deliberate and it is the whole reason this docstring says
    so first. Nothing in the scheduler's dispatch or tick path reads this
    field, and the external-schedule normalization drops it, so a schedule
    that asked for ``skip`` would have run concurrently anyway. A safety
    control that silently does nothing is worse than no control at all: the
    person who set it stops looking for the problem. Until enforcement lands,
    setting a value this release cannot honour fails loudly.

    The situation it will eventually describe is ordinary and usually
    unplanned: a nightly job that normally takes ten minutes takes seventy,
    and the scheduler arrives with the next one. Whether that is fine or
    catastrophic depends entirely on the task, which is why it belongs per
    schedule rather than as a global setting.

    - ``allow`` - fire regardless. The historical behaviour and the only
      implemented one, so it stays the default: an upgrade must not silently
      start withholding fires an operator was relying on.
    - ``skip`` - **not implemented.** Would not fire while a previous run is
      still in flight, recording the slot as skipped rather than dropping it
      in silence.
    - ``queue`` - **not implemented.** Would fire only after the running one
      finishes, so runs serialize instead of overlapping.

    If you need overlap protection today, take a lock in the task itself.
    """

    ALLOW = "allow"
    SKIP = "skip"
    QUEUE = "queue"


def _unimplemented_overlap_message(value: object) -> str:
    """The refusal text, shared by every door.

    Takes ``object`` rather than ``OverlapPolicy`` on purpose: the unvalidated
    doors (``model_construct``) receive whatever the caller passed, and a
    round-tripped ``model_dump(mode="json")`` carries the plain string
    ``"allow"``. Assuming the enum here is what made a VALID serialized
    schedule raise ``AttributeError: 'str' object has no attribute 'value'``.
    """
    raw = value.value if isinstance(value, OverlapPolicy) else value
    return (
        f"overlap_policy={raw!r} is not implemented in this release "
        f"and would be silently ignored, so it is refused rather than "
        f"accepted. Only {OverlapPolicy.ALLOW.value!r} is honoured; take a "
        f"lock inside the task if you need overlap protection today."
    )


def refuse_unimplemented_overlap(value: object) -> None:
    """Refuse anything but ``allow``, whatever shape the value arrives in.

    Compared BY VALUE, not by identity. Identity works only when the caller
    handed over a real enum member, and the doors that skip validation are
    exactly the ones where they may not have: ``model_construct`` takes the
    caller's dict verbatim, so a schedule round-tripped through
    ``model_dump(mode="json")`` arrives carrying the string ``"allow"``.
    """
    if value is None:
        return
    raw = value.value if isinstance(value, OverlapPolicy) else value
    if raw != OverlapPolicy.ALLOW.value:
        raise ValueError(_unimplemented_overlap_message(value))


class Schedule(Z4JModel):
    """A periodic or one-shot task trigger.

    Attributes:
        id: Brain-assigned UUID.
        project_id: Project this schedule belongs to.
        engine: Engine adapter this schedule fires tasks on
                (``celery``, ``rq``, ...).
        scheduler: Scheduler adapter managing this schedule
                   (``celery-beat``, ``apscheduler``, ...).
        name: Human-readable schedule name. Unique per
              ``(project, scheduler)``.
        task_name: Fully-qualified name of the task the schedule fires.
        kind: How firing times are defined.
        expression: Engine-native schedule expression.
                    For ``cron`` this is a cron string like
                    ``"0 3 * * *"``. For ``interval`` it is an integer
                    seconds count. For ``clocked`` it is an ISO8601
                    timestamp. For ``solar`` it is the event name.
        timezone: IANA timezone the expression is evaluated in.
        queue: Queue to route fired tasks to, if overridden.
        args: Positional arguments passed to the task on each fire.
        kwargs: Keyword arguments passed to the task on each fire.
        is_enabled: If False, the schedule exists but does not fire.
        last_run_at: Timestamp of the most recent fire, if any.
        next_run_at: Predicted next-fire timestamp, if computable.
        total_runs: Lifetime count of times this schedule has fired.
        external_id: Optional pointer back to the underlying system's
                     identifier (e.g. ``django_celery_beat.PeriodicTask.id``
                     as a string). Opaque to z4j.
        metadata: Adapter-specific extension data.
        catch_up: Policy applied when a fire was missed (process down,
                  leadership changeover, paused project). Honored by
                  z4j-scheduler's pending-fires replay worker.
        overlap_policy: What to do when the schedule comes due while a
                        previous run is still in flight. Defaults to
                        ``allow``, which is the historical behaviour.
        source: Surface that created/owns this schedule. Used by the
                dashboard to render a "managed by" badge and by
                declarative reconciliation to scope the
                replace-for-source delete set. Common values:
                ``dashboard``, ``imported``, ``declarative:django``,
                ``declarative:fastapi``, ``declarative:flask``.
        source_hash: Producer-defined content hash used by importers and
                     declarative reconcilers for re-import idempotency. The
                     exact covered fields depend on the producer's contract.
                     ``None`` for schedules created via the dashboard
                     where there is no upstream source state to diff
                     against.
        created_at: Brain-side insert time.
        updated_at: Brain-side last-modified time.
    """

    id: UUID
    project_id: UUID
    engine: str = Field(min_length=1, max_length=40)
    scheduler: str = Field(min_length=1, max_length=40)
    name: str = Field(min_length=1, max_length=200)
    task_name: str = Field(min_length=1, max_length=500)
    kind: ScheduleKind
    expression: str = Field(min_length=1, max_length=200)
    timezone: str = Field(default="UTC", max_length=100)
    queue: str | None = Field(default=None, max_length=200)
    args: list[Any] = Field(default_factory=list)
    kwargs: dict[str, Any] = Field(default_factory=dict)
    is_enabled: bool = True
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    total_runs: int = Field(default=0, ge=0)
    external_id: str | None = Field(default=None, max_length=200)
    metadata: dict[str, Any] = Field(default_factory=dict)
    catch_up: CatchUpPolicy = CatchUpPolicy.SKIP
    # validate_default so the refusal also covers a SUBCLASS that changes the
    # default. Pydantic does not validate defaults unless asked, so
    # ``class Mine(Schedule): overlap_policy = OverlapPolicy.SKIP`` produced an
    # instance the field validator never saw, which then reached the writable
    # celery-beat source and came back reporting ``allow``. That is the same
    # silent non-enforcement this guard exists to prevent, through a door the
    # first four fixes did not consider.
    overlap_policy: OverlapPolicy = Field(
        default=OverlapPolicy.ALLOW,
        validate_default=True,
    )

    def model_post_init(self, __context: Any) -> None:
        """Refuse an unimplemented policy on every instance this class builds.

        DEFENCE IN DEPTH, NOT THE AUTHORITY. A subclass can override this hook
        and omit the ``super()`` call, and there is no hook on a Python class
        that a subclass cannot override -- seven attempts at guarding the model
        established that the hard way. What this catches is the ordinary
        mistake, early, with a message naming the alternative. What it cannot
        catch is a caller who has taken the model apart.

        The enforceable boundary is the ADAPTER that would persist the value:
        see ``refuse_unimplemented_overlap`` in the celery-beat source's write
        paths. A user subclass of ``Schedule`` cannot reach inside that.

        This replaces a ``__pydantic_init_subclass__`` hook that inspected the
        subclass's declared default. That hook was the wrong altitude, and it
        took two rounds to see why: a subclass REDECLARING the field also drops
        the parent's ``validate_default``, and the declaration it leaves behind
        can be a ``default_factory`` -- which reads as ``PydanticUndefined`` at
        class-definition time, tells you nothing, and produces ``skip`` at
        construction with no validator in the path. Guarding the declaration
        meant reasoning about every shape a declaration can take; guarding the
        instance means reading the value that actually exists.

        ``model_post_init`` runs after validation for ordinary construction AND
        after ``model_construct``, so it covers the field validator's cases,
        every subclass default shape, and the documented validation-skipping
        escape hatch, with one check. ``model_copy`` and ``copy`` do NOT invoke
        it, which is why those two keep their own explicit guards below.

        The failure it prevents: a Schedule carrying ``skip`` reaches the
        writable celery-beat source, which persists the other fields and maps
        back to a schedule reporting ``allow``. The caller asked for collision
        prevention, was told it was applied, and gets concurrent runs.
        """
        super().model_post_init(__context)
        refuse_unimplemented_overlap(getattr(self, "overlap_policy", None))

    def model_copy(self, *, update: Any = None, deep: bool = False) -> Schedule:
        """Copy, then validate. ``model_copy`` normally skips validation.

        That skip is the hole two previous attempts at this failed to close.
        Refusing in the field validator caught construction; refusing in the
        serializer caught anything written to the wire. Neither caught
        ``model_copy(update={"overlap_policy": OverlapPolicy.SKIP})``, and the
        writable Django celery-beat source persists a Schedule's attributes
        directly without ever serializing it, so a caller could create a
        schedule asking for collision prevention, receive ``allow`` back, and
        get concurrent runs with nothing to tell them.

        Validating the copy closes it at the type rather than at each write
        path, so a route added later cannot reopen it. There is exactly one
        ``model_copy`` call site in the codebase and it is on another model, so
        the cost of validating here is not on any hot path.
        """
        copied = super().model_copy(update=update, deep=deep)
        # getattr, because ``include=``/``exclude=`` produce a PARTIAL model
        # that may not carry this field at all. Reading it directly raised
        # AttributeError on a copy pydantic documents as valid.
        refuse_unimplemented_overlap(getattr(copied, "overlap_policy", None))
        return copied

    def copy(self, **kwargs: Any) -> Schedule:
        """The pydantic v1 alias. It does NOT route through ``model_copy``.

        Overriding ``model_copy`` alone left this open, which is the third time
        this guard has been closed at one door and not the others. ``copy`` is
        deprecated but present and callable, and it takes the same ``update=``
        argument, so it reached the writable Django celery-beat source exactly
        as ``model_copy`` did.
        """
        copied = super().copy(**kwargs)
        refuse_unimplemented_overlap(getattr(copied, "overlap_policy", None))
        return copied

    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> Schedule:
        """``model_construct`` exists to skip validation. Do not let it skip THIS.

        It is the documented escape hatch for trusted data, so overriding it is
        deliberate and narrow: only the overlap refusal is re-applied, because
        that rule is not a validation convenience but a statement that the
        feature is unimplemented. A Schedule carrying ``skip`` reaching the
        Django source is persisted with its other fields and returns ``allow``
        to the caller, so they asked for collision prevention, were told it was
        applied, and get concurrent runs.
        """
        built = super().model_construct(*args, **kwargs)
        refuse_unimplemented_overlap(getattr(built, "overlap_policy", None))
        return built

    @model_serializer(mode="wrap")
    def _refuse_unimplemented_overlap_policy_on_the_wire(
        self,
        handler: SerializerFunctionWrapHandler,
    ) -> dict[str, Any]:
        """Refuse an unimplemented policy on the way out, not only on the way in.

        The field validator below catches construction. It does not catch
        ``model_copy(update=...)``, which is the normal way to change a frozen
        pydantic model and skips validation entirely, so a caller could hold a
        Schedule carrying ``skip`` and serialize it. The value would then be
        dropped by external-schedule normalization and the row would keep
        ``allow``: the original silent failure, reached by the ordinary update
        path rather than the constructor.

        Serialization is the boundary every route out crosses, so the refusal
        goes here as well. Two checks for one rule is deliberate: the
        constructor's message is the one a caller wants, and this one is the
        one they cannot go around.
        """
        # getattr for the same reason as model_copy: serializing a partial
        # copy that omits this field must not raise. ``None`` means "not
        # present", which the check treats as nothing to refuse.
        refuse_unimplemented_overlap(getattr(self, "overlap_policy", None))
        serialized: dict[str, Any] = handler(self)
        return serialized

    @field_validator("overlap_policy")
    @classmethod
    def _refuse_unimplemented_overlap_policy(cls, value: OverlapPolicy) -> OverlapPolicy:
        """Refuse a policy this release cannot honour.

        See :class:`OverlapPolicy`. Accepting ``skip`` here and then running
        the job concurrently is the failure mode worth preventing: the caller
        chose a collision-prevention policy, got no collision prevention, and
        had nothing to tell them.
        """
        refuse_unimplemented_overlap(value)
        return value

    source: str = Field(default="dashboard", min_length=1, max_length=64)
    source_hash: str | None = Field(default=None, max_length=128)
    created_at: datetime
    updated_at: datetime


__all__ = [
    "CatchUpPolicy",
    "OverlapPolicy",
    "Schedule",
    "ScheduleKind",
    "refuse_unimplemented_overlap",
]
