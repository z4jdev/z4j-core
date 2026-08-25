"""A safety control must work or refuse, never accept and do nothing.

``overlap_policy`` arrived with 1.9's schedule-control columns. The public model
documented ``skip`` as the right choice "for jobs that are not safe to run
concurrently", and the adapter contract accepted it on writes. Nothing enforced
it: no dispatch or tick path in the scheduler reads the field, and
``z4j_core.schedule_external`` normalization drops it before the brain ever
sees it, so the row kept the ``allow`` default.

A caller who chose collision prevention got none, and nothing told them. That is
worse than not offering the option, because it stops them looking for the
problem, and it is worse than the previous release, where the field did not
exist and could not mislead anyone.

Until enforcement lands, the values this release cannot honour are refused.
"""

from __future__ import annotations

import warnings
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError
from z4j_core.models.schedule import OverlapPolicy, Schedule, ScheduleKind


def _schedule(**overrides: object) -> Schedule:
    base: dict[str, object] = {
        "id": uuid4(),
        "project_id": uuid4(),
        "engine": "celery",
        "scheduler": "z4j-scheduler",
        "name": "cleanup",
        "task_name": "jobs.cleanup",
        "kind": ScheduleKind.INTERVAL,
        "expression": "5m",
        "timezone": "UTC",
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }
    base.update(overrides)
    return Schedule(**base)  # type: ignore[arg-type]


def test_the_default_is_allow_and_stays_accepted() -> None:
    """The historical behaviour keeps working, unset or explicit.

    An upgrade must not start refusing schedules that never asked for
    anything, nor ones that named the policy they were already getting.
    """
    assert _schedule().overlap_policy is OverlapPolicy.ALLOW
    assert _schedule(overlap_policy=OverlapPolicy.ALLOW).overlap_policy is OverlapPolicy.ALLOW


@pytest.mark.parametrize("policy", [OverlapPolicy.SKIP, OverlapPolicy.QUEUE])
def test_an_unimplemented_policy_is_refused_rather_than_ignored(policy: OverlapPolicy) -> None:
    """The failure this prevents: asking for skip and getting concurrent runs."""
    with pytest.raises(ValidationError) as caught:
        _schedule(overlap_policy=policy)
    message = str(caught.value)
    assert "not implemented" in message
    assert policy.value in message


def test_the_refusal_says_what_to_do_instead() -> None:
    """An error that only says no costs the reader a support round trip."""
    with pytest.raises(ValidationError) as caught:
        _schedule(overlap_policy=OverlapPolicy.SKIP)
    assert "lock inside the task" in str(caught.value)


def test_nothing_in_the_shipped_scheduler_reads_the_field() -> None:
    """The premise, asserted rather than assumed.

    If enforcement ever lands, this test fails and whoever landed it removes
    the refusal above. That is the intended way for this to be retired: by
    the code that makes it untrue, not by someone deciding it looks stale.
    """
    from pathlib import Path

    scheduler_src = Path(__file__).resolve().parents[3] / "z4j-scheduler" / "src"
    if not scheduler_src.is_dir():
        pytest.skip("z4j-scheduler source is not in this checkout layout")

    readers = [
        f"{path.name}:{ln}"
        for path in scheduler_src.rglob("*.py")
        for ln, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if "overlap_policy" in line
    ]
    assert readers == [], (
        "the scheduler now reads overlap_policy, so it may be enforced. If it "
        f"is, delete the refusal in z4j_core.models.schedule: {readers}"
    )


def test_the_serializer_backstop_is_now_unreachable_and_kept_anyway() -> None:
    """The serializer refusal is defence in depth; no route still reaches it.

    This test used to CONSTRUCT the smuggled object and assert only that
    serializing it refused -- which is to say it proved the bad object could
    exist and then checked one of the several things that might touch it. That
    is the wrong shape, because the public adapter forwards a Schedule to the
    writable Django source WITHOUT serializing it, so the serializer guard
    never ran on the path that mattered.

    Every construction door now refuses (see
    ``TestEveryConstructionPathRefuses``), so no smuggled object exists to
    serialize. The serializer check stays as a backstop for a door added
    later, and this test pins the property that actually holds now: the
    supported policy serializes, and the unsupported one cannot be built to
    begin with.
    """
    import pytest

    with pytest.raises((ValidationError, ValueError)):
        Schedule.model_construct(
            **{**_schedule().model_dump(), "overlap_policy": OverlapPolicy.SKIP},
        )

    # The backstop itself, exercised directly rather than through an object
    # the type system no longer permits.
    allowed = _schedule()
    assert allowed.model_dump()["overlap_policy"] == OverlapPolicy.ALLOW.value


def test_an_allow_schedule_still_serializes_both_ways() -> None:
    """The refusal must not cost the supported case."""
    schedule = _schedule()
    assert schedule.model_dump()["overlap_policy"] == "allow"
    assert '"allow"' in schedule.model_dump_json()


def test_model_copy_validates_so_the_bad_state_cannot_exist() -> None:
    """Two earlier attempts guarded the wrong boundaries.

    The field validator caught construction. The serializer caught anything
    written to the wire. Neither caught ``model_copy(update=...)``, which is
    how a frozen pydantic model is normally changed and which skips validation
    entirely, and the writable Django celery-beat source persists a Schedule's
    attributes directly without ever serializing it. So a caller could create a
    schedule asking for collision prevention, get ``allow`` back, and run
    concurrently with nothing to tell them.

    Closed at the type instead of at each write path, because "every route out"
    was the premise of the previous fix and it was false.
    """
    import pytest

    # ValueError, not ValidationError. The doors that run pydantic's
    # validation raise ValidationError (which IS a ValueError); the doors that
    # bypass it -- model_copy, copy, model_construct, the subclass hook --
    # raise the guard's own ValueError, because there is no validation pass to
    # wrap it. ``except ValueError`` catches every door, which is the contract
    # worth having.
    with pytest.raises(ValueError, match="not implemented"):
        _schedule().model_copy(update={"overlap_policy": OverlapPolicy.SKIP})


def test_model_copy_still_works_for_everything_else() -> None:
    """Validating the copy must not break the ordinary use of it."""
    original = _schedule()
    assert original.model_copy().name == original.name
    assert original.model_copy(update={"name": "renamed"}).name == "renamed"
    assert original.model_copy(update={"overlap_policy": OverlapPolicy.ALLOW}).overlap_policy is (
        OverlapPolicy.ALLOW
    )


def test_a_write_path_that_never_serializes_cannot_receive_a_bad_policy() -> None:
    """The end-to-end shape of the reported bypass, without Django.

    The reporter's reproduction went through the celery-beat Django source,
    which takes a Schedule and writes its attributes. What made that reachable
    was the existence of a Schedule carrying ``skip``. Assert that no such
    object can be produced by any of the three routes, so a write path that
    never serializes has nothing bad to receive.
    """
    import pytest
    from pydantic import ValidationError

    # ValueError throughout: ValidationError is a ValueError, and the doors
    # that bypass validation raise the guard's own ValueError, so this is the
    # one type that covers every route.
    with pytest.raises(ValueError):
        _schedule(overlap_policy=OverlapPolicy.SKIP)  # construction
    with pytest.raises(ValueError):
        _schedule().model_copy(update={"overlap_policy": OverlapPolicy.SKIP})  # copy
    with pytest.raises(ValidationError):
        Schedule.model_validate({**_schedule().model_dump(), "overlap_policy": "skip"})


def _via_deprecated_copy(schedule: Schedule, update: dict[str, object]) -> Schedule:
    """Call the v1 ``copy`` alias with its deprecation warning suppressed.

    This repo promotes warnings to errors, so ``copy()`` raises
    PydanticDeprecatedSince20 before reaching the guard -- which would make the
    refusal test pass for entirely the wrong reason, and the control test fail.
    User code has no such filter, so the door is real for them; suppress only
    the deprecation so what is asserted is the guard.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return schedule.copy(update=update)


def _via_deprecated_copy_kwargs(schedule: Schedule, **kwargs: object) -> Schedule:
    """``copy`` with arbitrary kwargs, deprecation warning suppressed."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return schedule.copy(**kwargs)


class TestEveryConstructionPathRefuses:
    """Four doors, not one. Three previous attempts closed a subset.

    The refusal is not a validation convenience: ``overlap_policy`` is
    documented as the way to stop a slow job overlapping itself, and nothing
    implements it. A Schedule carrying ``skip`` that reaches the writable
    Django celery-beat source is persisted with its other fields and returns
    ``allow`` to the caller, so an operator asks for collision prevention, is
    told it was applied, and gets concurrent runs with nothing to tell them.

    Closed in the field validator (construction), then the serializer (the
    wire), then ``model_copy``. Each time the remaining doors stayed open --
    ``copy(update=...)`` is the deprecated v1 alias and does NOT route through
    ``model_copy``, and ``model_construct`` exists precisely to skip
    validation. Both reach the adapter, which forwards the object without
    serializing it, so the serializer guard never runs.

    This parametrizes the doors so a new one cannot be added without a test.
    """

    @pytest.mark.parametrize(
        "door",
        ["constructor", "model_copy", "copy_v1_alias", "model_construct"],
    )
    @pytest.mark.parametrize("policy", [OverlapPolicy.SKIP, OverlapPolicy.QUEUE])
    def test_no_construction_path_yields_an_unimplemented_policy(
        self,
        door: str,
        policy: OverlapPolicy,
    ) -> None:
        base = _schedule()
        makers: dict[str, Callable[[], Schedule]] = {
            "constructor": lambda: _schedule(overlap_policy=policy),
            "model_copy": lambda: base.model_copy(update={"overlap_policy": policy}),
            "copy_v1_alias": lambda: _via_deprecated_copy(
                base,
                {"overlap_policy": policy},
            ),
            "model_construct": lambda: Schedule.model_construct(
                **{**dict(base), "overlap_policy": policy},
            ),
        }
        with pytest.raises((ValidationError, ValueError)):
            built = makers[door]()
            # If it did not raise, say what escaped rather than failing on a
            # bare "DID NOT RAISE" -- the object itself is the finding.
            msg = (
                f"{door} produced a Schedule carrying overlap_policy="
                f"{built.overlap_policy}, which nothing implements; the "
                "writable Django source would persist it and return allow"
            )
            raise AssertionError(msg)

    @pytest.mark.parametrize(
        "door",
        ["constructor", "model_copy", "copy_v1_alias", "model_construct"],
    )
    def test_the_default_policy_still_works_on_every_path(self, door: str) -> None:
        # Guards the guard: a refusal that also broke ordinary construction
        # would be caught here rather than in the field it protects.
        base = _schedule()
        makers: dict[str, Callable[[], Schedule]] = {
            "constructor": lambda: _schedule(),  # noqa: PLW0108 - keeps the dict homogeneous
            "model_copy": lambda: base.model_copy(update={"name": "other"}),
            "copy_v1_alias": lambda: _via_deprecated_copy(base, {"name": "other"}),
            "model_construct": lambda: Schedule.model_construct(**dict(base)),
        }
        assert makers[door]().overlap_policy is OverlapPolicy.ALLOW


def _base_without_overlap() -> dict[str, Any]:
    """Constructor kwargs that OMIT overlap_policy, so a default can fire.

    ``dict(_schedule())`` carries ``overlap_policy: allow`` from the instance,
    which means a subclass default is never consulted and a test using it
    asserts nothing about that default. That is the same wrong-input-shape
    mistake as passing ``dict(base)`` where production sends
    ``model_dump(mode="json")``.
    """
    return {k: v for k, v in dict(_schedule()).items() if k != "overlap_policy"}


class TestTheGuardDoesNotBreakValidUse:
    """Two regressions the guard itself introduced, plus the fifth door.

    The first version of this fix reached for whole-model revalidation where a
    targeted check was needed, and compared by identity where the value may not
    be an enum at all. Both broke ordinary, documented pydantic behaviour:

    - ``model_construct(**s.model_dump(mode="json"))`` carries the STRING
      ``"allow"``, so an identity comparison against the enum failed and the
      error path called ``.value`` on a str -- a valid serialized schedule
      raised AttributeError. The earlier test used ``dict(base)``, which
      preserves the enum, so it certified the wrong input shape.
    - ``copy(include=..., update=...)`` is a documented partial copy.
      Revalidating the whole result raised nine missing-field errors where 1.8
      returned the partial object.

    The guard now checks one field by value and validates nothing else, which
    is all it was ever entitled to do.
    """

    def test_a_json_round_tripped_schedule_can_be_reconstructed(self) -> None:
        original = _schedule()
        payload = original.model_dump(mode="json")
        assert payload["overlap_policy"] == "allow", "precondition: a plain string"
        rebuilt = Schedule.model_construct(**payload)
        assert rebuilt.overlap_policy == OverlapPolicy.ALLOW

    def test_a_json_round_tripped_bad_policy_is_still_refused(self) -> None:
        # The string form must not become a way around the refusal either.
        payload = {**_schedule().model_dump(mode="json"), "overlap_policy": "skip"}
        with pytest.raises(ValueError, match="not implemented"):
            Schedule.model_construct(**payload)

    def test_a_partial_copy_still_works(self) -> None:
        original = _schedule()
        partial = _via_deprecated_copy_kwargs(
            original,
            include={"name", "overlap_policy"},
            update={"name": "renamed"},
        )
        assert partial.name == "renamed"

    @pytest.mark.parametrize("shape", ["literal", "default_factory"])
    def test_a_subclass_cannot_default_to_an_unimplemented_policy(
        self,
        shape: str,
    ) -> None:
        """A subclass default must not smuggle an unimplemented policy in.

        Refused at CONSTRUCTION, not at class definition. An earlier fix hooked
        ``__pydantic_init_subclass__`` and inspected the declared default, which
        was the wrong altitude twice over: it rejected shapes 1.8 accepted
        (a required redeclaration reads as ``PydanticUndefined``), and then,
        once taught to skip that sentinel, it stopped seeing
        ``default_factory`` -- which also reads as ``PydanticUndefined`` at
        definition time and produces ``skip`` at construction with no validator
        in the path, because redeclaring the field drops the parent's
        ``validate_default``.

        ``model_post_init`` reads the value that actually exists on the
        instance, so the shape of the declaration stops mattering.
        """
        from pydantic import Field as _Field

        if shape == "literal":

            class _Sneaky(Schedule):
                overlap_policy: OverlapPolicy = OverlapPolicy.SKIP

            sneaky: type[Schedule] = _Sneaky
        else:

            class _SneakyFactory(Schedule):
                overlap_policy: OverlapPolicy = _Field(
                    default_factory=lambda: OverlapPolicy.SKIP,
                )

            sneaky = _SneakyFactory

        with pytest.raises(ValueError, match="not implemented"):
            sneaky(**_base_without_overlap())

    @pytest.mark.parametrize("shape", ["literal", "default_factory", "required"])
    def test_subclass_shapes_that_only_ever_yield_allow_are_untouched(
        self,
        shape: str,
    ) -> None:
        # The guard against over-reach: each of these is a shape 1.8 accepted,
        # and one of them (required) was rejected by the first version of this
        # fix at import time.
        from pydantic import Field as _Field

        if shape == "literal":

            class _A(Schedule):
                overlap_policy: OverlapPolicy = OverlapPolicy.ALLOW

            built: Schedule = _A(**_base_without_overlap())
        elif shape == "default_factory":

            class _B(Schedule):
                overlap_policy: OverlapPolicy = _Field(
                    default_factory=lambda: OverlapPolicy.ALLOW,
                )

            built = _B(**_base_without_overlap())
        else:

            class _C(Schedule):
                overlap_policy: OverlapPolicy

            built = _C(**_base_without_overlap(), overlap_policy=OverlapPolicy.ALLOW)

        assert built.overlap_policy is OverlapPolicy.ALLOW

    def test_an_ordinary_subclass_is_untouched(self) -> None:
        # The refusal must not make Schedule unsubclassable.
        class _Fine(Schedule):
            pass

        assert _Fine(**dict(_schedule())).overlap_policy is OverlapPolicy.ALLOW
