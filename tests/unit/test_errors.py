"""Unit tests for the z4j-core exception hierarchy."""

from __future__ import annotations

import pytest
from z4j_core import errors
from z4j_core.errors import (
    AdapterError,
    AgentIncompatibleError,
    AgentOfflineError,
    AuthenticationError,
    AuthorizationError,
    BufferStorageError,
    CommandTimeoutError,
    ConfigError,
    ConflictError,
    InvalidFrameError,
    NotFoundError,
    ProtocolError,
    ProtocolVersionError,
    RateLimitExceeded,
    RedactionConfigError,
    SignatureError,
    ValidationError,
    Z4JError,
)

#: Every exception class this module defines, with the machine code and HTTP
#: status it publishes.
#:
#: ``Z4JError.code`` promises to be stable across releases, and ``docs/API.md
#: §1.Errors`` publishes the strings, so a consumer is entitled to branch on
#: one. Changing a row here is therefore a breaking change for that consumer,
#: and a uniquely quiet one: an ``except`` clause goes on matching while the
#: string it dispatches on stops, so neither a type checker nor a test suite
#: that only checks the class reports anything. Editing a row must be a
#: deliberate act, which is what this table makes it.
#:
#: Two classes intentionally share ``protocol_incompatible``; see
#: ``test_the_incompatible_subclass_did_not_rename_the_condition``.
PUBLISHED_CODES: dict[type[Z4JError], tuple[str, int]] = {
    Z4JError: ("z4j_error", 500),
    ValidationError: ("validation_error", 422),
    AuthenticationError: ("unauthenticated", 401),
    AuthorizationError: ("forbidden", 403),
    NotFoundError: ("not_found", 404),
    ConflictError: ("conflict", 409),
    RateLimitExceeded: ("rate_limited", 429),
    ProtocolError: ("protocol_incompatible", 426),
    AgentIncompatibleError: ("protocol_incompatible", 426),
    ProtocolVersionError: ("protocol_version_mismatch", 426),
    InvalidFrameError: ("invalid_frame", 400),
    SignatureError: ("invalid_signature", 401),
    AdapterError: ("adapter_error", 500),
    AgentOfflineError: ("agent_offline", 503),
    CommandTimeoutError: ("command_timeout", 504),
    ConfigError: ("config_error", 500),
    RedactionConfigError: ("redaction_config_error", 500),
    BufferStorageError: ("buffer_storage_error", 500),
}


class TestBaseException:
    def test_message_is_preserved(self) -> None:
        err = Z4JError("something broke")
        assert str(err) == "something broke"
        assert err.message == "something broke"

    def test_details_default_to_empty_dict(self) -> None:
        err = Z4JError("x")
        assert err.details == {}

    def test_details_are_copied_from_input(self) -> None:
        original = {"foo": "bar"}
        err = Z4JError("x", details=original)
        assert err.details == {"foo": "bar"}
        # Ensure the input was copied - mutation must not affect the error.
        original["foo"] = "changed"
        assert err.details == {"foo": "bar"}

    def test_repr_includes_code_and_message(self) -> None:
        err = NotFoundError("missing")
        r = repr(err)
        assert "NotFoundError" in r
        assert "not_found" in r
        assert "missing" in r

    def test_to_dict_shape(self) -> None:
        err = ValidationError("bad", details={"field": "name"})
        d = err.to_dict()
        assert d == {
            "error": "validation_error",
            "message": "bad",
            "details": {"field": "name"},
        }


class TestCodes:
    """Error codes are stable and must not change silently."""

    @pytest.mark.parametrize(
        ("exc_cls", "code", "status"),
        [(cls, code, status) for cls, (code, status) in PUBLISHED_CODES.items()],
        ids=[cls.__name__ for cls in PUBLISHED_CODES],
    )
    def test_code_and_status(
        self,
        exc_cls: type[Z4JError],
        code: str,
        status: int,
    ) -> None:
        err = exc_cls("x")
        assert err.code == code
        assert err.http_status == status
        # The serialized form is what actually crosses the wire to a consumer,
        # so pin that too rather than only the attribute behind it.
        assert err.to_dict()["error"] == code

    def test_every_error_class_in_the_module_is_pinned(self) -> None:
        """The table has to be exhaustive or it does not enforce anything.

        A hand-maintained list only guards the classes somebody remembered to
        add. A new subclass is precisely the case that needs guarding -- it is
        the one that can arrive carrying a code nobody chose deliberately --
        and a list it is absent from waves it straight through.
        """
        declared = {
            obj
            for obj in vars(errors).values()
            if isinstance(obj, type)
            and issubclass(obj, Z4JError)
            and obj.__module__ == errors.__name__
        }

        assert declared - set(PUBLISHED_CODES) == set(), (
            "a Z4JError subclass has no pinned code. Add it to PUBLISHED_CODES "
            "with the code and status it should publish, and check that the "
            "code is one the release is prepared to keep forever."
        )

    def test_the_incompatible_subclass_did_not_rename_the_condition(self) -> None:
        """Sharing this code with the parent is the deliberate part.

        ``AgentIncompatibleError`` exists so a supervisor can pick a backoff
        schedule by exception type. The condition it reports is the same
        protocol incompatibility the parent reports, and the code is what a
        consumer branches on, so giving it a distinct one would have broken
        every such consumer while ``except ProtocolError`` carried on matching.
        A break nothing reports is the kind that reaches users.
        """
        assert AgentIncompatibleError.code == ProtocolError.code
        assert AgentIncompatibleError.code == "protocol_incompatible"

    def test_a_code_is_never_blank_or_padded(self) -> None:
        """Read off the classes, not off the table above.

        A code is compared by equality in consumer code and rendered into JSON,
        so a stray space or an empty string is a break that looks like nothing
        in a diff. Asserting the table's own literals here would only prove the
        table agrees with itself.
        """
        for cls in PUBLISHED_CODES:
            assert cls.code, cls.__name__
            assert cls.code == cls.code.strip(), cls.__name__


class TestHierarchy:
    def test_all_subclass_z4j_error(self) -> None:
        for cls in PUBLISHED_CODES:
            assert issubclass(cls, Z4JError)

    def test_redaction_config_error_is_config_error(self) -> None:
        assert issubclass(RedactionConfigError, ConfigError)

    def test_buffer_storage_error_is_config_error(self) -> None:
        assert issubclass(BufferStorageError, ConfigError)

    @pytest.mark.parametrize(
        "cls",
        [AgentIncompatibleError, ProtocolVersionError],
        ids=lambda cls: cls.__name__,
    )
    def test_the_protocol_subclasses_stay_catchable_as_protocol_error(
        self,
        cls: type[Z4JError],
    ) -> None:
        """Both were introduced to be DISTINGUISHABLE, not to be uncatchable.

        Callers wrote ``except ProtocolError`` against the base class; a
        subclass that stopped matching it would route a handled condition into
        whatever generic handler sits above, which is a behaviour change no
        caller asked for and none would see coming.
        """
        assert issubclass(cls, ProtocolError)
        assert cls is not ProtocolError

    def test_from_clause_preserves_cause(self) -> None:
        cause = ValueError("original")
        try:
            try:
                raise cause
            except ValueError as exc:
                raise AdapterError("wrapped") from exc
        except AdapterError as err:
            assert err.__cause__ is cause
