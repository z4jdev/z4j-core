"""Unit tests for the z4j-core exception hierarchy."""

from __future__ import annotations

import pytest

from z4j_core.errors import (
    AdapterError,
    AgentOfflineError,
    AuthenticationError,
    AuthorizationError,
    CommandTimeoutError,
    ConfigError,
    ConflictError,
    InvalidFrameError,
    NotFoundError,
    ProtocolError,
    RateLimitExceeded,
    RedactionConfigError,
    SignatureError,
    ValidationError,
    Z4JError,
)


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
        [
            (ValidationError, "validation_error", 422),
            (AuthenticationError, "unauthenticated", 401),
            (AuthorizationError, "forbidden", 403),
            (NotFoundError, "not_found", 404),
            (ConflictError, "conflict", 409),
            (RateLimitExceeded, "rate_limited", 429),
            (ProtocolError, "protocol_incompatible", 426),
            (InvalidFrameError, "invalid_frame", 400),
            (SignatureError, "invalid_signature", 401),
            (AdapterError, "adapter_error", 500),
            (AgentOfflineError, "agent_offline", 503),
            (CommandTimeoutError, "command_timeout", 504),
            (ConfigError, "config_error", 500),
            (RedactionConfigError, "redaction_config_error", 500),
        ],
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


class TestHierarchy:
    def test_all_subclass_z4j_error(self) -> None:
        classes = [
            ValidationError,
            AuthenticationError,
            AuthorizationError,
            NotFoundError,
            ConflictError,
            RateLimitExceeded,
            ProtocolError,
            InvalidFrameError,
            SignatureError,
            AdapterError,
            AgentOfflineError,
            CommandTimeoutError,
            ConfigError,
            RedactionConfigError,
        ]
        for cls in classes:
            assert issubclass(cls, Z4JError)

    def test_redaction_config_error_is_config_error(self) -> None:
        assert issubclass(RedactionConfigError, ConfigError)

    def test_from_clause_preserves_cause(self) -> None:
        cause = ValueError("original")
        try:
            try:
                raise cause
            except ValueError as exc:
                raise AdapterError("wrapped") from exc
        except AdapterError as err:
            assert err.__cause__ is cause
