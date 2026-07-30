"""Behavioral tests for context propagation and stdlib log formatting."""

from __future__ import annotations

import io
import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from z4j_core.observability.context import (
    ContextFilter,
    agent_id_var,
    bind,
    bound,
    clear,
    install_context_filter,
    snapshot,
)
from z4j_core.observability.logging import (
    JsonFormatter,
    TextFormatter,
    configure_stdlib_logging,
    resolve_log_format,
)


def _record(
    message: str = "hello %s",
    *,
    args: tuple[object, ...] = ("world",),
    **extra: object,
) -> logging.LogRecord:
    record = logging.LogRecord(
        "z4j.test",
        logging.WARNING,
        __file__,
        1,
        message,
        args,
        None,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_bind_snapshot_clear_and_nested_bound_restore_context() -> None:
    outer = bind(agent_id="agent-1", project_id="project-1")
    try:
        assert snapshot() == {"agent_id": "agent-1", "project_id": "project-1"}
        with bound(agent_id="agent-2", session_id="session-2"):
            assert snapshot() == {
                "agent_id": "agent-2",
                "session_id": "session-2",
                "project_id": "project-1",
            }
        assert snapshot() == {"agent_id": "agent-1", "project_id": "project-1"}
    finally:
        clear(outer)
    assert "agent_id" not in snapshot()
    assert "project_id" not in snapshot()


def test_bind_rejects_control_characters_non_strings_and_truncates_ids() -> None:
    tokens = bind(
        agent_id="a" * 80,
        session_id="line\nbreak",
        worker_id="tab\tbreak",
        project_id=123,  # type: ignore[arg-type]
        request_id="safe-request",
    )
    try:
        assert snapshot() == {
            "agent_id": "a" * 64,
            "request_id": "safe-request",
        }
    finally:
        clear(tokens)


def test_context_filter_preserves_explicit_record_fields() -> None:
    tokens = bind(agent_id="ambient", session_id="session")
    try:
        record = _record(agent_id="explicit")
        assert ContextFilter().filter(record) is True
        assert record.__dict__["agent_id"] == "explicit"
        assert record.__dict__["session_id"] == "session"
    finally:
        clear(tokens)


def test_install_context_filter_resolves_targets_and_is_idempotent() -> None:
    logger = logging.getLogger("z4j.test.context.install")
    original_filters = list(logger.filters)
    logger.filters.clear()
    try:
        first = install_context_filter(logger)
        assert install_context_filter(logger) is first
        assert install_context_filter(logger.name) is first
        assert logger.filters == [first]
    finally:
        logger.filters[:] = original_filters


def test_resolve_log_format_normalizes_and_falls_back(capsys: Any) -> None:
    assert resolve_log_format({}) == "text"
    assert resolve_log_format({"Z4J_LOG_FORMAT": " JSON "}) == "json"
    assert resolve_log_format({"Z4J_LOG_FORMAT": "yaml"}) == "text"
    assert "unknown Z4J_LOG_FORMAT='yaml'" in capsys.readouterr().err


def test_json_formatter_emits_ndjson_and_masks_secret_extras() -> None:
    record = _record(
        "first\nsecond %s",
        args=("line",),
        token="do-not-log",
        token_count=4,
        nested={"at": datetime(2026, 1, 2, tzinfo=UTC), "items": (1, object())},
        unicode_separator="\u2028",
    )
    rendered = JsonFormatter().format(record)
    payload = json.loads(rendered)

    assert "\n" not in rendered
    assert "\\n" in rendered
    assert "\\u2028" in rendered
    assert payload["level"] == "warning"
    assert payload["logger"] == "z4j.test"
    assert payload["msg"] == "first\nsecond line"
    assert payload["token"] == "***"
    assert payload["token_count"] == 4
    assert payload["nested"]["at"] == "2026-01-02T00:00:00+00:00"
    assert isinstance(payload["nested"]["items"][1], str)


def test_json_formatter_includes_exception_stack_and_worker_thread() -> None:
    def fail() -> None:
        raise RuntimeError("expected")

    try:
        fail()
    except RuntimeError:
        exc_info = sys.exc_info()
    record = _record()
    record.exc_info = exc_info
    record.stack_info = "stack details"
    record.threadName = "worker-thread"

    payload = json.loads(JsonFormatter().format(record))

    assert "RuntimeError: expected" in payload["exc"]
    assert payload["stack"] == "stack details"
    assert payload["thread"] == "worker-thread"
    assert isinstance(payload["process"], int)


def test_text_formatter_has_stable_single_line_shape() -> None:
    record = _record("plain", args=())
    record.created = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC).timestamp()
    rendered = TextFormatter().format(record)

    assert rendered.endswith("WARNING z4j.test plain")
    assert "\n" not in rendered


def test_configured_handler_preserves_foreign_handlers_and_enriches_children() -> None:
    root = logging.getLogger()
    z4j_logger = logging.getLogger("z4j")
    original_handlers = list(root.handlers)
    original_filters = list(root.filters)
    original_root_level = root.level
    original_z4j_level = z4j_logger.level
    foreign = logging.NullHandler()
    output = io.StringIO()
    root.handlers = [foreign]
    root.filters.clear()
    try:
        configure_stdlib_logging(level="DEBUG", log_format="json", stream=output)
        configure_stdlib_logging(level="INFO", log_format="json", stream=output)

        managed = [handler for handler in root.handlers if handler is not foreign]
        assert len(managed) == 1
        assert foreign in root.handlers
        assert root.level == logging.INFO
        tokens = bind(agent_id="agent-from-context")
        try:
            logging.getLogger("z4j.child").warning("child log")
        finally:
            clear(tokens)
        assert json.loads(output.getvalue())["agent_id"] == "agent-from-context"
    finally:
        root.handlers = original_handlers
        root.filters[:] = original_filters
        root.setLevel(original_root_level)
        z4j_logger.setLevel(original_z4j_level)


def test_agent_context_var_default_is_unset() -> None:
    assert agent_id_var.get() is None
