"""Behavioral tests for the shared agent configuration boundary."""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import Any

import pytest
from z4j_core.config import resolve_agent_config
from z4j_core.errors import ConfigError


def _required_env(**overrides: str) -> dict[str, str]:
    env = {
        "Z4J_BRAIN_URL": "https://brain.example.test",
        "Z4J_TOKEN": "project-token",
        "Z4J_PROJECT_ID": "sandbox",
    }
    env.update(overrides)
    return env


def test_missing_required_settings_names_every_operator_option() -> None:
    with pytest.raises(ConfigError) as raised:
        resolve_agent_config(framework_name="bare", env={})

    assert raised.value.details == {
        "missing": [
            "brain_url (or Z4J_BRAIN_URL)",
            "token (or Z4J_TOKEN)",
            "project_id (or Z4J_PROJECT_ID)",
        ],
    }


def test_environment_values_are_coerced_and_composites_are_parsed() -> None:
    config = resolve_agent_config(
        framework_name="django",
        env=_required_env(
            Z4J_AGENT_NAME="worker-one",
            Z4J_AGENT_ID="agent-id",
            Z4J_HMAC_SECRET="signing-secret",
            Z4J_ENVIRONMENT="staging",
            Z4J_TRANSPORT="ws",
            Z4J_LOG_LEVEL="DEBUG",
            Z4J_HEARTBEAT_SECONDS="30",
            Z4J_BUFFER_MAX_EVENTS="2000",
            Z4J_BUFFER_MAX_BYTES="2097152",
            Z4J_MAX_PAYLOAD_BYTES="256",
            Z4J_AUTOSTART="no",
            Z4J_STRICT_MODE="YES",
            Z4J_WORKER_ROLE="task",
            Z4J_ENGINES=" celery, rq, ,",
            Z4J_SCHEDULERS="celery-beat, apscheduler",
            Z4J_REDACTION_EXTRA_KEY_PATTERNS="private.*, custom",
            Z4J_REDACTION_EXTRA_VALUE_PATTERNS="Bearer .+,",
            Z4J_TAGS="region=us-east-1, team = platform, malformed",
        ),
    )

    assert str(config.brain_url) == "https://brain.example.test/"
    assert config.token.get_secret_value() == "project-token"
    assert config.agent_name == "worker-one"
    assert config.hmac_secret is not None
    assert config.hmac_secret.get_secret_value() == "signing-secret"
    assert config.environment == "staging"
    assert config.log_level == "DEBUG"
    assert config.heartbeat_seconds == 30
    assert config.buffer_max_events == 2000
    assert config.buffer_max_bytes == 2_097_152
    assert config.max_payload_bytes == 256
    assert config.autostart is False
    assert config.strict_mode is True
    assert config.worker_role == "task"
    assert config.engines == ["celery", "rq"]
    assert config.schedulers == ["celery-beat", "apscheduler"]
    assert config.redaction_extra_key_patterns == ["private.*", "custom"]
    assert config.redaction_extra_value_patterns == ["Bearer .+"]
    assert config.tags == {"region": "us-east-1", "team": "platform"}


def test_precedence_is_framework_then_environment_then_explicit(tmp_path: Path) -> None:
    buffer_path = tmp_path / "chosen.sqlite"
    config = resolve_agent_config(
        framework_name="fastapi",
        framework_overrides={
            "brain_url": "https://framework.example.test",
            "token": "framework-token",
            "project_id": "framework-project",
            "environment": "framework",
            "heartbeat_seconds": 11,
            "engines": ("dramatiq",),
            "tags": {"source": "framework"},
            "buffer_path": tmp_path / "framework.sqlite",
            "dev_mode": "true",
            "agent_name": None,
            "worker_role": "",
        },
        env=_required_env(
            Z4J_ENVIRONMENT="environment",
            Z4J_HEARTBEAT_SECONDS="22",
            Z4J_ENGINES="celery",
            Z4J_TAGS="source=environment",
        ),
        explicit_kwargs={
            "brain_url": None,
            "token": "explicit-token",
            "project_id": None,
            "environment": "explicit",
            "heartbeat_seconds": 33,
            "engines": ["rq"],
            "tags": {"source": "explicit"},
            "buffer_path": str(buffer_path),
        },
    )

    assert str(config.brain_url) == "https://brain.example.test/"
    assert config.token.get_secret_value() == "explicit-token"
    assert config.project_id == "sandbox"
    assert config.environment == "explicit"
    assert config.heartbeat_seconds == 33
    assert config.engines == ["rq"]
    assert config.tags == {"source": "explicit"}
    assert config.buffer_path == buffer_path
    assert config.dev_mode is True


def test_explicit_empty_string_blocks_environment_and_uses_default() -> None:
    config = resolve_agent_config(
        framework_name="bare",
        env=_required_env(Z4J_AGENT_NAME="from-environment"),
        explicit_kwargs={"agent_name": ""},
    )

    assert config.agent_name is None


def test_dev_mode_environment_is_warned_and_ignored() -> None:
    with pytest.warns(UserWarning, match="IGNORED for security reasons"):
        config = resolve_agent_config(
            framework_name="flask",
            env=_required_env(Z4J_DEV_MODE="on"),
        )

    assert config.dev_mode is False


@pytest.mark.parametrize("value", ["0", "false", "NO", "off", "unexpected"])
def test_false_dev_mode_environment_does_not_warn(value: str) -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        config = resolve_agent_config(
            framework_name="flask",
            env=_required_env(Z4J_DEV_MODE=value),
        )

    assert caught == []
    assert config.dev_mode is False


def test_framework_native_values_and_false_booleans_pass_through(tmp_path: Path) -> None:
    config = resolve_agent_config(
        framework_name="django",
        framework_overrides={
            "brain_url": "https://framework.example.test",
            "token": "framework-token",
            "project_id": "framework-project",
            "heartbeat_seconds": True,
            "autostart": 0,
            "redaction_defaults_enabled": "false",
            "engines": ["celery"],
            "tags": {"role": "web"},
            "buffer_path": tmp_path / "buffer.sqlite",
        },
        env={},
    )

    assert config.heartbeat_seconds == 1
    assert config.autostart is False
    assert config.redaction_defaults_enabled is False
    assert config.engines == ["celery"]
    assert config.tags == {"role": "web"}
    assert config.buffer_path == tmp_path / "buffer.sqlite"


def test_invalid_integer_has_a_field_specific_error() -> None:
    with pytest.raises(ConfigError, match="heartbeat_seconds must be an integer"):
        resolve_agent_config(
            framework_name="bare",
            env=_required_env(Z4J_HEARTBEAT_SECONDS="often"),
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"transport": "carrier-pigeon"}, "invalid z4j agent configuration"),
        (
            {"transport": "longpoll"},
            "transport='longpoll' requires agent_id",
        ),
        (
            {"transport": "longpoll", "agent_id": "not-a-uuid"},
            "valid UUID",
        ),
    ],
)
def test_model_validation_is_reported_as_config_error(
    overrides: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(ConfigError, match=message):
        resolve_agent_config(
            framework_name="bare",
            env=_required_env(),
            explicit_kwargs=overrides,
        )


def test_longpoll_accepts_a_valid_explicit_agent_id() -> None:
    config = resolve_agent_config(
        framework_name="bare",
        env=_required_env(),
        explicit_kwargs={
            "transport": "longpoll",
            "agent_id": "00000000-0000-4000-8000-000000000123",
        },
    )

    assert config.transport == "longpoll"
