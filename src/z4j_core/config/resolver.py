"""Unified agent ``Config`` resolver shared by every framework adapter.

Single source of truth for how :class:`z4j_core.models.Config` is
constructed from the four input sources operators can use. Replaces
~789 lines of duplicate env-var parsing across z4j-django, z4j-flask,
z4j-fastapi, and z4j-bare's ``install_agent``.

Precedence (highest to lowest):

1. ``explicit_kwargs`` - keyword arguments passed to FastAPI's
   ``install_z4j`` / ``z4j_lifespan`` or to bare's ``install_agent``.
   ``None`` means "not passed", which falls through to layer 2.
2. ``Z4J_*`` environment variables. The canonical name for each
   field is ``Z4J_<FIELD_NAME_UPPER>``.
3. ``framework_overrides`` - the framework's own settings mechanism.
   Django ``settings.Z4J`` dict; Flask ``app.config`` (flat keys are
   merged with the optional ``Z4J`` nested dict; flat wins on
   collision because flat values are typically operator overrides).
4. :class:`Config` code defaults.

``Z4J_DEV_MODE`` policy: untrusted env vars cannot disable HMAC
verification. The env-var setting is warn-and-ignored. Explicit
operator code (kwargs OR framework settings) honors ``dev_mode``
because writing it in source is a deliberate choice the operator
takes responsibility for. This policy was previously enforced only
by ``z4j-bare``; 1.5 makes it uniform across every adapter.

Empty-string env values are treated as "not set" so a shell-level
``Z4J_TOKEN=`` does not silently zero out a value provided in
``settings.Z4J``.
"""

from __future__ import annotations

import os
import warnings
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from z4j_core.errors import ConfigError
from z4j_core.models import Config


# Field name → canonical env var. Most are ``Z4J_<UPPER_FIELD>`` but
# we list them explicitly so renames in Config don't silently break
# the env contract.
_FIELD_TO_ENV: dict[str, str] = {
    "brain_url": "Z4J_BRAIN_URL",
    "token": "Z4J_TOKEN",
    "project_id": "Z4J_PROJECT_ID",
    "agent_name": "Z4J_AGENT_NAME",
    "agent_id": "Z4J_AGENT_ID",
    "hmac_secret": "Z4J_HMAC_SECRET",
    "environment": "Z4J_ENVIRONMENT",
    "transport": "Z4J_TRANSPORT",
    "log_level": "Z4J_LOG_LEVEL",
    "heartbeat_seconds": "Z4J_HEARTBEAT_SECONDS",
    "buffer_max_events": "Z4J_BUFFER_MAX_EVENTS",
    "buffer_max_bytes": "Z4J_BUFFER_MAX_BYTES",
    "max_payload_bytes": "Z4J_MAX_PAYLOAD_BYTES",
    "autostart": "Z4J_AUTOSTART",
    "strict_mode": "Z4J_STRICT_MODE",
    "worker_role": "Z4J_WORKER_ROLE",
}

# Field type categories for coercion. Strings are passthrough.
_INT_FIELDS = frozenset({
    "heartbeat_seconds", "buffer_max_events", "buffer_max_bytes",
    "max_payload_bytes",
})
_BOOL_FIELDS = frozenset({
    "autostart", "strict_mode", "redaction_defaults_enabled",
})
_LIST_CSV_FIELDS = frozenset({
    "engines", "schedulers",
    "redaction_extra_key_patterns", "redaction_extra_value_patterns",
})
# Fields with their own list-CSV env var (Z4J_<FIELD_NAME_UPPER>).
_LIST_ENV_VARS: dict[str, str] = {
    "engines": "Z4J_ENGINES",
    "schedulers": "Z4J_SCHEDULERS",
    "redaction_extra_key_patterns": "Z4J_REDACTION_EXTRA_KEY_PATTERNS",
    "redaction_extra_value_patterns": "Z4J_REDACTION_EXTRA_VALUE_PATTERNS",
}


_DEV_MODE_ENV_WARNING = (
    "Z4J_DEV_MODE env var is IGNORED for security reasons. A "
    "'dev mode' bypass disables HMAC verification on the wire, "
    "allowing any client with the project's bearer token to submit "
    "forged frames - untrusted env vars cannot be permitted to "
    "disable HMAC. If you really want dev_mode in a non-production "
    "environment, set it in your framework's settings (Django "
    "settings.Z4J, Flask app.config, FastAPI install_z4j kwargs, "
    "bare install_agent kwargs) - that's an explicit operator code "
    "choice. Z4J_DEV_MODE from environment is dropped."
)


def resolve_agent_config(
    *,
    framework_name: str,  # noqa: ARG001 - reserved for future per-framework defaults
    framework_overrides: Mapping[str, Any] | None = None,
    explicit_kwargs: Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
) -> Config:
    """Build a :class:`Config` from all sources with unified precedence.

    Args:
        framework_name: One of ``"django"`` / ``"flask"`` / ``"fastapi"``
            / ``"bare"``. Reserved for future per-framework defaults;
            currently only used in error messages.
        framework_overrides: The framework's own settings mechanism
            flattened to a ``{field_name: value}`` mapping. Django:
            ``settings.Z4J`` dict. Flask: merged ``app.config`` flat +
            nested. FastAPI/bare: ``None``.
        explicit_kwargs: Keyword args from FastAPI ``install_z4j``
            or bare ``install_agent``. Django/Flask: ``None``.
        env: Environment variable mapping. Defaults to ``os.environ``.

    Returns:
        A validated :class:`Config` instance.

    Raises:
        ConfigError: Required fields missing, type coercion failed,
            or :class:`Config` validation rejected the result.
    """
    if env is None:
        env = os.environ
    framework_overrides = dict(framework_overrides or {})
    explicit_kwargs = dict(explicit_kwargs or {})

    # Z4J_DEV_MODE security policy: untrusted env can't disable HMAC.
    # Strip it from env (with warn) before processing. Explicit code
    # (kwargs or framework settings) is honored.
    if _is_truthy(env.get("Z4J_DEV_MODE", "")):
        warnings.warn(
            _DEV_MODE_ENV_WARNING,
            stacklevel=4,
        )
        # Make a mutable copy with Z4J_DEV_MODE neutralized.
        env = {k: v for k, v in env.items() if k != "Z4J_DEV_MODE"}

    resolved: dict[str, Any] = {}

    # Layer 3: framework_overrides
    for field_name, value in framework_overrides.items():
        if value is None or value == "":
            continue
        coerced = _coerce(field_name, value)
        if coerced is not None:
            resolved[field_name] = coerced

    # Layer 2: env vars (scalar fields)
    for field_name, env_key in _FIELD_TO_ENV.items():
        raw = env.get(env_key, "")
        if not raw:  # empty string == not set
            continue
        coerced = _coerce(field_name, raw)
        if coerced is not None:
            resolved[field_name] = coerced

    # Layer 2: env vars (list-CSV fields)
    for field_name, env_key in _LIST_ENV_VARS.items():
        raw = env.get(env_key, "")
        if not raw:
            continue
        resolved[field_name] = _split_csv(raw)

    # Layer 2: env vars (special composite fields)
    raw_tags = env.get("Z4J_TAGS", "")
    if raw_tags:
        resolved["tags"] = _parse_tags(raw_tags)

    # Z4J_BUFFER_PATH was dropped in 1.5 (consolidated into Z4J_HOME).
    # ``reject_deprecated_path_env`` (called by the agent CLI and
    # install_agent at startup) hard-fails on the deprecated var, so
    # by the time the resolver runs we know it's not set.

    # Layer 1: explicit_kwargs
    for field_name, value in explicit_kwargs.items():
        if value is None:
            continue
        # Empty string from an explicit kwarg means "deliberately
        # blank" - block the env fallback for this field but leave
        # the resolved dict untouched so the Config default applies.
        # Callers use this idiom to express "I want the default, do
        # not check env".
        if isinstance(value, str) and value == "":
            resolved.pop(field_name, None)
            continue
        if field_name == "buffer_path":
            resolved[field_name] = Path(value)
            continue
        resolved[field_name] = value

    # Required-fields check produces a friendly error message that
    # names the env var alternatives. Without this, Pydantic produces
    # a generic "Field required" message that doesn't tell operators
    # which env vars they can use as alternatives.
    missing: list[str] = []
    if not resolved.get("brain_url"):
        missing.append("brain_url (or Z4J_BRAIN_URL)")
    if not resolved.get("token"):
        missing.append("token (or Z4J_TOKEN)")
    if not resolved.get("project_id"):
        missing.append("project_id (or Z4J_PROJECT_ID)")
    if missing:
        raise ConfigError(
            "missing required Z4J settings: " + ", ".join(missing),
            details={"missing": missing},
        )

    try:
        return Config(**resolved)
    except ConfigError:
        raise
    except Exception as exc:  # noqa: BLE001 - includes Pydantic ValidationError
        raise ConfigError(
            f"invalid z4j agent configuration: {exc}",
        ) from exc


def _coerce(field_name: str, value: Any) -> Any:
    """Coerce a value to the target field's type.

    String inputs from env vars and YAML/JSON-flat-config values get
    parsed. Native typed values (int / bool / list / dict) pass
    through unmodified.
    """
    if value is None:
        return None

    if field_name in _INT_FIELDS:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError as exc:
                raise ConfigError(
                    f"{field_name} must be an integer, got {value!r}",
                ) from exc
        return value

    if field_name in _BOOL_FIELDS:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return _is_truthy(value)
        return bool(value)

    if field_name == "dev_mode":
        # Honored from explicit code (framework_overrides /
        # explicit_kwargs); env var was filtered out earlier.
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return _is_truthy(value)
        return bool(value)

    if field_name in _LIST_CSV_FIELDS:
        if isinstance(value, str):
            return _split_csv(value)
        return list(value)

    if field_name == "tags":
        if isinstance(value, str):
            return _parse_tags(value)
        return dict(value)

    if field_name == "buffer_path":
        if isinstance(value, Path):
            return value
        return Path(str(value))

    return value


def _is_truthy(value: str) -> bool:
    """Standard truthy parsing for env-var-style boolean strings."""
    return value.strip().lower() in ("1", "true", "yes", "on")


def _split_csv(value: str) -> list[str]:
    """Split a comma-separated string, stripping whitespace and skipping empties."""
    return [s.strip() for s in value.split(",") if s.strip()]


def _parse_tags(value: str) -> dict[str, str]:
    """Parse ``key1=val1,key2=val2`` style tag strings."""
    out: dict[str, str] = {}
    for pair in value.split(","):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        out[k.strip()] = v.strip()
    return out


__all__ = ["resolve_agent_config"]
