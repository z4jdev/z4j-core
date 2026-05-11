"""Unified agent configuration resolver.

Every framework adapter (z4j-django, z4j-flask, z4j-fastapi,
z4j-bare's ``install_agent``) is a thin shim that gathers
framework-specific input (Django's ``settings.Z4J`` dict, Flask's
``app.config``, FastAPI/bare's kwargs) and hands the result to
:func:`resolve_agent_config`. One precedence rule, one
``Z4J_DEV_MODE`` policy, one type-coercion path.
"""

from z4j_core.config.resolver import resolve_agent_config

__all__ = ["resolve_agent_config"]
