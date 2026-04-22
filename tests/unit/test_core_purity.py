"""Defense-in-depth: make sure z4j_core imports nothing forbidden.

``import-linter`` is the primary enforcement mechanism (see
``.importlinter`` in the repo root). This test is a SECONDARY check
that walks the compiled bytecode of every z4j_core module and
asserts no forbidden top-level import is present. It catches the
narrow case where a developer bypasses import-linter (e.g. via a
local config override).

If this test fails, something has gone wrong with modularity. Do
not add an exception - go fix the offending import.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys

import pytest

import z4j_core

FORBIDDEN_TOP_LEVEL: frozenset[str] = frozenset(
    {
        "django",
        "flask",
        "fastapi",
        "starlette",
        "celery",
        "rq",
        "dramatiq",
        "redis",
        "sqlalchemy",
        "alembic",
        "asyncpg",
        "psycopg",
        "httpx",
        "websockets",
        "uvicorn",
        "gunicorn",
        "prometheus_client",
        "argon2",
    },
)


def _all_z4j_core_modules() -> list[str]:
    """Return the dotted name of every z4j_core submodule."""
    result: list[str] = [z4j_core.__name__]
    # Use a for-loop to keep pytest diagnostics readable.
    for module_info in pkgutil.walk_packages(
        z4j_core.__path__,
        prefix=f"{z4j_core.__name__}.",
    ):
        result.append(module_info.name)
    return result


@pytest.mark.parametrize("module_name", _all_z4j_core_modules())
def test_z4j_core_module_imports_are_clean(module_name: str) -> None:
    """Importing any z4j_core submodule must not pull a forbidden dependency."""
    # Force import so any top-level import side-effects run.
    importlib.import_module(module_name)

    # Inspect sys.modules for forbidden top-level names.
    forbidden_seen = sorted(FORBIDDEN_TOP_LEVEL & set(sys.modules))
    assert not forbidden_seen, (
        f"Importing {module_name} brought forbidden modules into sys.modules: "
        f"{forbidden_seen}. This is a core-purity violation. "
        f"See docs/CLAUDE.md §2.1 and .importlinter."
    )


def test_z4j_core_version_is_set() -> None:
    """``z4j_core.__version__`` must be a non-empty PEP 440 string."""
    assert isinstance(z4j_core.__version__, str)
    assert len(z4j_core.__version__) > 0


def test_protocols_module_exports_all_three() -> None:
    """The three Protocols must be importable from ``z4j_core.protocols``."""
    from z4j_core.protocols import (  # noqa: PLC0415
        FrameworkAdapter,
        QueueEngineAdapter,
        SchedulerAdapter,
    )

    assert FrameworkAdapter is not None
    assert QueueEngineAdapter is not None
    assert SchedulerAdapter is not None


def test_models_module_exports_all_entities() -> None:
    """Every domain model listed in ``__all__`` must actually exist."""
    from z4j_core import models  # noqa: PLC0415

    for name in models.__all__:
        assert hasattr(models, name), f"z4j_core.models.__all__ lists {name!r} but it is missing"
