"""z4j-core - the pure domain core of z4j.

This package contains the Pydantic domain models, the three adapter
Protocols, the wire protocol primitives, the secret redaction engine,
the policy engine, and the shared exception hierarchy.

**Design rule:** this package must not import any framework or engine
module (Django, Celery, Flask, FastAPI, Redis, SQLAlchemy, websockets,
httpx, ...). Only Pydantic and the Python standard library. This is
enforced by ``import-linter`` on every PR.

See ``docs/ARCHITECTURE.md`` for the full architecture and
``docs/CLAUDE.md §2.1`` for the modularity rules.

Licensed under Apache License 2.0. See the repository ``LICENSE-APACHE``.
"""

from __future__ import annotations

from z4j_core.version import __version__

__all__ = ["__version__"]
