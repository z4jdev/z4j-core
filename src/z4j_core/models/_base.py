"""Shared Pydantic base class and config for all z4j-core models.

Every domain model extends :class:`Z4JModel` so the strict-validation,
forbidden-extras, and frozen-by-default behavior is applied uniformly.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Z4JModel(BaseModel):
    """Common base for every z4j-core domain model.

    Behavior:

    - ``strict=True``  - no silent type coercion (``"5"`` does not become ``5``).
    - ``extra="forbid"`` - unknown fields are rejected, not silently dropped.
      Catches API drift at the boundary.
    - ``frozen=True`` - models are immutable after construction.
      Prevents accidental mutation across layers.
    - ``str_strip_whitespace=True`` - leading/trailing whitespace on all
      string fields is stripped at parse time.
    - ``validate_assignment=True`` - on frozen models this is defensive;
      attempts to set attributes fail with ``ValidationError``.
    - ``populate_by_name=True`` - permits populating a field by its Python
      name even if an alias exists.

    Subclasses may override ``model_config`` if they need additional
    settings, but should not relax strict, extra, or frozen.
    """

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
    )


__all__ = ["Z4JModel"]
