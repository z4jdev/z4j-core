"""Single source of truth for the z4j version string.

All packages in the z4j workspace use **SemVer** (``MAJOR.MINOR.PATCH``).
Each package is versioned independently (see ``docs/VERSIONING.md``),
but ``z4j-core``'s version is the reference - adapters pin against
it via ``z4j-core >=1.0,<2.0`` in their ``pyproject.toml``.

Pre-release suffixes follow PEP 440:
- ``1.0.0a1`` - alpha 1
- ``1.0.0b1`` - beta 1
- ``1.0.0rc1`` - release candidate 1
- ``1.0.0`` - stable release

The version is read from the ``VERSION`` file at the repository root
during development. When packages are built for PyPI, the build
system (hatch/setuptools) injects the version into the package
metadata, and this module falls back to ``importlib.metadata``.
"""

from __future__ import annotations

import importlib.metadata
from pathlib import Path


def _read_version() -> str:
    """Resolve the z4j version string.

    Priority:
    1. VERSION file at repo root (development mode)
    2. importlib.metadata (installed package)
    3. "0.0.0" (fallback)
    """
    # 1. Try the repo-root VERSION file (works in dev/editable installs).
    version_file = Path(__file__).resolve().parents[4] / "VERSION"
    if version_file.is_file():
        text = version_file.read_text().strip()
        if text:
            return text

    # 2. Try installed package metadata.
    try:
        return importlib.metadata.version("z4j-core")
    except importlib.metadata.PackageNotFoundError:
        pass

    return "0.0.0"


__version__: str = _read_version()
"""The current z4j-core version (SemVer: MAJOR.MINOR.PATCH)."""

PROTOCOL_VERSION = "2"
"""The current wire-protocol version.

This is the version the agent advertises in its ``hello`` frame and
the brain checks for compatibility. It is independent of the
``__version__`` of any individual package - breaking changes to the
wire format bump this, additive changes do not.

See ``docs/VERSIONING.md §7`` for the full compatibility story.
"""

__all__ = ["PROTOCOL_VERSION", "__version__"]
