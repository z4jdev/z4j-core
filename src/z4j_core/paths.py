"""Canonical state-directory resolution for z4j.

z4j stores per-host state in a single directory used by both the
brain process and the agent runtime. This module is the ONE place
that resolves where that directory lives.

Operators relocate z4j state via the single ``Z4J_HOME``
variable, resolved through :func:`z4j_home`. Deprecated
``Z4J_RUNTIME_DIR`` / ``Z4J_BUFFER_DIR`` / ``Z4J_BUFFER_PATH``
overrides hard-fail at startup (see
:func:`reject_deprecated_path_env`) so operators do not
silently end up with split state across multiple locations.

Design rule: any new code that wants to write to disk must route
its path through :func:`z4j_home`. Direct ``Path.home() / ".z4j"``
references are forbidden.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

__all__ = [
    "DEPRECATED_PATH_ENV_VARS",
    "buffer_root",
    "ensure_z4j_home",
    "reject_deprecated_path_env",
    "z4j_home",
]


# Deprecated path-override env vars. Read at startup by
# ``reject_deprecated_path_env``; if any of these are set the process
# refuses to start with a clear message pointing at Z4J_HOME. We
# hard-fail rather than silently ignore because silent ignore would
# leave operators believing they had relocated state when they
# hadn't, which is a security footgun (state could land in unexpected
# locations with unexpected permissions).
DEPRECATED_PATH_ENV_VARS: tuple[str, ...] = (
    "Z4J_RUNTIME_DIR",
    "Z4J_BUFFER_DIR",
    "Z4J_BUFFER_PATH",
)


def z4j_home() -> Path:
    """Return the canonical z4j state directory.

    Resolution order:
        1. ``$Z4J_HOME`` if set and non-empty
        2. ``Path.home() / ".z4j"``

    Always returned as an absolute, resolved Path. Caller is
    responsible for creating the directory if needed (see
    :func:`ensure_z4j_home`). This function does NOT touch the
    filesystem.
    """
    override = os.environ.get("Z4J_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.home() / ".z4j").resolve()


def ensure_z4j_home(mode: int = 0o700) -> Path:
    """Return :func:`z4j_home`, creating the directory if absent.

    Idempotent. Uses ``os.makedirs(mode=...)`` so the directory is
    created with the requested permission bits in a single syscall
    (no TOCTOU window between mkdir and chmod). If the directory
    already exists, ``mode`` is left alone - Phase A's stance is
    that the operator owns Z4J_HOME, and we don't want to silently
    widen or narrow a deliberately-set mode.

    On Windows ``mode`` has no POSIX meaning; ``os.makedirs`` still
    accepts it. NTFS ACL inheritance handles the equivalent.

    Args:
        mode: POSIX directory permission bits applied at create time.
            Defaults to ``0o700``.
    """
    home = z4j_home()
    if not home.exists():
        # Single-syscall create-with-mode. Closes the L-1 audit
        # finding's TOCTOU window (mkdir + later chmod let a
        # concurrent process replace the dir with a symlink between
        # the two steps).
        os.makedirs(home, mode=mode, exist_ok=True)
    return home


def buffer_root() -> Path:
    """Return the directory for the agent's per-process SQLite buffer.

    Normally identical to :func:`z4j_home`, but if the home directory
    is unwritable (low-privilege POSIX service users with HOME
    pointing at e.g. ``/`` or ``/nonexistent``), falls back to a
    per-uid temp directory: ``<tmpdir>/z4j-<uid>`` mode 0o700.

    The fallback exists because some service deployments cannot set
    ``HOME`` correctly for the worker user. With explicit
    ``Z4J_HOME`` configured to a writable path the fallback is
    never triggered. A WARNING is logged by the caller (not here)
    when the fallback fires, so operators can see they should set
    ``Z4J_HOME`` for production.
    """
    primary = z4j_home()
    try:
        primary.mkdir(parents=True, exist_ok=True)
        # Probe writability with an actual create+delete; checking
        # mode bits alone gives wrong answers on filesystems with
        # ACLs that override POSIX bits.
        probe = primary / ".z4j-write-probe"
        probe.touch()
        probe.unlink()
        return primary
    except OSError:
        pass

    # Fallback: per-uid temp directory.
    if hasattr(os, "getuid"):
        uid: str | int = os.getuid()
    else:
        # Windows: use USERNAME, falling back to "default". Sanitize
        # before interpolating into a path - NTFS permits a wider
        # character set than POSIX, and an attacker with control of
        # the USERNAME env var could otherwise produce values like
        # ``..\\..\\Users\\victim`` that traverse out of the temp
        # directory. Allow ASCII alphanumerics, dot, underscore,
        # hyphen; cap length at 32 to prevent oversized basenames.
        raw = (
            os.environ.get("USERNAME")
            or os.environ.get("USER")
            or "default"
        )
        sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", raw)[:32] or "default"
        uid = sanitized
    fallback = Path(tempfile.gettempdir()) / f"z4j-{uid}"
    fallback.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(fallback, 0o700)
    except OSError:
        pass
    return fallback.resolve()


def reject_deprecated_path_env() -> None:
    """Raise a clear error if any of the dropped path env vars are set.

    Called once at process startup (brain CLI and bare runtime). We
    hard-fail rather than warn because silent ignore would leave
    operators thinking they had relocated state when they hadn't.

    Raises:
        RuntimeError: if any of ``Z4J_RUNTIME_DIR``, ``Z4J_BUFFER_DIR``,
            or ``Z4J_BUFFER_PATH`` are set.
    """
    offenders = [
        var for var in DEPRECATED_PATH_ENV_VARS if os.environ.get(var)
    ]
    if not offenders:
        return
    listing = ", ".join(offenders)
    raise RuntimeError(
        f"z4j 1.5 removed the following environment variables: {listing}. "
        f"Set Z4J_HOME instead to relocate ALL z4j state (brain DB, "
        f"secrets, PKI, allowed-hosts, agent pidfiles, agent buffers) "
        f"to one directory. Default location is ~/.z4j. "
        f"Unset the offending variable(s) above to proceed.",
    )
