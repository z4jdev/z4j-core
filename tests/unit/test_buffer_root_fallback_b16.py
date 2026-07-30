"""B16 (CWE-377): the ``<tmpdir>/z4j-<uid>`` buffer fallback must not adopt
a predictable-name directory a local attacker pre-created. ``_is_own_private_dir``
gates adoption; anything not a real 0700 dir WE own is refused so the caller
falls back to an unguessable ``mkdtemp`` dir instead.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode semantics")

from z4j_core.paths import _is_own_private_dir  # noqa: E402


def test_own_private_dir_accepted(tmp_path: Path) -> None:
    d = tmp_path / "mine"
    d.mkdir(mode=0o700)
    assert _is_own_private_dir(d) is True


def test_group_or_other_accessible_dir_refused(tmp_path: Path) -> None:
    d = tmp_path / "loose"
    d.mkdir(mode=0o755)
    assert _is_own_private_dir(d) is False


def test_symlink_at_predictable_name_refused(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(target)
    # lstat sees the symlink itself (not a directory) -> refused, so the
    # planted symlink is never followed to the attacker's target.
    assert _is_own_private_dir(link) is False


def test_missing_path_refused(tmp_path: Path) -> None:
    assert _is_own_private_dir(tmp_path / "does-not-exist") is False


def test_fallback_creates_private_dir_when_home_unwritable(monkeypatch: pytest.MonkeyPatch) -> None:
    """With a fresh tmp root, buffer_root's fallback yields a 0700 dir we own."""
    from z4j_core import paths

    fresh_tmp = Path(tempfile.mkdtemp())
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(fresh_tmp))
    # Force the primary (z4j_home) path to be unwritable so the fallback runs.
    monkeypatch.setattr(paths, "z4j_home", lambda: Path("/nonexistent/z4j-home-xyz"))

    root = paths.buffer_root()
    st = root.lstat()
    import stat as _stat

    assert _stat.S_ISDIR(st.st_mode)
    assert st.st_uid == os.getuid()
    assert not (st.st_mode & 0o077)
