"""Guards for operator-facing source contracts that previously drifted."""

from __future__ import annotations

from pathlib import Path

from z4j_core.models import Config

_REPO_ROOT = Path(__file__).resolve().parents[4]


def test_config_descriptions_match_runtime_security_contract() -> None:
    config_doc = Config.__doc__ or ""

    assert '"auto"' in config_doc and "selects WebSocket exactly" in config_doc
    assert "does not disable frame signing" in config_doc
    assert "does not branch on it" in config_doc
    assert "including in ``dev_mode``" in config_doc


def test_dev_mode_warning_does_not_claim_hmac_is_disabled() -> None:
    resolver = (_REPO_ROOT / "packages/z4j-core/src/z4j_core/config/resolver.py").read_text(
        encoding="utf-8"
    )

    assert "bypass disables HMAC" not in resolver
    assert "frame HMAC remains required" in resolver


def test_brain_policy_engine_does_not_import_library_side_helper() -> None:
    backend_root = _REPO_ROOT / "packages/z4j/backend/src/z4j_brain"
    backend_sources = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(backend_root.rglob("*.py"))
    )

    assert "from z4j_core.policy" not in backend_sources
    assert "import z4j_core.policy" not in backend_sources
    assert (backend_root / "domain/policy_engine.py").is_file()
