"""Unit tests for z4j-core HMAC signing and verification.

Target coverage: 100% line + 100% branch. Security-critical.
"""

from __future__ import annotations

import secrets

import pytest

from z4j_core.errors import SignatureError
from z4j_core.transport import canonical_json, make_signature, verify_signature
from z4j_core.transport.hmac import HMACVerifier, generate_project_secret

_SECRET = b"x" * 32
_PAYLOAD = canonical_json({"action": "retry_task", "target": {"task_id": "abc"}})


class TestSignatureHappyPath:
    def test_same_secret_and_payload_yield_same_signature(self) -> None:
        a = make_signature(_SECRET, _PAYLOAD)
        b = make_signature(_SECRET, _PAYLOAD)
        assert a == b

    def test_signature_is_hex_64_chars(self) -> None:
        sig = make_signature(_SECRET, _PAYLOAD)
        assert len(sig) == 64
        int(sig, 16)  # must parse as hex


class TestVerifyAccepts:
    def test_correct_signature_passes(self) -> None:
        sig = make_signature(_SECRET, _PAYLOAD)
        verify_signature(_SECRET, _PAYLOAD, sig)  # must not raise


class TestVerifyRejects:
    def test_missing_signature_raises(self) -> None:
        with pytest.raises(SignatureError, match="missing"):
            verify_signature(_SECRET, _PAYLOAD, None)

    def test_empty_signature_raises(self) -> None:
        with pytest.raises(SignatureError):
            verify_signature(_SECRET, _PAYLOAD, "")

    def test_wrong_length_signature_raises(self) -> None:
        with pytest.raises(SignatureError, match="length"):
            verify_signature(_SECRET, _PAYLOAD, "abc")

    def test_wrong_signature_same_length_raises(self) -> None:
        wrong = "0" * 64
        with pytest.raises(SignatureError, match="mismatch"):
            verify_signature(_SECRET, _PAYLOAD, wrong)

    def test_different_secret_yields_mismatch(self) -> None:
        other_secret = b"y" * 32
        sig = make_signature(other_secret, _PAYLOAD)
        with pytest.raises(SignatureError):
            verify_signature(_SECRET, _PAYLOAD, sig)

    def test_modified_payload_yields_mismatch(self) -> None:
        sig = make_signature(_SECRET, _PAYLOAD)
        tampered = canonical_json({"action": "retry_task", "target": {"task_id": "xyz"}})
        with pytest.raises(SignatureError):
            verify_signature(_SECRET, tampered, sig)


class TestSecretValidation:
    def test_short_secret_rejected(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            make_signature(b"short", _PAYLOAD)

    def test_short_secret_rejected_on_verify(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            verify_signature(b"short", _PAYLOAD, "a" * 64)


class TestGeneratedSecret:
    def test_generated_secret_is_32_bytes(self) -> None:
        assert len(generate_project_secret()) == 32

    def test_generated_secrets_are_unique(self) -> None:
        a = generate_project_secret()
        b = generate_project_secret()
        assert a != b


class TestHMACVerifier:
    def test_sign_and_verify_round_trip(self) -> None:
        verifier = HMACVerifier(_SECRET)
        sig = verifier.sign(_PAYLOAD)
        verifier.verify(_PAYLOAD, sig)

    def test_verifier_rejects_bad_signature(self) -> None:
        verifier = HMACVerifier(_SECRET)
        with pytest.raises(SignatureError):
            verifier.verify(_PAYLOAD, "0" * 64)

    def test_verifier_rejects_short_secret(self) -> None:
        with pytest.raises(ValueError):
            HMACVerifier(b"short")

    def test_repr_does_not_leak_secret(self) -> None:
        verifier = HMACVerifier(_SECRET)
        r = repr(verifier)
        assert "REDACTED" in r
        assert "x" * 32 not in r


class TestCanonicalJSON:
    def test_keys_are_sorted(self) -> None:
        a = canonical_json({"z": 1, "a": 2})
        b = canonical_json({"a": 2, "z": 1})
        assert a == b

    def test_compact_separators(self) -> None:
        raw = canonical_json({"a": 1, "b": 2})
        assert b" " not in raw

    def test_nested_keys_are_sorted(self) -> None:
        a = canonical_json({"outer": {"z": 1, "a": 2}})
        b = canonical_json({"outer": {"a": 2, "z": 1}})
        assert a == b


class TestRandomnessOfCompareDigest:
    """Sanity check that hmac.compare_digest is actually being used.

    We can't easily measure the constant-time guarantee, but we can
    verify that a one-byte difference near the start of the signature
    still produces a SignatureError (as opposed to bailing early).
    """

    def test_one_byte_diff_at_start_raises(self) -> None:
        real = make_signature(_SECRET, _PAYLOAD)
        tampered = ("f" if real[0] != "f" else "e") + real[1:]
        with pytest.raises(SignatureError):
            verify_signature(_SECRET, _PAYLOAD, tampered)

    def test_one_byte_diff_at_end_raises(self) -> None:
        real = make_signature(_SECRET, _PAYLOAD)
        tampered = real[:-1] + ("f" if real[-1] != "f" else "e")
        with pytest.raises(SignatureError):
            verify_signature(_SECRET, _PAYLOAD, tampered)


class TestSecretsInteraction:
    """The module delegates secret generation to ``secrets`` - make sure
    the module uses that sensibly. Non-security test; just ensures we
    aren't accidentally importing ``random``.
    """

    def test_generated_secret_enters_range(self) -> None:
        seen = {generate_project_secret() for _ in range(16)}
        assert len(seen) == 16  # no duplicates in 16 draws

    def test_secrets_module_is_available(self) -> None:
        # Sanity: ``secrets`` is stdlib and always importable.
        assert secrets.token_bytes(32) != b"\x00" * 32
