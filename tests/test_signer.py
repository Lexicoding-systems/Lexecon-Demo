"""Tests for Ed25519 signing."""
import pytest
import base64

from lexecon.audit.signer import Signer


def test_key_generation_creates_files(tmp_path):
    """Signer must generate key files if they don't exist."""
    key_dir = tmp_path / "lexecon_keys"
    signer = Signer(key_dir=key_dir)
    # Access private key to trigger generation
    _ = signer.private_key
    assert (key_dir / "private_key.pem").exists()
    assert (key_dir / "public_key.pem").exists()


def test_signature_verifies(tmp_path):
    """A valid signature must verify correctly."""
    signer = Signer(key_dir=tmp_path / "keys")
    message = "test message to sign"
    signature = signer.sign(message)
    assert signer.verify(message, signature) is True


def test_signature_fails_if_message_modified(tmp_path):
    """Modifying the message after signing must fail verification."""
    signer = Signer(key_dir=tmp_path / "keys")
    message = "original message"
    signature = signer.sign(message)
    assert signer.verify("tampered message", signature) is False


def test_signature_is_base64(tmp_path):
    """Signature string must be valid base64."""
    signer = Signer(key_dir=tmp_path / "keys")
    signature = signer.sign("test")
    # Should not raise
    decoded = base64.b64decode(signature)
    # Ed25519 signatures are 64 bytes
    assert len(decoded) == 64


def test_existing_key_loading(tmp_path):
    """Signer should load existing keys rather than regenerate."""
    key_dir = tmp_path / "keys"
    signer1 = Signer(key_dir=key_dir)
    pubkey1 = signer1.public_key

    signer2 = Signer(key_dir=key_dir)
    pubkey2 = signer2.public_key

    # Same public key means same keypair
    pub_bytes1 = pubkey1.public_bytes_raw()
    pub_bytes2 = pubkey2.public_bytes_raw()
    assert pub_bytes1 == pub_bytes2


def test_sign_and_verify_bytes(tmp_path):
    """Signing bytes should work and verify."""
    signer = Signer(key_dir=tmp_path / "keys")
    message = b"bytes message"
    signature = signer.sign(message)
    assert signer.verify(message, signature) is True


def test_verify_different_key_fails(tmp_path):
    """Signature from one key should not verify with another key."""
    signer1 = Signer(key_dir=tmp_path / "keys1")
    signer2 = Signer(key_dir=tmp_path / "keys2")

    message = "test"
    signature = signer1.sign(message)
    assert signer2.verify(message, signature) is False


def test_key_file_permissions_restrictive(tmp_path):
    """Private key file must have 0o600 permissions."""
    import stat
    key_dir = tmp_path / "keys"
    signer = Signer(key_dir=key_dir)
    _ = signer.private_key  # trigger generation

    private_path = key_dir / "private_key.pem"
    mode = stat.S_IMODE(private_path.stat().st_mode)
    assert mode == 0o600, f"Private key file mode is {oct(mode)}, expected 0o600"


def test_key_directory_permissions_restrictive(tmp_path):
    """Key directory must have 0o700 permissions."""
    import stat
    key_dir = tmp_path / "keys"
    signer = Signer(key_dir=key_dir)
    _ = signer.private_key  # trigger generation

    mode = stat.S_IMODE(key_dir.stat().st_mode)
    assert mode == 0o700, f"Key directory mode is {oct(mode)}, expected 0o700"


def test_explicit_public_key_path_verifies_signature(tmp_path):
    """Signer with explicit public_key_path can verify signatures from matching private key."""
    key_dir = tmp_path / "keys"
    signer_with_private = Signer(key_dir=key_dir)
    message = "third-party verification test"
    signature = signer_with_private.sign(message)

    public_key_file = key_dir / "public_key.pem"
    third_party_signer = Signer(public_key_path=public_key_file)
    assert third_party_signer.verify(message, signature) is True


def test_explicit_public_key_path_wrong_key_fails(tmp_path):
    """Signer with explicit public_key_path from a different keypair must fail verification."""
    signer_a = Signer(key_dir=tmp_path / "keys_a")
    signer_b = Signer(key_dir=tmp_path / "keys_b")

    message = "test"
    signature = signer_a.sign(message)

    # Give signer_b's public key to a third-party verifier
    third_party = Signer(public_key_path=tmp_path / "keys_b" / "public_key.pem")
    # Trigger key_b generation
    _ = signer_b.public_key
    assert third_party.verify(message, signature) is False
