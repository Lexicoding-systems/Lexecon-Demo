"""Ed25519 key generation, signing, and verification."""
import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DEFAULT_KEY_DIR = Path(".lexecon")


class Signer:
    """Ed25519 key management and signing for local MVP use."""

    def __init__(self, key_dir: Path | None = None):
        self.key_dir = Path(key_dir) if key_dir else DEFAULT_KEY_DIR
        self._private_key: Ed25519PrivateKey | None = None
        self._public_key: Ed25519PublicKey | None = None

    def _ensure_key_dir(self) -> None:
        self.key_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.key_dir, 0o700)

    @property
    def private_key(self) -> Ed25519PrivateKey:
        if self._private_key is not None:
            return self._private_key

        private_path = self.key_dir / "private_key.pem"
        if private_path.exists():
            with open(private_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(f.read(), password=None)
            return self._private_key

        self._ensure_key_dir()
        self._private_key = Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self._save_missing_keys()
        return self._private_key

    @property
    def public_key(self) -> Ed25519PublicKey:
        if self._public_key is not None:
            return self._public_key

        public_path = self.key_dir / "public_key.pem"
        if public_path.exists():
            with open(public_path, "rb") as f:
                self._public_key = serialization.load_pem_public_key(f.read())
            return self._public_key

        self._public_key = self.private_key.public_key()
        self._save_missing_keys()
        return self._public_key

    def _save_missing_keys(self) -> None:
        """Create missing key files with restrictive permissions."""
        self._ensure_key_dir()
        private_path = self.key_dir / "private_key.pem"
        public_path = self.key_dir / "public_key.pem"

        if not private_path.exists():
            private_bytes = self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            fd = os.open(private_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(private_bytes)

        if not public_path.exists():
            public_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            with open(public_path, "wb") as f:
                f.write(public_bytes)

    def sign(self, message: bytes | str) -> str:
        """Sign message with Ed25519. Return base64-encoded signature."""
        if isinstance(message, str):
            message = message.encode("utf-8")
        signature = self.private_key.sign(message)
        return base64.b64encode(signature).decode("utf-8")

    def verify(self, message: bytes | str, signature: str) -> bool:
        """Verify signature. Return True/False."""
        try:
            if isinstance(message, str):
                message = message.encode("utf-8")
            sig_bytes = base64.b64decode(signature)
            self.public_key.verify(sig_bytes, message)
            return True
        except Exception:
            return False
