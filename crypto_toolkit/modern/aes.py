"""AES (Advanced Encryption Standard) implementation using Fernet (AES-128-CBC)."""

import base64
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class AESCipher:
    """AES encryption using Fernet (symmetric authenticated encryption)."""

    def __init__(self, key: Optional[bytes] = None, password: Optional[str] = None, salt: Optional[bytes] = None):
        """
        Initialize AES cipher.

        Args:
            key: Raw 32-byte key (optional). If not provided, use password.
            password: Password for key derivation (optional).
            salt: Salt for PBKDF2 (optional). Random 16 bytes used if not provided.
        """
        if key is not None:
            # Accept Fernet key (base64) or raw 32-byte key
            if len(key) == 32 and isinstance(key, bytes):
                key = base64.urlsafe_b64encode(key)
            self._fernet = Fernet(key)
        elif password is not None:
            salt = salt or os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=480000,
            )
            key = kdf.derive(password.encode())
            self._fernet = Fernet(base64.urlsafe_b64encode(key))
            self._salt = salt
        else:
            self._fernet = Fernet.generate_key()
            self._fernet = Fernet(self._fernet)
        self._salt = getattr(self, "_salt", None)

    @staticmethod
    def generate_key() -> bytes:
        """Generate a new random 32-byte key."""
        return Fernet.generate_key()

    def encrypt(self, plaintext: bytes | str) -> bytes:
        """Encrypt data. Returns base64-encoded ciphertext."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        return self._fernet.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data. Raises InvalidToken if key/tampering."""
        try:
            return self._fernet.decrypt(ciphertext)
        except InvalidToken:
            raise ValueError("Decryption failed: invalid key or corrupted data")

    def get_salt(self) -> Optional[bytes]:
        """Return salt used for key derivation (if password-based)."""
        return self._salt
