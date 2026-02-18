"""RSA asymmetric encryption implementation."""

from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend


class RSACipher:
    """RSA public/private key encryption."""

    def __init__(self, key_size: int = 2048):
        """
        Initialize RSA cipher and generate key pair.

        Args:
            key_size: Key size in bits (2048 or 4096 recommended).
        """
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        self._public_key = self._private_key.public_key()

    @staticmethod
    def from_private_key(pem_bytes: bytes) -> "RSACipher":
        """Load from PEM-encoded private key."""
        private_key = serialization.load_pem_private_key(
            pem_bytes, password=None, backend=default_backend()
        )
        cipher = RSACipher.__new__(RSACipher)
        cipher._private_key = private_key
        cipher._public_key = private_key.public_key()
        return cipher

    @staticmethod
    def from_public_key(pem_bytes: bytes) -> "RSACipher":
        """Load from PEM-encoded public key (encrypt only)."""
        public_key = serialization.load_pem_public_key(pem_bytes, backend=default_backend())
        cipher = RSACipher.__new__(RSACipher)
        cipher._private_key = None
        cipher._public_key = public_key
        return cipher

    def encrypt(self, plaintext: bytes | str) -> bytes:
        """Encrypt with public key. Max size ~190 bytes for 2048-bit key."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        return self._public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt with private key."""
        if self._private_key is None:
            raise ValueError("Private key required for decryption")
        return self._private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def get_public_pem(self) -> bytes:
        """Export public key as PEM."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def get_private_pem(self) -> bytes:
        """Export private key as PEM."""
        if self._private_key is None:
            raise ValueError("No private key available")
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
