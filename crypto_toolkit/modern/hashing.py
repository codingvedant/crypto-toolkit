"""Cryptographic hash functions."""

import hashlib
from typing import Literal

HashAlgorithm = Literal["sha256", "sha384", "sha512", "md5"]


class Hasher:
    """Simple interface to common hash algorithms."""

    ALGORITHMS: dict[HashAlgorithm, str] = {
        "sha256": "SHA-256",
        "sha384": "SHA-384",
        "sha512": "SHA-512",
        "md5": "MD5",
    }

    @staticmethod
    def hash(data: bytes | str, algorithm: HashAlgorithm = "sha256") -> str:
        """
        Compute hexadecimal hash of data.

        Args:
            data: Input data (bytes or string).
            algorithm: Hash algorithm to use.

        Returns:
            Hexadecimal hash string.
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        h = hashlib.new(algorithm)
        h.update(data)
        return h.hexdigest()

    @staticmethod
    def verify(data: bytes | str, expected_hash: str, algorithm: HashAlgorithm = "sha256") -> bool:
        """Verify that data hashes to expected value."""
        return Hasher.hash(data, algorithm) == expected_hash.lower()
