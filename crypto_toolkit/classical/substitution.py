"""Substitution cipher implementation - monoalphabetic substitution."""

import random
import string


class SubstitutionCipher:
    """Implements a general monoalphabetic substitution cipher."""

    def __init__(self, key: str | None = None):
        """
        Initialize the substitution cipher.

        Args:
            key: 26-letter permutation of the alphabet. If None, generates random key.
        """
        if key:
            if len(key) != 26 or set(key.upper()) != set(string.ascii_uppercase):
                raise ValueError("Key must be a 26-letter permutation of the alphabet")
            self.key = key.upper()
        else:
            chars = list(string.ascii_uppercase)
            random.shuffle(chars)
            self.key = "".join(chars)
        self.inverse_key = self._build_inverse()

    def _build_inverse(self) -> str:
        """Build inverse mapping for decryption."""
        inverse = [""] * 26
        for i, c in enumerate(self.key):
            inverse[ord(c) - ord("A")] = chr(ord("A") + i)
        return "".join(inverse)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext using substitution."""
        return self._transform(plaintext, self.key)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext using substitution."""
        return self._transform(ciphertext, self.inverse_key)

    def _transform(self, text: str, mapping: str) -> str:
        """Apply character mapping."""
        result = []
        for char in text:
            if char.isalpha():
                base = ord("A") if char.isupper() else ord("a")
                idx = ord(char.upper()) - ord("A")
                new_char = mapping[idx]
                result.append(new_char if char.isupper() else new_char.lower())
            else:
                result.append(char)
        return "".join(result)

    def get_key(self) -> str:
        """Return the current substitution key (useful for sharing with recipient)."""
        return self.key
