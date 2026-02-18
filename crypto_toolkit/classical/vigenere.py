"""Vigenère cipher implementation - a polyalphabetic substitution cipher."""


class VigenereCipher:
    """Implements the Vigenère cipher using a repeating keyword."""

    def __init__(self, key: str):
        """
        Initialize the Vigenère cipher.

        Args:
            key: The encryption/decryption keyword (non-empty, letters only)
        """
        self.key = "".join(c for c in key.upper() if c.isalpha()) or "A"

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext using Vigenère cipher."""
        return self._transform(plaintext, encrypt=True)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext using Vigenère cipher."""
        return self._transform(ciphertext, encrypt=False)

    def _transform(self, text: str, encrypt: bool) -> str:
        """Apply Vigenère transformation."""
        result = []
        key_idx = 0
        for char in text:
            if char.isalpha():
                base = ord("A") if char.isupper() else ord("a")
                key_char = self.key[key_idx % len(self.key)]
                shift = ord(key_char) - ord("A") if encrypt else -(ord(key_char) - ord("A"))
                shifted = (ord(char) - base + shift) % 26 + base
                result.append(chr(shifted))
                key_idx += 1
            else:
                result.append(char)
        return "".join(result)
