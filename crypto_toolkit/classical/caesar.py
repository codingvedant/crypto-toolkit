"""Caesar cipher implementation - a shift cipher from classical cryptography."""


class CaesarCipher:
    """Implements the Caesar cipher with configurable shift."""

    def __init__(self, shift: int = 3):
        """
        Initialize the Caesar cipher.

        Args:
            shift: The number of positions to shift letters (default: 3, as in original)
        """
        self.shift = shift % 26

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext using Caesar cipher."""
        return self._transform(plaintext, self.shift)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext using Caesar cipher."""
        return self._transform(ciphertext, -self.shift)

    def _transform(self, text: str, shift: int) -> str:
        """Apply shift transformation to text, preserving case and non-alphabetic chars."""
        result = []
        for char in text:
            if char.isalpha():
                base = ord("A") if char.isupper() else ord("a")
                shifted = (ord(char) - base + shift) % 26 + base
                result.append(chr(shifted))
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def brute_force(ciphertext: str) -> list[tuple[int, str]]:
        """Attempt all 26 possible shifts (useful for cryptanalysis)."""
        return [(i, CaesarCipher(i).decrypt(ciphertext)) for i in range(26)]
