"""Rail Fence cipher implementation - a transposition cipher."""


class RailFenceCipher:
    """Implements the Rail Fence (zigzag) transposition cipher."""

    def __init__(self, rails: int = 3):
        """
        Initialize the Rail Fence cipher.

        Args:
            rails: Number of rails (rows) - typically 2 or 3
        """
        self.rails = max(2, rails)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt by reading characters in zigzag pattern across rails."""
        # Filter to letters only for encryption pattern
        chars = [c for c in plaintext if c.isalpha()]
        if not chars:
            return plaintext

        # Build rails
        rail_matrix = [[] for _ in range(self.rails)]
        rail, direction = 0, 1
        for char in chars:
            rail_matrix[rail].append(char)
            rail += direction
            if rail in (0, self.rails - 1):
                direction *= -1

        return "".join("".join(rail) for rail in rail_matrix)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt by reconstructing zigzag pattern and reading row by row."""
        chars = [c for c in ciphertext if c.isalpha()]
        if not chars:
            return ciphertext

        n = len(chars)
        # Determine length of each rail
        cycle = 2 * (self.rails - 1)
        rail_lengths = [0] * self.rails
        for i in range(n):
            rail = self._rail_index(i)
            rail_lengths[rail] += 1

        # Split ciphertext into rails
        rails = []
        idx = 0
        for length in rail_lengths:
            rails.append(chars[idx : idx + length])
            idx += length

        # Read in zigzag order
        result = []
        indices = [0] * self.rails
        for i in range(n):
            rail = self._rail_index(i)
            result.append(rails[rail][indices[rail]])
            indices[rail] += 1
        return "".join(result)

    def _rail_index(self, position: int) -> int:
        """Get rail index for a given position in the zigzag."""
        cycle = 2 * (self.rails - 1)
        pos_in_cycle = position % cycle
        return min(pos_in_cycle, cycle - pos_in_cycle)
