#!/usr/bin/env python3
"""Demo script showcasing all crypto toolkit features."""

from crypto_toolkit.classical import CaesarCipher, VigenereCipher, RailFenceCipher, SubstitutionCipher
from crypto_toolkit.modern import AESCipher, RSACipher, Hasher


def main():
    print("=" * 60)
    print("  CRYPTO TOOLKIT DEMO")
    print("=" * 60)

    # Caesar
    print("\n📜 CAESAR CIPHER (shift=3)")
    caesar = CaesarCipher(shift=3)
    msg = "Hello, World!"
    enc = caesar.encrypt(msg)
    dec = caesar.decrypt(enc)
    print(f"  Original:  {msg}")
    print(f"  Encrypted: {enc}")
    print(f"  Decrypted: {dec}")

    # Vigenère
    print("\n📜 VIGENÈRE CIPHER (key=KEY)")
    vigenere = VigenereCipher(key="KEY")
    msg = "ATTACKATDAWN"
    enc = vigenere.encrypt(msg)
    dec = vigenere.decrypt(enc)
    print(f"  Original:  {msg}")
    print(f"  Encrypted: {enc}")
    print(f"  Decrypted: {dec}")

    # Rail Fence
    print("\n📜 RAIL FENCE CIPHER (3 rails)")
    rail = RailFenceCipher(rails=3)
    msg = "WEAREDISCOVERED"
    enc = rail.encrypt(msg)
    dec = rail.decrypt(enc)
    print(f"  Original:  {msg}")
    print(f"  Encrypted: {enc}")
    print(f"  Decrypted: {dec}")

    # Substitution
    print("\n📜 SUBSTITUTION CIPHER")
    sub = SubstitutionCipher()
    msg = "Hello"
    enc = sub.encrypt(msg)
    dec = sub.decrypt(enc)
    print(f"  Original:  {msg}")
    print(f"  Key:       {sub.get_key()}")
    print(f"  Encrypted: {enc}")
    print(f"  Decrypted: {dec}")

    # Hash
    print("\n🔐 HASHING (SHA-256)")
    msg = "Hello, World!"
    h = Hasher.hash(msg)
    print(f"  Message: {msg}")
    print(f"  Hash:    {h}")

    # AES
    print("\n🔐 AES ENCRYPTION")
    key = AESCipher.generate_key()
    aes = AESCipher(key=key)
    msg = b"Secret data"
    enc = aes.encrypt(msg)
    dec = aes.decrypt(enc)
    print(f"  Original:  {msg}")
    print(f"  Encrypted: {enc[:50]}...")
    print(f"  Decrypted: {dec}")

    # RSA
    print("\n🔐 RSA ENCRYPTION")
    rsa = RSACipher(key_size=1024)  # Small for demo speed
    msg = "Secret message"
    enc = rsa.encrypt(msg)
    dec = rsa.decrypt(enc)
    print(f"  Original:  {msg}")
    print(f"  Encrypted: {enc[:40]}...")
    print(f"  Decrypted: {dec}")

    print("\n" + "=" * 60)
    print("  Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
