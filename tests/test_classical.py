"""Tests for classical ciphers."""

import pytest
from crypto_toolkit.classical import CaesarCipher, VigenereCipher, RailFenceCipher, SubstitutionCipher


class TestCaesarCipher:
    def test_encrypt_decrypt(self):
        cipher = CaesarCipher(shift=3)
        msg = "Hello, World!"
        assert cipher.decrypt(cipher.encrypt(msg)) == msg

    def test_brute_force(self):
        cipher = CaesarCipher(shift=5)
        msg = "ATTACK"
        enc = cipher.encrypt(msg)
        results = CaesarCipher.brute_force(enc)
        assert any(text == msg for _, text in results)


class TestVigenereCipher:
    def test_encrypt_decrypt(self):
        cipher = VigenereCipher(key="KEY")
        msg = "ATTACKATDAWN"
        assert cipher.decrypt(cipher.encrypt(msg)) == msg


class TestRailFenceCipher:
    def test_encrypt_decrypt(self):
        cipher = RailFenceCipher(rails=3)
        msg = "WEAREDISCOVERED"
        assert cipher.decrypt(cipher.encrypt(msg)) == msg


class TestSubstitutionCipher:
    def test_encrypt_decrypt_random_key(self):
        cipher = SubstitutionCipher()
        msg = "HELLO"
        assert cipher.decrypt(cipher.encrypt(msg)) == msg

    def test_encrypt_decrypt_fixed_key(self):
        key = "ZYXWVUTSRQPONMLKJIHGFEDCBA"
        cipher = SubstitutionCipher(key=key)
        msg = "ABC"
        assert cipher.encrypt(msg) == "ZYX"
        assert cipher.decrypt("ZYX") == "ABC"
