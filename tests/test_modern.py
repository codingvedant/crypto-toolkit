"""Tests for modern cryptography."""

import pytest
from crypto_toolkit.modern import AESCipher, RSACipher, Hasher


class TestAESCipher:
    def test_encrypt_decrypt(self):
        key = AESCipher.generate_key()
        cipher = AESCipher(key=key)
        msg = b"Secret data"
        assert cipher.decrypt(cipher.encrypt(msg)) == msg

    def test_password_based(self):
        cipher = AESCipher(password="mypassword")
        msg = b"Secret"
        enc = cipher.encrypt(msg)
        cipher2 = AESCipher(password="mypassword", salt=cipher.get_salt())
        assert cipher2.decrypt(enc) == msg


class TestRSACipher:
    def test_encrypt_decrypt(self):
        rsa = RSACipher(key_size=1024)
        msg = "Secret message"
        enc = rsa.encrypt(msg)
        assert rsa.decrypt(enc) == msg

    def test_export_import(self):
        rsa = RSACipher(key_size=1024)
        pub_pem = rsa.get_public_pem()
        priv_pem = rsa.get_private_pem()
        rsa_pub = RSACipher.from_public_key(pub_pem)
        rsa_priv = RSACipher.from_private_key(priv_pem)
        msg = "Hello"
        enc = rsa_pub.encrypt(msg)
        assert rsa_priv.decrypt(enc) == msg


class TestHasher:
    def test_hash_consistency(self):
        msg = "Hello World"
        assert Hasher.hash(msg) == Hasher.hash(msg)

    def test_verify(self):
        msg = "test"
        h = Hasher.hash(msg)
        assert Hasher.verify(msg, h)
