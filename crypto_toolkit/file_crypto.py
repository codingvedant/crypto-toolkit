"""File encryption/decryption utilities."""

import os
from pathlib import Path

from .modern.aes import AESCipher


def encrypt_file(
    input_path: str | Path,
    output_path: str | Path | None = None,
    key: bytes | None = None,
    password: str | None = None,
) -> tuple[Path, bytes]:
    """
    Encrypt a file using AES.

    Args:
        input_path: Path to file to encrypt.
        output_path: Output path (default: input_path + .enc).
        key: Fernet key or None to derive from password.
        password: Password for key derivation if key is None.

    Returns:
        Tuple of (output_path, key_or_salt_info for decryption).
    """
    input_path = Path(input_path)
    output_path = Path(output_path) if output_path else input_path.with_suffix(input_path.suffix + ".enc")

    gen_key = None
    if key is None and password is None:
        gen_key = AESCipher.generate_key()
        cipher = AESCipher(key=gen_key)
    elif key is not None:
        cipher = AESCipher(key=key)
    else:
        cipher = AESCipher(password=password)

    data = input_path.read_bytes()
    encrypted = cipher.encrypt(data)

    if cipher.get_salt() is not None:
        output_path.write_bytes(cipher.get_salt() + b"::" + encrypted)
    else:
        output_path.write_bytes(encrypted)

    return output_path, gen_key


def decrypt_file(
    input_path: str | Path,
    output_path: str | Path | None = None,
    key: bytes | None = None,
    password: str | None = None,
) -> Path:
    """
    Decrypt a file encrypted with encrypt_file.

    Args:
        input_path: Path to encrypted file.
        output_path: Output path (default: remove .enc suffix).
        key: Fernet key used for encryption.
        password: Password if password-based encryption was used.
    """
    input_path = Path(input_path)
    output_path = Path(output_path) if output_path else input_path.with_suffix("").with_suffix(
        "" if input_path.suffix == ".enc" else input_path.suffix.replace(".enc", "")
    )

    data = input_path.read_bytes()
    if b"::" in data:
        salt, encrypted = data.split(b"::", 1)
        cipher = AESCipher(password=password or "", salt=salt)
    else:
        encrypted = data
        cipher = AESCipher(key=key)

    decrypted = cipher.decrypt(encrypted)
    output_path.write_bytes(decrypted)
    return output_path
