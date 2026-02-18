#!/usr/bin/env python3
"""
Crypto Toolkit - Command-line interface for encryption and decryption.
"""

import argparse
import base64
import sys
from pathlib import Path

from crypto_toolkit.classical import CaesarCipher, VigenereCipher, RailFenceCipher, SubstitutionCipher
from crypto_toolkit.modern import AESCipher, RSACipher, Hasher
from crypto_toolkit.file_crypto import encrypt_file, decrypt_file


def cmd_caesar(args):
    cipher = CaesarCipher(shift=args.shift)
    if args.mode == "encrypt":
        print(cipher.encrypt(args.text))
    elif args.mode == "decrypt":
        print(cipher.decrypt(args.text))
    else:
        for shift, text in CaesarCipher.brute_force(args.text):
            print(f"Shift {shift:2d}: {text}")


def cmd_vigenere(args):
    cipher = VigenereCipher(key=args.key)
    if args.mode == "encrypt":
        print(cipher.encrypt(args.text))
    else:
        print(cipher.decrypt(args.text))


def cmd_railfence(args):
    cipher = RailFenceCipher(rails=args.rails)
    if args.mode == "encrypt":
        print(cipher.encrypt(args.text))
    else:
        print(cipher.decrypt(args.text))


def cmd_substitution(args):
    cipher = SubstitutionCipher(key=args.key) if args.key else SubstitutionCipher()
    if args.mode == "encrypt":
        print(cipher.encrypt(args.text))
        if not args.key:
            print(f"[Key: {cipher.get_key()}]", file=sys.stderr)
    else:
        if not args.key:
            print("Error: --key required for decryption", file=sys.stderr)
            sys.exit(1)
        print(cipher.decrypt(args.text))


def cmd_aes(args):
    if args.mode == "encrypt":
        key = AESCipher.generate_key()
        cipher = AESCipher(key=key)
        encrypted = cipher.encrypt(args.text.encode() if isinstance(args.text, str) else args.text)
        print(base64.urlsafe_b64encode(encrypted).decode())
        print(f"[KEY - save this]: {key.decode()}", file=sys.stderr)
    else:
        cipher = AESCipher(key=args.key.encode() if isinstance(args.key, str) else args.key)
        decrypted = cipher.decrypt(base64.urlsafe_b64decode(args.text))
        print(decrypted.decode())


def cmd_hash(args):
    result = Hasher.hash(args.text, algorithm=args.algorithm)
    print(result)


def cmd_rsa(args):
    if args.action == "generate":
        cipher = RSACipher(key_size=args.bits)
        priv_path = Path(args.output + ".pem") if args.output else Path("private.pem")
        pub_path = Path(args.output + "_public.pem") if args.output else Path("public.pem")
        if not args.output:
            priv_path, pub_path = Path("private.pem"), Path("public.pem")
        priv_path.write_bytes(cipher.get_private_pem())
        pub_path.write_bytes(cipher.get_public_pem())
        print(f"Generated: {priv_path}, {pub_path}")
    elif args.action == "encrypt":
        pub = Path(args.public_key).read_bytes()
        cipher = RSACipher.from_public_key(pub)
        ct = cipher.encrypt(args.text.encode())
        print(base64.b64encode(ct).decode())
    else:
        priv = Path(args.private_key).read_bytes()
        cipher = RSACipher.from_private_key(priv)
        ct = base64.b64decode(args.ciphertext)
        print(cipher.decrypt(ct).decode())


def cmd_file(args):
    key = args.key.encode() if args.key and isinstance(args.key, str) else args.key
    if args.mode == "encrypt":
        out, gen_key = encrypt_file(args.input, args.output, key=key, password=args.password)
        print(f"Encrypted: {out}")
        if not args.password and not args.key and gen_key:
            print(f"[KEY - save for decryption]: {gen_key.decode()}", file=sys.stderr)
    else:
        decrypt_file(args.input, args.output, key=key, password=args.password)
        out_path = args.output or str(Path(args.input).with_suffix(""))
        print(f"Decrypted to: {out_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Crypto Toolkit - Classical & modern cryptography CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Caesar cipher
  python cli.py caesar encrypt -t "Hello World" -s 3
  python cli.py caesar decrypt -t "Khoor Zruog" -s 3
  python cli.py caesar brute -t "Khoor Zruog"

  # Vigenère
  python cli.py vigenere encrypt -t "Hello" -k KEY

  # Hash
  python cli.py hash "Hello World" -a sha256

  # File encryption (password-based)
  python cli.py file encrypt -i secret.txt -p mypassword
  python cli.py file decrypt -i secret.txt.enc -p mypassword

  # RSA key generation
  python cli.py rsa generate --output mykey
        """,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Caesar
    caesar = subparsers.add_parser("caesar", help="Caesar cipher")
    caesar.add_argument("mode", choices=["encrypt", "decrypt", "brute"])
    caesar.add_argument("-t", "--text", required=True)
    caesar.add_argument("-s", "--shift", type=int, default=3)
    caesar.set_defaults(func=cmd_caesar)

    # Vigenère
    vig = subparsers.add_parser("vigenere", help="Vigenère cipher")
    vig.add_argument("mode", choices=["encrypt", "decrypt"])
    vig.add_argument("-t", "--text", required=True)
    vig.add_argument("-k", "--key", required=True)
    vig.set_defaults(func=cmd_vigenere)

    # Rail Fence
    rf = subparsers.add_parser("railfence", help="Rail Fence cipher")
    rf.add_argument("mode", choices=["encrypt", "decrypt"])
    rf.add_argument("-t", "--text", required=True)
    rf.add_argument("-r", "--rails", type=int, default=3)
    rf.set_defaults(func=cmd_railfence)

    # Substitution
    sub = subparsers.add_parser("substitution", help="Substitution cipher")
    sub.add_argument("mode", choices=["encrypt", "decrypt"])
    sub.add_argument("-t", "--text", required=True)
    sub.add_argument("-k", "--key", help="26-letter key (omit for random on encrypt)")
    sub.set_defaults(func=cmd_substitution)

    # AES
    aes = subparsers.add_parser("aes", help="AES encryption (Fernet)")
    aes.add_argument("mode", choices=["encrypt", "decrypt"])
    aes.add_argument("-t", "--text", required=True)
    aes.add_argument("-k", "--key", help="Required for decrypt")
    aes.set_defaults(func=cmd_aes)

    # Hash
    h = subparsers.add_parser("hash", help="Compute hash")
    h.add_argument("text", nargs="?", default="", help="Text to hash (or stdin)")
    h.add_argument("-a", "--algorithm", choices=["sha256", "sha384", "sha512", "md5"], default="sha256")
    h.set_defaults(func=cmd_hash)

    # RSA
    rsa_p = subparsers.add_parser("rsa", help="RSA operations")
    rsa_p.add_argument("action", choices=["generate", "encrypt", "decrypt"])
    rsa_p.add_argument("--bits", type=int, default=2048)
    rsa_p.add_argument("--output", "-o")
    rsa_p.add_argument("--public-key")
    rsa_p.add_argument("--private-key")
    rsa_p.add_argument("-t", "--text")
    rsa_p.add_argument("--ciphertext")
    rsa_p.set_defaults(func=cmd_rsa)

    # File
    f = subparsers.add_parser("file", help="File encryption")
    f.add_argument("mode", choices=["encrypt", "decrypt"])
    f.add_argument("-i", "--input", required=True)
    f.add_argument("-o", "--output")
    f.add_argument("-p", "--password", help="Password for encryption/decryption")
    f.add_argument("-k", "--key", help="Fernet key for decrypt (if not password-based)")
    f.set_defaults(func=cmd_file)

    args = parser.parse_args()
    if args.command == "hash" and not args.text and not sys.stdin.isatty():
        args.text = sys.stdin.read()
    args.func(args)


if __name__ == "__main__":
    main()
