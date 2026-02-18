# 🔐 Crypto Toolkit

<p align="center">
  <strong>A comprehensive Python cryptography library</strong><br>
  Classical ciphers • Modern encryption • File security
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License">
  <img src="https://img.shields.io/badge/Status-Production--Ready-brightgreen?style=for-the-badge" alt="Production Ready">
</p>

---

## 📖 Overview

**Crypto Toolkit** is a showcase cryptography project demonstrating both historical and modern encryption techniques. Built with Python and the industry-standard `cryptography` library, it provides a clean API for learning, teaching, and securing data.

| Classical Ciphers | Modern Cryptography |
|-------------------|---------------------|
| Caesar, Vigenère  | AES-128 (Fernet)    |
| Rail Fence        | RSA (2048-bit)      |
| Substitution      | SHA-256/384/512     |

---

## ✨ Features

### 🏛️ Classical Ciphers *(educational)*
- **Caesar** — Shift cipher with brute-force cryptanalysis
- **Vigenère** — Polyalphabetic substitution
- **Rail Fence** — Transposition (zigzag) cipher
- **Substitution** — Monoalphabetic with random key generation

### 🔒 Modern Cryptography *(production-ready)*
- **AES (Fernet)** — Symmetric authenticated encryption
- **RSA** — Asymmetric encryption with OAEP padding
- **PBKDF2** — Password-based key derivation (480k iterations)
- **SHA-256/384/512** — Cryptographic hashing

### 📁 File Encryption
- Encrypt any file with a password or key
- Automatic salt generation for password-based encryption
- Simple CLI and Python API

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/crypto-toolkit.git
cd crypto-toolkit

# Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/macOS

# Install
pip install -r requirements.txt
pip install -e .
```

---

## 📚 Usage

### Python API

```python
from crypto_toolkit.classical import CaesarCipher, VigenereCipher
from crypto_toolkit.modern import AESCipher, RSACipher, Hasher

# Caesar cipher
caesar = CaesarCipher(shift=3)
print(caesar.encrypt("Hello, World!"))   # Khoor, Zruog!

# Brute-force attack (cryptanalysis)
for shift, text in CaesarCipher.brute_force("Khoor Zruog"):
    print(f"Shift {shift}: {text}")

# Vigenère cipher
vigenere = VigenereCipher(key="SECRET")
encrypted = vigenere.encrypt("Attack at dawn")

# AES encryption
key = AESCipher.generate_key()
aes = AESCipher(key=key)
ciphertext = aes.encrypt(b"Sensitive data")
plaintext = aes.decrypt(ciphertext)

# RSA
rsa = RSACipher(key_size=2048)
encrypted = rsa.encrypt("Secret message")

# Hashing
hash_value = Hasher.hash("Hello World", "sha256")
```

### Command Line

```bash
# Classical ciphers
python cli.py caesar encrypt -t "Hello World" -s 3
python cli.py caesar brute -t "Khoor Zruog"
python cli.py vigenere encrypt -t "Attack at dawn" -k SECRET
python cli.py railfence encrypt -t "WEAREDISCOVERED" -r 3

# Hashing
python cli.py hash "Hello World" -a sha256

# File encryption (password-based)
python cli.py file encrypt -i document.txt -p mypassword
python cli.py file decrypt -i document.txt.enc -p mypassword

# RSA key pair
python cli.py rsa generate -o mykey
# → mykey.pem (private), mykey_public.pem (public)
```

### Demo

```bash
python examples/demo.py
```

Runs through all ciphers and algorithms with example outputs.

---

## 📂 Project Structure

```
crypto-toolkit/
├── crypto_toolkit/
│   ├── classical/           # Caesar, Vigenère, Rail Fence, Substitution
│   ├── modern/              # AES, RSA, hashing
│   └── file_crypto.py       # File encryption
├── cli.py                   # Command-line interface
├── examples/
│   └── demo.py              # Interactive demo
├── tests/                   # Unit tests
├── requirements.txt
└── pyproject.toml
```

---

## 🧪 Testing

```bash
pip install pytest
pytest tests/ -v
```

---

## 🔒 Security Notes

| Use Case | Recommendation |
|----------|----------------|
| Classical ciphers | Educational only — **not secure** |
| AES / RSA | Production-ready via `cryptography` library |
| File encryption | Use strong, unique passwords |
| Keys | Never commit `*.pem` or secrets to git |

---

## 📜 License

MIT License — free for personal and commercial use.

---

<p align="center">
  <sub>Built with Python • Powered by cryptography</sub>
</p>
