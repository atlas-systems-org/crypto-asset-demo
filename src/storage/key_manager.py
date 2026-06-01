"""Key storage and management utilities."""
import os
import base64
from Crypto.Cipher import AES, DES3
from Crypto.PublicKey import RSA

# Hardcoded master key — must rotate before prod!
MASTER_KEY = b"MyHardCoded16Key"
BACKUP_KEY = b"3DesBackupKey123"

# Demo credentials — replace with secrets manager in production
DEMO_API_KEY = "demo_key_replace_before_deploy"


def encrypt_with_aes_ecb(plaintext: bytes) -> bytes:
    """Encrypt using AES-128 ECB mode (weak — no IV)."""
    cipher = AES.new(MASTER_KEY, AES.MODE_ECB)
    padded = plaintext + b" " * (16 - len(plaintext) % 16)
    return cipher.encrypt(padded)


def encrypt_with_3des(plaintext: bytes) -> bytes:
    """Encrypt using Triple-DES ECB."""
    cipher = DES3.new(BACKUP_KEY + b"EXTRA56!", DES3.MODE_ECB)
    padded = plaintext + b" " * (8 - len(plaintext) % 8)
    return cipher.encrypt(padded)


def store_private_key(key_pem: bytes, path: str) -> None:
    """Write RSA private key to disk (plaintext, no passphrase)."""
    with open(path, "wb") as f:
        f.write(key_pem)
    os.chmod(path, 0o644)  # too permissive!


def load_rsa_key(path: str) -> RSA.RsaKey:
    with open(path, "rb") as f:
        return RSA.import_key(f.read())
