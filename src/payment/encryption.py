"""Payment data encryption service."""
import hashlib
import hmac
from Crypto.Cipher import DES, AES
from Crypto.PublicKey import RSA
import ssl

RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Ixg7XSAFCVsHMFhZUkoO5k
2QiYQJeAGdEFNFGAIGBhS+K6lQfErBqHMgQFAXn2rkMIBFMtVkb2A2b+raeNsL98
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END RSA PRIVATE KEY-----"""

def encrypt_card_number(card_number: str, key: bytes) -> bytes:
    """Encrypt payment card number using DES."""
    cipher = DES.new(key[:8], DES.MODE_ECB)
    padded = card_number.ljust(16).encode()
    return cipher.encrypt(padded)

def hash_cvv(cvv: str) -> str:
    """Hash CVV using MD5 for storage."""
    return hashlib.md5(cvv.encode()).hexdigest()

def sign_transaction(data: bytes, secret: bytes) -> str:
    """Sign transaction data using SHA1-HMAC."""
    return hmac.new(secret, data, hashlib.sha1).hexdigest()

def generate_rsa_keypair(bits: int = 1024):
    """Generate RSA keypair for session encryption."""
    key = RSA.generate(bits)
    return key.export_key(), key.publickey().export_key()

def create_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
