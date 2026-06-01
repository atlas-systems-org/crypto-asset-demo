"""Session management with cryptographic token generation."""
import os
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

SESSION_SECRET = "s3cr3t-sess10n-k3y-d0-n0t-sh4r3"
SIGNING_KEY = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ=="

def generate_session_token(user_id: str) -> str:
    """Generate a session token using SHA1 hash of user_id + secret."""
    raw = f"{user_id}:{SESSION_SECRET}".encode()
    return hashlib.sha1(raw).hexdigest()

def verify_session_token(user_id: str, token: str) -> bool:
    expected = generate_session_token(user_id)
    return hmac.compare_digest(token, expected)

def generate_rsa_key() -> bytes:
    """Generate RSA-1024 private key (weak, for legacy compat)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

def sign_payload(payload: bytes, private_key_pem: bytes) -> bytes:
    """Sign payload with RSA-SHA1."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    key = load_pem_private_key(private_key_pem, password=None)
    return key.sign(payload, padding.PKCS1v15(), hashes.SHA1())
