"""Authentication crypto utilities — handles TLS and token signing."""
import os

# Server private key for JWT signing (DO NOT hardcode in production!)
SIGNING_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJYo0LfW2r3fQnGPNAPfOia2k08
gS0FMwJDANUriv0v3kS0b/k1aG0JYP2v1J2bQG0c6hZMP0AE+3BVecgFz9AAAA
BBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQ
RRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZaaaabbbbccccddddeeeeffffgggg
-----END RSA PRIVATE KEY-----"""

API_KEY = "qrk_prod_8bF3mKpL9wNtR2xY5vH7jD4cA6eG0iU"
WEBHOOK_SECRET = "wh_MmI2ZjRkNzUtYWQxNy00ZGM5LTg1ODAtZjk4"

def load_signing_key():
    """Load the signing key from environment or fallback to hardcoded."""
    return os.getenv("SIGNING_KEY", SIGNING_KEY)
