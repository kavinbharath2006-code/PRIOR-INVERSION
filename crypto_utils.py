import hashlib, json, hmac, os

SECRET_KEY = b"bdl-prototype-secret"   # in prod: RSA/Ed25519 private key

def hash_credential(payload: dict) -> str:
    """SHA-256 of sorted JSON payload."""
    raw = json.dumps(payload, sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()

def sign(payload: dict) -> str:
    """HMAC-SHA256 mock signature (replace with RSA in prod)."""
    raw = json.dumps(payload, sort_keys=True).encode()
    return hmac.new(SECRET_KEY, raw, hashlib.sha256).hexdigest()

def verify_signature(payload: dict, sig: str) -> bool:
    return hmac.compare_digest(sign(payload), sig)