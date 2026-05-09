"""
crypto_util.py — Advanced Cryptographic Utilities
Upgraded from SHA-256 to PBKDF2-HMAC with salt for password hashing.
Uses Fernet (AES-128-CBC + HMAC-SHA256) for field-level encryption.
"""

from cryptography.fernet import Fernet
import hashlib, os, base64, json, secrets

# ─── Key Management ──────────────────────────────────────────────────────────

def generate_key() -> bytes:
    return Fernet.generate_key()

def load_or_create_key(path: str = "key.key") -> bytes:
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    key = generate_key()
    with open(path, "wb") as f:
        f.write(key)
    return key

# ─── Field Encryption ────────────────────────────────────────────────────────

def encrypt(message: str, key: bytes) -> str:
    """Encrypt a string field, return base64 token."""
    if not message:
        return ""
    return Fernet(key).encrypt(message.encode()).decode()

def decrypt(token: str, key: bytes) -> str:
    """Decrypt a base64 token, return plaintext."""
    if not token:
        return ""
    return Fernet(key).decrypt(token.encode()).decode()

def encrypt_contact(contact: dict, key: bytes) -> dict:
    """Encrypt all sensitive fields of a contact dict."""
    sensitive = ["name", "phone", "email", "address", "company", "notes"]
    enc = {**contact}
    for field in sensitive:
        if field in enc and enc[field]:
            enc[field] = encrypt(enc[field], key)
    return enc

def decrypt_contact(contact: dict, key: bytes) -> dict:
    """Decrypt all sensitive fields of an encrypted contact dict."""
    sensitive = ["name", "phone", "email", "address", "company", "notes"]
    dec = {**contact}
    for field in sensitive:
        if field in dec and dec[field]:
            try:
                dec[field] = decrypt(dec[field], key)
            except Exception:
                dec[field] = "[decryption error]"
    return dec

# ─── Password Hashing (PBKDF2-HMAC-SHA256) ───────────────────────────────────

def hash_password(password: str, salt: str = None) -> dict:
    """
    Hash password using PBKDF2-HMAC-SHA256 with 260,000 iterations.
    Returns dict with 'hash' and 'salt' (both hex strings).
    """
    if salt is None:
        salt = secrets.token_hex(32)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        260_000,
    )
    return {"hash": dk.hex(), "salt": salt}

def check_password(password: str, stored: dict) -> bool:
    """
    Verify password against stored hash dict {hash, salt}.
    Also supports legacy SHA-256 (plain hex string) for migration.
    """
    # Legacy support: stored is a plain hex string (old SHA-256)
    if isinstance(stored, str):
        legacy = hashlib.sha256(password.encode()).hexdigest()
        return legacy == stored

    derived = hash_password(password, stored["salt"])
    return secrets.compare_digest(derived["hash"], stored["hash"])

# ─── Token Utilities ─────────────────────────────────────────────────────────

def generate_session_token() -> str:
    """Generate a secure random session token."""
    return secrets.token_urlsafe(48)
