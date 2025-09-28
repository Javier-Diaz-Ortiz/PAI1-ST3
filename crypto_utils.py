# crypto_utils.py
import secrets
import hashlib
import hmac
import binascii

# Genera salt seguro
def generate_salt(nbytes: int = 16) -> bytes:
    return secrets.token_bytes(nbytes)

# Deriva una "verifier" (clave) a partir de la contraseña: PBKDF2-HMAC-SHA256
def derive_verifier(password: str, salt: bytes, iterations: int = 200_000, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen)

# HMAC-SHA256
def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()

# Comparación segura en tiempo constante
def secure_compare(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

# Generar nonce (hex string)
def gen_nonce_hex(nbytes: int = 16) -> str:
    return secrets.token_hex(nbytes)

# Utilidades para hex <-> bytes
def to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode()

def from_hex(s: str) -> bytes:
    return binascii.unhexlify(s.encode())
