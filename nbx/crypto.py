from __future__ import annotations
import base64
import os
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
NONCE_SIZE = 12
KEY_INFO = b'nbx-file-key-v1'

def generate_master_key() -> str:
    return base64.b64encode(os.urandom(32)).decode('ascii')

def derive_subkey(master_key: bytes, file_salt: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=file_salt, info=KEY_INFO)
    return hkdf.derive(master_key)

def encrypt(data: bytes, master_key: bytes) -> bytes:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_subkey(master_key, salt)
    ct = ChaCha20Poly1305(key).encrypt(nonce, data, None)
    return salt + nonce + ct

def decrypt(blob: bytes, master_key: bytes) -> bytes:
    if len(blob) < 16 + NONCE_SIZE + 16:
        raise ValueError('ciphertext too short')
    salt, nonce, ct = (blob[:16], blob[16:16 + NONCE_SIZE], blob[16 + NONCE_SIZE:])
    key = derive_subkey(master_key, salt)
    return ChaCha20Poly1305(key).decrypt(nonce, ct, None)
