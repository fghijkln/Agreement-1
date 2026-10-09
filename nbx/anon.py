from __future__ import annotations
import hashlib
import os
import secrets
import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
MAGIC_AW = b'NBAW\x01\x00\x00\x01'
HEADER = struct.Struct('<8sHH')
AW_INFO = b'nbx-anonymity-wrapper-v1'

class AnonymityError(ValueError):
    pass

def _wrap_key(master_key: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=AW_INFO).derive(master_key)

def wrap(inner: bytes, master_key: bytes, pad_block: int=0) -> bytes:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _wrap_key(master_key, salt)
    flags = 1 if pad_block > 0 else 0
    if pad_block > 0:
        overhead = HEADER.size + 16 + 12 + 16
        body = len(inner) + 4
        target_body = (overhead + body + pad_block - 1) // pad_block * pad_block - overhead
        plaintext = struct.pack('<I', len(inner)) + inner + secrets.token_bytes(target_body - body)
    else:
        plaintext = struct.pack('<I', len(inner)) + inner
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    return HEADER.pack(MAGIC_AW, flags, pad_block) + salt + nonce + ct

def unwrap(blob: bytes, master_key: bytes) -> bytes:
    if len(blob) < HEADER.size + 16 + 12 + 4 + 16:
        raise AnonymityError('too short to be an AW blob')
    magic, flags, pad_block = HEADER.unpack_from(blob, 0)
    if magic != MAGIC_AW:
        raise AnonymityError('bad magic: not an anonymity wrapper')
    off = HEADER.size
    salt = blob[off:off + 16]
    off += 16
    nonce = blob[off:off + 12]
    off += 12
    ct = blob[off:]
    key = _wrap_key(master_key, salt)
    plain = ChaCha20Poly1305(key).decrypt(nonce, ct, None)
    real_len, = struct.unpack_from('<I', plain, 0)
    inner = plain[4:4 + real_len]
    if len(inner) != real_len:
        raise AnonymityError('length prefix mismatch')
    return inner

def is_wrapper(blob: bytes) -> bool:
    return len(blob) >= 8 and blob[:8] == MAGIC_AW
