"""Anonymity Wrapper — 可选的元数据隐藏外层。

问题: NBX 容器的元数据（JSON 头）是明文的——文件名、类型、大小、时间戳
对任何拿到文件的人都可见。

方案: Anonymity Wrapper 把整个 NBX 容器（含元数据）再包一层加密:
    MAGIC_AW(8) || ver(1) || flags(1) || salt(16) || nonce(12) || ct || tag implied
外层观察者只能看到: 随机长度、随机内容的字节。全部元数据都在密文里。

填充 (padding): 可选 --pad 把长度补齐到指定倍数，抵抗流量分析
（密文长度本身也泄露信息）。

开启时机（用户自选）:
  nbx anon pack inner.nbx outer.nbx [--pad 4096]
  nbx anon unpack outer.nbx inner.nbx --keyfile nbx.key
"""
from __future__ import annotations

import hashlib
import os
import secrets
import struct

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MAGIC_AW = b"NBAW\x01\x00\x00\x01"   # 8B: NB Anonymity Wrapper
HEADER = struct.Struct("<8sHH")       # magic + flags + pad_block(16bit)
AW_INFO = b"nbx-anonymity-wrapper-v1"


class AnonymityError(ValueError):
    pass


def _wrap_key(master_key: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=salt, info=AW_INFO).derive(master_key)


def wrap(inner: bytes, master_key: bytes, pad_block: int = 0) -> bytes:
    """把任意内层容器（通常为完整 .nbx）包成匿名外层。

    pad_block > 0 时把明文（长度前缀 + inner）预填充到使外层总长
    恰为 pad_block 的整数倍，ct 本身对齐——unwrap 单次 AEAD 解密即可，
    无需猜测填充长度。外层观察者（无密钥）无法区分补齐前的大小。
    """
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _wrap_key(master_key, salt)
    flags = 1 if pad_block > 0 else 0
    if pad_block > 0:
        # 外层总长 = HEADER(12) + salt(16) + nonce(12) + len(plain) + tag(16)
        overhead = HEADER.size + 16 + 12 + 16
        body = len(inner) + 4
        target_body = ((overhead + body + pad_block - 1) // pad_block) * pad_block - overhead
        plaintext = struct.pack("<I", len(inner)) + inner + secrets.token_bytes(target_body - body)
    else:
        plaintext = struct.pack("<I", len(inner)) + inner
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    return HEADER.pack(MAGIC_AW, flags, pad_block) + salt + nonce + ct


def unwrap(blob: bytes, master_key: bytes) -> bytes:
    """解开匿名外层, 返回内层原始容器。单次 AEAD 解密。"""
    if len(blob) < HEADER.size + 16 + 12 + 4 + 16:
        raise AnonymityError("too short to be an AW blob")
    magic, flags, pad_block = HEADER.unpack_from(blob, 0)
    if magic != MAGIC_AW:
        raise AnonymityError("bad magic: not an anonymity wrapper")
    off = HEADER.size
    salt = blob[off:off + 16]; off += 16
    nonce = blob[off:off + 12]; off += 12
    ct = blob[off:]
    key = _wrap_key(master_key, salt)
    plain = ChaCha20Poly1305(key).decrypt(nonce, ct, None)
    (real_len,) = struct.unpack_from("<I", plain, 0)
    inner = plain[4:4 + real_len]
    if len(inner) != real_len:
        raise AnonymityError("length prefix mismatch")
    return inner


def is_wrapper(blob: bytes) -> bool:
    return len(blob) >= 8 and blob[:8] == MAGIC_AW
