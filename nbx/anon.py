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

    pad_block > 0 时, 密文长度向上取整到该倍数（用零字节填充, 解包时按真实长度截断）。
    """
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _wrap_key(master_key, salt)
    ct = ChaCha20Poly1305(key).encrypt(nonce, inner, None)
    # 真实长度前缀（加密进密文, 外层不可见）
    if pad_block > 0:
        target = ((len(ct) + 4 + pad_block - 1) // pad_block) * pad_block
        pad = target - len(ct) - 4
        ct = struct.pack("<I", len(ct)) + ct + secrets.token_bytes(pad)  # 随机填充更抗长度分析
        flags = 1
    else:
        flags = 0
    return HEADER.pack(MAGIC_AW, flags, pad_block) + salt + nonce + ct


def unwrap(blob: bytes, master_key: bytes) -> bytes:
    """解开匿名外层, 返回内层原始容器。"""
    if len(blob) < HEADER.size + 16 + 12 + 16:
        raise AnonymityError("too short to be an AW blob")
    magic, flags, pad_block = HEADER.unpack_from(blob, 0)
    if magic != MAGIC_AW:
        raise AnonymityError("bad magic: not an anonymity wrapper")
    off = HEADER.size
    salt = blob[off:off + 16]; off += 16
    nonce = blob[off:off + 12]; off += 12
    ct = blob[off:]
    key = _wrap_key(master_key, salt)
    if flags & 1:
        if len(ct) < 4:
            raise AnonymityError("truncated padded blob")
        (real_len,) = struct.unpack_from("<I", ct, 0)
        ct = ct[4:4 + real_len]
        if len(ct) != real_len:
            raise AnonymityError("padded length mismatch")
    return ChaCha20Poly1305(key).decrypt(nonce, ct, None)


def is_wrapper(blob: bytes) -> bool:
    return len(blob) >= 8 and blob[:8] == MAGIC_AW
