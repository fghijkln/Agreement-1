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

    pad_block > 0 时, 外层总长向上取整到该倍数。真实长度前缀加密进密文内,
    外层观察者（无密钥）无法区分补齐前的大小。
    """
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _wrap_key(master_key, salt)
    # 真实长度前缀放在被加密的明文里，外层不可见
    plaintext = struct.pack("<I", len(inner)) + inner
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    flags = 0
    if pad_block > 0:
        body = 12 + len(ct)  # nonce 已在 ct 外计? 不: ct 含 AEAD tag
        # 外层总长 = HEADER(12) + salt(16) + nonce(12) + ct(len+tag)
        total_body = 16 + 12 + len(ct)
        target = ((HEADER.size + total_body + pad_block - 1) // pad_block) * pad_block
        pad = target - HEADER.size - total_body
        flags = 1
    else:
        pad = 0
    return HEADER.pack(MAGIC_AW, flags, pad_block) + salt + nonce + ct + secrets.token_bytes(pad)


def unwrap(blob: bytes, master_key: bytes) -> bytes:
    """解开匿名外层, 返回内层原始容器。"""
    if len(blob) < HEADER.size + 16 + 12 + 4 + 16:
        raise AnonymityError("too short to be an AW blob")
    magic, flags, pad_block = HEADER.unpack_from(blob, 0)
    if magic != MAGIC_AW:
        raise AnonymityError("bad magic: not an anonymity wrapper")
    off = HEADER.size
    salt = blob[off:off + 16]; off += 16
    nonce = blob[off:off + 12]; off += 12
    ct = blob[off:]
    if flags & 1 and pad_block:
        # 尾部填充是随机字节：AEAD 解密会自动忽略吗？不会，填充在 ct 之外。
        # 但我们不知道 pad 的确切长度（这正是设计目标），所以尝试逐步裁剪直到解密成功。
        # 更快：外层总长已对齐 pad_block，pad 长度 = 总长 - HEADER - 16 - 12 - ct_real。
        # ct_real 未知，但必然满足 (HEADER+16+12+ct_real+pad) % pad_block == 0。
        # 逐个候选 pad 长度（0..pad_block-1 步长）尝试最坏 pad_block 次；实际只用试
        # 使剩余长度合法的那几个。这里做有界尝试。
        key = _wrap_key(master_key, salt)
        # pad 长度在 [0, pad_block) 内且外层已对齐，最多试 pad_block 次
        for cut in range(0, min(pad_block, len(ct) - 16) + 1):
            trial = ct[:len(ct) - cut] if cut else ct
            try:
                plain = ChaCha20Poly1305(key).decrypt(nonce, trial, None)
            except Exception:
                continue
            (real_len,) = struct.unpack_from("<I", plain, 0)
            if 4 + real_len == len(plain):
                return plain[4:]
            # AEAD 通过但长度不符：继续
        raise AnonymityError("padding recovery failed: no valid ciphertext length")
    key = _wrap_key(master_key, salt)
    plain = ChaCha20Poly1305(key).decrypt(nonce, ct, None)
    (real_len,) = struct.unpack_from("<I", plain, 0)
    inner = plain[4:4 + real_len]
    if len(inner) != real_len:
        raise AnonymityError("length prefix mismatch")
    return inner


def is_wrapper(blob: bytes) -> bool:
    return len(blob) >= 8 and blob[:8] == MAGIC_AW
