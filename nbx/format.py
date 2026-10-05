"""NBX 专属文件容器格式。

结构（小端）:
  offset 0   8B  魔数 b"NBXFILE\\x01"
  offset 8   1B  版本
  offset 9   1B  标志位
  offset 10  2B  元数据长度 (LE uint16)
  offset 12  M   元数据 JSON (UTF-8)
  ...        4B  数据长度 (LE uint32)
  ...        N   数据
  ...        32B SHA-256(数据)
"""
from __future__ import annotations

import hashlib
import json
import struct

MAGIC = b"NBXFILE\x01"
VERSION = 1
FLAG_ENCRYPTED = 0x01

HEADER = struct.Struct("<8sBBH")


class NBXError(ValueError):
    pass


def pack(data: bytes, meta: dict | None = None) -> bytes:
    meta_bytes = json.dumps(meta or {}, ensure_ascii=False).encode("utf-8")
    if len(meta_bytes) > 0xFFFF:
        raise NBXError("metadata too large")
    if len(data) > 0xFFFFFFFF:
        raise NBXError("data too large")
    digest = hashlib.sha256(data).digest()
    return (
        HEADER.pack(MAGIC, VERSION, 0, len(meta_bytes))
        + meta_bytes
        + struct.pack("<I", len(data))
        + data
        + digest
    )


def unpack(blob: bytes) -> tuple[dict, bytes]:
    if len(blob) < HEADER.size + 4 + 32:
        raise NBXError("file too short")
    magic, version, flags, meta_len = HEADER.unpack_from(blob, 0)
    if magic != MAGIC:
        raise NBXError("bad magic: not an NBX file")
    if version != VERSION:
        raise NBXError(f"unsupported version {version}")
    off = HEADER.size
    meta = json.loads(blob[off : off + meta_len].decode("utf-8"))
    off += meta_len
    (data_len,) = struct.unpack_from("<I", blob, off)
    off += 4
    data = blob[off : off + data_len]
    if len(data) != data_len:
        raise NBXError("truncated data")
    (digest,) = struct.unpack_from("<32s", blob, off + data_len)
    if hashlib.sha256(data).digest() != digest:
        raise NBXError("checksum mismatch: data corrupted")
    return meta, data
