"""NBX 消息信封 v1（nbx/message.py）— IM 负载帧。

一条 IM 消息 = 消息头（明文元数据，服务器可见）+ 加密体（ratchet 报文）。
设计原则：服务器路由所需的最小明文元数据（收件人指纹 + 消息 ID + 类型），
其余全部在加密体内——正文、文件名、时间戳、会话上下文服务器不可见。

明文头（服务器可见，用于路由/去重/优先级）:
  MAGIC_MSG(8) || ver(1) || ptype(1) || flags(1) || reserved(1)
  || sender_fp(8) || recv_fp(8) || msg_id(16) || body_len(4, LE)

负载类型 ptype:
  0x01 TEXT      文本消息（body = ratchet 报文）
  0x02 FILE_OFFER 文件提供（加密体内含文件名/大小/sha256，等待 ACK）
  0x03 FILE_CHUNK 文件分块（加密体内含 offset + 数据）
  0x04 FILE_ACK   文件确认
  0x05 TYPING     正在输入（body 可空）
  0x06 READ       已读回执（加密体内含已读到的 msg_id）
  0x07 HANDSHAKE  ratchet 握手载荷（FS 信封外壳）
  0x08 PING/0x09 PONG  存活探测

加密体即 nbx/ratchet.RatchetSession 的报文（逐消息前向保密）。
"""
from __future__ import annotations

import hashlib
import os
import struct

MAGIC_MSG = b"NBXMSG\x01\x00"     # 8 字节
VERSION = 1

PT_TEXT = 0x01
PT_FILE_OFFER = 0x02
PT_FILE_CHUNK = 0x03
PT_FILE_ACK = 0x04
PT_TYPING = 0x05
PT_READ = 0x06
PT_HANDSHAKE = 0x07
PT_PING = 0x08
PT_PONG = 0x09

HEADER = struct.Struct("<8sBBBB8s8s16sI")
HEADER_SIZE = HEADER.size          # 8+1+1+1+1+8+8+16+4 = 48


def fingerprint_of(pub_material: bytes) -> bytes:
    """8 字节收件人指纹（与 Identity.fingerprint 同源：SHA-256 前 8 字节）。"""
    return hashlib.sha256(pub_material).digest()[:8]


def pack_message(ptype: int, sender_fp: bytes, recv_fp: bytes,
                 body: bytes, msg_id: bytes | None = None,
                 flags: int = 0) -> bytes:
    if len(sender_fp) != 8 or len(recv_fp) != 8:
        raise ValueError("fingerprint must be 8 bytes")
    if msg_id is None:
        msg_id = os.urandom(16)
    hdr = HEADER.pack(MAGIC_MSG, VERSION, ptype, flags, 0,
                      sender_fp, recv_fp, msg_id, len(body))
    return hdr + body


def parse_message(blob: bytes) -> dict:
    if len(blob) < HEADER_SIZE or blob[:8] != MAGIC_MSG:
        raise ValueError("not an NBX message")
    magic, ver, ptype, flags, _r, sfp, rfp, mid, blen = HEADER.unpack(blob[:HEADER_SIZE])
    if ver != VERSION:
        raise ValueError(f"unsupported version {ver}")
    body = blob[HEADER_SIZE:]
    if len(body) != blen:
        raise ValueError("body length mismatch")
    return {"ptype": ptype, "flags": flags, "sender_fp": sfp,
            "recv_fp": rfp, "msg_id": mid, "body": body}


# ---------- 加密体内部的小型 TLV（TEXT/READ/FILE_* 通用） ----------

def _pack_fields(fields: list[tuple[int, bytes]]) -> bytes:
    out = b""
    for t, v in fields:
        out += struct.pack("<BI", t, len(v)) + v
    return out


def _parse_fields(data: bytes) -> dict[int, bytes]:
    out, off = {}, 0
    while off < len(data):
        t, ln = struct.unpack("<BI", data[off:off + 5])
        out[t] = data[off + 5:off + 5 + ln]
        off += 5 + ln
    return out


F_TEXT, F_MSG_REF, F_NAME, F_SIZE, F_SHA, F_OFFSET = 1, 2, 3, 4, 5, 6


def encode_text(text: str) -> bytes:
    return _pack_fields([(F_TEXT, text.encode("utf-8"))])


def decode_text(body: bytes) -> str:
    return _parse_fields(body)[F_TEXT].decode("utf-8")


def encode_read(ref_msg_id: bytes) -> bytes:
    return _pack_fields([(F_MSG_REF, ref_msg_id)])


def decode_read(body: bytes) -> bytes:
    return _parse_fields(body)[F_MSG_REF]


def encode_file_offer(name: str, size: int, sha256: bytes) -> bytes:
    return _pack_fields([(F_NAME, name.encode("utf-8")),
                         (F_SIZE, struct.pack("<Q", size)),
                         (F_SHA, sha256)])


def decode_file_offer(body: bytes) -> tuple[str, int, bytes]:
    f = _parse_fields(body)
    return (f[F_NAME].decode("utf-8"),
            struct.unpack("<Q", f[F_SIZE])[0],
            f[F_SHA])


def encode_file_chunk(offset: int, data: bytes) -> bytes:
    return _pack_fields([(F_OFFSET, struct.pack("<Q", offset)), (F_TEXT, data)])


def decode_file_chunk(body: bytes) -> tuple[int, bytes]:
    f = _parse_fields(body)
    return struct.unpack("<Q", f[F_OFFSET])[0], f[F_TEXT]


def new_msg_id() -> bytes:
    return os.urandom(16)
