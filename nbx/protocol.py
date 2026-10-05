"""自定义传输协议帧。

帧结构（小端）:
  2B 魔数 b"NX" | 1B 帧类型 | 4B 载荷长度 (LE) | 载荷

帧类型:
  0x01 HELLO   握手（协议名+版本）
  0x02 FILE    文件清单（文件名长度+文件名 + 文件内容）
  0x03 ACK     确认（"OK" 或错误信息）
  0x04 BYE     结束
"""
from __future__ import annotations

import struct

MAGIC = b"NX"
HEADER = struct.Struct("<2sBI")

T_HELLO, T_FILE, T_ACK, T_BYE = 0x01, 0x02, 0x03, 0x04
PROTO_NAME = b"NBXPROTO\x01"


class ProtocolError(ValueError):
    pass


def frame(ftype: int, payload: bytes = b"") -> bytes:
    return HEADER.pack(MAGIC, ftype, len(payload)) + payload


def recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProtocolError("connection closed mid-frame")
        buf += chunk
    return buf


def recv_frame(sock) -> tuple[int, bytes]:
    magic, ftype, length = HEADER.unpack(recv_exact(sock, HEADER.size))
    if magic != MAGIC:
        raise ProtocolError("bad frame magic")
    if length > 1 << 30:
        raise ProtocolError("frame too large")
    return ftype, recv_exact(sock, length) if length else b""


def hello() -> bytes:
    return frame(T_HELLO, PROTO_NAME)


def file_frame(filename: str, content: bytes) -> bytes:
    name = filename.encode("utf-8")
    if len(name) > 0xFF:
        raise ProtocolError("filename too long")
    return frame(T_FILE, struct.pack("<H", len(name)) + name + content)


def parse_file(payload: bytes) -> tuple[str, bytes]:
    (name_len,) = struct.unpack_from("<H", payload, 0)
    name = payload[2 : 2 + name_len].decode("utf-8")
    return name, payload[2 + name_len :]


def ack(message: str = "OK") -> bytes:
    return frame(T_ACK, message.encode("utf-8"))


def bye() -> bytes:
    return frame(T_BYE)
