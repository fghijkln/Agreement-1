from __future__ import annotations
import hashlib
import os
import struct
MAGIC_MSG = b'NBXMSG\x01\x00'
VERSION = 1
PT_TEXT = 1
PT_FILE_OFFER = 2
PT_FILE_CHUNK = 3
PT_FILE_ACK = 4
PT_TYPING = 5
PT_READ = 6
PT_HANDSHAKE = 7
PT_PING = 8
PT_PONG = 9
HEADER = struct.Struct('<8sBBBB8s8s16sI')
HEADER_SIZE = HEADER.size

def fingerprint_of(pub_material: bytes) -> bytes:
    return hashlib.sha256(pub_material).digest()[:8]

def routing_aad(ptype: int, sender_fp: bytes, recv_fp: bytes) -> bytes:
    return HEADER.pack(MAGIC_MSG, VERSION, ptype, 0, 0, sender_fp, recv_fp, b'\x00' * 16, 0)[:28]

def pack_message(ptype: int, sender_fp: bytes, recv_fp: bytes, body: bytes, msg_id: bytes | None=None, flags: int=0) -> bytes:
    if len(sender_fp) != 8 or len(recv_fp) != 8:
        raise ValueError('fingerprint must be 8 bytes')
    if msg_id is None:
        msg_id = os.urandom(16)
    hdr = HEADER.pack(MAGIC_MSG, VERSION, ptype, flags, 0, sender_fp, recv_fp, msg_id, len(body))
    return hdr + body

def parse_message(blob: bytes) -> dict:
    if len(blob) < HEADER_SIZE or blob[:8] != MAGIC_MSG:
        raise ValueError('not an NBX message')
    magic, ver, ptype, flags, _r, sfp, rfp, mid, blen = HEADER.unpack(blob[:HEADER_SIZE])
    if ver != VERSION:
        raise ValueError(f'unsupported version {ver}')
    body = blob[HEADER_SIZE:]
    if len(body) != blen:
        raise ValueError('body length mismatch')
    return {'ptype': ptype, 'flags': flags, 'sender_fp': sfp, 'recv_fp': rfp, 'msg_id': mid, 'body': body}

def _pack_fields(fields: list[tuple[int, bytes]]) -> bytes:
    out = b''
    for t, v in fields:
        out += struct.pack('<BI', t, len(v)) + v
    return out

def _parse_fields(data: bytes) -> dict[int, bytes]:
    out, off = ({}, 0)
    while off < len(data):
        t, ln = struct.unpack('<BI', data[off:off + 5])
        out[t] = data[off + 5:off + 5 + ln]
        off += 5 + ln
    return out
F_TEXT, F_MSG_REF, F_NAME, F_SIZE, F_SHA, F_OFFSET = (1, 2, 3, 4, 5, 6)

def encode_text(text: str) -> bytes:
    return _pack_fields([(F_TEXT, text.encode('utf-8'))])

def decode_text(body: bytes) -> str:
    return _parse_fields(body)[F_TEXT].decode('utf-8')

def encode_read(ref_msg_id: bytes) -> bytes:
    return _pack_fields([(F_MSG_REF, ref_msg_id)])

def decode_read(body: bytes) -> bytes:
    return _parse_fields(body)[F_MSG_REF]

def encode_file_offer(name: str, size: int, sha256: bytes) -> bytes:
    return _pack_fields([(F_NAME, name.encode('utf-8')), (F_SIZE, struct.pack('<Q', size)), (F_SHA, sha256)])

def decode_file_offer(body: bytes) -> tuple[str, int, bytes]:
    f = _parse_fields(body)
    return (f[F_NAME].decode('utf-8'), struct.unpack('<Q', f[F_SIZE])[0], f[F_SHA])

def encode_file_chunk(offset: int, data: bytes) -> bytes:
    return _pack_fields([(F_OFFSET, struct.pack('<Q', offset)), (F_TEXT, data)])

def decode_file_chunk(body: bytes) -> tuple[int, bytes]:
    f = _parse_fields(body)
    return (struct.unpack('<Q', f[F_OFFSET])[0], f[F_TEXT])

def new_msg_id() -> bytes:
    return os.urandom(16)
