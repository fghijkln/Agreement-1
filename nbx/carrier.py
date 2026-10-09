from __future__ import annotations
import hashlib
import json
import struct
from pathlib import Path
MAGIC = b'NBXFILE\x02'
VERSION = 2
FLAG_ENCRYPTED = 1
FLAG_COMPRESSED = 2
FLAG_MULTIPART = 4
HEADER = struct.Struct('<8sBBH')
U32 = struct.Struct('<I')
TLV = struct.Struct('<BI')
TLV_TEXT, TLV_BIN, TLV_SUBMETA = (1, 2, 3)
KNOWN_TEXT_EXT = {'.txt': 'text', '.md': 'markdown', '.markdown': 'markdown', '.html': 'html', '.htm': 'html', '.xhtml': 'html', '.css': 'text', '.js': 'text', '.json': 'text', '.xml': 'text', '.csv': 'text', '.log': 'text', '.py': 'text', '.c': 'text', '.h': 'text', '.cpp': 'text', '.rs': 'text', '.go': 'text', '.java': 'text', '.sh': 'text', '.yaml': 'text', '.yml': 'text', '.toml': 'text', '.ini': 'text', '.svg': 'text'}

class NBXError(ValueError):
    pass

def _build_payload(streams: list[tuple[int, bytes]]) -> bytes:
    out = b''
    for stype, content in streams:
        out += TLV.pack(stype, len(content)) + content
    return out

def pack(streams: list[tuple[int, bytes]], meta: dict | None=None, flags: int=0, compress: bool=False) -> bytes:
    meta = dict(meta or {})
    if compress:
        import lzma
        compressed = [(stype, lzma.compress(c, preset=6)) for stype, c in streams]
        if sum((len(c) for _, c in compressed)) < sum((len(c) for _, c in streams)):
            streams = compressed
            flags |= FLAG_COMPRESSED
            meta['comp'] = 'lzma'
    if len(streams) > 1:
        flags |= FLAG_MULTIPART
    meta.setdefault('parts', [{'type': s, 'len': len(c)} for s, c in streams])
    meta_bytes = json.dumps(meta, ensure_ascii=False).encode('utf-8')
    if len(meta_bytes) > 65535:
        raise NBXError('metadata too large')
    payload = _build_payload(streams)
    if len(payload) > 4294967295:
        raise NBXError('payload too large')
    return HEADER.pack(MAGIC, VERSION, flags, len(meta_bytes)) + meta_bytes + U32.pack(len(payload)) + payload + hashlib.sha256(payload).digest()

def unpack(blob: bytes) -> tuple[dict, list[tuple[int, bytes]], int]:
    if len(blob) < HEADER.size + 4 + 32:
        raise NBXError('file too short')
    magic, version, flags, meta_len = HEADER.unpack_from(blob, 0)
    if magic != MAGIC:
        raise NBXError('bad magic: not an NBX v2 file')
    if version != VERSION:
        raise NBXError(f'unsupported version {version}')
    off = HEADER.size
    meta = json.loads(blob[off:off + meta_len].decode('utf-8'))
    off += meta_len
    payload_len, = U32.unpack_from(blob, off)
    off += 4
    payload = blob[off:off + payload_len]
    if len(payload) != payload_len:
        raise NBXError('truncated payload')
    digest, = struct.unpack_from('<32s', blob, off + payload_len)
    if hashlib.sha256(payload).digest() != digest:
        raise NBXError('checksum mismatch: data corrupted')
    streams = []
    p = 0
    while p < len(payload):
        if p + TLV.size > len(payload):
            raise NBXError('truncated TLV header')
        stype, slen = TLV.unpack_from(payload, p)
        p += TLV.size
        if p + slen > len(payload):
            raise NBXError('truncated stream')
        streams.append((stype, payload[p:p + slen]))
        p += slen
    if flags & FLAG_COMPRESSED:
        import lzma
        streams = [(stype, lzma.decompress(c)) for stype, c in streams]
    return (meta, streams, flags)
MAGIC_SNIFF = [(b'\x89PNG\r\n\x1a\n', 'image/png'), (b'\xff\xd8\xff', 'image/jpeg'), (b'GIF8', 'image/gif'), (b'BM', 'image/bmp'), (b'%PDF', 'application/pdf'), (b'PK\x03\x04', 'application/zip'), (b'\x1f\x8b', 'application/gzip'), (b'ID3', 'audio/mpeg'), (b'OggS', 'audio/ogg'), (b'RIFF', 'application/octet-stream'), (b'\x00\x00\x00\x18ftyp', 'video/mp4'), (b'\x1aE\xdf\xa3', 'video/webm'), (b"7z\xbc\xaf'\x1c", 'application/x-7z-compressed'), (b'Rar!', 'application/vnd.rar')]

def sniff_mime(data: bytes, name: str='') -> tuple[str, str]:
    suffix = Path(name).suffix.lower()
    if suffix in KNOWN_TEXT_EXT:
        return (KNOWN_TEXT_EXT[suffix], f'text/plain')
    for magic, mime in MAGIC_SNIFF:
        if data.startswith(magic):
            if mime == 'application/octet-stream' and suffix == '.wav':
                mime = 'audio/wav'
            elif mime == 'application/octet-stream' and suffix == '.avi':
                mime = 'video/x-msvideo'
            return ('binary', mime)
    try:
        data.decode('utf-8')
        t = KNOWN_TEXT_EXT.get(suffix, 'text')
        return (t, 'text/plain')
    except UnicodeDecodeError:
        pass
    return ('binary', 'application/octet-stream')

def convert(path: str | Path) -> bytes:
    p = Path(path)
    data = p.read_bytes()
    ctype, mime = sniff_mime(data, p.name)
    meta = {'type': ctype, 'mime': mime, 'filename': p.name, 'size': len(data)}
    if ctype in ('text', 'html', 'markdown'):
        return pack([(TLV_TEXT, data)], meta)
    return pack([(TLV_BIN, data)], meta)

def convert_text(text: str, title: str='', ctype: str='text') -> bytes:
    meta = {'type': ctype, 'mime': 'text/plain', 'filename': title or 'untitled.txt'}
    return pack([(TLV_TEXT, text.encode('utf-8'))], meta)

def convert_bundle(paths: list[str | Path], main_name: str='') -> bytes:
    streams, parts = ([], [])
    for i, p in enumerate(paths):
        p = Path(p)
        data = p.read_bytes()
        ctype, mime = sniff_mime(data, p.name)
        stype = TLV_TEXT if ctype in ('text', 'html', 'markdown') else TLV_BIN
        streams.append((stype, data))
        parts.append({'name': p.name, 'type': ctype, 'mime': mime, 'len': len(data)})
    meta = {'type': 'bundle', 'filename': main_name or 'bundle.nbx', 'parts': parts}
    return pack(streams, meta)

def extract(blob: bytes) -> list[tuple[str, bytes]]:
    meta, streams, _ = unpack(blob)
    ctype = meta.get('type', 'binary')
    filename = meta.get('filename', 'untitled')
    if ctype == 'bundle' and 'parts' in meta:
        out = []
        for part, (stype, content) in zip(meta['parts'], streams):
            out.append((part.get('name', 'part'), content))
        return out
    if ctype == 'binary':
        return [(filename, streams[0][1])]
    return [(filename, streams[0][1])]
