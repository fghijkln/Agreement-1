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
    raw_lens = [len(c) for _, c in streams]
    if flags & FLAG_COMPRESSED:
        import lzma
        streams = [(stype, lzma.decompress(c)) for stype, c in streams]
    if not isinstance(meta, dict):
        raise NBXError('metadata must be a JSON object')
    if not flags & FLAG_ENCRYPTED:
        _check_meta_consistency(meta, streams, raw_lens)
    return (meta, streams, flags)


TEXT_TYPES = ('text', 'html', 'markdown')
META_AAD_MARKER = 'meta-v1'
META_AAD_LABEL = b'nbx-carrier-meta-v1'


def _check_meta_consistency(meta: dict, streams: list[tuple[int, bytes]], raw_lens: list[int] | None=None) -> None:
    """审计 T4：元数据与实际流必须一致，否则拒绝（防部分数/长度/类型伪造导致静默丢流）。"""
    parts = meta.get('parts')
    if parts is not None:
        if not isinstance(parts, list) or not all((isinstance(p, dict) for p in parts)):
            raise NBXError('metadata parts malformed')
        if len(parts) != len(streams):
            raise NBXError(f'metadata parts count {len(parts)} != stream count {len(streams)}')
        for i, (part, (stype, content)) in enumerate(zip(parts, streams)):
            want = part.get('len')
            if want is not None:
                ok = {len(content)}
                if raw_lens is not None:
                    ok.add(raw_lens[i])
                if want not in ok:
                    raise NBXError(f'metadata part {i} length mismatch')
            ptype = part.get('type')
            if ptype in TEXT_TYPES and stype != TLV_TEXT:
                raise NBXError(f'metadata part {i} claims {ptype} but stream is binary')
    if meta.get('type') in TEXT_TYPES and any((stype != TLV_TEXT for stype, _ in streams)):
        raise NBXError(f"metadata type {meta.get('type')!r} does not match binary stream")
    if meta.get('type') == 'bundle' and parts is None:
        raise NBXError('bundle without parts metadata')


def _meta_aad(meta: dict, flags: int) -> bytes:
    canon = json.dumps(meta, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return META_AAD_LABEL + bytes([flags & 255]) + canon


def encrypt_carrier(blob: bytes, master_key: bytes) -> bytes:
    """把明文载体整体加密：payload 进 AEAD，元数据(含 flags)作为 associated data 认证。"""
    from . import crypto
    meta, streams, _ = unpack(blob)
    meta = dict(meta)
    meta.setdefault('parts', [{'type': s, 'len': len(c)} for s, c in streams])
    meta['enc'] = 'chacha20poly1305'
    meta['aad'] = META_AAD_MARKER
    flags = FLAG_ENCRYPTED
    enc = crypto.encrypt(_build_payload(streams), master_key, aad=_meta_aad(meta, flags))
    return pack([(TLV_BIN, enc)], meta, flags=flags)


def decrypt_streams(meta: dict, flags: int, streams: list[tuple[int, bytes]], master_key: bytes) -> list[tuple[int, bytes]]:
    """解密加密载体并解析内部 TLV。新格式(meta['aad']=='meta-v1')校验元数据；
    旧格式（无 aad 标记）兼容解密但元数据未认证。剥掉 aad 标记降级会因 AEAD 失败被拒。"""
    from . import crypto
    if not flags & FLAG_ENCRYPTED:
        return streams
    if len(streams) != 1:
        raise NBXError('encrypted carrier must have exactly one stream')
    aad = _meta_aad(meta, flags) if meta.get('aad') == META_AAD_MARKER else None
    payload = crypto.decrypt(streams[0][1], master_key, aad=aad)
    if aad is None and meta.get('auto'):
        # 旧版 transfer 自动加密：payload 为原始文件字节而非 TLV
        return [(TLV_BIN, payload)]
    inner = []
    p = 0
    while p < len(payload):
        if p + TLV.size > len(payload):
            raise NBXError('truncated TLV header')
        stype, slen = TLV.unpack_from(payload, p)
        p += TLV.size
        if p + slen > len(payload):
            raise NBXError('truncated stream')
        inner.append((stype, payload[p:p + slen]))
        p += slen
    if aad is not None:
        _check_meta_consistency(meta, inner)
    return inner
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
    if ctype == 'bundle':
        parts = meta.get('parts')
        if not isinstance(parts, list) or len(parts) != len(streams):
            raise NBXError('bundle parts metadata does not match streams')
        return [(part.get('name', 'part'), content) for part, (stype, content) in zip(parts, streams)]
    if not streams:
        raise NBXError('container has no streams')
    return [(filename, streams[0][1])]
