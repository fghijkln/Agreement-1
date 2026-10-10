"""审计 T4：Carrier 元数据完整性（加密载体元数据进 AEAD AAD；明文载体结构一致性校验）。"""
import json

import pytest
from cryptography.exceptions import InvalidTag

from nbx import carrier, cli, crypto

MASTER = b'm' * 32


def _rewrite_meta(blob: bytes, mutate) -> bytes:
    """攻击者视角：无密钥改写元数据并重算校验和（载体校验和不含密钥）。"""
    magic, version, flags, meta_len = carrier.HEADER.unpack_from(blob, 0)
    off = carrier.HEADER.size
    meta = json.loads(blob[off:off + meta_len])
    rest = blob[off + meta_len:]
    mutate(meta)
    mb = json.dumps(meta, ensure_ascii=False).encode()
    return carrier.HEADER.pack(magic, version, flags, len(mb)) + mb + rest


def _set_flags(blob: bytes, flags: int) -> bytes:
    magic, version, _, meta_len = carrier.HEADER.unpack_from(blob, 0)
    return carrier.HEADER.pack(magic, version, flags, meta_len) + blob[carrier.HEADER.size:]


def _enc_bundle(tmp_path):
    a = tmp_path / 'a.txt'
    a.write_text('alpha')
    b = tmp_path / 'b.bin'
    b.write_bytes(b'\x00\x01binary')
    return carrier.encrypt_carrier(carrier.convert_bundle([a, b], 'x.nbx'), MASTER)


def _open(blob):
    meta, streams, flags = carrier.unpack(blob)
    return meta, carrier.decrypt_streams(meta, flags, streams, MASTER)


def test_encrypted_roundtrip(tmp_path):
    meta, streams = _open(_enc_bundle(tmp_path))
    assert meta['aad'] == 'meta-v1'
    assert [c for _, c in streams] == [b'alpha', b'\x00\x01binary']


@pytest.mark.parametrize('mutate', [
    lambda m: m.__setitem__('filename', 'evil.exe'),
    lambda m: m.__setitem__('type', 'text'),
    lambda m: m['parts'].reverse(),
    lambda m: m['parts'].append({'name': 'ghost', 'type': 'binary', 'len': 1}),
    lambda m: m['parts'][0].__setitem__('name', '../../etc/passwd'),
    lambda m: m.__setitem__('extra', 1),
])
def test_encrypted_meta_tamper_rejected(tmp_path, mutate):
    blob = _rewrite_meta(_enc_bundle(tmp_path), mutate)
    meta, streams, flags = carrier.unpack(blob)
    with pytest.raises(InvalidTag):
        carrier.decrypt_streams(meta, flags, streams, MASTER)


def test_encrypted_aad_marker_strip_downgrade_rejected(tmp_path):
    blob = _rewrite_meta(_enc_bundle(tmp_path), lambda m: m.pop('aad'))
    meta, streams, flags = carrier.unpack(blob)
    with pytest.raises(InvalidTag):
        carrier.decrypt_streams(meta, flags, streams, MASTER)


def test_encrypted_flags_tamper_rejected(tmp_path):
    blob = _enc_bundle(tmp_path)
    blob = _set_flags(blob, carrier.FLAG_ENCRYPTED | carrier.FLAG_MULTIPART)
    meta, streams, flags = carrier.unpack(blob)
    with pytest.raises(InvalidTag):
        carrier.decrypt_streams(meta, flags, streams, MASTER)


def test_legacy_encrypted_carrier_still_readable(tmp_path):
    """旧格式（无 aad 标记，crypto.encrypt 无 AAD）仍可解。"""
    inner = carrier.convert_text('legacy secret', 'l.txt')
    meta, streams, _ = carrier.unpack(inner)
    meta['enc'] = 'chacha20poly1305'
    enc = crypto.encrypt(carrier._build_payload(streams), MASTER)
    blob = carrier.pack([(carrier.TLV_BIN, enc)], meta, flags=carrier.FLAG_ENCRYPTED)
    m, s = _open(blob)
    assert s[0][1] == b'legacy secret'


def test_legacy_transfer_auto_carrier_readable():
    meta = {'type': 'binary', 'filename': 'r.txt', 'enc': 'chacha20poly1305', 'auto': True}
    blob = carrier.pack([(carrier.TLV_BIN, crypto.encrypt(b'raw-bytes', MASTER))], meta, flags=carrier.FLAG_ENCRYPTED)
    _, s = _open(blob)
    assert s == [(carrier.TLV_BIN, b'raw-bytes')]


# ---- 明文载体：结构一致性 ----

def test_plain_bundle_parts_count_forgery_rejected(tmp_path):
    a = tmp_path / 'a.txt'
    a.write_text('A')
    b = tmp_path / 'b.txt'
    b.write_text('B')
    blob = carrier.convert_bundle([a, b])
    forged = _rewrite_meta(blob, lambda m: m['parts'].extend([{'name': 'c'}, {'name': 'd'}, {'name': 'e'}]))
    with pytest.raises(carrier.NBXError, match='parts count'):
        carrier.unpack(forged)


def test_plain_part_length_forgery_rejected(tmp_path):
    blob = carrier.convert_text('hello', 'h.txt')
    forged = _rewrite_meta(blob, lambda m: m['parts'][0].__setitem__('len', 999))
    with pytest.raises(carrier.NBXError, match='length'):
        carrier.unpack(forged)


def test_plain_binary_labelled_text_rejected(tmp_path):
    f = tmp_path / 'x.bin'
    f.write_bytes(bytes(range(256)))
    blob = carrier.convert(f)
    forged = _rewrite_meta(blob, lambda m: (m.__setitem__('type', 'text'), m['parts'][0].__setitem__('type', 'text')))
    with pytest.raises(carrier.NBXError):
        carrier.unpack(forged)


def test_compressed_bundle_still_valid(tmp_path):
    a = tmp_path / 'a.txt'
    a.write_text('A' * 5000)
    meta, streams, flags = carrier.unpack(carrier.convert_bundle([a]))
    blob = carrier.pack(streams, meta, flags=flags, compress=True)
    m2, s2, f2 = carrier.unpack(blob)
    assert f2 & carrier.FLAG_COMPRESSED and s2[0][1] == b'A' * 5000


def test_cli_convert_encrypt_extract_and_tamper(tmp_path):
    key = tmp_path / 'k.key'
    key.write_text(crypto.generate_master_key() + '\n')
    src = tmp_path / 'doc.txt'
    src.write_text('cli secret')
    out = tmp_path / 'doc.nbx'
    cli.main(['convert', str(src), str(out), '--encrypt', '--keyfile', str(key)])
    od = tmp_path / 'o'
    cli.main(['extract', str(out), '--outdir', str(od), '--keyfile', str(key)])
    assert (od / 'doc.txt').read_text() == 'cli secret'
    out.write_bytes(_rewrite_meta(out.read_bytes(), lambda m: m.__setitem__('filename', '../escape.txt')))
    with pytest.raises(SystemExit) as e:
        cli.main(['extract', str(out), '--outdir', str(tmp_path / 'o2'), '--keyfile', str(key)])
    assert 'tampered' in str(e.value)
    assert not (tmp_path / 'escape.txt').exists()


def test_cli_extract_unsafe_name_rejected(tmp_path):
    blob = _rewrite_meta(carrier.convert_text('x', 'ok.txt'), lambda m: m.__setitem__('filename', '..'))
    p = tmp_path / 'bad.nbx'
    p.write_bytes(blob)
    with pytest.raises(SystemExit):
        cli.main(['extract', str(p), '--outdir', str(tmp_path / 'o')])
