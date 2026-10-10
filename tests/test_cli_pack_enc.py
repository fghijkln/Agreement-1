from nbx import cli, format


def test_pack_enc_field_and_unpack_roundtrip(tmp_path):
    key = tmp_path / 'nbx.key'
    src = tmp_path / 'source.bin'
    packed = tmp_path / 'source.nbx'
    restored = tmp_path / 'restored.bin'
    payload = b'nebula payload \x00\x01\x02 ' * 64
    src.write_bytes(payload)

    cli.main(['keygen', '--out', str(key)])
    cli.main(['pack', str(src), str(packed), '--keyfile', str(key)])

    meta, _inner = format.unpack(packed.read_bytes())
    assert meta['enc'] == 'chacha20poly1305'

    cli.main(['unpack', str(packed), str(restored), '--keyfile', str(key)])
    assert restored.read_bytes() == payload
