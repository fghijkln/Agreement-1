"""审计：TOFU 指纹 8→16 字节（兼容旧 8 字节 pin 并升级），pin 只在解密验签成功后写入。"""
import hashlib
import base64
import json
import os

import pytest

from nbx import cli, fskey, pins


def _write(p, t):
    with open(p, 'w', encoding='utf-8') as f:
        f.write(t)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.delenv('NBX_SENDER_PINS', raising=False)
    monkeypatch.delenv('NBX_REPLAY_CACHE', raising=False)
    snd, rec = fskey.Identity.generate(), fskey.Identity.generate()
    rec_id = tmp_path / 'rec.key'
    snd_id = tmp_path / 'snd.key'
    rec.save(str(rec_id))
    snd.save(str(snd_id))
    from_pub = tmp_path / 'from.pub'
    to_pub = tmp_path / 'to.pub'
    _write(from_pub, snd.export_public() + '\n')
    _write(to_pub, rec.export_public() + '\n')
    src = tmp_path / 'm.bin'
    src.write_bytes(b'hello')
    envf = tmp_path / 'm.env'
    cli.main(['seal', str(src), str(envf), '--my-id', str(snd_id), '--to-pub', str(to_pub)])
    return dict(tmp=tmp_path, rec_id=str(rec_id), from_pub=from_pub, to_pub=to_pub, env=envf, snd=snd)


def _unseal(e, out, envf=None, extra=()):
    return cli.main(['unseal', str(envf or e['env']), str(out), '--my-id', e['rec_id'],
                     '--from-pub', str(e['from_pub']), *extra])


def _pinfile(e):
    return e['tmp'] / '.nbx_sender_pins.json'


def test_fingerprint_is_128_bit():
    pub = fskey.Identity.generate().export_public()
    fp = pins.pubkey_fingerprint(pub)
    assert len(fp) == 32
    assert fp == hashlib.sha256(base64.b64decode(pub)).digest()[:16].hex()


def test_legacy_8_byte_pin_accepted_and_upgraded(env, tmp_path):
    full = pins.pubkey_fingerprint(env['from_pub'].read_text())
    name = os.path.abspath(str(env['from_pub']))
    _pinfile(env).write_text(json.dumps({name: full[:16]}))
    _unseal(env, tmp_path / 'o.bin')
    assert (tmp_path / 'o.bin').read_bytes() == b'hello'
    assert json.loads(_pinfile(env).read_text())[name] == full


def test_legacy_8_byte_pin_mismatch_rejected(env, tmp_path):
    name = os.path.abspath(str(env['from_pub']))
    _pinfile(env).write_text(json.dumps({name: 'deadbeefdeadbeef'}))
    with pytest.raises(SystemExit):
        _unseal(env, tmp_path / 'o.bin')
    assert not (tmp_path / 'o.bin').exists()
    assert json.loads(_pinfile(env).read_text())[name] == 'deadbeefdeadbeef'


def test_legacy_8_byte_from_fp_accepted(env, tmp_path):
    full = pins.pubkey_fingerprint(env['from_pub'].read_text())
    _unseal(env, tmp_path / 'o.bin', extra=['--from-fp', full[:16]])
    assert (tmp_path / 'o.bin').read_bytes() == b'hello'


def test_odd_length_from_fp_rejected(env, tmp_path):
    full = pins.pubkey_fingerprint(env['from_pub'].read_text())
    with pytest.raises(SystemExit):
        _unseal(env, tmp_path / 'o.bin', extra=['--from-fp', full[:20]])


def test_first_contact_pin_not_written_when_decrypt_fails(env, tmp_path):
    """首次见到的发送方：信封验签/解密失败时不得写入 pin（否则首次冒充即被永久信任）。"""
    atk = fskey.Identity.generate()
    _write(env['from_pub'], atk.export_public() + '\n')  # 冒充：公钥与信封签名者不符
    with pytest.raises(SystemExit):
        _unseal(env, tmp_path / 'o.bin')
    assert not (tmp_path / 'o.bin').exists()
    assert not _pinfile(env).exists() or os.path.abspath(str(env['from_pub'])) not in json.loads(_pinfile(env).read_text())


def test_first_contact_pin_not_written_on_tampered_envelope(env, tmp_path):
    blob = bytearray(env['env'].read_bytes())
    blob[-1] ^= 1
    bad = tmp_path / 'bad.env'
    bad.write_bytes(bytes(blob))
    with pytest.raises(SystemExit):
        _unseal(env, tmp_path / 'o.bin', envf=bad)
    assert not _pinfile(env).exists()
    # 合法信封随后仍可首次信任
    _unseal(env, tmp_path / 'o2.bin')
    assert _pinfile(env).exists()


def test_pinstore_check_is_readonly(tmp_path):
    store = pins.PinStore(str(tmp_path / 'p.json'))
    assert store.check('alice', 'ab' * 16) == 'new'
    assert not (tmp_path / 'p.json').exists()
    store.commit('alice', 'ab' * 16)
    assert store.check('alice', 'ab' * 16) == 'ok'
    with pytest.raises(ValueError):
        store.check('alice', 'cd' * 16)
