import json
import os

import pytest

from nbx import cli, fskey, pins
from nbx.pq import PQIdentity
import nbx.pq as pq


def _write(path, text):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)


def _make_env(tmp_path, scheme):
    payload = b'payload-' + scheme.encode()
    if scheme == 'fs':
        snd = fskey.Identity.generate()
        rec = fskey.Identity.generate()
    else:
        snd = PQIdentity.generate()
        rec = PQIdentity.generate()
    snd_id = tmp_path / f'snd.{scheme}'
    rec_id = tmp_path / f'rec.{scheme}'
    snd.save(str(snd_id))
    rec.save(str(rec_id))
    from_pub = tmp_path / f'from.{scheme}.pub'
    to_pub = tmp_path / f'to.{scheme}.pub'
    _write(from_pub, snd.export_public() + '\n')
    _write(to_pub, rec.export_public() + '\n')
    src = tmp_path / f'msg.{scheme}.bin'
    src.write_bytes(payload)
    env = tmp_path / f'msg.{scheme}.env'
    seal_cmd = 'seal' if scheme == 'fs' else 'pqseal'
    cli.main([seal_cmd, str(src), str(env), '--my-id', str(snd_id), '--to-pub', str(to_pub)])
    return {
        'scheme': scheme,
        'snd': snd,
        'rec': rec,
        'rec_id': str(rec_id),
        'from_pub': from_pub,
        'to_pub': to_pub,
        'env': env,
        'payload': payload,
    }


def _unseal_cmd(e, out, extra=()):
    cmd = 'unseal' if e['scheme'] == 'fs' else 'pqunseal'
    return [cmd, str(e['env']), str(out), '--my-id', e['rec_id'],
            '--from-pub', str(e['from_pub']), *extra]


def _attacker_env(e, tmp_path, payload=b'pwned'):
    if e['scheme'] == 'fs':
        atk = fskey.Identity.generate()
        rx, re_ = fskey.Identity.parse_public(e['to_pub'].read_text())
        blob = fskey.seal_envelope(payload, atk, rx, re_)
    else:
        atk = PQIdentity.generate()
        rx, re_, rk = PQIdentity.parse_public(e['to_pub'].read_text())
        blob = pq.seal_pq(payload, atk, rx, re_, rk)
    _write(e['from_pub'], atk.export_public() + '\n')
    env_file = tmp_path / f'atk.{e["scheme"]}.env'
    env_file.write_bytes(blob)
    return env_file


@pytest.fixture(params=['fs', 'pq'])
def env(request, tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.delenv('NBX_REPLAY_CACHE', raising=False)
    monkeypatch.delenv('NBX_SENDER_PINS', raising=False)
    return _make_env(tmp_path, request.param)


def test_tofu_first_trust_writes_pin(env, tmp_path, capsys):
    out = tmp_path / 'out.bin'
    cli.main(_unseal_cmd(env, out))
    assert out.read_bytes() == env['payload']

    pinfile = tmp_path / '.nbx_sender_pins.json'
    assert pinfile.exists()
    data = json.loads(pinfile.read_text())
    name = os.path.abspath(str(env['from_pub']))
    fp = pins.pubkey_fingerprint(env['from_pub'].read_text())
    assert data[name] == fp
    assert (pinfile.stat().st_mode & 0o777) == 0o600
    err = capsys.readouterr().err
    assert '首次信任' in err and fp in err


def test_tofu_same_name_swapped_key_rejected(env, tmp_path):
    name = os.path.abspath(str(env['from_pub']))
    original_fp = pins.pubkey_fingerprint(env['from_pub'].read_text())

    out = tmp_path / 'out.bin'
    cli.main(_unseal_cmd(env, out))
    assert out.exists()

    atk_env = _attacker_env(env, tmp_path)
    out2 = tmp_path / 'out2.bin'
    with pytest.raises(SystemExit):
        cli.main(_unseal_cmd({'scheme': env['scheme'], 'rec_id': env['rec_id'],
                              'from_pub': env['from_pub'], 'env': atk_env}, out2))
    assert not out2.exists()

    stored = json.loads((tmp_path / '.nbx_sender_pins.json').read_text())
    assert stored[name] == original_fp
    assert stored[name] != pins.pubkey_fingerprint(env['from_pub'].read_text())


def test_explicit_fp_accepts_correct(env, tmp_path):
    fp = pins.pubkey_fingerprint(env['from_pub'].read_text())
    out = tmp_path / 'ok.bin'
    cli.main(_unseal_cmd(env, out, ['--from-fp', fp]))
    assert out.read_bytes() == env['payload']


def test_explicit_fp_rejects_wrong(env, tmp_path):
    out = tmp_path / 'bad.bin'
    with pytest.raises(SystemExit):
        cli.main(_unseal_cmd(env, out, ['--from-fp', 'deadbeefdeadbeef']))
    assert not out.exists()


def test_corrupt_pin_file_rejected(env, tmp_path):
    pinfile = tmp_path / '.nbx_sender_pins.json'
    pinfile.write_text('{ this is not valid json')
    out = tmp_path / 'out.bin'
    with pytest.raises(SystemExit):
        cli.main(_unseal_cmd(env, out))
    assert not out.exists()


def test_pin_env_override(env, tmp_path, monkeypatch):
    custom = tmp_path / 'custom_pins.json'
    monkeypatch.setenv('NBX_SENDER_PINS', str(custom))
    out = tmp_path / 'out.bin'
    cli.main(_unseal_cmd(env, out))
    assert custom.exists()
    assert not (tmp_path / '.nbx_sender_pins.json').exists()
