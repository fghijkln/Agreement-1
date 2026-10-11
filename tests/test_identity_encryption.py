import os
import stat

import pytest
from nbx import fskey
from nbx.pq import PQIdentity
from nbx import storage

def test_identity_encrypted_roundtrip(tmp_path):
    ident = fskey.Identity.generate()
    p = tmp_path / 'id.enc'
    ident.save_encrypted(str(p), 'hunter2')
    loaded = fskey.Identity.load_encrypted(str(p), 'hunter2')
    assert loaded.export_public() == ident.export_public()
    assert loaded.fingerprint() == ident.fingerprint()

def test_identity_wrong_passphrase_rejected(tmp_path):
    ident = fskey.Identity.generate()
    p = tmp_path / 'id.enc'
    ident.save_encrypted(str(p), 'hunter2')
    with pytest.raises(Exception):
        fskey.Identity.load_encrypted(str(p), 'wrong-pass')

def test_identity_encrypted_file_not_plaintext(tmp_path):
    ident = fskey.Identity.generate()
    p = tmp_path / 'id.enc'
    ident.save_encrypted(str(p), 'hunter2')
    import base64
    raw = base64.b64decode(p.read_bytes().strip())
    assert b'BEGIN' not in raw
    priv_bytes = ident.to_bytes()
    assert priv_bytes not in raw
    assert priv_bytes[:32] not in raw

def test_identity_plaintext_load_still_works(tmp_path):
    ident = fskey.Identity.generate()
    p = tmp_path / 'id.key'
    ident.save(str(p))
    loaded = fskey.Identity.load(str(p))
    assert loaded.export_public() == ident.export_public()

@pytest.mark.parametrize('encrypted', [False, True])
def test_identity_load_tightens_existing_file_mode(tmp_path, encrypted):
    ident = fskey.Identity.generate()
    p = tmp_path / ('id.enc' if encrypted else 'id.key')
    if encrypted:
        ident.save_encrypted(str(p), 'passphrase')
    else:
        ident.save(str(p))
    p.chmod(0o644)

    if encrypted:
        loaded = fskey.Identity.load_encrypted(str(p), 'passphrase')
    else:
        loaded = fskey.Identity.load(str(p))

    assert loaded.export_public() == ident.export_public()
    assert stat.S_IMODE(p.stat().st_mode) == 0o600

@pytest.mark.parametrize('encrypted', [False, True])
def test_identity_private_files_are_created_with_mode_0600(tmp_path, encrypted):
    ident = fskey.Identity.generate()
    p = tmp_path / ('id.enc' if encrypted else 'id.key')
    old_umask = os.umask(0)
    try:
        if encrypted:
            ident.save_encrypted(str(p), 'passphrase')
        else:
            ident.save(str(p))
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(p.stat().st_mode) == 0o600

def test_daemon_plaintext_identity_is_created_with_mode_0600(tmp_path):
    from nbx.daemon import Daemon
    state_dir = tmp_path / 'state'
    daemon = Daemon(str(state_dir), 'https://relay.example')
    assert stat.S_IMODE((state_dir / 'identity.key').stat().st_mode) == 0o600

def test_daemon_tightens_existing_plaintext_identity_mode(tmp_path):
    from nbx.daemon import Daemon
    state_dir = tmp_path / 'state'
    state_dir.mkdir()
    ident = fskey.Identity.generate()
    identity_path = state_dir / 'identity.key'
    ident.save(str(identity_path))
    identity_path.chmod(0o644)

    daemon = Daemon(str(state_dir), 'https://relay.example')

    assert daemon.identity.export_public() == ident.export_public()
    assert stat.S_IMODE(identity_path.stat().st_mode) == 0o600

def test_daemon_tightens_existing_encrypted_identity_mode(tmp_path):
    from nbx.daemon import Daemon
    state_dir = tmp_path / 'state'
    state_dir.mkdir()
    ident = fskey.Identity.generate()
    identity_path = state_dir / 'identity.key.enc'
    ident.save_encrypted(str(identity_path), 'passphrase')
    identity_path.chmod(0o644)

    daemon = Daemon(str(state_dir), 'https://relay.example', passphrase='passphrase')

    assert daemon.identity.export_public() == ident.export_public()
    assert stat.S_IMODE(identity_path.stat().st_mode) == 0o600

def test_pq_identity_encrypted_roundtrip(tmp_path):
    ident = PQIdentity.generate()
    p = tmp_path / 'pqid.enc'
    ident.save_encrypted(str(p), 'pass-phrase')
    loaded = PQIdentity.load_encrypted(str(p), 'pass-phrase')
    assert loaded.export_public() == ident.export_public()

@pytest.mark.parametrize('encrypted', [False, True])
def test_pq_identity_load_tightens_existing_file_mode(tmp_path, encrypted):
    ident = PQIdentity.generate()
    p = tmp_path / ('pqid.enc' if encrypted else 'pqid.key')
    if encrypted:
        ident.save_encrypted(str(p), 'pass-phrase')
    else:
        ident.save(str(p))
    p.chmod(0o644)

    if encrypted:
        loaded = PQIdentity.load_encrypted(str(p), 'pass-phrase')
    else:
        loaded = PQIdentity.load(str(p))

    assert loaded.export_public() == ident.export_public()
    assert stat.S_IMODE(p.stat().st_mode) == 0o600

@pytest.mark.parametrize('encrypted', [False, True])
def test_pq_identity_private_files_are_created_with_mode_0600(tmp_path, encrypted):
    ident = PQIdentity.generate()
    p = tmp_path / ('pqid.enc' if encrypted else 'pqid.key')
    old_umask = os.umask(0)
    try:
        if encrypted:
            ident.save_encrypted(str(p), 'pass-phrase')
        else:
            ident.save(str(p))
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(p.stat().st_mode) == 0o600

@pytest.mark.parametrize('encrypted', [False, True])
def test_pq_identity_save_is_atomic_when_replace_fails(tmp_path, monkeypatch, encrypted):
    ident = PQIdentity.generate()
    p = tmp_path / ('pqid.enc' if encrypted else 'pqid.key')
    p.write_bytes(b'previous identity')

    def fail_replace(source, destination):
        raise OSError('simulated atomic replace failure')

    monkeypatch.setattr(storage.os, 'replace', fail_replace)
    with pytest.raises(OSError, match='simulated atomic replace failure'):
        if encrypted:
            ident.save_encrypted(str(p), 'pass-phrase')
        else:
            ident.save(str(p))

    assert p.read_bytes() == b'previous identity'
    assert list(tmp_path.glob('.nbx_*.tmp')) == []

def test_pq_identity_wrong_passphrase_rejected(tmp_path):
    ident = PQIdentity.generate()
    p = tmp_path / 'pqid.enc'
    ident.save_encrypted(str(p), 'pass-phrase')
    with pytest.raises(Exception):
        PQIdentity.load_encrypted(str(p), 'nope')

def test_daemon_passphrase_creates_encrypted_identity(tmp_path):
    from nbx.daemon import Daemon
    sd = tmp_path / 'state'
    d1 = Daemon(str(sd), 'https://relay.example', passphrase='pw123')
    fp1 = d1.my_fp
    assert (sd / 'identity.key.enc').exists()
    assert stat.S_IMODE((sd / 'identity.key.enc').stat().st_mode) == 0o600
    assert not (sd / 'identity.key').exists(), '明文身份文件不得残留'
    d2 = Daemon(str(sd), 'https://relay.example', passphrase='pw123')
    assert d2.my_fp == fp1
