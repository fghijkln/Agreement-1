"""audit R-13 / R-10 回归测试：身份私钥加密落盘。"""
import pytest
from nbx import fskey
from nbx.pq import PQIdentity


def test_identity_encrypted_roundtrip(tmp_path):
    ident = fskey.Identity.generate()
    p = tmp_path / "id.enc"
    ident.save_encrypted(str(p), "hunter2")
    loaded = fskey.Identity.load_encrypted(str(p), "hunter2")
    assert loaded.export_public() == ident.export_public()
    assert loaded.fingerprint() == ident.fingerprint()


def test_identity_wrong_passphrase_rejected(tmp_path):
    ident = fskey.Identity.generate()
    p = tmp_path / "id.enc"
    ident.save_encrypted(str(p), "hunter2")
    with pytest.raises(Exception):
        fskey.Identity.load_encrypted(str(p), "wrong-pass")


def test_identity_encrypted_file_not_plaintext(tmp_path):
    """落盘内容不得含原始私钥字节。"""
    ident = fskey.Identity.generate()
    p = tmp_path / "id.enc"
    ident.save_encrypted(str(p), "hunter2")
    import base64
    raw = base64.b64decode(p.read_bytes().strip())
    assert b"BEGIN" not in raw
    priv_bytes = ident.to_bytes()
    # scrypt+AEAD 输出不应包含完整的 64B 私钥明文
    assert priv_bytes not in raw
    assert priv_bytes[:32] not in raw


def test_identity_plaintext_load_still_works(tmp_path):
    """旧明文文件兼容读取（迁移路径）。"""
    ident = fskey.Identity.generate()
    p = tmp_path / "id.key"
    ident.save(str(p))
    loaded = fskey.Identity.load(str(p))
    assert loaded.export_public() == ident.export_public()


def test_pq_identity_encrypted_roundtrip(tmp_path):
    ident = PQIdentity.generate()
    p = tmp_path / "pqid.enc"
    ident.save_encrypted(str(p), "pass-phrase")
    loaded = PQIdentity.load_encrypted(str(p), "pass-phrase")
    assert loaded.export_public() == ident.export_public()


def test_pq_identity_wrong_passphrase_rejected(tmp_path):
    ident = PQIdentity.generate()
    p = tmp_path / "pqid.enc"
    ident.save_encrypted(str(p), "pass-phrase")
    with pytest.raises(Exception):
        PQIdentity.load_encrypted(str(p), "nope")


def test_daemon_passphrase_creates_encrypted_identity(tmp_path):
    """daemon 传 passphrase 时：身份加密落盘、不残留明文、重启可加载。"""
    from nbx.daemon import Daemon
    sd = tmp_path / "state"
    d1 = Daemon(str(sd), "https://relay.example", passphrase="pw123")
    fp1 = d1.my_fp
    assert (sd / "identity.key.enc").exists()
    assert not (sd / "identity.key").exists(), "明文身份文件不得残留"
    d2 = Daemon(str(sd), "https://relay.example", passphrase="pw123")
    assert d2.my_fp == fp1
