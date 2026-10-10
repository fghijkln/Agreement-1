"""审计 T4/2.2：棘轮会话状态与消息历史静态加密（AEAD + 版本头 + 0600 + 原子写 + 旧格式迁移）。"""
import base64
import json
import os
import stat
import time

import pytest

from nbx import fskey, storage
from nbx.contacts import ContactBook
from nbx.daemon import Daemon, _b64e
from nbx.ratchet import RatchetSession


class OfflineClient:
    def __init__(self):
        self.posted = []

    def auth(self, *a, **k):
        pass

    def post_envelope(self, blob, proof=None):
        self.posted.append(blob)
        return {'ok': True}

    def fetch(self, fp, proof):
        return []


def _pair():
    from cryptography.hazmat.primitives import serialization

    def ed_pub(i):
        return i.ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    a_id, b_id = fskey.Identity.generate(), fskey.Identity.generate()
    a, b = RatchetSession(), RatchetSession()
    ha, hb = a.begin(a_id), b.begin(b_id)
    a.finish(a_id, ed_pub(b_id), hb, speaks_first=True)
    b.finish(b_id, ed_pub(a_id), ha, speaks_first=False)
    return a, b


def _mk(tmp_path, name='a'):
    d = Daemon(str(tmp_path / name), 'http://fake', poll_interval=999)
    d.client = OfflineClient()
    return d


def _mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


# ---- storage 原语 ----

def test_seal_roundtrip_and_header():
    k = storage.derive_storage_key(b's' * 32)
    blob = storage.seal(k, b'secret', b'ctx')
    assert blob.startswith(b'NBXSEAL1\x01')
    assert b'secret' not in blob
    assert storage.open_sealed(k, blob, b'ctx') == b'secret'


@pytest.mark.parametrize('pos', [0, 8, 9, 15, 25, -1])
def test_seal_tamper_rejected(pos):
    k = storage.derive_storage_key(b's' * 32)
    blob = bytearray(storage.seal(k, b'secret', b'ctx'))
    blob[pos] ^= 0x01
    with pytest.raises(storage.StorageError):
        storage.open_sealed(k, bytes(blob), b'ctx')


def test_seal_wrong_context_or_key_rejected():
    k = storage.derive_storage_key(b's' * 32)
    blob = storage.seal(k, b'secret', b'ctx-a')
    with pytest.raises(storage.StorageError):
        storage.open_sealed(k, blob, b'ctx-b')
    with pytest.raises(storage.StorageError):
        storage.open_sealed(storage.derive_storage_key(b't' * 32), blob, b'ctx-a')


# ---- 会话状态 ----

def test_session_file_encrypted_0600_and_roundtrip(tmp_path):
    d = _mk(tmp_path)
    peer = fskey.Identity.generate().export_public()
    cs = d.add_contact(peer)
    sess, other = _pair()
    cs.session = sess
    d.save_session(cs)
    p = d._session_path(cs)
    raw = p.read_bytes()
    assert storage.is_sealed(raw)
    plain_state = base64.b64decode(sess.export_state())
    assert sess._root_key not in raw and plain_state[:20] not in raw
    assert sess.export_state()[:20] not in raw
    assert _mode(p) == 0o600
    assert not list(p.parent.glob('*.tmp')), '原子写不应残留临时文件'
    d.contacts.clear()
    cs2 = d.add_contact(peer)
    d.load_session(cs2)
    assert cs2.session.decrypt(other.encrypt(b'hi')) == b'hi'


def test_session_file_tamper_rejected(tmp_path):
    d = _mk(tmp_path)
    peer = fskey.Identity.generate().export_public()
    cs = d.add_contact(peer)
    cs.session, _ = _pair()
    d.save_session(cs)
    p = d._session_path(cs)
    raw = bytearray(p.read_bytes())
    raw[-5] ^= 0xFF
    p.write_bytes(bytes(raw))
    d.contacts.clear()
    with pytest.raises(storage.StorageError):
        d.load_session(d.add_contact(peer))


def test_session_file_swap_between_peers_rejected(tmp_path):
    """AAD 绑定 peer_fp：把 A 的加密状态挪成 B 的文件名必须被拒。"""
    d = _mk(tmp_path)
    pa, pb = fskey.Identity.generate().export_public(), fskey.Identity.generate().export_public()
    ca, cb = d.add_contact(pa), d.add_contact(pb)
    ca.session, _ = _pair()
    d.save_session(ca)
    d._session_path(cb).write_bytes(d._session_path(ca).read_bytes())
    with pytest.raises(storage.StorageError):
        d.load_session(cb)


def test_legacy_plaintext_session_migrated(tmp_path):
    d = _mk(tmp_path)
    peer = fskey.Identity.generate().export_public()
    cs = d.add_contact(peer)
    sess, other = _pair()
    legacy = sess.export_state()
    d._session_path(cs).write_bytes(legacy)
    # 1) 运行中：旧明文可直接读取
    d.load_session(cs)
    assert cs.session is not None
    # 2) 重启：启动时自动迁移为加密格式
    d2 = _mk(tmp_path)
    raw = d2._session_path(cs).read_bytes()
    assert storage.is_sealed(raw) and legacy not in raw
    cs2 = d2.add_contact(peer)
    d2.load_session(cs2)
    assert cs2.session.decrypt(other.encrypt(b'after-migrate')) == b'after-migrate'


# ---- 消息历史 / outbox ----

def test_history_not_plaintext_on_disk(tmp_path):
    d = _mk(tmp_path)
    peer = fskey.Identity.generate().export_public()
    cs = d.add_contact(peer)
    d.log_message('out', cs.peer_fp, 'TOP-SECRET-机密')
    d.log_message('in', cs.peer_fp, 'reply-plaintext')
    files = list((d.state_dir / 'messages').glob('*.jsonl'))
    assert files
    for f in files:
        body = f.read_bytes()
        assert b'TOP-SECRET' not in body and 'TOP-SECRET-机密'.encode() not in body
        assert b'reply-plaintext' not in body
        assert _mode(f) == 0o600
    assert [e['text'] for e in d.history(peer)] == ['TOP-SECRET-机密', 'reply-plaintext']


def test_history_tampered_line_dropped(tmp_path):
    d = _mk(tmp_path)
    peer = fskey.Identity.generate().export_public()
    cs = d.add_contact(peer)
    d.log_message('out', cs.peer_fp, 'one')
    d.log_message('out', cs.peer_fp, 'two')
    f = next((d.state_dir / 'messages').glob('*.jsonl'))
    lines = f.read_text().splitlines()
    blob = bytearray(base64.b64decode(lines[0][len(storage.LINE_PREFIX):]))
    blob[-1] ^= 1
    lines[0] = storage.LINE_PREFIX + base64.b64encode(bytes(blob)).decode()
    f.write_text('\n'.join(lines) + '\n')
    assert [e['text'] for e in d.history(peer)] == ['two']


def test_history_line_moved_between_days_rejected(tmp_path):
    d = _mk(tmp_path)
    peer = fskey.Identity.generate().export_public()
    cs = d.add_contact(peer)
    d.log_message('out', cs.peer_fp, 'today')
    f = next((d.state_dir / 'messages').glob('*.jsonl'))
    (f.parent / '1999-01-01.jsonl').write_text(f.read_text())
    assert [e['text'] for e in d.history(peer)] == ['today']


def test_legacy_plaintext_history_and_outbox_migrated(tmp_path):
    state = tmp_path / 'a'
    d = _mk(tmp_path)
    peer = fskey.Identity.generate().export_public()
    cs = d.add_contact(peer)
    legacy_day = state / 'messages' / '2020-01-01.jsonl'
    legacy_day.write_text(json.dumps({'ts': 1.0, 'dir': 'in', 'peer': _b64e(cs.peer_fp), 'text': 'legacy-msg'}) + '\n')
    d._outbox_path().write_text(json.dumps({'ts': 1.0, 'pub': peer, 'text': 'legacy-out'}) + '\n')
    # 旧明文可读
    assert [e['text'] for e in d.history(peer)] == ['legacy-msg']
    # 重启迁移
    d2 = _mk(tmp_path)
    assert b'legacy-msg' not in legacy_day.read_bytes()
    assert b'legacy-out' not in d2._outbox_path().read_bytes()
    d2.add_contact(peer)
    assert [e['text'] for e in d2.history(peer)] == ['legacy-msg']
    assert [e['text'] for e, _ in d2._read_jsonl(d2._outbox_path())] == ['legacy-out']


def test_mixed_legacy_file_migrated_on_next_write(tmp_path):
    d = _mk(tmp_path)
    peer = fskey.Identity.generate().export_public()
    cs = d.add_contact(peer)
    day = time.strftime('%Y-%m-%d')
    f = d.state_dir / 'messages' / f'{day}.jsonl'
    f.write_text(json.dumps({'ts': 1.0, 'dir': 'in', 'peer': _b64e(cs.peer_fp), 'text': 'old-plain'}) + '\n')
    d.log_message('out', cs.peer_fp, 'new')
    assert b'old-plain' not in f.read_bytes()
    assert [e['text'] for e in d.history(peer)] == ['old-plain', 'new']


def test_storage_secret_override(tmp_path):
    d = Daemon(str(tmp_path / 'x'), 'http://fake', storage_secret=b'k' * 32)
    d2 = Daemon(str(tmp_path / 'x'), 'http://fake', storage_secret=b'j' * 32)
    peer = fskey.Identity.generate().export_public()
    cs = d.add_contact(peer)
    cs.session, _ = _pair()
    d.save_session(cs)
    with pytest.raises(storage.StorageError):
        d2.load_session(d2.add_contact(peer))


# ---- ContactBook ----

def test_contactbook_encrypted_session_and_legacy_migration(tmp_path):
    key = storage.derive_storage_key(b'z' * 32, b'contacts')
    path = str(tmp_path / 'c.json')
    sess, other = _pair()
    state = sess.export_state().decode()
    # 旧格式（明文 session）写入
    legacy = ContactBook(path)
    c = legacy.add(fskey.Identity.generate().export_public())
    c.session_state = state
    legacy.save()
    with open(path) as fh:
        assert state in fh.read()
    # 用密钥打开：可读旧明文，save 后迁移
    book = ContactBook(path, storage_key=key)
    assert book.load_session(c.fp) is not None
    book.save()
    with open(path) as fh:
        on_disk = fh.read()
    assert state not in on_disk and 'session_enc' in on_disk
    assert _mode(path) == 0o600
    book2 = ContactBook(path, storage_key=key)
    s2 = book2.load_session(c.fp)
    assert s2.decrypt(other.encrypt(b'ok')) == b'ok'
    # 篡改 → 不加载
    data = json.loads(on_disk)
    k = next(iter(data))
    blob = bytearray(base64.b64decode(data[k]['session_enc']))
    blob[-1] ^= 1
    data[k]['session_enc'] = base64.b64encode(bytes(blob)).decode()
    with open(path, 'w') as f:
        json.dump(data, f)
    assert ContactBook(path, storage_key=key).load_session(c.fp) is None
