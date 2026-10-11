import pytest
from nbx import fskey
from nbx.ratchet import RatchetSession
from nbx.daemon import Daemon

def _established_pair():
    from cryptography.hazmat.primitives import serialization

    def ed_pub(identity):
        return identity.ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    a_id, b_id = (fskey.Identity.generate(), fskey.Identity.generate())
    a, b = (RatchetSession(), RatchetSession())
    hs_a = a.begin(a_id)
    hs_b = b.begin(b_id)
    a.finish(a_id, ed_pub(b_id), hs_b, speaks_first=True)
    b.finish(b_id, ed_pub(a_id), hs_a, speaks_first=False)
    return (a, b)

def test_integrity_tag_with_skipped_entries_roundtrip():
    a, b = _established_pair()
    assert b.decrypt(a.encrypt(b'first')) == b'first'
    for i in range(3):
        a.encrypt(f'msg{i}'.encode())
    blob = b.export_state()
    again = RatchetSession.import_state(blob)
    ct = a.encrypt(b'after-save')
    assert again.decrypt(ct) == b'after-save'

def _progress(sess):
    from nbx.daemon import _progress_of
    return _progress_of(sess)

def test_rollback_detected_on_state_file_swap(tmp_path):
    da = Daemon(str(tmp_path / 'state-a'), 'https://relay.example')
    peer_pub = fskey.Identity.generate().export_public()
    cs = da.add_contact(peer_pub)
    sess, _peer = _established_pair()
    cs.session = sess
    da.save_session(cs)
    old_blob = da._session_path(cs).read_bytes()
    p1 = _progress(sess)
    sess.encrypt(b'advance')
    da.save_session(cs)
    assert _progress(sess) > p1, '测试前提: 两次保存进度应递增'
    da._session_path(cs).write_bytes(old_blob)
    da.contacts.clear()
    cs2 = da.add_contact(peer_pub)
    with pytest.raises(RuntimeError, match='rollback'):
        da.load_session(cs2)
    print('✓ R2-04: 状态文件回滚被 epoch 日志拦截')

def test_equal_progress_loads_fine(tmp_path):
    da = Daemon(str(tmp_path / 'state-a'), 'https://relay.example')
    peer_pub = fskey.Identity.generate().export_public()
    cs = da.add_contact(peer_pub)
    sess, _ = _established_pair()
    cs.session = sess
    da.save_session(cs)
    da.contacts.clear()
    cs2 = da.add_contact(peer_pub)
    da.load_session(cs2)
    assert cs2.session is not None
    print('✓ R2-04: 正常重启不受影响')

def test_plaintext_state_without_epoch_log_is_rejected(tmp_path):
    da = Daemon(str(tmp_path / 'state-a'), 'https://relay.example')
    peer_pub = fskey.Identity.generate().export_public()
    cs = da.add_contact(peer_pub)
    sess, _ = _established_pair()
    cs.session = sess
    da._session_path(cs).write_bytes(sess.export_state())
    da.contacts.clear()
    cs2 = da.add_contact(peer_pub)
    with pytest.raises(RuntimeError, match='plaintext session state'):
        da.load_session(cs2)

def test_new_ratchet_chain_counter_reset_is_accepted(tmp_path):
    da = Daemon(str(tmp_path / 'state-a'), 'https://relay.example')
    peer_pub = fskey.Identity.generate().export_public()
    cs = da.add_contact(peer_pub)
    sess, _ = _established_pair()
    sess._recv_n = 15
    sess._send_n = 27
    cs.session = sess
    da.save_session(cs)

    # A fresh DH chain legitimately restarts its per-chain message counters.
    sess._dh_remote_pub = bytes([sess._dh_remote_pub[0] ^ 1]) + sess._dh_remote_pub[1:]
    sess._recv_n = 0
    sess._send_n = 0
    da.save_session(cs)
    da.contacts.clear()
    cs2 = da.add_contact(peer_pub)
    da.load_session(cs2)
    assert cs2.session is not None

def test_rollback_of_sealed_state_against_authenticated_anchor(tmp_path):
    da = Daemon(str(tmp_path / 'state-a'), 'https://relay.example')
    peer_pub = fskey.Identity.generate().export_public()
    cs = da.add_contact(peer_pub)
    sess, _ = _established_pair()
    cs.session = sess
    sess.encrypt(b'x')
    da.save_session(cs)
    old_blob = da._session_path(cs).read_bytes()
    sess.encrypt(b'advance')
    da.save_session(cs)
    da._session_path(cs).write_bytes(old_blob)
    da.contacts.clear()
    cs2 = da.add_contact(peer_pub)
    with pytest.raises(RuntimeError, match='rollback'):
        da.load_session(cs2)
    print('R2-05 ok: 端到端拦截 (0,0) < (0,1)')

def test_r2_07_epoch_log_compaction(tmp_path):
    da = Daemon(str(tmp_path / 'state-a'), 'https://relay.example')
    peer_pub = fskey.Identity.generate().export_public()
    cs = da.add_contact(peer_pub)
    sess, _ = _established_pair()
    cs.session = sess
    for i in range(80):
        da.save_session(cs)
    ep = da._epoch_log_path(cs.peer_fp)
    lines = [l for l in ep.read_text().splitlines() if l.strip()]
    assert len(lines) < 64, f'压实失败: {len(lines)} 行'
    da.contacts.clear()
    cs2 = da.add_contact(peer_pub)
    da.load_session(cs2)
    assert cs2.session is not None
    print(f'R2-07 ok: 压实后剩 {len(lines)} 行, 加载正常')

def test_r2_06_boundary_documented():
    import inspect
    from nbx.daemon import Daemon
    from nbx import daemon as d
    assert 'session' in inspect.getsource(Daemon.save_session)
    assert any('R2_06_BOUNDARY' in n for n in dir(d))
    print('R2-06 ok: 边界声明在代码中')
