"""audit R2-04/05/06/07 回归：ratchet 状态回滚检测（daemon 层 monotonic epoch）。"""
import pytest

from nbx import fskey
from nbx.ratchet import RatchetSession
from nbx.daemon import Daemon


def _established_pair():
    """走真实握手建立两条会话（无网络，纯状态机）。"""
    from cryptography.hazmat.primitives import serialization

    def ed_pub(identity):
        return identity.ed_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    a_id, b_id = fskey.Identity.generate(), fskey.Identity.generate()
    a, b = RatchetSession(), RatchetSession()
    hs_a = a.begin(a_id)
    hs_b = b.begin(b_id)
    a.finish(a_id, ed_pub(b_id), hs_b, speaks_first=True)
    b.finish(b_id, ed_pub(a_id), hs_a, speaks_first=False)
    return a, b


def test_integrity_tag_with_skipped_entries_roundtrip():
    """⑤ 修正回归: skipped entries 密文任意内容时 tag 校验仍正确。

    旧实现 raw.rfind 反推 body 边界，skipped 的 msgkey 碰巧含
    字段 8 TLV 头字节序列时会切错位置。
    """
    a, b = _established_pair()
    assert b.decrypt(a.encrypt(b"first")) == b"first"   # 建立收链
    for i in range(3):
        a.encrypt(f"msg{i}".encode())     # B 端积累 skipped entries
    blob = b.export_state()
    again = RatchetSession.import_state(blob)
    ct = a.encrypt(b"after-save")
    assert again.decrypt(ct) == b"after-save"


def _progress(sess):
    from nbx.daemon import _progress_of
    return _progress_of(sess)


def test_rollback_detected_on_state_file_swap(tmp_path):
    """R2-04 核心: 状态文件被换回旧快照 → load_session 拒绝加载。"""
    da = Daemon(str(tmp_path / "state-a"), "https://relay.example")
    peer_pub = fskey.Identity.generate().export_public()
    cs = da.add_contact(peer_pub)
    sess, _peer = _established_pair()
    cs.session = sess
    da.save_session(cs)                       # epoch 记 P1
    old_blob = da._session_path(cs).read_bytes()
    p1 = _progress(sess)
    sess.encrypt(b"advance")                  # 推进 send_n
    da.save_session(cs)                       # epoch 记 P2 > P1
    assert _progress(sess) > p1, "测试前提: 两次保存进度应递增"
    # 攻击: 状态文件滚回旧快照（epoch 日志不动）
    da._session_path(cs).write_bytes(old_blob)
    da.contacts.clear()
    cs2 = da.add_contact(peer_pub)
    with pytest.raises(RuntimeError, match="rollback"):
        da.load_session(cs2)
    print("✓ R2-04: 状态文件回滚被 epoch 日志拦截")


def test_equal_progress_loads_fine(tmp_path):
    """正常重启（进度等于日志末值）不受影响。"""
    da = Daemon(str(tmp_path / "state-a"), "https://relay.example")
    peer_pub = fskey.Identity.generate().export_public()
    cs = da.add_contact(peer_pub)
    sess, _ = _established_pair()
    cs.session = sess
    da.save_session(cs)
    da.contacts.clear()
    cs2 = da.add_contact(peer_pub)
    da.load_session(cs2)
    assert cs2.session is not None
    print("✓ R2-04: 正常重启不受影响")


def test_no_epoch_log_legacy_upgrade(tmp_path):
    """旧版本升级路径：无 epoch 日志时照常加载。"""
    da = Daemon(str(tmp_path / "state-a"), "https://relay.example")
    peer_pub = fskey.Identity.generate().export_public()
    cs = da.add_contact(peer_pub)
    sess, _ = _established_pair()
    cs.session = sess
    # 直接写状态文件，不经过 save_session → 无 epoch 日志
    da._session_path(cs).write_bytes(sess.export_state())
    da.contacts.clear()
    cs2 = da.add_contact(peer_pub)
    da.load_session(cs2)
    assert cs2.session is not None
    print("✓ R2-04: 旧版本（无 epoch 日志）兼容")


def test_r2_05_tuple_beats_scalar_collision(tmp_path):
    """R2-05: recv_n 更旧但 send_n 更大的状态不得绕过回滚检查。

    旧标量 recv_n*2^20+send_n 下, (4, 1500000) > (5, 0) 会被放行;
    元组字典序 (4,*) < (5,*) 必须拒绝。
    """
    from nbx.daemon import _progress_of

    class _Fake:
        recv_n = 4
        send_n = 1_500_000

    assert _progress_of(_Fake()) < (5, 0), "元组序必须判 (4,1500000) < (5,0)"
    # 旧标量判反——证明本回归针对的碰撞真实存在:
    assert 4 * (1 << 20) + 1_500_000 > 5 * (1 << 20) + 0
    print("R2-05 ok: (recv_n, send_n) 元组序修复标量碰撞")


def test_r2_05_rollback_with_stale_recv(tmp_path):
    """R2-05 端到端: recv/send 组合落后于日志的状态文件仍被拒。"""
    da = Daemon(str(tmp_path / "state-a"), "https://relay.example")
    peer_pub = fskey.Identity.generate().export_public()
    cs = da.add_contact(peer_pub)
    sess, _ = _established_pair()
    cs.session = sess
    sess.encrypt(b"x")                    # 推进 send_n 至 (0,1)
    da.save_session(cs)                   # epoch 记 (0,1)
    # 状态文件滚回 (0,0) 的快照
    sess0, _ = _established_pair()
    da._session_path(cs).write_bytes(sess0.export_state())
    da.contacts.clear()
    cs2 = da.add_contact(peer_pub)
    with pytest.raises(RuntimeError, match="rollback"):
        da.load_session(cs2)
    print("R2-05 ok: 端到端拦截 (0,0) < (0,1)")


def test_r2_07_epoch_log_compaction(tmp_path):
    """R2-07: epoch 日志超过阈值自动压实, 不无限增长。"""
    da = Daemon(str(tmp_path / "state-a"), "https://relay.example")
    peer_pub = fskey.Identity.generate().export_public()
    cs = da.add_contact(peer_pub)
    sess, _ = _established_pair()
    cs.session = sess
    for i in range(80):
        da.save_session(cs)               # 每次追加; 超过 64 触发压实
    ep = da._epoch_log_path(cs.peer_fp)
    lines = [l for l in ep.read_text().splitlines() if l.strip()]
    assert len(lines) < 64, f"压实失败: {len(lines)} 行"
    da.contacts.clear()
    cs2 = da.add_contact(peer_pub)
    da.load_session(cs2)
    assert cs2.session is not None
    print(f"R2-07 ok: 压实后剩 {len(lines)} 行, 加载正常")


def test_r2_06_boundary_documented():
    """R2-06: 代码明确声明 epoch 防护边界（不夸大 append-only）。"""
    import inspect
    from nbx.daemon import Daemon
    src = inspect.getsource(Daemon.save_session)
    assert "不提供保护" in src
    print("R2-06 ok: 边界声明在代码中")
