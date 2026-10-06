"""握手代际防护测试（真机 InvalidTag 事故的回归）。

场景：中继桶里残留上一代会话的握手/正文信封（7 天 TTL），
新会话建立时若误取旧握手，将与对端当前会话错位 → InvalidTag。
防线：verify_handshake 的时效窗口 + _wait_handshake 选取最新候选。
"""
import time

import pytest

from nbx.chat import ChatSession, fingerprint8
from nbx.fskey import Identity
from nbx.ratchet import (RatchetSession, HandshakeStale, handshake_age,
                         make_handshake, verify_handshake)
from nbx import message as msg


def _mk_hs(identity, eph_pub=None, ts=None, sender_fp=b"\x00" * 8,
           recv_fp=b"\x00" * 8):
    """构造握手 v2 载荷，可注入旧时间戳。"""
    if eph_pub is None:
        eph_pub = bytes(range(32))
    if ts is None:
        ts = int(time.time())
    import struct
    ts_b = struct.pack("<Q", ts)
    sig = identity.ed_priv.sign(
        b"NBXRATCH1" + sender_fp + recv_fp + eph_pub + ts_b)
    return b"NBXRATCH1" + sender_fp + recv_fp + eph_pub + ts_b + sig


def test_stale_handshake_rejected(tmp_path):
    """超过时效窗口的握手必须被 HandshakeStale 拒绝。"""
    a = Identity.generate()
    old = _mk_hs(a, ts=int(time.time()) - 3600)   # 1 小时前
    with pytest.raises(HandshakeStale):
        verify_handshake(Identity.parse_public(a.export_public())[1], old)


def test_future_handshake_beyond_skew_rejected(tmp_path):
    """来自"未来"太久的握手同样拒绝（防时钟倒放滥用）。"""
    a = Identity.generate()
    future = _mk_hs(a, ts=int(time.time()) + 100000)
    with pytest.raises(HandshakeStale):
        verify_handshake(Identity.parse_public(a.export_public())[1], future)


def test_fresh_handshake_accepted(tmp_path):
    """新鲜握手正常通过。"""
    a = Identity.generate()
    fresh = make_handshake(a, bytes(range(32)))
    eph = verify_handshake(Identity.parse_public(a.export_public())[1], fresh)
    assert eph == bytes(range(32))


def test_wait_handshake_prefers_fresh_over_stale(tmp_path):
    """_wait_handshake 在新旧混杂时必须选新鲜的，跳过旧代残留。"""
    alice = Identity.generate()
    bob = Identity.generate()

    class FakeClient:
        """一次性返回 [旧握手, 新握手]，之后为空。"""
        def __init__(self, blobs):
            self._blobs = blobs
            self.my_fp = fingerprint8(alice.export_public())

        def auth(self, *_): pass

        def fetch(self, fp, proof):
            out, self._blobs = self._blobs, []
            return out

        def post_envelope(self, blob):
            return {}

    old_hs = _mk_hs(bob, ts=int(time.time()) - 3600)
    new_hs = _mk_hs(bob, ts=int(time.time()))
    old_env = msg.pack_message(msg.PT_HANDSHAKE,
                               fingerprint8(bob.export_public()),
                               fingerprint8(alice.export_public()), old_hs)
    new_env = msg.pack_message(msg.PT_HANDSHAKE,
                               fingerprint8(bob.export_public()),
                               fingerprint8(alice.export_public()), new_hs)

    cs = ChatSession(alice, bob.export_public(), "http://fake",
                     speaks_first=True)
    cs.client = FakeClient([old_env, new_env])
    got = cs._wait_handshake(timeout=5)
    assert got == new_hs                       # 必须是新代握手
    assert got != old_hs


def test_stale_text_pending_does_not_break_session(tmp_path):
    """残留的旧正文缓存在 _pending，不应阻断新会话建立。"""
    # 旧正文 + 新握手同批：新握手必须被采纳（旧正文留给 poll_once 报错跳过）
    alice = Identity.generate()
    bob = Identity.generate()

    class FakeClient:
        def __init__(self, blobs):
            self._blobs = blobs
            self.my_fp = fingerprint8(alice.export_public())

        def auth(self, *_): pass

        def fetch(self, fp, proof):
            out, self._blobs = self._blobs, []
            return out

        def post_envelope(self, blob):
            return {}

    stale_text = msg.pack_message(msg.PT_TEXT,
                                  fingerprint8(bob.export_public()),
                                  fingerprint8(alice.export_public()),
                                  b"garbage from dead session")
    new_hs = _mk_hs(bob, ts=int(time.time()))
    new_env = msg.pack_message(msg.PT_HANDSHAKE,
                               fingerprint8(bob.export_public()),
                               fingerprint8(alice.export_public()), new_hs)

    cs = ChatSession(alice, bob.export_public(), "http://fake",
                     speaks_first=True)
    cs.client = FakeClient([stale_text, new_env])
    got = cs._wait_handshake(timeout=5)
    assert got == new_hs
    # 旧正文进 _pending 而非丢失/阻断
    assert len(cs._pending) == 1
