import time
import pytest
from nbx.chat import ChatSession, fingerprint8
from nbx.fskey import Identity
from nbx.ratchet import RatchetSession, HandshakeStale, handshake_age, make_handshake, verify_handshake
from nbx import message as msg

def _mk_hs(identity, eph_pub=None, ts=None, sender_fp=b'\x00' * 8, recv_fp=b'\x00' * 8):
    if eph_pub is None:
        eph_pub = bytes(range(32))
    if ts is None:
        ts = int(time.time())
    import struct
    ts_b = struct.pack('<Q', ts)
    sig = identity.ed_priv.sign(b'NBXRATCH1' + sender_fp + recv_fp + eph_pub + ts_b)
    return b'NBXRATCH1' + sender_fp + recv_fp + eph_pub + ts_b + sig

def test_stale_handshake_rejected(tmp_path):
    a = Identity.generate()
    old = _mk_hs(a, ts=int(time.time()) - 3600)
    with pytest.raises(HandshakeStale):
        verify_handshake(Identity.parse_public(a.export_public())[1], old)

def test_future_handshake_beyond_skew_rejected(tmp_path):
    a = Identity.generate()
    future = _mk_hs(a, ts=int(time.time()) + 100000)
    with pytest.raises(HandshakeStale):
        verify_handshake(Identity.parse_public(a.export_public())[1], future)

def test_fresh_handshake_accepted(tmp_path):
    a = Identity.generate()
    fresh = make_handshake(a, bytes(range(32)))
    eph = verify_handshake(Identity.parse_public(a.export_public())[1], fresh)
    assert eph == bytes(range(32))

def test_wait_handshake_prefers_fresh_over_stale(tmp_path):
    alice = Identity.generate()
    bob = Identity.generate()

    class FakeClient:

        def __init__(self, blobs):
            self._blobs = blobs
            self.my_fp = fingerprint8(alice.export_public())

        def auth(self, *_):
            pass

        def fetch(self, fp, proof):
            out, self._blobs = (self._blobs, [])
            return out

        def post_envelope(self, blob):
            return {}
    old_hs = _mk_hs(bob, ts=int(time.time()) - 3600)
    new_hs = _mk_hs(bob, ts=int(time.time()))
    old_env = msg.pack_message(msg.PT_HANDSHAKE, fingerprint8(bob.export_public()), fingerprint8(alice.export_public()), old_hs)
    new_env = msg.pack_message(msg.PT_HANDSHAKE, fingerprint8(bob.export_public()), fingerprint8(alice.export_public()), new_hs)
    cs = ChatSession(alice, bob.export_public(), 'http://fake', speaks_first=True)
    cs.client = FakeClient([old_env, new_env])
    got = cs._wait_handshake(timeout=5)
    assert got == new_hs
    assert got != old_hs

def test_stale_text_pending_does_not_break_session(tmp_path):
    alice = Identity.generate()
    bob = Identity.generate()

    class FakeClient:

        def __init__(self, blobs):
            self._blobs = blobs
            self.my_fp = fingerprint8(alice.export_public())

        def auth(self, *_):
            pass

        def fetch(self, fp, proof):
            out, self._blobs = (self._blobs, [])
            return out

        def post_envelope(self, blob):
            return {}
    stale_text = msg.pack_message(msg.PT_TEXT, fingerprint8(bob.export_public()), fingerprint8(alice.export_public()), b'garbage from dead session')
    new_hs = _mk_hs(bob, ts=int(time.time()))
    new_env = msg.pack_message(msg.PT_HANDSHAKE, fingerprint8(bob.export_public()), fingerprint8(alice.export_public()), new_hs)
    cs = ChatSession(alice, bob.export_public(), 'http://fake', speaks_first=True)
    cs.client = FakeClient([stale_text, new_env])
    got = cs._wait_handshake(timeout=5)
    assert got == new_hs
    assert len(cs._pending) == 1
