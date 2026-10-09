import secrets
import struct
import pytest
from cryptography.exceptions import InvalidTag
from nbx.chat import ChatSession
from nbx.fskey import Identity
from nbx.ratchet import RatchetSession, MAX_SKIP, HEADER_SIZE, NONCE_SIZE

def mk_pair():
    a, b = (RatchetSession(), RatchetSession())
    ia, ib = (Identity.generate(), Identity.generate())
    hs_a = a.begin(ia)
    hs_b = b.begin(ib)
    _, ed_a = Identity.parse_public(ia.export_public())
    _, ed_b = Identity.parse_public(ib.export_public())
    a.finish(ia, ed_b, hs_b, speaks_first=True)
    b.finish(ib, ed_a, hs_a, speaks_first=False)
    return (a, b)

def state_fingerprint(rs: RatchetSession) -> tuple:
    return (rs._root_key, rs._send_ck, rs._recv_ck, rs._send_n, rs._recv_n, rs._dh_remote_pub, frozenset(rs._skipped.items()))

def test_forged_ratchet_pub_cannot_poison_state():
    a, b = mk_pair()
    a.encrypt(b'real msg 1')
    a.encrypt(b'real msg 2')
    before = state_fingerprint(b)
    fake_hdr = secrets.token_bytes(32) + struct.pack('<II', 0, 0)
    fake_blob = fake_hdr + secrets.token_bytes(NONCE_SIZE + 48)
    with pytest.raises(InvalidTag):
        b.decrypt(fake_blob)
    assert state_fingerprint(b) == before, '失败解密不得改变任何状态'
    wire = a.encrypt(b'real msg 3')
    assert b.decrypt(wire) == b'real msg 3'

def test_prev_len_uint32_cannot_trigger_mass_kdf():
    a, b = mk_pair()
    assert b.decrypt(a.encrypt(b'm1')) == b'm1'
    before = state_fingerprint(b)
    fake_hdr = secrets.token_bytes(32) + struct.pack('<II', 4294967295, 0)
    fake_blob = fake_hdr + secrets.token_bytes(NONCE_SIZE + 48)
    with pytest.raises(ValueError):
        b.decrypt(fake_blob)
    assert state_fingerprint(b) == before
    assert len(b._skipped) <= MAX_SKIP, 'skipped 不得爆炸'

def test_tampered_out_of_order_keeps_skipped_key():
    a, b = mk_pair()
    w1 = a.encrypt(b'msg1')
    w2 = a.encrypt(b'msg2')
    w3 = a.encrypt(b'msg3')
    assert b.decrypt(w1) == b'msg1'
    assert b.decrypt(w3) == b'msg3'
    assert len(b._skipped) == 1
    tampered = w2[:-1] + bytes([w2[-1] ^ 1])
    with pytest.raises(InvalidTag):
        b.decrypt(tampered)
    assert b.decrypt(w2) == b'msg2'
    assert len(b._skipped) == 0

def test_forged_ratchet_pub_then_real_ratchet_still_works():
    a, b = mk_pair()
    a.encrypt(b'm1')
    fake_hdr = secrets.token_bytes(32) + struct.pack('<II', 0, 0)
    with pytest.raises(InvalidTag):
        b.decrypt(fake_hdr + secrets.token_bytes(NONCE_SIZE + 48))
    assert b.decrypt(a.encrypt(b'm2')) == b'm2'
    back = b.encrypt(b'reply')
    assert a.decrypt(back) == b'reply'

def test_random_garbage_fuzz_state_unchanged():
    a, b = mk_pair()
    wires = [a.encrypt(b'legit %d' % i) for i in range(5)]
    before = state_fingerprint(b)
    for _ in range(100):
        garbage = secrets.token_bytes(200)
        try:
            b.decrypt(garbage)
        except Exception:
            pass
    assert state_fingerprint(b) == before
    for i, w in enumerate(wires):
        assert b.decrypt(w) == b'legit %d' % i

def test_out_of_order_after_attack_still_works():
    a, b = mk_pair()
    w1 = a.encrypt(b'x1')
    w2 = a.encrypt(b'x2')
    w3 = a.encrypt(b'x3')
    with pytest.raises(InvalidTag):
        b.decrypt(secrets.token_bytes(32) + struct.pack('<II', 0, 0) + secrets.token_bytes(NONCE_SIZE + 48))
    assert b.decrypt(w1) == b'x1'
    assert b.decrypt(w3) == b'x3'
    assert b.decrypt(w2) == b'x2'
    back = b.encrypt(b'reply')
    assert a.decrypt(back) == b'reply'
    assert b.decrypt(a.encrypt(b'x4')) == b'x4'
