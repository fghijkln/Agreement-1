import base64
import struct

import pytest
from nbx import fskey
from nbx.ratchet import MAGIC_STATE, RatchetSession

def _ed_pub(identity):
    from cryptography.hazmat.primitives import serialization
    return identity.ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def _established_pair():
    a_id, b_id = (fskey.Identity.generate(), fskey.Identity.generate())
    a, b = (RatchetSession(), RatchetSession())
    hs_a = a.begin(a_id)
    hs_b = b.begin(b_id)
    a.finish(a_id, _ed_pub(b_id), hs_b, speaks_first=True)
    b.finish(b_id, _ed_pub(a_id), hs_a, speaks_first=False)
    return (a, b)

def _live_state(sender: bool=False) -> bytes:
    a, b = _established_pair()
    assert b.decrypt(a.encrypt(b'm1')) == b'm1'
    for i in range(5):
        a.encrypt(f'msg{i}'.encode())
    assert b.decrypt(a.encrypt(b'm6')) == b'm6'
    assert b.skipped_count > 0, '前提: 接收端应留有 skipped 条目'
    assert a.send_n > 0, '前提: 发送端应有计数推进'
    return a.export_state() if sender else b.export_state()

def _decoded_fields(state: bytes) -> dict:
    raw = base64.b64decode(state)
    assert raw[:len(MAGIC_STATE)] == MAGIC_STATE
    off = len(MAGIC_STATE) + 1
    fields = {}
    while off < len(raw):
        t = raw[off]
        ln = struct.unpack('<I', raw[off + 1:off + 5])[0]
        fields[t] = raw[off + 5:off + 5 + ln]
        off += 5 + ln
    return fields

def _counters(state: bytes) -> tuple:
    return struct.unpack('<III', _decoded_fields(state)[7])

def _rebuild(fields: dict, drop=()) -> bytes:
    out = bytearray(MAGIC_STATE + bytes([1]))
    for t in sorted(fields):
        if t in drop:
            continue
        v = fields[t]
        out += bytes([t]) + struct.pack('<I', len(v)) + v
    return base64.b64encode(bytes(out))

def _tamper(state: bytes, ftype: int, mutate) -> bytes:
    fields = _decoded_fields(state)
    fields[ftype] = mutate(fields[ftype])
    return _rebuild(fields)

def _rollback_recv_n(state: bytes) -> bytes:
    prev_len, send_n, _recv_n = _counters(state)
    return _tamper(state, 7, lambda c: struct.pack('<III', prev_len, send_n, 0))

def _rollback_send_n(state: bytes) -> bytes:
    prev_len, _send_n, recv_n = _counters(state)
    return _tamper(state, 7, lambda c: struct.pack('<III', prev_len, 0, recv_n))

def _flip_last(v: bytes) -> bytes:
    return v[:-1] + bytes([v[-1] ^ 1])

def test_untampered_state_roundtrips():
    a, b = _established_pair()
    state = b.export_state()
    restored = RatchetSession.import_state(state)
    assert restored._root_key == b._root_key
    assert (restored._send_ck, restored._recv_ck) == (b._send_ck, b._recv_ck)
    assert (restored.send_n, restored.recv_n, restored._prev_send_len) == (b.send_n, b.recv_n, b._prev_send_len)
    assert restored._dh_remote_pub == b._dh_remote_pub
    assert restored._skipped == b._skipped
    assert restored.decrypt(a.encrypt(b'after import')) == b'after import'

def test_untampered_state_with_skipped_entries_roundtrips():
    state = _live_state()
    assert len(_decoded_fields(state)[6]) >= 68
    restored = RatchetSession.import_state(state)
    assert restored.skipped_count > 0

def test_tampered_recv_n_rejected():
    state = _live_state()
    assert _counters(state)[2] > 0, '前提: recv_n 应为正'
    bad = _rollback_recv_n(state)
    assert _decoded_fields(bad)[8] == _decoded_fields(state)[8], '前提: 攻击者不重算标签'
    with pytest.raises(ValueError, match='integrity'):
        RatchetSession.import_state(bad)

def test_tampered_send_n_rejected():
    state = _live_state(sender=True)
    assert _counters(state)[1] > 0, '前提: send_n 应为正'
    bad = _rollback_send_n(state)
    with pytest.raises(ValueError, match='integrity'):
        RatchetSession.import_state(bad)

def test_tampered_root_key_rejected():
    state = _live_state()
    bad = _tamper(state, 1, _flip_last)
    with pytest.raises(ValueError, match='integrity'):
        RatchetSession.import_state(bad)

def test_tampered_send_ck_rejected():
    state = _live_state(sender=True)
    assert len(_decoded_fields(state)[2]) == 32, '前提: 发送端应有 32B send_ck'
    bad = _tamper(state, 2, _flip_last)
    with pytest.raises(ValueError, match='integrity'):
        RatchetSession.import_state(bad)

def test_tampered_dh_private_key_rejected():
    state = _live_state()
    bad = _tamper(state, 4, _flip_last)
    with pytest.raises(ValueError, match='integrity'):
        RatchetSession.import_state(bad)

def test_tampered_skipped_entries_rejected():
    state = _live_state()
    bad = _tamper(state, 6, _flip_last)
    with pytest.raises(ValueError, match='integrity'):
        RatchetSession.import_state(bad)

def test_tag_binds_blob_not_just_root_key():
    from nbx.ratchet import _state_integrity_tag
    root_key = _decoded_fields(_live_state())[1]
    bodies, tags = [], set()
    for i in range(3):
        a, b = _established_pair()
        for j in range(i + 1):
            a.encrypt(f'pad{j}'.encode())
        fields = _decoded_fields(b.export_state())
        body = base64.b64decode(_rebuild(fields, drop=(8,)))
        bodies.append(body)
        tags.add(_state_integrity_tag(root_key, body))
    assert len(bodies) == 3
    assert len(set(bodies)) == 3, '前提: 三段 blob 内容互不相同'
    assert len(tags) == 3, '相同 root_key 下不同内容必须得到不同标签'
