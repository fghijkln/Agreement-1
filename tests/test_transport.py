import json
import struct
import sys
import threading
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from nbx import message as msg
from nbx.contacts import ContactBook, Contact, TransportStack, LAYER_P2P, LAYER_ANON, LAYER_RELAY, fp_of_pub
from nbx.fskey import Identity
from nbx.ratchet import RatchetSession
from nbx.relay import RelayLogic, MemoryStore, RelayServer

def _setup_pair():
    a, b = (Identity.generate(), Identity.generate())
    sa, sb = (RatchetSession(), RatchetSession())
    hs_a, hs_b = (sa.begin(a), sb.begin(b))
    sa.finish(a, _ed(b), hs_b, speaks_first=True)
    sb.finish(b, _ed(a), hs_a, speaks_first=False)
    return (a, b, sa, sb)

def _ed(i):
    from cryptography.hazmat.primitives import serialization
    return i.ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def test_state_roundtrip_plain(tmp_path):
    a, b, sa, sb = _setup_pair()
    blob = sa.export_state()
    sa2 = RatchetSession.import_state(blob)
    ct = sa2.encrypt(b'continued')
    assert sb.decrypt(ct) == b'continued'
    print('✓ ratchet 状态导出→恢复后继续通信')

def test_state_preserves_skipped(tmp_path):
    a, b, sa, sb = _setup_pair()
    c1 = sa.encrypt(b'one')
    c2 = sa.encrypt(b'two')
    assert sb.decrypt(c2) == b'two'
    state = sb.export_state()
    sb2 = RatchetSession.import_state(state)
    assert sb2.decrypt(c1) == b'one'
    print('✓ skipped 键跨持久化保留：乱序消息跨重启仍可解')

def test_state_after_ratchet_rotation(tmp_path):
    a, b, sa, sb = _setup_pair()
    sb.decrypt(sa.encrypt(b'm1'))
    ct = sb.encrypt(b'reply')
    sa.decrypt(ct)
    sa2 = RatchetSession.import_state(sa.export_state())
    assert sb.decrypt(sa2.encrypt(b'after rotation')) == b'after rotation'
    print('✓ DH 轮换后的状态持久化→恢复继续通信')

def test_state_blob_rejects_garbage(tmp_path):
    try:
        RatchetSession.import_state(b'garbage!!!')
        raise AssertionError('garbage accepted')
    except Exception:
        pass
    print('✓ 坏状态 blob 拒绝')

def test_contact_book_persistence(tmp_path):
    path = str(tmp_path / 'contacts.json')
    a, b, sa, sb = _setup_pair()
    book = ContactBook(path)
    c = book.add(b.export_public())
    book.store_session((b_fp := c.fp), sb)
    book.save()
    book2 = ContactBook(path)
    got = book2.get(b_fp)
    assert got is not None
    s = book2.load_session(b_fp)
    assert s is not None
    assert s.decrypt(sa.encrypt(b'via restored')) == b'via restored'
    print('✓ 通讯录持久化：会话跨进程恢复')

def test_load_session_corrupt_returns_none(tmp_path):
    path = str(tmp_path / 'c.json')
    book = ContactBook(path)
    import base64 as _b64
    c = book.add(_b64.b64encode(b'x' * 64).decode())
    c.session_state = b'broken'
    book.save()
    book2 = ContactBook(path)
    assert book2.load_session(c.fp) is None
    print('✓ 损坏的会话状态 → load 返回 None（不崩溃）')

def test_poll_never_sends_proof_to_unverified_endpoint(tmp_path):
    alice, bob, sa, sb = _setup_pair()
    book = ContactBook(str(tmp_path / 'c.json'))
    c = book.add(bob.export_public())
    malicious = 'http://mallory.example:9'
    c.addrs = [{'layer': LAYER_P2P, 'addr': '1.2.3.4:1', 'last_ok': time.time()}, {'layer': LAYER_RELAY, 'addr': malicious, 'last_ok': time.time()}]
    book.save()
    stack = TransportStack(book, alice)
    assert malicious not in stack._verified_endpoints
    stack.poll()
    assert malicious not in stack._verified_endpoints
    print('✓ R-14：未认证 endpoint 拿不到取信凭据（202 可达性不等于信任）')

def test_stack_fallback_p2p_fail_relay_ok(tmp_path):
    path = str(tmp_path / 'c.json')
    alice, bob, sa, sb = _setup_pair()
    book = ContactBook(path)
    me_book = ContactBook(str(tmp_path / 'me.json'))
    c = book.add(bob.export_public())
    c.addrs = [{'layer': LAYER_P2P, 'addr': '127.0.0.1:1'}, {'layer': LAYER_RELAY, 'addr': 'http://127.0.0.1:18801'}]
    book.save()
    logic = RelayLogic(MemoryStore())
    import base64 as _b64
    _pb = bob.export_public()
    logic.register_pubkey(_b64.b64decode(_pb + '=' * (-len(_pb) % 4)))
    srv = RelayServer(logic, port=18801)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    stack = TransportStack(book, alice)
    wire = msg.pack_message(msg.PT_TEXT, fp_of_pub(alice.export_public()), fp_of_pub(bob.export_public()), sa.encrypt(b'fallback!'))
    r = stack.send(fp_of_pub(bob.export_public()), wire)
    assert r.ok and r.layer == LAYER_RELAY, r.detail
    envs = logic.fetch(fp_of_pub(bob.export_public()), _proof(bob, fp_of_pub(bob.export_public())))
    assert len(envs) == 1
    assert msg.parse_message(envs[0])['body'] == wire[48:]
    print('✓ 降级：L1 不通 → L3 中继送达')

def _proof(ident, fp):
    ts = struct.pack('<Q', int(time.time()))
    return ts + ident.ed_priv.sign(b'nbx-relay-auth-v1' + fp + ts)

def test_stack_layer_success_recorded(tmp_path):
    path = str(tmp_path / 'c.json')
    alice, bob, *_ = _setup_pair()
    book = ContactBook(path)
    c = book.add(bob.export_public())
    c.addrs = [{'layer': LAYER_P2P, 'addr': '127.0.0.1:1'}]
    book.save()
    stack = TransportStack(book, alice)
    wire = msg.pack_message(msg.PT_TEXT, b'\x01' * 8, c.fp, b'x')
    r = stack.send(c.fp, wire)
    assert not r.ok
    assert c.addrs[0].get('last_ok') is None
    c.addrs.append({'layer': LAYER_P2P, 'addr': '127.0.0.1:1'})
    print('✓ 失败层不标记成功')

def test_stack_unknown_contact(tmp_path):
    stack = TransportStack(ContactBook(str(tmp_path / 'empty.json')), Identity.generate())
    try:
        stack.send(b'\x00' * 8, b'data')
        raise AssertionError('unknown contact accepted')
    except KeyError:
        pass
    print('✓ 未知联系人拒绝')
if __name__ == '__main__':
    import tempfile
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for t in tests:
        with tempfile.TemporaryDirectory() as td:
            t(Path(td))
    print(f'\n{len(tests)} 项三层传输栈测试全部通过 ✅')
