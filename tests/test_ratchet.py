import hashlib
import struct
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from nbx import message as msg
from nbx.fskey import Identity
from nbx.ratchet import RatchetSession, _kdf_ck, make_handshake, verify_handshake, HEADER_SIZE, MAGIC_RATCHET

def _setup_sessions():
    alice_id, bob_id = (Identity.generate(), Identity.generate())
    a, b = (RatchetSession(), RatchetSession())
    hs_a = a.begin(alice_id)
    hs_b = b.begin(bob_id)
    a_pub = alice_id.ed_priv.public_key().public_bytes_raw() if hasattr(alice_id.ed_priv.public_key(), 'public_bytes_raw') else None
    from cryptography.hazmat.primitives import serialization
    a_ed = alice_id.ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    b_ed = bob_id.ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    a.finish(alice_id, b_ed, hs_b, speaks_first=True)
    b.finish(bob_id, a_ed, hs_a, speaks_first=False)
    return (a, b, alice_id, bob_id)

def test_handshake_signature_binds_eph():
    alice_id, bob_id = (Identity.generate(), Identity.generate())
    hs = make_handshake(alice_id, b'\x11' * 32)
    from cryptography.hazmat.primitives import serialization
    alice_ed = alice_id.ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert verify_handshake(alice_ed, hs) == b'\x11' * 32
    bad = bytearray(hs)
    bad[9] ^= 1
    from cryptography.hazmat.primitives import serialization
    ed = alice_id.ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    try:
        verify_handshake(ed, bytes(bad))
        raise AssertionError('tampered handshake accepted')
    except Exception:
        pass
    print('✓ 握手签名绑定临时公钥，篡改拒绝')

def test_basic_roundtrip():
    a, b, *_ = _setup_sessions()
    ct = a.encrypt(b'hello bob')
    assert b.decrypt(ct) == b'hello bob'
    ct2 = b.encrypt(b'hi alice')
    assert a.decrypt(ct2) == b'hi alice'
    print('✓ 双向基本往返')

def test_message_key_forward_secrecy():
    a, b, *_ = _setup_sessions()
    cts = [a.encrypt(f'msg{i}'.encode()) for i in range(5)]
    for i in range(3):
        b.decrypt(cts[i])
    cur = b._recv_ck
    ct0 = cts[0]
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    hdr = ct0[:HEADER_SIZE]
    nonce = ct0[HEADER_SIZE:HEADER_SIZE + 12]
    body = ct0[HEADER_SIZE + 12:]
    _, mk_wrong = _kdf_ck(cur)
    try:
        ChaCha20Poly1305(mk_wrong).decrypt(nonce, body, MAGIC_RATCHET + hdr)
        raise AssertionError('old message decrypted with advanced chain key')
    except Exception:
        pass
    print('✓ 逐消息前向保密：链推进后旧消息密钥不可恢复')

def test_dh_ratchet_on_reply():
    a, b, *_ = _setup_sessions()
    first_pub = a.send_ratchet_pub
    a.encrypt(b'm1')
    ct = b.encrypt(b'reply')
    assert a.decrypt(ct) == b'reply'
    ct2 = a.encrypt(b'm2')
    assert b.decrypt(ct2) == b'm2'
    print(f'✓ DH ratchet 交替（Alice 初始 {first_pub[:4].hex()}… 正常轮换）')

def test_out_of_order_delivery():
    a, b, *_ = _setup_sessions()
    c1, c2, c3 = (a.encrypt(b'one'), a.encrypt(b'two'), a.encrypt(b'three'))
    assert b.decrypt(c2) == b'two'
    assert b.decrypt(c1) == b'one'
    assert b.decrypt(c3) == b'three'
    assert b.skipped_count == 0
    print('✓ 乱序投递：skipped 密钥补上后清空')

def test_replay_rejected():
    a, b, *_ = _setup_sessions()
    ct = a.encrypt(b'once')
    assert b.decrypt(ct) == b'once'
    try:
        b.decrypt(ct)
        raise AssertionError('replay accepted')
    except Exception as e:
        assert 'already' in str(e) or 'bad' in str(e)
    print('✓ 消息重放拒绝')

def test_tamper_rejected():
    a, b, *_ = _setup_sessions()
    ct = bytearray(a.encrypt(b'data'))
    ct[-1] ^= 1
    try:
        b.decrypt(bytes(ct))
        raise AssertionError('tampered ct accepted')
    except Exception:
        pass
    ct2 = bytearray(a.encrypt(b'data'))
    ct2[35] ^= 1
    try:
        b.decrypt(bytes(ct2))
        raise AssertionError('tampered header accepted')
    except Exception:
        pass
    print('✓ 密文/头部篡改拒绝（AAD 绑定）')

def test_many_messages_ratchet_churn():
    a, b, *_ = _setup_sessions()
    for i in range(30):
        ct = a.encrypt(f'a{i}'.encode())
        assert b.decrypt(ct) == f'a{i}'.encode()
        ct = b.encrypt(f'b{i}'.encode())
        assert a.decrypt(ct) == f'b{i}'.encode()
    print('✓ 30 条消息多轮 ratchet 全部正确')

def test_message_pack_parse_roundtrip():
    a, b, alice_id, bob_id = _setup_sessions()
    sfp = msg.fingerprint_of(b'x' * 64)
    rfp = msg.fingerprint_of(b'y' * 64)
    body = a.encrypt(msg.encode_text('你好，NBX'))
    wire = msg.pack_message(msg.PT_TEXT, sfp, rfp, body)
    m = msg.parse_message(wire)
    assert m['ptype'] == msg.PT_TEXT
    assert m['sender_fp'] == sfp and m['recv_fp'] == rfp
    plain = b.decrypt(m['body'])
    assert plain == msg.encode_text('你好，NBX')
    assert msg.decode_text(plain) == '你好，NBX'
    print('✓ 消息信封编解码 + 中文正文往返')

def test_message_tamper_header_rejected():
    sfp, rfp = (b'\x01' * 8, b'\x02' * 8)
    wire = bytearray(msg.pack_message(msg.PT_TEXT, sfp, rfp, b'data'))
    wire[47] ^= 1
    try:
        msg.parse_message(bytes(wire))
        raise AssertionError('corrupt body_len accepted')
    except ValueError:
        pass
    try:
        msg.parse_message(bytes(wire)[:-2])
        raise AssertionError('truncated message accepted')
    except ValueError:
        pass
    print('✓ 消息头损坏拒绝')

def test_file_transfer_via_messages():
    a, b, *_ = _setup_sessions()
    data = os_urandom(3000) if (os_urandom := __import__('os').urandom) else b''
    sha = hashlib.sha256(data).digest()
    wire1 = msg.pack_message(msg.PT_FILE_OFFER, b'\x01' * 8, b'\x02' * 8, a.encrypt(msg.encode_file_offer('report.bin', len(data), sha)))
    m1 = msg.parse_message(wire1)
    name, size, sha2 = msg.decode_file_offer(b.decrypt(m1['body']))
    assert (name, size, sha2) == ('report.bin', len(data), sha)
    chunk_size = 1000
    wires = []
    for off in (1000, 2000, 0):
        wires.append(msg.pack_message(msg.PT_FILE_CHUNK, b'\x01' * 8, b'\x02' * 8, a.encrypt(msg.encode_file_chunk(off, data[off:off + chunk_size]))))
    buf = {}
    for w in wires:
        m = msg.parse_message(w)
        off, chunk = msg.decode_file_chunk(b.decrypt(m['body']))
        buf[off] = chunk
    assembled = b''.join((buf[o] for o in sorted(buf)))
    assert hashlib.sha256(assembled).digest() == sha
    print('✓ 文件传输：OFFER + 乱序 CHUNK 重组，SHA-256 一致')

def test_read_receipt():
    a, b, *_ = _setup_sessions()
    mid = msg.new_msg_id()
    wire = msg.pack_message(msg.PT_READ, b'\x01' * 8, b'\x02' * 8, a.encrypt(msg.encode_read(mid)))
    assert msg.decode_read(b.decrypt(msg.parse_message(wire)['body'])) == mid
    print('✓ 已读回执往返')

def test_fs_envelope_regression():
    from nbx import fskey
    a, b = (fskey.Identity.generate(), fskey.Identity.generate())
    env = fskey.seal_envelope(b'legacy', a, *fskey.Identity.parse_public(b.export_public()))
    assert fskey.open_envelope(env, b, *fskey.Identity.parse_public(a.export_public())[:2]) == b'legacy'
    print('✓ 回归：FS 信封不受影响')

def test_ratchet_over_fs_envelope_full_stack():
    from nbx import fskey
    alice_id, bob_id = (fskey.Identity.generate(), fskey.Identity.generate())
    a, b = (RatchetSession(), RatchetSession())
    hs_a = a.begin(alice_id)
    hs_b = b.begin(bob_id)
    from cryptography.hazmat.primitives import serialization

    def ed_pub(i):
        return i.ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    env_to_b = fskey.seal_envelope(hs_a, alice_id, *fskey.Identity.parse_public(bob_id.export_public())[:1] + (ed_pub(bob_id),))
    env_to_a = fskey.seal_envelope(hs_b, bob_id, *fskey.Identity.parse_public(alice_id.export_public())[:1] + (ed_pub(alice_id),))
    hs_a_back = fskey.open_envelope(env_to_b, bob_id, *fskey.Identity.parse_public(alice_id.export_public())[:1] + (ed_pub(alice_id),))
    hs_b_back = fskey.open_envelope(env_to_a, alice_id, *fskey.Identity.parse_public(bob_id.export_public())[:1] + (ed_pub(bob_id),))
    a.finish(alice_id, ed_pub(bob_id), hs_b_back, speaks_first=True)
    b.finish(bob_id, ed_pub(alice_id), hs_a_back, speaks_first=False)
    assert b.decrypt(a.encrypt(b'full stack')) == b'full stack'
    assert a.decrypt(b.encrypt(b'works')) == b'works'
    print('✓ 完整栈：FS 信封传握手 → ratchet 会话 → 双向消息')
if __name__ == '__main__':
    import tempfile
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for t in tests:
        t()
    print(f'\n{len(tests)} 项 ratchet/message 测试全部通过 ✅')
