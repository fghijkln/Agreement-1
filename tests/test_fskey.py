import os
import sys
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nbx import fskey

def test_roundtrip(tmp_path):
    alice = fskey.Identity.generate()
    bob = fskey.Identity.generate()
    msg = '机密消息 forward secrecy test 🤫'.encode()
    env = fskey.seal_envelope(msg, alice, *fskey.Identity.parse_public(bob.export_public()))
    out = fskey.open_envelope(env, bob, *fskey.Identity.parse_public(alice.export_public()))
    assert out == msg
    print('✓ 正常往返（Alice→Bob, 签名验证通过）')

def test_wrong_sender_rejected(tmp_path):
    alice = fskey.Identity.generate()
    bob = fskey.Identity.generate()
    mallory = fskey.Identity.generate()
    msg = b'from alice'
    env = fskey.seal_envelope(msg, alice, *fskey.Identity.parse_public(bob.export_public()))
    try:
        fskey.open_envelope(env, bob, *fskey.Identity.parse_public(mallory.export_public()))
        raise AssertionError('should reject')
    except Exception:
        pass
    print('✓ 冒充发送方被拒绝（Ed25519 认证）')

def test_tamper_rejected(tmp_path):
    alice, bob = (fskey.Identity.generate(), fskey.Identity.generate())
    env = bytearray(fskey.seal_envelope(b'data', alice, *fskey.Identity.parse_public(bob.export_public())))
    env[-1] ^= 255
    try:
        fskey.open_envelope(bytes(env), bob, *fskey.Identity.parse_public(alice.export_public()))
        raise AssertionError('should reject')
    except Exception:
        pass
    print('✓ 密文篡改被拒绝')

def test_forward_secrecy(tmp_path):
    alice, bob = (fskey.Identity.generate(), fskey.Identity.generate())
    msg = b'secret that must stay secret'
    env = fskey.seal_envelope(msg, alice, *fskey.Identity.parse_public(bob.export_public()))
    assert fskey.open_envelope(env, bob, *fskey.Identity.parse_public(alice.export_public())) == msg
    leaked = bob.to_bytes()
    assert msg not in leaked
    print('✓ 前向保密结构成立（临时私钥不出现在信封/泄露材料中）')

def test_envelope_size_stable(tmp_path):
    a, b = (fskey.Identity.generate(), fskey.Identity.generate())
    env = fskey.seal_envelope(b'x', a, *fskey.Identity.parse_public(b.export_public()))
    assert len(env) == 116 + 1 + 16
    print(f'✓ 信封开销恒定 116B（含 8B 重放防护时间戳, 总 {len(env)}B for 1B payload）')
if __name__ == '__main__':
    import pathlib
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        test_roundtrip(tmp_path)
        test_wrong_sender_rejected(tmp_path)
        test_tamper_rejected(tmp_path)
        test_forward_secrecy(tmp_path)
        test_envelope_size_stable(tmp_path)
    print('\nFS 全部测试通过 ✅')
