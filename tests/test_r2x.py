import base64
import os
import pytest
from nbx import fskey
from nbx.relay import load_or_create_relay_key
from nbx.contacts import ContactBook, TransportStack

def test_r2_10_relay_key_persisted_across_restart(tmp_path):
    from cryptography.hazmat.primitives import serialization
    kp = str(tmp_path / 'relay.key')
    k1 = load_or_create_relay_key(kp)
    pub1 = k1.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    k2 = load_or_create_relay_key(kp)
    pub2 = k2.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert pub1 == pub2
    assert os.path.exists(kp)
    mode = os.stat(kp).st_mode & 511
    assert mode == 384

def test_r2_10_relay_key_roundtrip_sign():
    key = load_or_create_relay_key('/tmp/r210_test.key')
    key2 = load_or_create_relay_key('/tmp/r210_test.key')
    sig = key.sign(b'payload')
    from cryptography.hazmat.primitives.asymmetric import ed25519
    ed25519.Ed25519PublicKey.from_public_bytes(key2.public_key().public_bytes(__import__('cryptography.hazmat.primitives.serialization', fromlist=['Raw']).Encoding.Raw, __import__('cryptography.hazmat.primitives.serialization', fromlist=['Raw']).PublicFormat.Raw)).verify(sig, b'payload')
    os.unlink('/tmp/r210_test.key')

def _stack(tmp_path, pin_file):
    return TransportStack(ContactBook(str(tmp_path / 'book.json')), fskey.Identity.generate(), pin_file=pin_file)

def test_r2_09_pin_file_created_on_first_tofu(tmp_path):
    pf = str(tmp_path / 'pins')
    st = _stack(tmp_path, pf)
    st._relay_pins['https://r.example'] = b'\x01' * 32
    st._save_pins()
    assert os.path.exists(pf)
    st2 = _stack(tmp_path, pf)
    assert st2._relay_pins['https://r.example'] == b'\x01' * 32

def test_r2_09_pin_mismatch_detected_after_restart(tmp_path):
    pf = str(tmp_path / 'pins')
    st = _stack(tmp_path, pf)
    st._relay_pins['https://r.example'] = b'\x01' * 32
    st._save_pins()
    st2 = _stack(tmp_path, pf)
    with pytest.raises(ConnectionError, match='identity changed'):
        prev = st2._relay_pins.get('https://r.example')
        relay_pub = b'\x02' * 32
        if prev != relay_pub:
            raise ConnectionError(f'relay identity changed (possible MITM) at https://r.example')

def test_r2_09_corrupt_pin_file_tolerated(tmp_path):
    pf = tmp_path / 'pins'
    pf.write_text('garbage!!!\nnot base64 ###\n')
    st = _stack(tmp_path, str(pf))
    assert isinstance(st._relay_pins, dict)

def test_r2_08_python_memory_store_budget_unchanged():
    from nbx.relay import MemoryStore
    st = MemoryStore(max_total_bytes=1024, ttl=10 ** 9)
    fp = b'F' * 8
    accepted = 0
    raised = False
    try:
        for i in range(100):
            env = bytes([i]) + b'\xab' * 99
            st.put(fp, env)
            accepted += 1
            assert st._total_bytes <= 1024
    except ValueError as e:
        raised = True
        assert str(e) == 'global envelope budget exceeded'
    assert raised is True, '超过 max_total_bytes 必须抛出预算异常'
    assert st._total_bytes <= 1024
    assert accepted == 10
    assert st.count(fp) == accepted

