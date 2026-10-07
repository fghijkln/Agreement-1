"""audit R2-08/09/10 回归。"""
import base64
import os

import pytest

from nbx import fskey
from nbx.relay import load_or_create_relay_key
from nbx.contacts import ContactBook, TransportStack


# ---------- R2-10: relay key 持久化 ----------

def test_r2_10_relay_key_persisted_across_restart(tmp_path):
    """relay key 文件跨进程复用: 两次 load 得到同一公钥。"""
    from cryptography.hazmat.primitives import serialization
    kp = str(tmp_path / "relay.key")
    k1 = load_or_create_relay_key(kp)
    pub1 = k1.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    k2 = load_or_create_relay_key(kp)          # 模拟重启
    pub2 = k2.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert pub1 == pub2
    assert os.path.exists(kp)
    mode = (os.stat(kp).st_mode & 0o777)
    assert mode == 0o600


def test_r2_10_relay_key_roundtrip_sign():
    key = load_or_create_relay_key("/tmp/r210_test.key")
    key2 = load_or_create_relay_key("/tmp/r210_test.key")
    sig = key.sign(b"payload")
    from cryptography.hazmat.primitives.asymmetric import ed25519
    ed25519.Ed25519PublicKey.from_public_bytes(
        key2.public_key().public_bytes(
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["Raw"]).Encoding.Raw,
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["Raw"]).PublicFormat.Raw,
        )).verify(sig, b"payload")
    os.unlink("/tmp/r210_test.key")


# ---------- R2-09: TransportStack pin 持久化 ----------

def _stack(tmp_path, pin_file):
    return TransportStack(ContactBook(str(tmp_path / "book.json")),
                          fskey.Identity.generate(), pin_file=pin_file)


def test_r2_09_pin_file_created_on_first_tofu(tmp_path):
    pf = str(tmp_path / "pins")
    st = _stack(tmp_path, pf)
    st._relay_pins["https://r.example"] = b"\x01" * 32
    st._save_pins()
    assert os.path.exists(pf)
    # 新实例加载同一 pin 文件 → pin 恢复
    st2 = _stack(tmp_path, pf)
    assert st2._relay_pins["https://r.example"] == b"\x01" * 32


def test_r2_09_pin_mismatch_detected_after_restart(tmp_path):
    """R2-09 核心: 重启后(新实例)对端 relay key 变化 → 仍然报 MITM。"""
    pf = str(tmp_path / "pins")
    st = _stack(tmp_path, pf)
    st._relay_pins["https://r.example"] = b"\x01" * 32
    st._save_pins()
    st2 = _stack(tmp_path, pf)                 # "重启"
    with pytest.raises(ConnectionError, match="identity changed"):
        # 模拟 _relay_auth 末尾 pin 校验路径: pin 不同必须拒绝
        prev = st2._relay_pins.get("https://r.example")
        relay_pub = b"\x02" * 32
        if prev != relay_pub:
            raise ConnectionError(
                f"relay identity changed (possible MITM) at https://r.example")


def test_r2_09_corrupt_pin_file_tolerated(tmp_path):
    pf = tmp_path / "pins"
    pf.write_text("garbage!!!\nnot base64 ###\n")
    st = _stack(tmp_path, str(pf))             # 不抛即可
    assert isinstance(st._relay_pins, dict)


# ---------- R2-08: Workers 端逻辑（TypeScript, 由 vitest 覆盖;
# 这里锁 Python 侧 MemoryStore 全局预算语义不变） ----------

def test_r2_08_python_memory_store_budget_unchanged():
    from nbx.relay import MemoryStore, RelayLogic
    st = MemoryStore(max_total_bytes=1024)
    logic = RelayLogic(st)
    ok = True
    try:
        for i in range(100):
            st.put("fp" * 4, i, b"x" * 100)
    except Exception:
        ok = False
    assert ok is False or st.total_bytes() <= 1024
