"""第二轮审计回归：R2-01 中继身份认证 / R2-02 投递签名绑定完整信封。"""
import base64
import json
import struct
import time
from unittest import mock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from nbx import fskey, message as msg
from nbx.chat import (RelayClient, fingerprint8, delivery_proof,
                      RELAY_AUTH_INFO)
from nbx.relay import RelayLogic, MemoryStore, RELAY_AUTH_INFO as SRV_AUTH_INFO


def _raw_pub(identity):
    x = identity.x_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    e = identity.ed_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return x + e


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


# ---------- R2-02: 投递签名必须绑定完整信封 ----------

def test_ciphertext_swap_rejected():
    """R2-02: 拿合法 proof 换掉密文后重投 → 中继拒绝。"""
    alice = fskey.Identity.generate()
    bob_fp = fingerprint8(fskey.Identity.generate().export_public())
    sender_fp = fingerprint8(alice.export_public())
    logic = RelayLogic(MemoryStore())
    logic.register_pubkey(_raw_pub(alice))

    env = msg.pack_message(msg.PT_TEXT, sender_fp, bob_fp, b"real-body")
    proof = delivery_proof(alice, env)
    assert logic.accept(env + proof)["ok"]

    evil = msg.pack_message(msg.PT_TEXT, sender_fp, bob_fp, b"evil-body")
    with pytest.raises(ValueError):
        logic.accept(evil + proof)
    print("✓ R2-02: 换密文被拒")


def test_proof_cannot_be_recycled_for_queue_pollution():
    """R2-02: 同一 proof 无法为多个不同密文信封背书（绕去重/灌桶被堵）。"""
    alice = fskey.Identity.generate()
    bob_fp = fingerprint8(fskey.Identity.generate().export_public())
    sender_fp = fingerprint8(alice.export_public())
    logic = RelayLogic(MemoryStore())
    logic.register_pubkey(_raw_pub(alice))

    env = msg.pack_message(msg.PT_TEXT, sender_fp, bob_fp, b"body")
    proof = delivery_proof(alice, env)
    assert logic.accept(env + proof)["ok"]

    for i in range(3):
        evil = msg.pack_message(msg.PT_TEXT, sender_fp, bob_fp,
                                f"variant-{i}".encode())
        with pytest.raises(ValueError):
            logic.accept(evil + proof)
    assert logic.inbox_count(bob_fp) == 1
    print("✓ R2-02: proof 不可回收复用")


# ---------- R2-01: 中继身份认证 ----------

def test_relay_attestation_verifies():
    """R2-01: 中继对 (client_fp, relay_pub, ts) 的签名可用 relay_pub 验证。"""
    logic = RelayLogic(MemoryStore())
    client_fp = b"\x01" * 8
    ts = struct.pack("<Q", int(time.time()))
    att = logic.relay_attestation(client_fp, ts)
    ed25519.Ed25519PublicKey.from_public_bytes(logic.relay_pub).verify(
        att, SRV_AUTH_INFO + client_fp + logic.relay_pub + ts)
    print("✓ R2-01: 中继身份签名可验证")


def test_client_rejects_self_attesting_relay():
    """R2-01: 恶意 endpoint 仅回显受害者 fp（无身份证明）→ 客户端拒绝。

    这条链正是第一轮 R-14 修复被重新打开处：
    污染通讯录 → 向 evil AUTH → evil 回显受害者 fp →
    骗取 verified 地位 → 拿走 inbox proof。
    """
    alice = fskey.Identity.generate()
    my_fp = fingerprint8(alice.export_public())
    client = RelayClient("https://evil.example")

    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self):
            return json.dumps({"ok": True, "fp": _b64(my_fp)}).encode()

    import nbx.chat as chat
    with mock.patch.object(chat, "_http_req", return_value=None), \
         mock.patch.object(chat, "_urlopen_retry", return_value=FakeResp()):
        with pytest.raises(Exception):
            client.auth(alice, my_fp)
    assert client.relay_pinned_pub is None
    print("✓ R2-01: 自报 fp 且无身份证明 → 拒绝")


def test_client_rejects_empty_fp():
    """R2-01 直接 bug：服务器不回 fp 时旧代码 `if srv_fp and ...` 静默放行。"""
    alice = fskey.Identity.generate()
    my_fp = fingerprint8(alice.export_public())
    client = RelayClient("https://evil.example")

    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self):
            return json.dumps({"ok": True}).encode()

    import nbx.chat as chat
    with mock.patch.object(chat, "_http_req", return_value=None), \
         mock.patch.object(chat, "_urlopen_retry", return_value=FakeResp()):
        with pytest.raises(Exception, match="missing fp"):
            client.auth(alice, my_fp)
    print("✓ R2-01: 空 fp 不再被放行")


def test_client_rejects_relay_key_change(tmp_path):
    """R2-01: 已 pin 的中继换钥匙（MITM 信号）→ 客户端拒绝。"""
    alice = fskey.Identity.generate()
    my_fp = fingerprint8(alice.export_public())
    pin = tmp_path / "relay.pin"

    def make_resp(server_priv):
        server_pub = server_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ts = struct.pack("<Q", int(time.time()))
        sig = server_priv.sign(RELAY_AUTH_INFO + my_fp + server_pub + ts)

        class FakeResp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self):
                return json.dumps({"ok": True, "fp": _b64(my_fp),
                                   "relay_pub": _b64(server_pub),
                                   "relay_sig": _b64(sig)}).encode()
        return FakeResp()

    real = ed25519.Ed25519PrivateKey.generate()
    attacker = ed25519.Ed25519PrivateKey.generate()

    import nbx.chat as chat
    c = RelayClient("https://relay.example", pin_file=str(pin))
    with mock.patch.object(chat, "_http_req", return_value=None), \
         mock.patch.object(chat, "_urlopen_retry", return_value=make_resp(real)):
        c.auth(alice, my_fp)                     # 首次: TOFU pin
    assert c.relay_pinned_pub
    assert pin.exists()
    with mock.patch.object(chat, "_http_req", return_value=None), \
         mock.patch.object(chat, "_urlopen_retry", return_value=make_resp(attacker)):
        with pytest.raises(Exception, match="changed|MITM"):
            c.auth(alice, my_fp)                 # 换钥匙 → 报错
    print("✓ R2-01: 中继钥匙变更被检测")
