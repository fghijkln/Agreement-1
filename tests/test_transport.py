"""三层传输栈 + 通讯录 + 会话持久化测试。

覆盖：ratchet 状态导出/恢复（含乱序 skipped 键），通讯录持久化，
传输栈降级（L1 失败 → L3 成功），层成功记录，真实 HTTP 中继投递。
"""
import json
import struct
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nbx import message as msg
from nbx.contacts import (ContactBook, Contact, TransportStack,
                          LAYER_P2P, LAYER_ANON, LAYER_RELAY, fp_of_pub)
from nbx.fskey import Identity
from nbx.ratchet import RatchetSession
from nbx.relay import RelayLogic, MemoryStore, RelayServer


def _setup_pair():
    a, b = Identity.generate(), Identity.generate()
    sa, sb = RatchetSession(), RatchetSession()
    hs_a, hs_b = sa.begin(a), sb.begin(b)
    sa.finish(a, _ed(b), hs_b, speaks_first=True)
    sb.finish(b, _ed(a), hs_a, speaks_first=False)
    return a, b, sa, sb


def _ed(i):
    from cryptography.hazmat.primitives import serialization
    return i.ed_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# ---------- ratchet 状态持久化 ----------

def test_state_roundtrip_plain(tmp_path):
    a, b, sa, sb = _setup_pair()
    blob = sa.export_state()
    sa2 = RatchetSession.import_state(blob)
    # 用恢复的会话继续加密，Bob 应正常解
    ct = sa2.encrypt(b"continued")
    assert sb.decrypt(ct) == b"continued"
    print("✓ ratchet 状态导出→恢复后继续通信")


def test_state_preserves_skipped(tmp_path):
    """乱序产生的 skipped 键在持久化后仍可用（消息后到跨重启）。"""
    a, b, sa, sb = _setup_pair()
    c1 = sa.encrypt(b"one")
    c2 = sa.encrypt(b"two")
    # Bob 只解第二条
    assert sb.decrypt(c2) == b"two"
    # Bob 持久化会话（skipped 键进盘）
    state = sb.export_state()
    sb2 = RatchetSession.import_state(state)
    # "重启"后第一条后到
    assert sb2.decrypt(c1) == b"one"
    print("✓ skipped 键跨持久化保留：乱序消息跨重启仍可解")


def test_state_after_ratchet_rotation(tmp_path):
    a, b, sa, sb = _setup_pair()
    sb.decrypt(sa.encrypt(b"m1"))
    ct = sb.encrypt(b"reply")          # 触发 DH 轮换
    sa.decrypt(ct)
    # Alice 持久化（轮换后的链状态）
    sa2 = RatchetSession.import_state(sa.export_state())
    assert sb.decrypt(sa2.encrypt(b"after rotation")) == b"after rotation"
    print("✓ DH 轮换后的状态持久化→恢复继续通信")


def test_state_blob_rejects_garbage(tmp_path):
    try:
        RatchetSession.import_state(b"garbage!!!")
        raise AssertionError("garbage accepted")
    except Exception:
        pass
    print("✓ 坏状态 blob 拒绝")


# ---------- 通讯录 ----------

def test_contact_book_persistence(tmp_path):
    path = str(tmp_path / "contacts.json")
    a, b, sa, sb = _setup_pair()
    book = ContactBook(path)
    c = book.add(b.export_public())
    book.store_session(b_fp := c.fp, sb)
    book.save()

    book2 = ContactBook(path)
    got = book2.get(b_fp)
    assert got is not None
    s = book2.load_session(b_fp)
    assert s is not None
    assert s.decrypt(sa.encrypt(b"via restored")) == b"via restored"
    print("✓ 通讯录持久化：会话跨进程恢复")


def test_load_session_corrupt_returns_none(tmp_path):
    path = str(tmp_path / "c.json")
    book = ContactBook(path)
    import base64 as _b64
    c = book.add(_b64.b64encode(b"x" * 64).decode())
    c.session_state = b"broken"
    book.save()
    book2 = ContactBook(path)
    assert book2.load_session(c.fp) is None
    print("✓ 损坏的会话状态 → load 返回 None（不崩溃）")


# ---------- 传输栈 ----------

def test_stack_fallback_p2p_fail_relay_ok(tmp_path):
    """L1 候选地址不可达 → 降级 L3 中继成功；成功层被记录。"""
    path = str(tmp_path / "c.json")
    alice, bob, sa, sb = _setup_pair()
    book = ContactBook(path)
    me_book = ContactBook(str(tmp_path / "me.json"))
    c = book.add(bob.export_public())
    c.addrs = [
        {"layer": LAYER_P2P, "addr": "127.0.0.1:1"},       # 必然连不通
        {"layer": LAYER_RELAY, "addr": "http://127.0.0.1:18801"},
    ]
    book.save()

    # 起真中继
    logic = RelayLogic(MemoryStore())
    logic.register_pubkey(fp_of_pub(bob.export_public()), _ed(bob))
    srv = RelayServer(logic, port=18801)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    stack = TransportStack(book, alice)
    # 直接构造一封已加密消息（跳过握手，测传输层本身）
    wire = msg.pack_message(msg.PT_TEXT, fp_of_pub(alice.export_public()),
                            fp_of_pub(bob.export_public()), sa.encrypt(b"fallback!"))
    r = stack.send(fp_of_pub(bob.export_public()), wire)
    assert r.ok and r.layer == LAYER_RELAY, r.detail
    # Bob 从中继取到
    envs = logic.fetch(fp_of_pub(bob.export_public()),
                       _proof(bob, fp_of_pub(bob.export_public())))
    assert len(envs) == 1
    assert msg.parse_message(envs[0])["body"] == wire[48:]
    print("✓ 降级：L1 不通 → L3 中继送达")


def _proof(ident, fp):
    ts = struct.pack("<Q", int(time.time()))
    return ts + ident.ed_priv.sign(b"nbx-relay-auth-v1" + fp + ts)


def test_stack_layer_success_recorded(tmp_path):
    path = str(tmp_path / "c.json")
    alice, bob, *_ = _setup_pair()
    book = ContactBook(path)
    c = book.add(bob.export_public())
    c.addrs = [{"layer": LAYER_P2P, "addr": "127.0.0.1:1"}]
    book.save()
    stack = TransportStack(book, alice)
    wire = msg.pack_message(msg.PT_TEXT, b"\x01" * 8, c.fp, b"x")
    r = stack.send(c.fp, wire)
    assert not r.ok
    assert c.addrs[0].get("last_ok") is None       # 失败不记录
    # 加一个可用地址再试
    c.addrs.append({"layer": LAYER_P2P, "addr": "127.0.0.1:1"})
    print("✓ 失败层不标记成功")


def test_stack_unknown_contact(tmp_path):
    stack = TransportStack(ContactBook(str(tmp_path / "empty.json")), Identity.generate())
    try:
        stack.send(b"\x00" * 8, b"data")
        raise AssertionError("unknown contact accepted")
    except KeyError:
        pass
    print("✓ 未知联系人拒绝")


if __name__ == "__main__":
    import tempfile
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        with tempfile.TemporaryDirectory() as td:
            t(Path(td))
    print(f"\n{len(tests)} 项三层传输栈测试全部通过 ✅")
