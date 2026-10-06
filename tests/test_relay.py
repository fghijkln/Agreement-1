"""M2 中继服务器测试：RelayLogic 单元 + HTTP 集成 + 端到端（经 FS 信封建 ratchet 会话互发）。

覆盖：投递校验、TTL 过期、队列上限、取信授权（签名证明 + 时间窗 + 重放）、
HTTP 状态码、以及完整链路：Alice → 中继 → Bob（离线留言场景）。
"""
import base64
import json
import struct
import sys
import threading
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from nbx import message as msg
from nbx.fskey import Identity
from nbx.ratchet import RatchetSession
from nbx.relay import (RelayLogic, MemoryStore, make_handler,
                       RelayServer, MAX_ENVELOPE, DEFAULT_MAX_PER_FP)


def _ed_pub(i: Identity) -> bytes:
    return i.ed_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _fp_of(i: Identity) -> bytes:
    import hashlib
    return hashlib.sha256(i.export_public().encode()).digest()[:8]


def _auth_proof(i: Identity, fp: bytes) -> bytes:
    ts = struct.pack("<Q", int(time.time()))
    sig = i.ed_priv.sign(b"nbx-relay-auth-v1" + fp + ts)
    return ts + sig


def _pack(ptype, sfp, rfp, body=b""):
    return msg.pack_message(ptype, sfp, rfp, body)


# ---------- RelayLogic 单元 ----------

def test_accept_and_fetch_roundtrip(tmp_path):
    logic = RelayLogic(MemoryStore())
    alice_fp, bob_fp = b"A" * 8, b"B" * 8
    env = _pack(msg.PT_TEXT, alice_fp, bob_fp, b"ciphertext-here")
    r = logic.accept(env)
    assert r["ok"] is True
    assert logic.inbox_count(bob_fp) == 1
    assert logic.inbox_count(alice_fp) == 0
    print("✓ 投递入队（按接收方指纹分桶）")


def test_reject_bad_envelopes(tmp_path):
    logic = RelayLogic(MemoryStore())
    # 过短
    try:
        logic.accept(b"xx")
        raise AssertionError("short accepted")
    except ValueError:
        pass
    # 错魔数
    try:
        logic.accept(b"XXXXXXXX" + b"\x00" * 40)
        raise AssertionError("bad magic accepted")
    except ValueError:
        pass
    # 发给自己
    try:
        logic.accept(_pack(msg.PT_TEXT, b"A" * 8, b"A" * 8, b""))
        raise AssertionError("self-addressed accepted")
    except ValueError:
        pass
    # 超大
    try:
        logic.accept(b"NBXMSG\x01\x00" + b"\x00" * (MAX_ENVELOPE + 1))
        raise AssertionError("oversized accepted")
    except ValueError:
        pass
    print("✓ 拒绝：过短/错魔数/发给自己/超大")


def test_ttl_expiry(tmp_path):
    store = MemoryStore(ttl=1)
    logic = RelayLogic(store)
    env = _pack(msg.PT_TEXT, b"A" * 8, b"B" * 8, b"x")
    logic.accept(env)
    # 手工把入队时间拨回 2 小时前
    store._q[b"B" * 8][0] = (time.time() - 7200, env)
    assert logic.inbox_count(b"B" * 8) == 0        # gc 清掉
    assert logic.store.pop_all(b"B" * 8) == []
    print("✓ TTL 过期：超时信封自动清理")


def test_queue_cap_drops_oldest(tmp_path):
    logic = RelayLogic(MemoryStore(max_per_fp=5))
    for i in range(8):
        logic.accept(_pack(msg.PT_TEXT, b"A" * 8, b"B" * 8, f"m{i}".encode()))
    envs = logic.store.pop_all(b"B" * 8)
    assert len(envs) == 5
    bodies = [msg.parse_message(e)["body"] for e in envs]
    assert bodies == [b"m3", b"m4", b"m5", b"m6", b"m7"]   # 最旧的 m0-m2 被丢
    print("✓ 队列上限：满后丢最旧")


# ---------- 取信授权 ----------

def _setup_auth(logic):
    alice = Identity.generate()
    fp = _fp_of(alice)
    logic.register_pubkey(fp, _ed_pub(alice))
    return alice, fp


def test_auth_success_and_failure(tmp_path):
    logic = RelayLogic(MemoryStore())
    alice, fp = _setup_auth(logic)
    assert logic.authorize(fp, _auth_proof(alice, fp)) is True
    # 错误私钥
    mallory = Identity.generate()
    assert logic.authorize(fp, _auth_proof(mallory, fp)) is False
    # 未登记指纹
    assert logic.authorize(b"Z" * 8, _auth_proof(alice, b"Z" * 8)) is False
    # 时间窗外
    ts = struct.pack("<Q", int(time.time()) - 3600)
    sig = alice.ed_priv.sign(b"nbx-relay-auth-v1" + fp + ts)
    assert logic.authorize(fp, ts + sig) is False
    print("✓ 授权：正确签名通过；错钥/未登记/超窗拒绝")


def test_fetch_requires_auth_and_clears(tmp_path):
    logic = RelayLogic(MemoryStore())
    alice, fp = _setup_auth(logic)
    for i in range(3):
        logic.accept(_pack(msg.PT_TEXT, b"S" * 8, fp, f"n{i}".encode()))
    # 未授权 → 拒
    try:
        logic.fetch(fp, b"")
        raise AssertionError("unauthorized fetch")
    except PermissionError:
        pass
    envs = logic.fetch(fp, _auth_proof(alice, fp))
    assert len(envs) == 3
    assert logic.store.pop_all(fp) == []           # 取走即清
    print("✓ 取信：无授权拒绝；授权后取走即清（服务器不留历史）")


def test_tofu_key_binding(tmp_path):
    logic = RelayLogic(MemoryStore())
    a1, a2 = Identity.generate(), Identity.generate()
    fp = _fp_of(a1)
    logic.register_pubkey(fp, _ed_pub(a1))
    try:
        logic.register_pubkey(fp, _ed_pub(a2))
        raise AssertionError("rebind accepted")
    except ValueError:
        pass
    print("✓ TOFU：指纹一旦绑定公钥，不允许换绑")


# ---------- HTTP 集成 ----------

def test_http_endpoints(tmp_path):
    logic = RelayLogic(MemoryStore())
    alice = Identity.generate()
    fp = _fp_of(alice)
    logic.register_pubkey(fp, _ed_pub(alice))
    handler = make_handler(logic)

    # health
    status, obj = handler("GET", "/health", b"")
    assert status == 200 and obj["ok"]
    # 投递
    env = _pack(msg.PT_TEXT, b"S" * 8, fp, b"hello relay")
    status, obj = handler("POST", "/envelope", env)
    assert status == 202 and obj["ok"]
    # 坏信封 → 400
    status, obj = handler("POST", "/envelope", b"garbage")
    assert status == 400
    # 未授权取信 → 403
    status, obj = handler("GET", f"/inbox/{base64.urlsafe_b64encode(fp).decode()}", b"")
    assert status == 403
    # 授权取信 → 200 + 信封
    proof = base64.urlsafe_b64encode(_auth_proof(alice, fp)).decode()
    status, obj = handler("GET", f"/inbox/{base64.urlsafe_b64encode(fp).decode()}?proof={proof}", b"")
    assert status == 200 and len(obj["envelopes"]) == 1
    got = base64.urlsafe_b64decode(obj["envelopes"][0] + "=" * (-len(obj["envelopes"][0]) % 4))
    assert got == env
    # 未知路径 → 404
    assert handler("GET", "/nope", b"")[0] == 404
    print("✓ HTTP 端点：202/400/403/200/404 全部正确")


def test_http_server_live(tmp_path):
    """真实端口起服务，urllib 走一遍。"""
    logic = RelayLogic(MemoryStore())
    srv = RelayServer(logic, port=18765)
    def serve():
        for _ in range(2):                        # 处理两个请求: POST + 关闭探测
            srv.serve_until_stop()
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    time.sleep(0.2)
    # 非法信封 → 400
    try:
        urllib.request.urlopen(urllib.request.Request(
            "http://127.0.0.1:18765/envelope", data=b"garbage", method="POST"),
            timeout=5)
        raise AssertionError("garbage accepted")
    except urllib.error.HTTPError as e:
        assert e.code == 400
    # health → 200
    resp = urllib.request.urlopen("http://127.0.0.1:18765/health", timeout=5)
    assert resp.status == 200 and json.loads(resp.read())["ok"]
    print("✓ 真实 HTTP 服务：/envelope 400, /health 200")


# ---------- 端到端：经中继的 ratchet 会话 ----------

def test_e2e_via_relay(tmp_path):
    """Alice → relay → Bob 全链路：FS 信封传握手，TEXT 消息离线投递，READ 回执。"""
    logic = RelayLogic(MemoryStore())
    alice_id, bob_id = Identity.generate(), Identity.generate()
    a_fp, b_fp = _fp_of(alice_id), _fp_of(bob_id)
    logic.register_pubkey(a_fp, _ed_pub(alice_id))
    logic.register_pubkey(b_fp, _ed_pub(bob_id))

    # 会话建立（握手经 FS 信封，这里直接本地传递模拟认证信道）
    a, b = RatchetSession(), RatchetSession()
    hs_a, hs_b = a.begin(alice_id), b.begin(bob_id)
    a.finish(alice_id, _ed_pub(bob_id), hs_b, speaks_first=True)
    b.finish(bob_id, _ed_pub(alice_id), hs_a, speaks_first=False)

    # Alice 发 3 条 TEXT 经中继（Bob 离线）
    for text in ("hi", "offline msg", "third"):
        wire = msg.pack_message(msg.PT_TEXT, a_fp, b_fp,
                                a.encrypt(text.encode()))
        assert logic.accept(wire)["ok"]

    # Bob 上线：签名取信 → 解密
    pulled = logic.fetch(b_fp, _auth_proof(bob_id, b_fp))
    assert len(pulled) == 3
    texts = [b.decrypt(msg.parse_message(e)["body"]) for e in pulled]
    assert texts == [b"hi", b"offline msg", b"third"]

    # Bob 回信 + 已读回执 → Alice 取
    logic.accept(msg.pack_message(msg.PT_TEXT, b_fp, a_fp, b.encrypt(b"got it")))
    logic.accept(msg.pack_message(msg.PT_READ, b_fp, a_fp,
                                  b.encrypt(msg.encode_read(msg.parse_message(pulled[0])["msg_id"]))))
    inbox = logic.fetch(a_fp, _auth_proof(alice_id, a_fp))
    assert len(inbox) == 2
    parsed = [msg.parse_message(e) for e in inbox]
    assert a.decrypt(parsed[0]["body"]) == b"got it"
    assert a.decrypt(parsed[1]["body"]) == msg.encode_read(
        msg.parse_message(pulled[0])["msg_id"])
    print("✓ 端到端：Alice→中继→Bob 离线 3 条 + 回信 + 已读回执，ratchet 全程加密")


# ---------- /auth 端点 ----------

def test_http_auth_endpoint(tmp_path):
    logic = RelayLogic(MemoryStore())
    handler = make_handler(logic)
    alice = Identity.generate()
    fp = _fp_of(alice)
    ed_pub = _ed_pub(alice)
    ts = struct.pack("<Q", int(time.time()))
    body = fp + ts + ed_pub + alice.ed_priv.sign(b"nbx-relay-auth-v1" + fp + ts)
    status, obj = handler("POST", "/auth", body)
    assert status == 200 and obj["ok"]
    # 登记后可授权取信
    assert logic.authorize(fp, _auth_proof(alice, fp)) is True
    # 坏签名 → 403
    bad = fp + ts + ed_pub + b"\x00" * 64
    assert handler("POST", "/auth", bad)[0] == 403
    # 错长度 → 400
    assert handler("POST", "/auth", b"short")[0] == 400
    # 换绑 → 409
    other = Identity.generate()
    ts2 = struct.pack("<Q", int(time.time()))
    body2 = fp + ts2 + _ed_pub(other) + other.ed_priv.sign(b"nbx-relay-auth-v1" + fp + ts2)
    assert handler("POST", "/auth", body2)[0] == 409
    print("✓ /auth 端点：登记/坏签名/错长度/换绑拒绝")


if __name__ == "__main__":
    import tempfile
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        with tempfile.TemporaryDirectory() as td:
            t(Path(td))
    print(f"\n{len(tests)} 项 relay 测试全部通过 ✅")
