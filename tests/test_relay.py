"""M2 中继服务器测试：RelayLogic 单元 + HTTP 集成 + 端到端（经 FS 信封建 ratchet 会话互发）。

覆盖：投递校验、TTL 过期、队列上限、取信授权（签名证明 + 时间窗 + 重放）、
HTTP 状态码、以及完整链路：Alice → 中继 → Bob（离线留言场景）。
"""
import base64
import json
import pytest
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


def _raw_pub(i: Identity) -> bytes:
    """64B 公钥材料 x||ed（audit R-03：/auth 携带它，服务器算 fp）。"""
    x = i.x_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return x + _ed_pub(i)


def _fp_of(i: Identity) -> bytes:
    """路由指纹 = SHA-256(原始公钥材料 x||ed)[:8]（与 chat.fingerprint8 一致）。"""
    import hashlib
    return hashlib.sha256(_raw_pub(i)).digest()[:8]


def _auth_proof(i: Identity, fp: bytes) -> bytes:
    ts = struct.pack("<Q", int(time.time()))
    sig = i.ed_priv.sign(b"nbx-relay-auth-v1" + fp + ts)
    return ts + sig


def _pack(ptype, sfp, rfp, body=b""):
    return msg.pack_message(ptype, sfp, rfp, body)


def _proof_of(i: Identity, env: bytes) -> bytes:
    """构造投递签名后缀（ts||sig），R2-02: 签名覆盖完整信封。"""
    import hashlib, struct as _s
    ts = _s.pack("<Q", int(time.time()))
    digest = hashlib.sha256(env).digest()
    return ts + i.ed_priv.sign(b"nbx-relay-delivery-v2" + digest + ts)


# ---------- RelayLogic 单元 ----------

def test_accept_and_fetch_roundtrip(tmp_path):
    logic = RelayLogic(MemoryStore())
    alice_fp, bob_fp = b"A" * 8, b"B" * 8
    env = _pack(msg.PT_TEXT, alice_fp, bob_fp, b"ciphertext-here")
    r = logic.accept(env, verify=False)
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
    logic.accept(env, verify=False)
    # 手工把入队时间拨回 2 小时前
    store._q[b"B" * 8][0] = (time.time() - 7200, env)
    assert logic.inbox_count(b"B" * 8) == 0        # gc 清掉
    assert logic.store.pop_all(b"B" * 8) == []
    print("✓ TTL 过期：超时信封自动清理")


def test_queue_cap_drops_oldest(tmp_path):
    logic = RelayLogic(MemoryStore(max_per_fp=5))
    for i in range(8):
        logic.accept(_pack(msg.PT_TEXT, b"A" * 8, b"B" * 8, f"m{i}".encode()),
                     verify=False)
    envs = logic.store.pop_all(b"B" * 8)
    assert len(envs) == 5
    bodies = [msg.parse_message(e)["body"] for e in envs]
    assert bodies == [b"m3", b"m4", b"m5", b"m6", b"m7"]   # 最旧的 m0-m2 被丢
    print("✓ 队列上限：满后丢最旧")


# ---------- 取信授权 ----------

def _setup_auth(logic):
    alice = Identity.generate()
    fp = _fp_of(alice)
    logic.register_pubkey(_raw_pub(alice))
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
        logic.accept(_pack(msg.PT_TEXT, b"S" * 8, fp, f"n{i}".encode()),
                     verify=False)
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
    """TOFU: fp 由钥匙决定且绑定后不可变 (R-03 后 fp 无法与钥匙解耦)。"""
    logic = RelayLogic(MemoryStore())
    a1 = Identity.generate()
    fp1 = logic.register_pubkey(_raw_pub(a1))
    assert fp1 == _fp_of(a1)
    # 同一钥匙重复登记（重连场景）必须幂等成功
    fp1b = logic.register_pubkey(_raw_pub(a1))
    assert fp1b == fp1
    # 不同钥匙 → 不同 fp，各自独立桶（抢注不成立，见 test_fp_hijack_rejected）
    a2 = Identity.generate()
    fp2 = logic.register_pubkey(_raw_pub(a2))
    assert fp2 != fp1
    print("✓ TOFU：fp=Hash(钥匙) 且绑定幂等，钥匙决定身份")


# ---------- HTTP 集成 ----------

def test_http_endpoints(tmp_path):
    logic = RelayLogic(MemoryStore())
    alice = Identity.generate()
    fp = _fp_of(alice)
    logic.register_pubkey(_raw_pub(alice))
    handler = make_handler(logic)

    # health
    status, obj = handler("GET", "/health", b"")
    assert status == 200 and obj["ok"]
    # 投递（audit R-06：先登记发送者，再附投递签名）
    sender = Identity.generate()
    sender_fp = _fp_of(sender)
    logic.register_pubkey(_raw_pub(sender))
    env = _pack(msg.PT_TEXT, sender_fp, fp, b"hello relay")
    status, obj = handler("POST", "/envelope", env + _proof_of(sender, env))
    assert status == 202 and obj["ok"]
    # 坏信封 → 400
    status, obj = handler("POST", "/envelope", b"garbage")
    assert status == 400
    # 错误 proof（未授权）→ 403
    status, obj = handler("POST", f"/inbox/{base64.urlsafe_b64encode(fp).decode()}",
                          b"\x00" * 72)
    assert status == 403
    # 授权取信 → 200 + 信封（R-04: proof 在 POST body）
    status, obj = handler("POST", f"/inbox/{base64.urlsafe_b64encode(fp).decode()}",
                          _auth_proof(alice, fp))
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
    logic.register_pubkey(_raw_pub(alice_id))
    logic.register_pubkey(_raw_pub(bob_id))

    # 会话建立（握手经 FS 信封，这里直接本地传递模拟认证信道）
    a, b = RatchetSession(), RatchetSession()
    hs_a, hs_b = a.begin(alice_id), b.begin(bob_id)
    a.finish(alice_id, _ed_pub(bob_id), hs_b, speaks_first=True)
    b.finish(bob_id, _ed_pub(alice_id), hs_a, speaks_first=False)

    # Alice 发 3 条 TEXT 经中继（Bob 离线）
    for text in ("hi", "offline msg", "third"):
        wire = msg.pack_message(msg.PT_TEXT, a_fp, b_fp,
                                a.encrypt(text.encode()))
        assert logic.accept(wire + _proof_of(alice_id, wire))["ok"]

    # Bob 上线：签名取信 → 解密
    pulled = logic.fetch(b_fp, _auth_proof(bob_id, b_fp))
    assert len(pulled) == 3
    texts = [b.decrypt(msg.parse_message(e)["body"]) for e in pulled]
    assert texts == [b"hi", b"offline msg", b"third"]

    # Bob 回信 + 已读回执 → Alice 取
    w1 = msg.pack_message(msg.PT_TEXT, b_fp, a_fp, b.encrypt(b"got it"))
    logic.accept(w1 + _proof_of(bob_id, w1))
    w2 = msg.pack_message(msg.PT_READ, b_fp, a_fp,
                          b.encrypt(msg.encode_read(msg.parse_message(pulled[0])["msg_id"])))
    logic.accept(w2 + _proof_of(bob_id, w2))
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
    pub_material = _raw_pub(alice)
    ts = struct.pack("<Q", int(time.time()))
    # R-03: body = pub_material(64) || ts || sig，fp 由服务器计算
    body = pub_material + ts + alice.ed_priv.sign(b"nbx-relay-auth-v1" + pub_material + ts)
    status, obj = handler("POST", "/auth", body)
    assert status == 200 and obj["ok"]
    assert base64.urlsafe_b64decode(obj["fp"] + "=" * (-len(obj["fp"]) % 4)) == fp, \
        "服务器算出的 fp 必须与本地 raw-byte 指纹一致"
    # 登记后可授权取信
    assert logic.authorize(fp, _auth_proof(alice, fp)) is True
    # 坏签名 → 403
    bad = pub_material + ts + b"\x00" * 64
    assert handler("POST", "/auth", bad)[0] == 403
    # 错长度 → 400
    assert handler("POST", "/auth", b"short")[0] == 400
    # R-03 后"换绑"攻击不复存在：fp 由服务器从钥匙算出，Mallory 的钥匙
    # 必然得到不同的 fp（见 test_fp_hijack_rejected），无法顶替 Alice 的登记
    other = Identity.generate()
    ts2 = struct.pack("<Q", int(time.time()))
    pm2 = _raw_pub(other)
    body2 = pm2 + ts2 + other.ed_priv.sign(b"nbx-relay-auth-v1" + pm2 + ts2)
    status2, obj2 = handler("POST", "/auth", body2)
    assert status2 == 200
    fp_other = base64.urlsafe_b64decode(obj2["fp"] + "=" * (-len(obj2["fp"]) % 4))
    assert fp_other != fp, "不同钥匙必须得到不同 fp"
    print("✓ /auth 端点：登记/服务器算 fp/坏签名/错长度/抢注不成立")


def test_unauthenticated_sender_cannot_fill_queue(tmp_path):
    """R-06 攻击回归：未 AUTH 登记的发送者投递被拒，无法灌满收件桶。"""
    logic = RelayLogic(MemoryStore())
    mallory = Identity.generate()
    bob_fp = _fp_of(Identity.generate())
    env = _pack(msg.PT_TEXT, _fp_of(mallory), bob_fp, b"spam")
    for _ in range(300):                       # 超过队列上限 256 的灌桶尝试
        try:
            logic.accept(env + _proof_of(mallory, env))
        except ValueError:
            break                              # 未登记 → 立即拒
    else:
        raise AssertionError("unauthenticated spam accepted")
    assert logic.inbox_count(bob_fp) == 0
    print("✓ R-06：未认证发送者无法投递（灌桶不成立）")


def test_authenticated_sender_per_fp_quota(tmp_path):
    """R-06 配套：认证发送者也不能用自己的钥匙灌爆单个收件桶。"""
    logic = RelayLogic(MemoryStore(max_per_fp=50))
    mallory = Identity.generate()
    logic.register_pubkey(_raw_pub(mallory))
    bob_fp = _fp_of(Identity.generate())
    for i in range(100):                       # 尝试灌 100 封
        env = _pack(msg.PT_TEXT, _fp_of(mallory), bob_fp, f"m{i}".encode())
        logic.accept(env + _proof_of(mallory, env))
    envs = logic.store.pop_all(bob_fp)
    assert len(envs) <= 50, "队列上限必须生效"
    print("✓ R-06：认证发送者同样受队列上限约束")


def test_global_envelope_budget(tmp_path):
    """R-07 攻击回归：全局信封总量/字节数有上限，多收件人不能绕过。"""
    logic = RelayLogic(MemoryStore(max_total_bytes=4096))
    mallory = Identity.generate()
    logic.register_pubkey(_raw_pub(mallory))
    accepted = 0
    for i in range(64):                        # 64 个不同收件人 × 512B
        recv = bytes([i]) + b"\x01" * 7
        env = _pack(msg.PT_TEXT, _fp_of(mallory), recv, b"x" * 512)
        try:
            logic.accept(env + _proof_of(mallory, env))
            accepted += 1
        except ValueError:
            break
    assert accepted < 64, "全局字节预算必须封顶"
    print(f"✓ R-07：全局预算生效（{accepted}/64 封后拒绝）")


def test_replay_processing_is_atomic(tmp_path):
    """R-12 回归: 并发投递同一信封只入队一次 (check+remember 原子)。"""
    logic = RelayLogic(MemoryStore())
    sender = Identity.generate()
    logic.register_pubkey(_raw_pub(sender))
    bob_fp = _fp_of(Identity.generate())
    env = _pack(msg.PT_TEXT, _fp_of(sender), bob_fp, b"once")
    results = []
    import threading
    def worker():
        for _ in range(20):
            try:
                results.append(logic.accept(env + _proof_of(sender, env)).get("duplicate", False))
            except ValueError:
                results.append("err")
    ts = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    accepted = sum(1 for r in results if r is False)      # duplicate=False 即真正入队
    assert accepted == 1, f"同一信封必须恰好入队一次，实际 {accepted}"
    assert logic.inbox_count(bob_fp) == 1
    print("✓ R-12：并发 replay check+remember 原子（exactly-once 入队）")


def test_budget_rejection_does_not_poison_replay_cache(tmp_path):
    """R-11 回归: 投递被预算拒绝后, 额度恢复时同一信封可再次投递。"""
    logic = RelayLogic(MemoryStore(max_total_bytes=300))
    sender = Identity.generate()
    logic.register_pubkey(_raw_pub(sender))
    bob_fp = _fp_of(Identity.generate())
    env = _pack(msg.PT_TEXT, _fp_of(sender), bob_fp, b"x" * 512)
    with_payload = env + _proof_of(sender, env)
    with pytest.raises(ValueError):
        logic.accept(with_payload)             # 超预算拒绝
    # 模拟预算恢复（收件方取走存量）后重试同一信封——不得被 replay cache 挡掉
    logic.store.max_total_bytes = 10_000_000
    assert logic.accept(with_payload)["ok"], \
        "被拒信封重试时不得被 replay 缓存误杀"
    print("✓ R-11：失败路径不污染 replay 状态（消息不丢）")


def test_fp_hijack_rejected(tmp_path):
    """R-03 回归：Mallory 不能用 Alice 的 fp 配自己的钥匙抢注。"""
    logic = RelayLogic(MemoryStore())
    handler = make_handler(logic)
    alice, mallory = Identity.generate(), Identity.generate()
    ts = struct.pack("<Q", int(time.time()))
    pm_m = _raw_pub(mallory)
    body = pm_m + ts + mallory.ed_priv.sign(b"nbx-relay-auth-v1" + pm_m + ts)
    status, obj = handler("POST", "/auth", body)
    assert status == 200
    mallory_fp = base64.urlsafe_b64decode(obj["fp"] + "=" * (-len(obj["fp"]) % 4))
    assert mallory_fp != _fp_of(alice), \
        "Mallory 的 fp 由其自身钥匙决定，不可能等于 Alice 的 fp"
    print("✓ R-03：指纹由服务器从公钥材料计算，抢注不成立")


if __name__ == "__main__":
    import tempfile
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        with tempfile.TemporaryDirectory() as td:
            t(Path(td))
    print(f"\n{len(tests)} 项 relay 测试全部通过 ✅")
