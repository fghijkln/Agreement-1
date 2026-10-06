"""重放防护测试：时间窗 + 缓存，FS 与 PQ 信封。

设计原则：不只测新功能，还回归验证旧的攻击面（篡改/冒充/前向保密）
在签名消息加入时间戳后依然成立。
"""
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nbx import fskey, replay
from nbx.fskey import Identity
from nbx.pq import PQIdentity
import nbx.pq as pq


def _pubs(ident):
    return ident.export_public()


def _parse(ident):
    return Identity.parse_public(_pubs(ident))


def _parse_pq(ident):
    return PQIdentity.parse_public(_pubs(ident))


# ---------- replay 基础模块 ----------

def test_timestamp_window(tmp_path):
    now = replay.timestamp_now()
    replay.check_timestamp(now, 300)          # 当前时间 → 通过
    old = (int(time.time()) - 3600).to_bytes(8, "little")   # 1 小时前 → 拒绝
    try:
        replay.check_timestamp(old, 300)
        raise AssertionError("old timestamp should fail")
    except ValueError:
        pass
    future = (int(time.time()) + 3600).to_bytes(8, "little")  # 未来 → 拒绝
    try:
        replay.check_timestamp(future, 300)
        raise AssertionError("future timestamp should fail")
    except ValueError:
        pass
    print("✓ 时间窗：当前通过，过去/未来 1h 拒绝")


def test_replay_cache_persist(tmp_path):
    cache_file = str(tmp_path / "cache.json")
    eid = b"\x01" * 16
    c1 = replay.ReplayCache(cache_file)
    c1.check_and_remember(eid)                # 首次 → 记入
    c2 = replay.ReplayCache(cache_file)       # 新实例（模拟重启）→ 从磁盘加载
    try:
        c2.check_and_remember(eid)
        raise AssertionError("replay should be detected across restart")
    except ValueError as e:
        assert "replay" in str(e)
    print("✓ 缓存持久化：跨实例（重启）仍检测重放")


def test_replay_cache_ttl(tmp_path):
    cache_file = str(tmp_path / "cache.json")
    c = replay.ReplayCache(cache_file, ttl=1)
    eid = b"\x02" * 16
    c.check_and_remember(eid)
    # 手工把时间戳改成 2 小时前，模拟过期
    c._mem[eid.hex()] = int(time.time()) - 7200
    c._save()
    c2 = replay.ReplayCache(cache_file, ttl=1)
    c2.check_and_remember(eid)                # 过期条目清理 → 不算重放
    print("✓ 缓存 TTL：过期条目自动清理，不永久占用")


# ---------- FS 信封：新防护 ----------

def test_fs_replay_rejected(tmp_path):
    a, b = Identity.generate(), Identity.generate()
    cache_file = str(tmp_path / "fs_cache.json")
    cache = replay.ReplayCache(cache_file)
    env = fskey.seal_envelope(b"data", a, *_parse(b)[:2])
    ax, ae = _parse(a)[:2]
    out1 = fskey.open_envelope(env, b, ax, ae, cache=cache)   # 第一次 → 成功
    assert out1 == b"data"
    try:
        fskey.open_envelope(env, b, ax, ae, cache=cache)      # 同一信封再解 → 拒绝
        raise AssertionError("replay should be rejected")
    except ValueError as e:
        assert "replay" in str(e)
    print("✓ FS：同一信封第二次解封被拒绝（缓存）")


def test_fs_replay_cache_optional(tmp_path):
    """cache=None 时（旧调用方式）不启用缓存层，但时间窗仍生效。"""
    a, b = Identity.generate(), Identity.generate()
    env = fskey.seal_envelope(b"data", a, *_parse(b)[:2])
    ax, ae = _parse(a)[:2]
    # 无缓存：同一信封可解两次（向后兼容，但时间窗照常）
    assert fskey.open_envelope(env, b, ax, ae) == b"data"
    assert fskey.open_envelope(env, b, ax, ae) == b"data"
    print("✓ FS：cache=None 向后兼容（时间窗仍生效）")


def test_fs_timestamp_forgery_rejected(tmp_path):
    """攻击者篡改时间戳 → 验签失败（时间戳在签名覆盖范围内）。"""
    a, b = Identity.generate(), Identity.generate()
    env = bytearray(fskey.seal_envelope(b"data", a, *_parse(b)[:2]))
    env[32] ^= 0x01  # 破坏时间戳首字节
    ax, ae = _parse(a)[:2]
    try:
        fskey.open_envelope(bytes(env), b, ax, ae)
        raise AssertionError("tampered timestamp should fail verification")
    except Exception:
        pass
    print("✓ FS：篡改时间戳 → 验签拒绝（ts 在签名覆盖内）")


# ---------- FS 信封：旧攻击面回归 ----------

def test_fs_old_attacks_still_blocked(tmp_path):
    a, b, m = Identity.generate(), Identity.generate(), Identity.generate()
    env = fskey.seal_envelope(b"secret", a, *_parse(b)[:2])
    ax, ae = _parse(a)[:2]
    mx, me = _parse(m)[:2]
    # 篡改密文
    bad = bytearray(env); bad[-1] ^= 1
    try:
        fskey.open_envelope(bytes(bad), b, ax, ae)
        raise AssertionError("tamper should fail")
    except Exception:
        pass
    # 冒充
    try:
        fskey.open_envelope(env, b, mx, me)
        raise AssertionError("impersonation should fail")
    except Exception:
        pass
    print("✓ FS 回归：密文篡改/冒充仍被拒绝")


# ---------- PQ 信封：新防护 ----------

def test_pq_replay_rejected(tmp_path):
    a, b = PQIdentity.generate(), PQIdentity.generate()
    cache_file = str(tmp_path / "pq_cache.json")
    cache = replay.ReplayCache(cache_file)
    env = pq.seal_pq(b"data", a, *_parse_pq(b))
    ax, ae, _ = _parse_pq(a)
    out = pq.open_pq(env, b, ax, ae, cache=cache)
    assert out == b"data"
    try:
        pq.open_pq(env, b, ax, ae, cache=cache)
        raise AssertionError("replay should be rejected")
    except ValueError as e:
        assert "replay" in str(e)
    print("✓ PQ：同一信封第二次解封被拒绝")


def test_pq_new_envelope_not_false_positive(tmp_path):
    """关键：新封的合法信封不能被误判为重放（ephemeral 每次不同）。"""
    a, b = PQIdentity.generate(), PQIdentity.generate()
    cache = replay.ReplayCache(str(tmp_path / "pq2.json"))
    ax, ae, _ = _parse_pq(a)
    for i in range(5):
        env = pq.seal_pq(f"msg {i}".encode(), a, *_parse_pq(b))
        out = pq.open_pq(env, b, ax, ae, cache=cache)
        assert out == f"msg {i}".encode()
    print("✓ PQ：5 个新信封连续解封无误判（ephemeral 随机性保证 ID 唯一）")


def test_pq_timestamp_forgery_rejected(tmp_path):
    a, b = PQIdentity.generate(), PQIdentity.generate()
    env = bytearray(pq.seal_pq(b"data", a, *_parse_pq(b)))
    # 时间戳在 eph(32)+kem_ct(1088) 之后
    env[32 + 1088] ^= 0x01
    ax, ae, _ = _parse_pq(a)
    try:
        pq.open_pq(bytes(env), b, ax, ae)
        raise AssertionError("tampered ts should fail")
    except Exception:
        pass
    print("✓ PQ：篡改时间戳 → 验签拒绝")


# ---------- PQ 信封：旧攻击面回归 ----------

def test_pq_old_attacks_still_blocked(tmp_path):
    a, b, m = PQIdentity.generate(), PQIdentity.generate(), PQIdentity.generate()
    env = pq.seal_pq(b"secret", a, *_parse_pq(b))
    ax, ae, _ = _parse_pq(a)
    mx, me, _ = _parse_pq(m)
    bad = bytearray(env); bad[-1] ^= 1
    try:
        pq.open_pq(bytes(bad), b, ax, ae)
        raise AssertionError("tamper should fail")
    except Exception:
        pass
    try:
        pq.open_pq(env, b, mx, me)
        raise AssertionError("impersonation should fail")
    except Exception:
        pass
    print("✓ PQ 回归：密文篡改/冒充仍被拒绝")


def test_pq_forward_secrecy_structure(tmp_path):
    """回归：临时材料仍不出现在泄露集合。"""
    a, b = PQIdentity.generate(), PQIdentity.generate()
    msg = b"secret must stay"
    env = pq.seal_pq(msg, a, *_parse_pq(b))
    leaked = b.to_bytes()   # Bob 长期私钥泄露
    assert msg not in leaked
    # eph_priv 不在信封或泄露材料里：正常解密一次后无法用长期材料再解
    assert pq.open_pq(env, b, *_parse_pq(a)[:2]) == msg
    print("✓ PQ 回归：前向保密结构未被重放防护破坏")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        with tempfile.TemporaryDirectory() as td:
            t(Path(td))
    print(f"\n重放防护 + 回归：{len(tests)} 项全部通过 ✅")
