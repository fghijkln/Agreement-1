"""重放防护：时间窗 + 接收端信封 ID 缓存。

机制（FS 与 PQ 信封共用）：
- 签名消息加入 8 字节时间戳（Unix 秒，LE u64），签名绑定时间戳。
- 解封方校验 |now - ts| <= max_skew（默认 300 秒），过期拒绝。
- 解封成功后把信封 ID（SHA-256(eph_pub || kem_ct/签名材料)[:16]）记入缓存，
  缓存有效期内重复 ID 拒绝——同一天内同发送方的重放在时间窗内必然撞缓存。

缓存持久化到磁盘（.nbx_replay_cache.json），跨进程/重启有效。
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import time

DEFAULT_MAX_SKEW = 300  # 秒
CACHE_FILE = os.path.join(os.path.expanduser("~"), ".nbx_replay_cache.json")


def timestamp_now() -> bytes:
    """当前时间戳，8 字节 LE u64。"""
    return struct.pack("<Q", int(time.time()))


def envelope_id(eph_pub: bytes, ct: bytes) -> bytes:
    """信封唯一 ID：SHA-256(eph_pub || ct) 前 16 字节。"""
    return hashlib.sha256(eph_pub + ct).digest()[:16]


def check_timestamp(ts_bytes: bytes, max_skew: int = DEFAULT_MAX_SKEW) -> None:
    """时间窗校验，越界抛 ValueError。"""
    if len(ts_bytes) != 8:
        raise ValueError("bad timestamp length")
    (ts,) = struct.unpack("<Q", ts_bytes)
    now = int(time.time())
    if abs(now - ts) > max_skew:
        raise ValueError(
            f"envelope timestamp out of window: ts={ts}, now={now}, skew>{max_skew}s")


# ---------- 缓存（进程内 + 磁盘持久化） ----------

class ReplayCache:
    def __init__(self, path: str = CACHE_FILE, ttl: int = 86400):
        self.path = path
        self.ttl = ttl  # 缓存条目存活时间（秒），应 >= 2*max_skew
        self._mem = self._load()

    def _load(self) -> dict:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            pass
        return {}

    def _save(self):
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._mem, f)
            os.replace(tmp, self.path)
        except OSError:
            pass  # 缓存写失败不阻断解密（内存缓存仍在本进程内生效）

    def seen(self, eid: bytes) -> bool:
        self._cleanup()
        return eid.hex() in self._mem

    def remember(self, eid: bytes):
        self._mem[eid.hex()] = int(time.time())
        self._save()

    def _cleanup(self):
        now = int(time.time())
        stale = [k for k, v in self._mem.items() if now - v > self.ttl]
        if stale:
            for k in stale:
                del self._mem[k]
            self._save()

    def check_and_remember(self, eid: bytes):
        """先查后记：重复 → 抛 ValueError；首次 → 记入。"""
        if self.seen(eid):
            raise ValueError("replay detected: envelope already processed")
        self.remember(eid)
