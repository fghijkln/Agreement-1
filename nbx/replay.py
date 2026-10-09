from __future__ import annotations
import hashlib
import json
import os
import struct
import time
DEFAULT_MAX_SKEW = 300
CACHE_FILE = os.path.join(os.path.expanduser('~'), '.nbx_replay_cache.json')

def timestamp_now() -> bytes:
    return struct.pack('<Q', int(time.time()))

def envelope_id(eph_pub: bytes, ct: bytes) -> bytes:
    return hashlib.sha256(eph_pub + ct).digest()[:16]

def check_timestamp(ts_bytes: bytes, max_skew: int=DEFAULT_MAX_SKEW) -> None:
    if len(ts_bytes) != 8:
        raise ValueError('bad timestamp length')
    ts, = struct.unpack('<Q', ts_bytes)
    now = int(time.time())
    if abs(now - ts) > max_skew:
        raise ValueError(f'envelope timestamp out of window: ts={ts}, now={now}, skew>{max_skew}s')

class ReplayCache:

    def __init__(self, path: str=CACHE_FILE, ttl: int=86400):
        self.path = path
        self.ttl = ttl
        self._mem = self._load()

    def _load(self) -> dict:
        try:
            with open(self.path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            pass
        return {}

    def _save(self):
        try:
            tmp = self.path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(self._mem, f)
            os.replace(tmp, self.path)
        except OSError:
            pass

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
        if self.seen(eid):
            raise ValueError('replay detected: envelope already processed')
        self.remember(eid)
