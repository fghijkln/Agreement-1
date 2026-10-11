from __future__ import annotations
import hashlib
import json
import os
import struct
import time
from contextlib import contextmanager
from . import storage

DEFAULT_MAX_SKEW = 300
DEFAULT_MAX_ENTRIES = 100000
MAX_FILE_BYTES = 16 * 1024 * 1024
CACHE_FILE = os.path.join(os.path.expanduser('~'), '.nbx_replay_cache.json')
REPLAY_CACHE_ENV = 'NBX_REPLAY_CACHE'

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None

try:
    import msvcrt
except ImportError:  # pragma: no cover - non-Windows
    msvcrt = None


def default_cache_path() -> str:
    return os.environ.get(REPLAY_CACHE_ENV) or os.path.join(os.path.expanduser('~'), '.nbx_replay_cache.json')


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


def _is_hex_key(key) -> bool:
    if not isinstance(key, str) or len(key) != 32:
        return False
    return all(c in '0123456789abcdefABCDEF' for c in key)


class ReplayCache:
    """信封重放缓存，跨进程安全。

    - 读-改-写全程持有 ``path + '.lock'`` 上的跨进程排他锁；锁不可用时拒绝操作。
    - ``check_and_remember`` 在锁内重新从磁盘加载最新内容再判定+写入，
      避免多进程互相覆盖丢失记录。
    - ``max_entries`` 限制条目数，超限按时间戳淘汰最旧。
    - 文件损坏、超过 ``MAX_FILE_BYTES``、锁失败或写入失败时拒绝解封，避免 fail-open。
    """

    def __init__(self, path: str | None=None, ttl: int=86400, max_entries: int=DEFAULT_MAX_ENTRIES):
        if ttl < 0 or max_entries <= 0:
            raise ValueError('ttl must be non-negative and max_entries must be positive')
        self.path = path if path is not None else default_cache_path()
        self.ttl = ttl
        self.max_entries = int(max_entries)
        self._corrupt = False
        self._mem = self._load()

    def _load(self) -> dict:
        self._corrupt = False
        try:
            with open(self.path, 'rb') as f:
                raw = f.read(MAX_FILE_BYTES + 1)
        except FileNotFoundError:
            return {}
        except OSError:
            self._corrupt = True
            return {}
        if len(raw) > MAX_FILE_BYTES:
            self._corrupt = True
            return {}
        try:
            data = json.loads(raw.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            self._corrupt = True
            return {}
        if not isinstance(data, dict):
            self._corrupt = True
            return {}
        return self._sanitize(data)

    def _sanitize(self, data: dict) -> dict:
        now = int(time.time())
        clean = {}
        for key, value in data.items():
            if (not _is_hex_key(key) or isinstance(value, bool) or
                    not isinstance(value, int) or value < 0 or value > now + self.ttl):
                self._corrupt = True
                continue
            if now - value > self.ttl:
                continue
            clean[key] = value
        if self.max_entries > 0 and len(clean) > self.max_entries:
            newest = sorted(clean.items(), key=lambda kv: kv[1], reverse=True)[:self.max_entries]
            clean = dict(newest)
        return clean

    def _save(self):
        if self._corrupt:
            raise RuntimeError('replay cache is corrupt; refusing to overwrite it')
        try:
            storage.atomic_write(self.path, json.dumps(self._mem, separators=(',', ':')).encode('utf-8'))
        except Exception as e:
            raise RuntimeError('replay cache persistence failed; refusing to accept envelope') from e

    def _require_healthy(self) -> None:
        if self._corrupt:
            raise RuntimeError('replay cache is corrupt or unavailable; refusing to accept envelope')

    @contextmanager
    def _locked(self):
        try:
            directory = os.path.dirname(os.path.abspath(self.path))
            if directory:
                os.makedirs(directory, exist_ok=True)
            fd = open(self.path + '.lock', 'a+b')
        except OSError as e:
            raise RuntimeError('replay cache lock file is unavailable; refusing to accept envelope') from e
        if fcntl is None and msvcrt is None:
            fd.close()
            raise RuntimeError('cross-process replay cache locking is unavailable')
        try:
            if fcntl is not None:
                fcntl.flock(fd.fileno(), fcntl.LOCK_EX)
            else:
                fd.seek(0, os.SEEK_END)
                if fd.tell() == 0:
                    fd.write(b'\0')
                    fd.flush()
                fd.seek(0)
                msvcrt.locking(fd.fileno(), msvcrt.LK_LOCK, 1)
        except OSError as e:
            fd.close()
            raise RuntimeError('replay cache lock acquisition failed; refusing to accept envelope') from e
        try:
            yield
        finally:
            try:
                if fcntl is not None:
                    fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
                else:
                    fd.seek(0)
                    msvcrt.locking(fd.fileno(), msvcrt.LK_UNLCK, 1)
            finally:
                fd.close()

    def _drop_stale(self) -> bool:
        now = int(time.time())
        stale = [k for k, v in self._mem.items() if now - v > self.ttl]
        for k in stale:
            del self._mem[k]
        return bool(stale)

    def _evict(self) -> bool:
        if self.max_entries <= 0 or len(self._mem) <= self.max_entries:
            return False
        ordered = sorted(self._mem.items(), key=lambda kv: kv[1])
        for key, _ts in ordered[: len(self._mem) - self.max_entries]:
            del self._mem[key]
        return True

    def seen(self, eid: bytes) -> bool:
        with self._locked():
            self._mem = self._load()
            self._require_healthy()
            self._drop_stale()
            return eid.hex() in self._mem

    def remember(self, eid: bytes):
        with self._locked():
            self._mem = self._load()
            self._require_healthy()
            self._drop_stale()
            self._mem[eid.hex()] = int(time.time())
            self._evict()
            self._save()

    def _cleanup(self):
        if self._drop_stale():
            self._save()

    def check_and_remember(self, eid: bytes):
        with self._locked():
            self._mem = self._load()
            self._require_healthy()
            self._drop_stale()
            key = eid.hex()
            if key in self._mem:
                raise ValueError('replay detected: envelope already processed')
            self._mem[key] = int(time.time())
            self._evict()
            self._save()
