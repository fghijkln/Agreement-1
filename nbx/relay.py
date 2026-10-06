"""NBX 中继服务器 v0（nbx/relay.py）— 密文搬运工。

设计原则（M2）：
- 服务器只见明文路由头（nbx/message.py 的 48 字节头），永远见不到正文。
  它做的三件事：收信（按接收方指纹分桶入队）、取信（拉取自己的桶）、
  删除（取走即删——不支持服务器端历史，离线消息靠存储期内取走）。
- 无账号体系：身份 = 公钥指纹。取信授权 = 证明持有对应私钥（挑战-应答）。
- 无状态友好：全部状态 = 一个信封队列，可放内存 / SQLite / Workers KV。
  存储层抽象成 RelayStore，内存实现开箱即用，Workers 部署换一个 Store 即可。

信封 TTL：入队时打时间戳，默认 7 天过期，拉取时顺带清理。
队列上限：每个指纹最多 MAX_PER_FP 条，满了丢最旧的（防滥用）。

取信授权（简化版挑战-应答，v0）：
  客户端 POST /inbox/<fp>，body = fp(8) || ts(8) || sig(64)，
  sig = Ed25519_sign("nbx-relay-auth-v1" + fp + ts)（audit R-04：
  proof 不走 URL query，避免进入反代/边缘访问日志可被重放）。
  服务器用 AUTH 登记的公钥验证。AUTH 登记 pub_material(64)，
  指纹由服务器计算（audit R-03：客户端不得自报地址）。

HTTP API（任意 ASGI/WSGI 可包，核心逻辑在 RelayStore + RelayLogic）：
  POST /envelope            body = 消息信封（明文头+加密体）→ 202 或 4xx
  GET  /inbox/<fp>          取走该指纹全部信封 → 200 JSON / 404
  GET  /health              存活探测
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct
import time
from typing import Protocol

from .message import parse_message, HEADER_SIZE

DEFAULT_TTL = 7 * 86400          # 信封保存 7 天
DEFAULT_MAX_PER_FP = 256         # 每个指纹队列上限
MAX_ENVELOPE = 1 << 20           # 单信封 1 MiB（大文件走 FILE_OFFER + 外部 blob）

AUTH_INFO = b"nbx-relay-auth-v1"


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class RelayStore(Protocol):
    """存储抽象：内存版之外可换 SQLite / Workers KV / D1。"""

    def put(self, recv_fp: bytes, envelope: bytes) -> bool: ...
    def pop_all(self, recv_fp: bytes) -> list[bytes]: ...
    def count(self, recv_fp: bytes) -> int: ...


class MemoryStore:
    """内存实现：{recv_fp: [(enqueued_at, envelope), ...]}。"""

    def __init__(self, ttl: int = DEFAULT_TTL, max_per_fp: int = DEFAULT_MAX_PER_FP):
        self.ttl = ttl
        self.max_per_fp = max_per_fp
        self._q: dict[bytes, list[tuple[float, bytes]]] = {}
        self._seen: dict[bytes, float] = {}     # msg_id -> 入队时间（幂等去重）

    def _gc(self, fp: bytes):
        now = time.time()
        q = self._q.get(fp, [])
        self._q[fp] = [(t, e) for t, e in q if now - t < self.ttl]
        self._seen = {mid: t for mid, t in self._seen.items() if now - t < self.ttl}

    def put(self, recv_fp: bytes, envelope: bytes) -> bool:
        """入队。返回 False 表示重复信封（同 msg_id），已忽略。

        幂等去重：客户端在网络抖动下重发同一信封（POST 无响应重试）时，
        中继侧只收一件——否则重复投递会让 ratchet 解密侧产生无谓的失败。
        """
        mid = envelope[:8] + hashlib.blake2b(envelope, digest_size=16).digest()
        self._gc(recv_fp)
        if mid in self._seen:
            return False
        self._seen[mid] = time.time()
        q = self._q.setdefault(recv_fp, [])
        q.append((time.time(), envelope))
        if len(q) > self.max_per_fp:            # 满了丢最旧
            self._q[recv_fp] = q[-self.max_per_fp:]
        return True

    def pop_all(self, recv_fp: bytes) -> list[bytes]:
        self._gc(recv_fp)
        out = [e for _, e in self._q.get(recv_fp, [])]
        self._q[recv_fp] = []
        return out

    def count(self, recv_fp: bytes) -> int:
        self._gc(recv_fp)
        return len(self._q.get(recv_fp, []))


class RelayLogic:
    """协议逻辑：校验入队信封、打包取信响应。与传输层（HTTP/WS）解耦。"""

    def __init__(self, store: RelayStore,
                 ttl: int = DEFAULT_TTL,
                 max_per_fp: int = DEFAULT_MAX_PER_FP):
        self.store = store
        self.ttl = ttl
        self.max_per_fp = max_per_fp
        self._pubkeys: dict[bytes, bytes] = {}   # fp -> ed25519 公钥（AUTH 登记）

    # ---------- 投递 ----------

    def accept(self, blob: bytes) -> dict:
        """校验并投递一封信。返回 {'ok': True, 'msg_id': ...} 或抛 ValueError。"""
        if len(blob) > MAX_ENVELOPE:
            raise ValueError("envelope too large")
        if len(blob) < HEADER_SIZE:
            raise ValueError("envelope too short")
        try:
            m = parse_message(blob)
        except ValueError as e:
            raise ValueError(f"bad envelope: {e}")
        if m["ptype"] == 0:                      # 0 不是合法 ptype
            raise ValueError("invalid ptype")
        recv_fp = m["recv_fp"]
        if recv_fp == m["sender_fp"]:
            raise ValueError("self-addressed")
        self.store.put(recv_fp, blob)
        return {"ok": True, "msg_id": _b64e(m["msg_id"]), "ptype": m["ptype"]}

    # ---------- 取信 ----------

    def register_pubkey(self, pub_material: bytes) -> bytes:
        """AUTH 登记（TOFU：首见为准）。

        安全（audit R-03）：中继从完整公钥材料 x||ed 自行计算指纹，
        客户端无权自报地址——否则攻击者可用"任意 fp + 自己的钥匙"
        抢注受害者桶（身份冒用/消息截获窗口）。
        返回中继认定的 fp。
        """
        if len(pub_material) != 64:
            raise ValueError("pub material must be 64 bytes (x||ed)")
        fp = hashlib.sha256(pub_material).digest()[:8]
        ed_pub = pub_material[32:]
        if fp in self._pubkeys and self._pubkeys[fp] != ed_pub:
            raise ValueError("fingerprint already bound to another key")
        self._pubkeys[fp] = ed_pub
        return fp

    def authorize(self, fp: bytes, proof: bytes, now_skew: int = 300) -> bool:
        """取信授权：Ed25519_sign(AUTH_INFO || fp || ts(8))，ts 在窗口内。"""
        import struct
        ed_pub = self._pubkeys.get(fp)
        if ed_pub is None or len(proof) != 64 + 8:
            return False
        ts, sig = proof[:8], proof[8:]
        if abs(time.time() - struct.unpack("<Q", ts)[0]) > now_skew:
            return False
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(ed_pub).verify(
                sig, AUTH_INFO + fp + ts)
            return True
        except Exception:
            return False

    def fetch(self, fp: bytes, proof: bytes) -> list[bytes]:
        """授权通过 → 取走全部并清桶。"""
        if not self.authorize(fp, proof):
            raise PermissionError("unauthorized")
        return self.store.pop_all(fp)

    def inbox_count(self, fp: bytes) -> int:
        return self.store.count(fp)


# ---------- HTTP 适配（stdlib, 无依赖；生产可换 ASGI） ----------

def make_handler(logic: RelayLogic):
    """返回一个可被 http.server / 任意框架调用的 (method, path, body) -> (status, json) 函数。"""

    def handle(method: str, path: str, body: bytes) -> tuple[int, dict]:
        if method == "GET" and path == "/health":
            return 200, {"ok": True}
        if method == "POST" and path == "/envelope":
            try:
                return 202, logic.accept(body)
            except ValueError as e:
                return 400, {"ok": False, "error": str(e)}
        if method == "POST" and path == "/auth":
            # body = pub_material(64) || ts(8) || sig(64)
            # sig = Ed25519_sign(ed_priv, AUTH_INFO || pub_material || ts)
            # 安全（R-03）：fp 由中继从 pub_material 计算，客户端不自报地址
            if len(body) != 64 + 8 + 64:
                return 400, {"ok": False, "error": "bad auth payload"}
            pub_material, ts, sig = body[:64], body[64:72], body[72:136]
            if abs(time.time() - struct.unpack("<Q", ts)[0]) > 300:
                return 400, {"ok": False, "error": "timestamp out of window"}
            from cryptography.hazmat.primitives.asymmetric import ed25519
            ed_pub = pub_material[32:]
            try:
                ed25519.Ed25519PublicKey.from_public_bytes(ed_pub).verify(
                    sig, AUTH_INFO + pub_material + ts)
            except Exception:
                return 403, {"ok": False, "error": "bad signature"}
            try:
                fp = logic.register_pubkey(pub_material)
            except ValueError as e:
                return 409, {"ok": False, "error": str(e)}
            return 200, {"ok": True, "fp": _b64e(fp)}
        if method == "POST" and path.startswith("/inbox/"):
            # 安全（audit R-04）：proof 不走 URL query——查询串会进
            # 反代/边缘（Cloudflare）访问日志，5 分钟窗口内可重放。
            # 改 POST body = ts(8) || sig(64)，与 /auth 同构；fp 取自 URL path。
            if len(body) != 8 + 64:
                return 400, {"ok": False, "error": "bad proof payload"}
            fp_b64 = path.split("/inbox/", 1)[1]
            try:
                fp = _b64d(fp_b64)
            except Exception:
                return 400, {"ok": False, "error": "bad fingerprint"}
            if len(fp) != 8:
                return 400, {"ok": False, "error": "bad fingerprint"}
            ts, sig = body[:8], body[8:72]
            if abs(time.time() - struct.unpack("<Q", ts)[0]) > 300:
                return 403, {"ok": False, "error": "timestamp out of window"}
            try:
                envs = logic.fetch(fp, ts + sig)
                return 200, {"ok": True,
                             "envelopes": [_b64e(e) for e in envs]}
            except PermissionError:
                return 403, {"ok": False, "error": "unauthorized"}
            except Exception:
                return 400, {"ok": False, "error": "bad request"}
        return 404, {"ok": False, "error": "not found"}

    return handle


class RelayServer:
    """stdlib http.server 包装，测试与小部署用。"""

    def __init__(self, logic: RelayLogic | None = None, port: int = 8765):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        self.logic = logic or RelayLogic(MemoryStore())
        self.port = port
        handler = make_handler(self.logic)

        class H(BaseHTTPRequestHandler):
            def _run(self):
                body = b""
                if self.headers.get("Content-Length"):
                    body = self.rfile.read(int(self.headers["Content-Length"]))
                status, obj = handler(self.command, self.path, body)
                data = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _run

            def log_message(self, *a):      # 测试时静音
                pass

        self._httpd = HTTPServer(("127.0.0.1", port), H)

    def serve_forever(self):
        self._httpd.serve_forever()

    def serve_until_stop(self):
        self._httpd.handle_request()        # 处理一个请求即返回（测试用）
