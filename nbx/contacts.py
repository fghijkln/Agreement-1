"""NBX 通讯录 + 三层传输栈（nbx/contacts.py, nbx/transport.py 合并）。

M2.5a 地基：
- Contact：一个联系人 = 身份公钥材料 + 最近 ratchet 会话状态 + 候选地址表
- 三层传输，按优先级降级：
    L1 P2P 直连（候选地址，UDP 打洞 — 本模块只做地址簿管理与直连 TCP 局域网，UDP 打洞在 M2.5c）
    L2 匿名网络（Tor SOCKS5 连 .onion / I2P — 候选地址为 onion:port）
    L3 中继服务器（HTTP relay）
- 传输结果统一为 (layer, bytes)，供上层记录"哪层成功"

联系人文件格式（JSON，敏感——含 ratchet 状态，等同长期私钥）：
  { "<fp_b32>": {
      "pub": "<b64 身份公钥材料>",
      "session": "<b64 ratchet 状态>",
      "addrs": [{"layer": 1|2|3, "addr": "...", "ts": <unix>}],
      "pref": [1, 2, 3]   # 降级顺序
  } }
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import time
import urllib.request
import urllib.error

from . import message as msg
from .fskey import Identity
from .ratchet import RatchetSession

LAYER_P2P = 1
LAYER_ANON = 2
LAYER_RELAY = 3

LAYER_NAMES = {LAYER_P2P: "p2p", LAYER_ANON: "anon", LAYER_RELAY: "relay"}


def fp_of_pub(pub_b64: str) -> bytes:
    """路由指纹 = SHA-256(原始公钥材料 x||ed)[:8]。

    audit R-03 配套统一：与 chat.fingerprint8 / fskey.fingerprint /
    服务器端 fp 计算同源（历史版本哈希 b64 字符串，与身份显示指纹不一致）。
    """
    pub_raw = base64.b64decode(pub_b64 + "=" * (-len(pub_b64) % 4))
    return hashlib.sha256(pub_raw).digest()[:8]


def fp_b32(fp: bytes) -> str:
    return base64.b32encode(fp).decode().rstrip("=")


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


class Contact:
    def __init__(self, pub_b64: str, session_state: bytes | None = None,
                 addrs: list[dict] | None = None, pref: list[int] | None = None):
        self.pub_b64 = pub_b64
        self.fp = fp_of_pub(pub_b64)
        self.session_state = session_state      # export_state() 的 b64
        self.addrs = addrs or []                # [{"layer", "addr", "ts"}]
        self.pref = pref or [LAYER_P2P, LAYER_ANON, LAYER_RELAY]

    def last_session_layer(self) -> int | None:
        used = [a["layer"] for a in self.addrs if a.get("last_ok")]
        return used[-1] if used else None


class ContactBook:
    """通讯录持久化。文件敏感：建议放 anon() 包装或加密目录。"""

    def __init__(self, path: str):
        self.path = path
        self._c: dict[str, Contact] = {}
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            for k, v in raw.items():
                self._c[k] = Contact(v["pub"], v.get("session"),
                                     v.get("addrs"), v.get("pref"))

    def save(self):
        def enc(v):
            if isinstance(v, bytes):
                return _b64e(v)
            return v
        data = {fp_b32(c.fp): {"pub": c.pub_b64, "session": enc(c.session_state),
                               "addrs": c.addrs, "pref": c.pref}
                for c in self._c.values()}
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1)
        os.replace(tmp, self.path)

    def add(self, pub_b64: str, pref: list[int] | None = None) -> Contact:
        c = Contact(pub_b64, pref=pref)
        self._c[fp_b32(c.fp)] = c
        return c

    def get(self, fp: bytes) -> Contact | None:
        return self._c.get(fp_b32(fp))

    def get_by_b32(self, b32: str) -> Contact | None:
        return self._c.get(b32)

    def all(self) -> list[Contact]:
        return list(self._c.values())

    # ---------- 会话简历 ----------

    def store_session(self, fp: bytes, session: RatchetSession):
        c = self.get(fp)
        if c is None:
            raise KeyError(f"unknown contact fp {fp.hex()}")
        c.session_state = session.export_state().decode("ascii")

    def load_session(self, fp: bytes) -> RatchetSession | None:
        c = self.get(fp)
        if c is None or c.session_state is None:
            return None
        try:
            return RatchetSession.import_state(c.session_state)
        except (ValueError, KeyError):
            return None


# ---------- 传输层 ----------

class TransportResult:
    def __init__(self, layer: int, ok: bool, detail: str = ""):
        self.layer = layer
        self.ok = ok
        self.detail = detail


class TransportStack:
    """三层传输栈：按联系人 pref 顺序尝试，成功即记录该层可用。

    L3 中继：现有 relay HTTP 协议（auth 一次，之后直接 post/poll）。
    L2 匿名：SOCKS5 代理（Tor 默认 127.0.0.1:9050）连 onion:port 上的
             同款 relay 协议——onion 服务后面跑什么（自建 relay / 对端
             的收信服务）对栈透明。
    L1 P2P：候选地址 TCP 直连（局域网/已打通的公网映射），协议同 L3
            （对端跑 mini-relay）。UDP 打洞在 M2.5c 加入，届时 L1 地址
            表扩充 udp:// 类型。
    """

    def __init__(self, book: ContactBook, my_identity: Identity,
                 socks_proxy: str | None = None):
        self.book = book
        self.me = my_identity
        self.my_fp = fp_of_pub(my_identity.export_public())
        self.socks_proxy = socks_proxy      # "127.0.0.1:9050"
        self._relay_authed: set[bytes] = set()

    # ---- 各层实现 ----

    def _http_post(self, url: str, data: bytes, proxy: str | None,
                   timeout: float = 8.0) -> tuple[int, bytes]:
        if proxy:
            s = self._socks_connect(*self._split_addr(url))
            http = (f"POST {url} HTTP/1.0\r\nContent-Length: {len(data)}\r\n\r\n").encode() + data
            s.sendall(http)
            resp = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp += chunk
            s.close()
            status = int(resp.split(b" ")[1]) if resp else 0
            return status, resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
        handler = urllib.request.ProxyHandler({})
        opener = urllib.request.build_opener(handler)
        req = urllib.request.Request(url, data=data, method="POST")
        try:
            with opener.open(req, timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def _http_get(self, url: str, proxy: str | None,
                  timeout: float = 8.0) -> tuple[int, bytes]:
        handler = urllib.request.ProxyHandler({})
        opener = urllib.request.build_opener(handler)
        try:
            with opener.open(url, timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def _socks_opener(self, proxy: str):
        """SOCKS5 opener（需要 PySocks；Tor 场景）。"""
        import socks  # noqa
        host, port = proxy.rsplit(":", 1)
        socks.set_default_proxy(socks.SOCKS5, host, int(port))
        socket.socket = socks.socksocket
        return urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _send_via_relay(self, c: Contact, addr: str, blob: bytes) -> TransportResult:
        try:
            base = addr.rstrip("/")
            if base not in self._relay_authed:
                self._relay_auth(base)
            status, _ = self._http_post(base + "/envelope",
                                        blob + self._delivery_proof(blob), None)
            return TransportResult(LAYER_RELAY, status == 202, f"HTTP {status}")
        except Exception as e:
            return TransportResult(LAYER_RELAY, False, str(e))

    def _delivery_proof(self, blob: bytes) -> bytes:
        """信封投递签名（audit R-06）：中继拒收未认证投递。"""
        import struct as _s
        ts = _s.pack("<Q", int(time.time()))
        hdr = blob[:msg.HEADER_SIZE]
        return ts + self.me.ed_priv.sign(b"nbx-relay-auth-v1" + hdr + ts)

    def _relay_auth(self, base: str):
        """TOFU 登记本方公钥（audit R-03：发送 64B 公钥材料，fp 由服务器算）。"""
        import struct as _s
        ts = _s.pack("<Q", int(time.time()))
        from cryptography.hazmat.primitives import serialization
        x_pub = self.me.x_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ed_pub = self.me.ed_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        pub_material = x_pub + ed_pub
        sig = self.me.ed_priv.sign(b"nbx-relay-auth-v1" + pub_material + ts)
        status, resp = self._http_post(base + "/auth", pub_material + ts + sig, None)
        if status != 200:
            raise ConnectionError(f"relay auth failed: HTTP {status}")
        self._relay_authed.add(base)

    def _send_via_anon(self, c: Contact, onion_addr: str, blob: bytes) -> TransportResult:
        if not self.socks_proxy:
            return TransportResult(LAYER_ANON, False, "no socks proxy configured")
        try:
            host, port = onion_addr.replace("http://", "").rsplit(":", 1)
            # Tor 的 DNS/连接走 SOCKS5；用原始 socket 发 HTTP/1.0 请求
            s = self._socks_connect(host, int(port))
            data = blob + self._delivery_proof(blob)
            http = (f"POST /envelope HTTP/1.0\r\nHost: {onion_addr}\r\n"
                    f"Content-Length: {len(data)}\r\n\r\n").encode() + data
            s.sendall(http)
            resp = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 65536:
                    break
            s.close()
            ok = b" 202 " in resp.split(b"\r\n")[0] if resp else False
            return TransportResult(LAYER_ANON, ok, resp.split(b"\r\n")[0].decode(errors="replace"))
        except Exception as e:
            return TransportResult(LAYER_ANON, False, str(e))

    def _socks_connect(self, host: str, port: int) -> socket.socket:
        if not self.socks_proxy:
            raise RuntimeError("no socks proxy")
        phost, pport = self.socks_proxy.rsplit(":", 1)
        s = socket.create_connection((phost, int(pport)), timeout=10)
        # SOCKS5 握手: 05 01 00 → 05 00; CONNECT domain
        s.sendall(b"\x05\x01\x00")
        assert s.recv(2) == b"\x05\x00"
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode()
                  + struct.pack(">H", port))
        resp = s.recv(10)
        if resp[1] != 0:
            s.close()
            raise ConnectionError(f"SOCKS5 connect failed: {resp[1]}")
        return s

    def _send_via_p2p(self, c: Contact, addr: str, blob: bytes) -> TransportResult:
        """TCP 直连对端 mini-relay（host:port）。"""
        try:
            host, port = addr.rsplit(":", 1)
            data = blob + self._delivery_proof(blob)
            with socket.create_connection((host, int(port)), timeout=5) as s:
                http = (f"POST /envelope HTTP/1.0\r\nHost: {host}\r\n"
                        f"Content-Length: {len(data)}\r\n\r\n").encode() + data
                s.sendall(http)
                resp = s.recv(4096)
            ok = b" 202 " in resp.split(b"\r\n")[0] if resp else False
            return TransportResult(LAYER_P2P, ok, resp.split(b"\r\n")[0].decode(errors="replace"))
        except Exception as e:
            return TransportResult(LAYER_P2P, False, str(e))

    # ---- 对外统一接口 ----

    def send(self, peer_fp: bytes, blob: bytes) -> TransportResult:
        """按联系人 pref 顺序尝试投递；成功即记录层并返回。"""
        c = self.book.get(peer_fp)
        if c is None:
            raise KeyError(f"unknown contact {peer_fp.hex()}")
        senders = {LAYER_P2P: self._send_via_p2p,
                   LAYER_ANON: self._send_via_anon,
                   LAYER_RELAY: self._send_via_relay}
        for layer in c.pref:
            for a in [a for a in c.addrs if a["layer"] == layer]:
                r = senders[layer](c, a["addr"], blob)
                if r.ok:
                    a["last_ok"] = time.time()
                    return r
        return TransportResult(-1, False, "all layers failed")

    def poll(self, peer_hint: bytes | None = None) -> list[tuple[int, bytes]]:
        """从所有可达层取信（L3 中继取自己桶；L1/L2 的对端 mini-relay 同理）。

        audit R-04：proof 走 POST body，不进 URL。
        返回 [(layer, envelope_bytes), ...]。
        """
        results: list[tuple[int, bytes]] = []
        proof = self._relay_proof()
        for c in self.book.all():
            for a in c.addrs:
                if a["layer"] == LAYER_RELAY:
                    try:
                        status, body = self._http_post(
                            a["addr"].rstrip("/") + f"/inbox/{_b64e(self.my_fp)}",
                            proof, None)
                        if status == 200:
                            for e in json.loads(body).get("envelopes", []):
                                results.append((LAYER_RELAY, _b64d(e)))
                    except Exception:
                        continue
                # L1/L2 取信: 对端 mini-relay 同款 /inbox 接口
                elif a.get("last_ok"):
                    try:
                        if a["layer"] == LAYER_ANON:
                            s = self._socks_connect(*self._split_addr(a["addr"]))
                        else:
                            host, port = self._split_addr(a["addr"])
                            s = socket.create_connection((host, port), timeout=5)
                        body = proof
                        http = (f"POST /inbox/{_b64e(self.my_fp)} HTTP/1.0\r\nHost: {a['addr']}\r\n"
                                f"Content-Length: {len(body)}\r\n\r\n").encode() + body
                        s.sendall(http)
                        resp = b""
                        while True:
                            chunk = s.recv(65536)
                            if not chunk:
                                break
                            resp += chunk
                        s.close()
                        if b"\r\n\r\n" in resp:
                            body = resp.split(b"\r\n\r\n", 1)[1]
                            for e in json.loads(body).get("envelopes", []):
                                results.append((a["layer"], _b64d(e)))
                    except Exception:
                        continue
        return results

    @staticmethod
    def _split_addr(addr: str) -> tuple[str, int]:
        a = addr.replace("http://", "")
        host, port = a.rsplit(":", 1)
        return host, int(port)

    def _relay_proof(self) -> bytes:
        import struct as _s
        ts = _s.pack("<Q", int(time.time()))
        return ts + self.me.ed_priv.sign(b"nbx-relay-auth-v1" + self.my_fp + ts)
