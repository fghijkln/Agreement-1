"""NBX chat 客户端（nbx/chat.py）— M2 端点雏形。

经中继的加密会话：ratchet 会话 + 消息信封 + 中继 HTTP API。
- 会话密钥协商：双方身份私钥签名的临时密钥握手，经中继 HANDSHAKE 信封交换
- 收发循环：poll 线程取信解密打印，stdin 输入加密发出
- 离线消息：中继存 7 天，上线即收

用法（两个终端）：
  python -m nbx.cli relay --port 8765
  python -m nbx.cli chat --my-id alice.id --to-pub <bob.pub>   # 一方加 --first 发起
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct
import threading
import time
import urllib.error
import urllib.request

from . import message as msg
from . import replay
from .fskey import Identity
from .ratchet import RatchetSession

AUTH_INFO = b"nbx-relay-auth-v1"
_UA = "NBX-Client/1.0"          # 部分 Cloudflare 前置拦截无 UA / 默认 UA 的请求


def _http_req(url: str, data: bytes | None = None, method: str = "GET"):
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"User-Agent": _UA})
    return req


def _urlopen_retry(req, timeout: float = 10, attempts: int = 5):
    """带重试的 urlopen。

    针对受审查网络下 TLS 握手被随机重置 (ConnectionReset / SSL EOF):
    同一请求原样重发是安全的——GET 幂等, POST 信封有 msg_id 去重语义
    (重复投递同一信封在中继侧无害, 收件人 ratchet 侧由重放防护兜底)。
    """
    delay = 1.0
    for i in range(attempts):
        try:
            return urllib.request.urlopen(req, timeout=timeout)
        except (urllib.error.URLError, ConnectionError, OSError) as e:
            # HTTPError (4xx/5xx) 是服务端明确响应, 不该重试
            if isinstance(e, urllib.error.HTTPError):
                raise
            if i == attempts - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 8.0)
    raise RuntimeError("unreachable")


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def fingerprint8(pub_b64: str) -> bytes:
    """8 字节路由指纹 = SHA-256(原始公钥材料 x||ed)[:8]。

    与 fskey.Identity.fingerprint()（用户可见 base32 显示形式）同源：
    绑定公钥字节本身而非其 base64 编码。历史版本曾哈希 b64 字符串——
    与身份显示指纹不一致（安全审计要求统一后以原始字节为准）。
    """
    pub_raw = base64.b64decode(pub_b64 + "=" * (-len(pub_b64) % 4))
    if len(pub_raw) != 64:
        raise ValueError("public material must be 64 bytes (x||ed)")
    return hashlib.sha256(pub_raw).digest()[:8]


def raw_public(identity: Identity) -> bytes:
    """64B 原始公钥材料（x||ed），AUTH 协议携带、中继据此计算 fp。"""
    from cryptography.hazmat.primitives import serialization
    x_pub = identity.x_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ed_pub = identity.ed_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return x_pub + ed_pub


DELIVERY_INFO = b"nbx-relay-delivery-v2"


def delivery_proof(sender_identity, envelope: bytes) -> bytes:
    """信封投递签名（audit R-06 / R2-02）：ts(8) + Ed25519_sign。

    sig = Ed25519_sign(DELIVERY_INFO || SHA256(envelope) || ts)。
    R2-02: 签名绑定**完整信封**（明文头 + 密文体）——只签 header 时
    攻击者可拿合法 proof 换掉密文再投（绕过 msg_id 去重、毁掉合法消息）。
    域分隔 DELIVERY_INFO 与 /auth、/inbox proof 的 AUTH_INFO 隔离。
    """
    import hashlib, struct as _s
    ts = _s.pack("<Q", int(time.time()))
    digest = hashlib.sha256(envelope).digest()
    return ts + sender_identity.ed_priv.sign(DELIVERY_INFO + digest + ts)


def auth_proof(identity: Identity, fp: bytes) -> bytes:
    ts = struct.pack("<Q", int(time.time()))
    return ts + identity.ed_priv.sign(AUTH_INFO + fp + ts)


RELAY_AUTH_INFO = b"nbx-relay-server-auth-v1"


class RelayClient:
    """中继 HTTP 客户端。

    audit R2-01: 中继身份为密码学认证而非自证——AUTH 响应附
    relay_pub + 中继对 (RELAY_AUTH_INFO||client_fp||relay_pub||ts) 的签名。
    首次见到 relay_pub 时 TOFU-pin（可持久化到 pin 文件）；此后
    relay_pub 变化即视为中间人攻击立即报错。空 fp / 无签名 / 验签
    失败一律拒绝——不再有 `if srv_fp and ...` 的放行分支。
    """

    def __init__(self, base: str, pin_file: str | None = None):
        self.base = base.rstrip("/")
        self.relay_pinned_pub: bytes | None = None
        self._pin_file = pin_file
        if pin_file:
            import os
            if os.path.exists(pin_file):
                with open(pin_file, "rb") as f:
                    self.relay_pinned_pub = f.read().strip() or None

    def post_envelope(self, blob: bytes, proof: bytes | None = None) -> dict:
        # audit R-06：proof = delivery_proof(...)，中继验证发送者签名
        data = blob + proof if proof else blob
        req = _http_req(self.base + "/envelope", data=data, method="POST")
        with _urlopen_retry(req) as r:
            return json.loads(r.read())

    def auth(self, identity: Identity, fp: bytes) -> None:
        """登记公钥（TOFU）：证明持有该指纹的私钥。

        安全（audit R-03）：发送完整公钥材料 x||ed，fp 由中继计算——
        客户端无法用别人的 fp 配自己的钥匙抢注。
        """
        ts = struct.pack("<Q", int(time.time()))
        pub_material = raw_public(identity)
        body = pub_material + ts + identity.ed_priv.sign(
            AUTH_INFO + pub_material + ts)
        req = _http_req(self.base + "/auth", data=body, method="POST")
        with _urlopen_retry(req) as r:
            obj = json.loads(r.read())
        if not obj.get("ok"):
            raise PermissionError(f"relay auth failed: {obj}")
        # audit R2-01: 严格校验（不再有空 fp 放行分支）
        if "fp" not in obj or not obj["fp"]:
            raise PermissionError("relay auth: missing fp in response")
        srv_fp = _b64d(obj["fp"])
        if srv_fp != fp:
            raise PermissionError(
                f"relay fp mismatch: local={fp.hex()} relay={srv_fp.hex()}")
        # audit R2-01: 中继身份验证（TOFU pin）
        if "relay_pub" not in obj or "relay_sig" not in obj:
            raise PermissionError("relay auth: missing relay identity proof")
        relay_pub = _b64d(obj["relay_pub"])
        relay_sig = _b64d(obj["relay_sig"])
        if len(relay_pub) != 32 or len(relay_sig) != 64:
            raise PermissionError("relay auth: malformed relay identity proof")
        from cryptography.hazmat.primitives.asymmetric import ed25519
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(relay_pub).verify(
                relay_sig, RELAY_AUTH_INFO + fp + relay_pub + ts)
        except Exception:
            raise PermissionError("relay auth: bad relay signature")
        if self.relay_pinned_pub is None:
            self.relay_pinned_pub = relay_pub        # TOFU 首次 pin
            if self._pin_file:
                with open(self._pin_file, "wb") as f:
                    f.write(relay_pub)
        elif self.relay_pinned_pub != relay_pub:
            raise PermissionError(
                "relay identity changed (possible MITM): "
                f"pinned={self.relay_pinned_pub.hex()} got={relay_pub.hex()}")

    def fetch(self, fp: bytes, proof: bytes) -> list[bytes]:
        # 安全（audit R-04）：proof 走 POST body，不进 URL/访问日志
        url = f"{self.base}/inbox/{_b64e(fp)}"
        try:
            with _urlopen_retry(_http_req(url, data=proof, method="POST")) as r:
                obj = json.loads(r.read())
            return [_b64d(e) for e in obj.get("envelopes", [])]
        except urllib.error.HTTPError as e:
            if e.code == 403:
                raise PermissionError("relay rejected our auth proof")
            if e.code == 404:
                return []
            raise


class ChatSession:
    """一个端点：身份 + ratchet 会话 + 中继收发。"""

    def __init__(self, identity: Identity, peer_pub_b64: str,
                 relay_base: str, speaks_first: bool):
        self.identity = identity
        self.my_fp = fingerprint8(identity.export_public())
        self.peer_pub_b64 = peer_pub_b64
        self.peer_fp = fingerprint8(peer_pub_b64)
        self.peer_ed_pub = Identity.parse_public(peer_pub_b64)[1]
        self.client = RelayClient(relay_base)
        self.speaks_first = speaks_first
        self.session: RatchetSession | None = None
        self._pending: list[bytes] = []      # 等待握手期间取到、待后续处理的消息
        self._hs_candidate: bytes | None = None  # _wait_handshake 的最新候选握手

    # ---------- 会话建立 ----------

    def connect(self):
        """AUTH 登记 → 发握手 + 收对方握手（经中继）。"""
        self.client.auth(self.identity, self.my_fp)
        hs = RatchetSession()
        payload = hs.begin(self.identity, self.my_fp, self.peer_fp)
        hs_wire = msg.pack_message(
            msg.PT_HANDSHAKE, self.my_fp, self.peer_fp, payload)
        self.client.post_envelope(
            hs_wire, delivery_proof(self.identity, hs_wire))
        peer_hs = self._wait_handshake()
        hs.finish(self.identity, self.peer_ed_pub, peer_hs,
                  speaks_first=self.speaks_first,
                  expect_sender_fp=self.peer_fp,
                  expect_recv_fp=self.my_fp)
        self.session = hs

    def _wait_handshake(self, timeout: float = 30.0) -> bytes:
        """等对端握手，取时效最新的一个。

        桶里可能堆积历代会话的握手残留（中继取走即清 + 7 天 TTL 意味着
        对端多次重试会留下多代信封）。代际错配曾导致 InvalidTag——
        因此这里丢弃过期握手（verify_handshake 的时效检查），并在一批
        信封里选时间戳最新的握手，而不是"取到第一个就用"。
        """
        from .ratchet import HANDSHAKE_MAX_AGE, handshake_age
        deadline = time.time() + timeout
        while time.time() < deadline:
            for blob in self.client.fetch(
                    self.my_fp, auth_proof(self.identity, self.my_fp)):
                m = msg.parse_message(blob)
                if m["ptype"] != msg.PT_HANDSHAKE:
                    # 正文先到（与握手同批）：缓存，poll_once 时解密
                    self._pending.append(blob)
                    continue
                age = handshake_age(m["body"])
                if abs(age) > HANDSHAKE_MAX_AGE:
                    continue                     # 旧代残留/未来时钟：丢弃
                # 候选握手。记录最新的；旧候选已被过期筛除挡住，
                # 同批多个新鲜握手（对端连发两轮）取 ts 较新者。
                if (self._hs_candidate is None or
                        handshake_age(m["body"]) <
                        handshake_age(self._hs_candidate)):
                    self._hs_candidate = m["body"]
            if self._hs_candidate is not None:
                body, self._hs_candidate = self._hs_candidate, None
                return body
            time.sleep(1.0)
        raise TimeoutError("peer handshake not received in time")

    # ---------- 收发 ----------

    def send_text(self, text: str) -> bytes:
        if self.session is None:
            raise RuntimeError("not connected")
        inner = self.session.encrypt(
            text.encode("utf-8"), outer_aad=msg.routing_aad(
                msg.PT_TEXT, self.my_fp, self.peer_fp))
        wire = msg.pack_message(msg.PT_TEXT, self.my_fp, self.peer_fp, inner)
        self.client.post_envelope(
            wire, delivery_proof(self.identity, wire))
        return wire

    def poll_once(self) -> list[tuple[int, str]]:
        """取信并解密，返回 [(ptype, text), ...]。"""
        out = []
        blobs = self._pending
        self._pending = []
        blobs += self.client.fetch(
            self.my_fp, auth_proof(self.identity, self.my_fp))
        for blob in blobs:
            m = msg.parse_message(blob)
            if m["ptype"] == msg.PT_TEXT:
                out.append((msg.PT_TEXT,
                            self.session.decrypt(
                                m["body"],
                                outer_aad=msg.routing_aad(
                                    msg.PT_TEXT, m["sender_fp"],
                                    m["recv_fp"])).decode("utf-8")))
        return out


def run_chat(identity: Identity, peer_pub_b64: str, relay_base: str,
             speaks_first: bool, poll: float = 2.0):
    """CLI 交互循环：poll 线程收信，stdin 发信。"""
    me = ChatSession(identity, peer_pub_b64, relay_base, speaks_first)
    my_fp_short = identity.fingerprint()
    print(f"[nbx chat] my fingerprint: {my_fp_short}")
    print("[nbx chat] establishing session via relay ...")
    me.connect()
    print("[nbx chat] session established. type messages, /quit to exit.")

    stop = threading.Event()

    def poller():
        while not stop.is_set():
            try:
                for ptype, text in me.poll_once():
                    print(f"\r[peer] {text}\n> ", end="", flush=True)
            except Exception as e:
                print(f"\r[poll error] {e}\n> ", end="", flush=True)
            stop.wait(poll)

    t = threading.Thread(target=poller, daemon=True)
    t.start()
    try:
        while True:
            line = input("> ")
            if line.strip() in ("/quit", "/exit"):
                break
            if line.strip():
                me.send_text(line)
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        stop.set()
        print("\n[nbx chat] bye")
