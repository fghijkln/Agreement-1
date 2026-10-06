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


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def fingerprint8(pub_b64: str) -> bytes:
    """与中继分桶一致的 8 字节指纹（SHA-256(公钥材料) 前 8 字节）。"""
    return hashlib.sha256(pub_b64.encode()).digest()[:8]


def auth_proof(identity: Identity, fp: bytes) -> bytes:
    ts = struct.pack("<Q", int(time.time()))
    return ts + identity.ed_priv.sign(AUTH_INFO + fp + ts)


class RelayClient:
    """中继 HTTP 客户端。"""

    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def post_envelope(self, blob: bytes) -> dict:
        req = urllib.request.Request(self.base + "/envelope", data=blob,
                                     method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())

    def auth(self, identity: Identity, fp: bytes) -> None:
        """登记公钥（TOFU）：证明持有该指纹的私钥。"""
        ts = struct.pack("<Q", int(time.time()))
        ed_pub = identity.ed_priv.public_key().public_bytes_raw() \
            if hasattr(identity.ed_priv, "public_key_raw") else \
            identity.ed_priv.public_key().public_bytes(
                __import__("cryptography.hazmat.primitives.serialization",
                           fromlist=["Encoding"]).Encoding.Raw,
                __import__("cryptography.hazmat.primitives.serialization",
                           fromlist=["PublicFormat"]).PublicFormat.Raw)
        body = fp + ts + ed_pub + identity.ed_priv.sign(AUTH_INFO + fp + ts)
        req = urllib.request.Request(self.base + "/auth", data=body,
                                     method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            obj = json.loads(r.read())
        if not obj.get("ok"):
            raise PermissionError(f"relay auth failed: {obj}")

    def fetch(self, fp: bytes, proof: bytes) -> list[bytes]:
        url = f"{self.base}/inbox/{_b64e(fp)}?proof={_b64e(proof)}"
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
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

    # ---------- 会话建立 ----------

    def connect(self):
        """AUTH 登记 → 发握手 + 收对方握手（经中继）。"""
        self.client.auth(self.identity, self.my_fp)
        hs = RatchetSession()
        payload = hs.begin(self.identity)
        self.client.post_envelope(msg.pack_message(
            msg.PT_HANDSHAKE, self.my_fp, self.peer_fp, payload))
        peer_hs = self._wait_handshake()
        hs.finish(self.identity, self.peer_ed_pub, peer_hs,
                  speaks_first=self.speaks_first)
        self.session = hs

    def _wait_handshake(self, timeout: float = 30.0) -> bytes:
        deadline = time.time() + timeout
        while time.time() < deadline:
            for blob in self.client.fetch(
                    self.my_fp, auth_proof(self.identity, self.my_fp)):
                m = msg.parse_message(blob)
                if m["ptype"] == msg.PT_HANDSHAKE:
                    return m["body"]
            time.sleep(1.0)
        raise TimeoutError("peer handshake not received in time")

    # ---------- 收发 ----------

    def send_text(self, text: str) -> bytes:
        if self.session is None:
            raise RuntimeError("not connected")
        wire = msg.pack_message(msg.PT_TEXT, self.my_fp, self.peer_fp,
                                self.session.encrypt(text.encode("utf-8")))
        self.client.post_envelope(wire)
        return wire

    def poll_once(self) -> list[tuple[int, str]]:
        """取信并解密，返回 [(ptype, text), ...]。"""
        out = []
        for blob in self.client.fetch(
                self.my_fp, auth_proof(self.identity, self.my_fp)):
            m = msg.parse_message(blob)
            if m["ptype"] == msg.PT_TEXT:
                out.append((msg.PT_TEXT,
                            self.session.decrypt(m["body"]).decode("utf-8")))
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
