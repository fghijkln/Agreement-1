"""NBX M3 — 常驻会话 daemon。

架构（用户拍板：中继只存密文，端点自治）：
  ┌────────────┐   IPC(unix socket)   ┌──────────────────┐   HTTPS   ┌────────┐
  │ UI / cli    │ <------------------> │     Daemon        │ --------> │ 中继    │
  └────────────┘                       │ · 每联系人会话状态 │           └────────┘
                                       │ · 消息日志(JSONL)  │
                                       │ · 后台轮询收信     │
                                       └──────────────────┘

信任边界：ratchet 状态只存在本机（状态目录下，export_state 序列化）；
中继只见密文信封（取走即清）。daemon 是唯一的持久层。

与旧脚本模式的本质区别：
  · 会话状态存活于 daemon 进程 + 磁盘，UI 进程随意启停
  · 异步握手：发消息时若无活跃会话 → 发出握手即返回，不等对端在线；
    对端 daemon 收到握手自动 finish 并缓存，之后的消息正常解密
    （代际防护 ratchet.HandshakeStale 保证旧握手不污染新会话）
"""
from __future__ import annotations

import base64
import json
import os
import socket
import threading
import time
from pathlib import Path

from .fskey import Identity
from .chat import RelayClient, auth_proof, fingerprint8, _urlopen_retry
from .ratchet import RatchetSession, HandshakeStale, handshake_age
from . import message as msg

DAEMON_MAGIC = b"NBXDAEMON1"
IPC_VERSION = 1


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class ContactSession:
    """单个联系人的活跃会话（内存中）+ 持久化。"""

    def __init__(self, daemon: "Daemon", peer_pub_b64: str):
        self.daemon = daemon
        self.peer_pub = peer_pub_b64
        self.peer_fp = fingerprint8(peer_pub_b64)
        self.session: RatchetSession | None = None
        self.handshake_sent_at = 0.0      # 异步握手去重：5 分钟内不重发
        self.speaks_first_flag: bool | None = None   # None=按指纹确定性判定

    # ---------- 会话建立（异步握手） ----------

    def ensure_handshake(self) -> None:
        """无活跃会话则发握手（异步，不等待对方在线）。"""
        if self.session is not None:
            return
        now = time.time()
        if now - self.handshake_sent_at < 300:
            return                          # 已有在途握手，等对方 finish
        self.handshake_sent_at = now
        hs = RatchetSession()
        payload = hs.begin(self.daemon.identity)
        self.daemon._pending_hs[self.peer_fp] = hs     # 对方握手到达时 finish
        wire = msg.pack_message(msg.PT_HANDSHAKE, self.daemon.my_fp,
                                self.peer_fp, payload)
        self.daemon.client.post_envelope(wire)
        self.daemon.log_event(f"握手已发 → {self.peer_fp.hex()}")

    def finish_handshake(self, peer_hs: bytes) -> None:
        """收到对方握手：完成本方半程，并把自己的握手回发（对端可离线）。

        双向握手各自独立（X3DH 简化版）：A 发握手 A1 给 B；B finish A1
        后必须把自己的握手 B1 发回 A —— A finish B1 才算双向会话就绪。
        任何一方都不需要双方同时在线。
        """
        hs = self.daemon._pending_hs.pop(self.peer_fp, None)
        if hs is None:
            # 纯被动方：新建本方会话并回发握手
            hs = RatchetSession()
            payload = hs.begin(self.daemon.identity)
            self.daemon.client.post_envelope(msg.pack_message(
                msg.PT_HANDSHAKE, self.daemon.my_fp, self.peer_fp, payload))
        hs.finish(self.daemon.identity, self.daemon._peer_ed_pub(self.peer_pub),
                  peer_hs, speaks_first=self.daemon.speaks_first_for(self.peer_pub))
        self.session = hs
        self.daemon.save_session(self)
        self.daemon.log_event(f"会话建立 ✓ {self.peer_fp.hex()}")
        self.daemon.flush_outbox()              # 建立会话后立即补发排队消息

    def send_text(self, text: str) -> dict:
        """发消息。无活跃会话时进 outbox，会话建立后自动补发。

        queued=True: 消息已落 outbox（掉线安全——即使本进程退出，
        重启后 flush_outbox 仍会投递），等握手完成即发。
        queued=False: 已直接投递。
        """
        if self.session is None:
            self.ensure_handshake()
            self.daemon.enqueue_outbox(self.peer_pub, text)
            return {"queued": True,
                    "note": "无活跃会话：已发握手，消息入 outbox 待自动补发"}
        wire = msg.pack_message(msg.PT_TEXT, self.daemon.my_fp,
                                self.peer_fp, self.session.encrypt(text.encode()))
        self.daemon.client.post_envelope(wire)
        self.daemon.log_message("out", self.peer_fp, text)
        self.daemon.save_session(self)          # 每条消息后立即持久化（ratchet 前跳）
        return {"queued": False}

    def decrypt_incoming(self, body: bytes) -> str:
        if self.session is None:
            raise RuntimeError("no active session")
        text = self.session.decrypt(body).decode("utf-8")
        self.daemon.save_session(self)
        return text


class Daemon:
    """常驻会话服务。UI 通过 IPC 与之通信，daemon 独立生命周期。"""

    def __init__(self, state_dir: str, relay_url: str,
                 poll_interval: float = 3.0):
        self.state_dir = Path(state_dir).expanduser()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        (self.state_dir / "messages").mkdir(exist_ok=True)
        (self.state_dir / "sessions").mkdir(exist_ok=True)
        self.relay_url = relay_url
        self.poll_interval = poll_interval

        id_path = self.state_dir / "identity.key"
        if id_path.exists():
            self.identity = Identity.load(str(id_path))
        else:
            self.identity = Identity.generate()
            self.identity.save(str(id_path))
            os.chmod(id_path, 0o600)
        self.my_fp = fingerprint8(self.identity.export_public())
        self.client = RelayClient(relay_url)
        self.contacts: dict[str, ContactSession] = {}   # peer_pub_b64 -> CS
        self._pending_hs: dict[bytes, RatchetSession] = {}
        self._stop = threading.Event()
        self._lock = threading.Lock()

    # ---------- 身份与联系人 ----------

    def export_public(self) -> str:
        return self.identity.export_public()

    def add_contact(self, peer_pub_b64: str, speaks_first: bool | None = None) -> ContactSession:
        if peer_pub_b64 not in self.contacts:
            self.contacts[peer_pub_b64] = ContactSession(self, peer_pub_b64)
        if speaks_first is not None:
            self.contacts[peer_pub_b64].speaks_first_flag = speaks_first
        return self.contacts[peer_pub_b64]

    def speaks_first_for(self, peer_pub_b64: str) -> bool:
        """先发方判定——必须双方独立算出同一答案。

        规则：指纹较小的一方持发送链（speaks_first=True）。确定性、
        与谁先上线无关（对比手动传参：两边都默认 False 会导致双方
        都持接收链，谁也发不出首条消息）。
        """
        cs = self.contacts.get(peer_pub_b64)
        if cs is not None and getattr(cs, "speaks_first_flag", None) is not None:
            return bool(cs.speaks_first_flag)
        return self.my_fp < fingerprint8(peer_pub_b64)

    def _peer_ed_pub(self, peer_pub_b64: str) -> bytes:
        _, ed = Identity.parse_public(peer_pub_b64)
        return ed

    # ---------- 持久化 ----------

    def _session_path(self, cs: ContactSession) -> Path:
        return self.state_dir / "sessions" / f"{_b64e(cs.peer_fp)}.session"

    def save_session(self, cs: ContactSession) -> None:
        if cs.session is None:
            return
        blob = cs.session.export_state()
        tmp = self._session_path(cs).with_suffix(".tmp")
        tmp.write_bytes(blob)
        os.replace(tmp, self._session_path(cs))
        os.chmod(self._session_path(cs), 0o600)

    def load_session(self, cs: ContactSession) -> None:
        p = self._session_path(cs)
        if not p.exists() or cs.session is not None:
            return
        rs = RatchetSession()
        rs.import_state(p.read_bytes())
        cs.session = rs

    def log_message(self, direction: str, peer_fp: bytes, text: str) -> None:
        day = time.strftime("%Y-%m-%d")
        entry = {"ts": time.time(), "dir": direction,
                 "peer": _b64e(peer_fp), "text": text}
        with open(self.state_dir / "messages" / f"{day}.jsonl", "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def log_event(self, text: str) -> None:
        day = time.strftime("%Y-%m-%d")
        entry = {"ts": time.time(), "event": text}
        with open(self.state_dir / "events.log", "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    # ---------- 发件箱（掉线安全的补发） ----------

    def _outbox_path(self) -> Path:
        return self.state_dir / "outbox.jsonl"

    def enqueue_outbox(self, peer_pub: str, text: str) -> None:
        entry = {"ts": time.time(), "pub": peer_pub, "text": text}
        with open(self._outbox_path(), "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def flush_outbox(self) -> int:
        """会话建立后调用：把 outbox 里该联系人的排队消息按序补发。

        outbox 整体重写（去掉已发条目），crash-safe：先写 tmp 再 replace。
        返回补发条数。
        """
        p = self._outbox_path()
        if not p.exists():
            return 0
        remain = []
        sent = 0
        for line in p.read_text().splitlines():
            e = json.loads(line)
            cs = self.contacts.get(e["pub"])
            if cs is not None and cs.session is not None:
                cs.send_text(e["text"])
                sent += 1
            else:
                remain.append(line)
        tmp = p.with_suffix(".tmp")
        tmp.write_text("\n".join(remain) + ("\n" if remain else ""))
        os.replace(tmp, p)
        if sent:
            self.log_event(f"outbox 补发 {sent} 条")
        return sent

    def history(self, peer_pub_b64: str, limit: int = 50) -> list[dict]:
        cs = self.contacts.get(peer_pub_b64)
        if cs is None:
            return []
        want = _b64e(cs.peer_fp)
        out = []
        for day_file in sorted((self.state_dir / "messages").glob("*.jsonl"),
                               reverse=True):
            for line in reversed(day_file.read_text().splitlines()):
                e = json.loads(line)
                if e["peer"] == want:
                    out.append(e)
                    if len(out) >= limit:
                        return list(reversed(out))
        return list(reversed(out))

    # ---------- 收信循环 ----------

    def _poll_once(self) -> None:
        try:
            blobs = self.client.fetch(self.my_fp,
                                      auth_proof(self.identity, self.my_fp))
        except Exception as e:
            # _urlopen_retry 已重试 5 次，到这里是网络持续不可用：静默等下轮
            self.log_event(f"poll 失败: {type(e).__name__}")
            return
        for blob in blobs:
            try:
                self._handle_envelope(blob)
            except Exception as e:
                self.log_event(f"信封处理失败: {type(e).__name__}: {e}")

    def _handle_envelope(self, blob: bytes) -> None:
        m = msg.parse_message(blob)
        peer_fp = m["sender_fp"]
        # 找联系人
        cs = None
        for c in self.contacts.values():
            if c.peer_fp == peer_fp:
                cs = c
                break
        if cs is None:
            self.log_event(f"未知发件人 {peer_fp.hex()}，信封丢弃")
            return
        self.load_session(cs)                   # daemon 重启后惰性恢复

        if m["ptype"] == msg.PT_HANDSHAKE:
            try:
                handshake_age(m["body"])
            except HandshakeStale:
                self.log_event(f"丢弃过期握手 from {peer_fp.hex()}")
                return
            cs.finish_handshake(m["body"])
            return
        if m["ptype"] == msg.PT_TEXT:
            if cs.session is None:
                # 正文先到、握手未到（乱序）：缓存到 _pending 等握手
                self._pending_texts.setdefault(peer_fp, []).append(blob)
                self.log_event(f"TEXT 先于握手，暂缓 {peer_fp.hex()}")
                return
            try:
                text = cs.decrypt_incoming(m["body"])
            except Exception:
                # 可能是旧会话残留——握手代际防护之下应已罕见
                self.log_event(f"TEXT 解密失败 from {peer_fp.hex()}（旧代残留?）")
                return
            self.log_message("in", peer_fp, text)
            self._on_message(cs, text)

    _pending_texts: dict[bytes, list[bytes]] = {}

    def _on_message(self, cs: ContactSession, text: str) -> None:
        """收到消息的钩子（子类/信号可覆盖）。默认：处理握手前缓存的正文。"""
        pass

    def poll_loop(self) -> None:
        while not self._stop.is_set():
            self._poll_once()
            self._stop.wait(self.poll_interval)

    # ---------- IPC ----------

    def handle_ipc(self, req: dict) -> dict:
        """UI 请求处理。cmd: send/history/status/add_contact。"""
        cmd = req.get("cmd")
        if cmd == "status":
            return {"ok": True, "fp": _b64e(self.my_fp),
                    "relay": self.relay_url,
                    "contacts": list(self.contacts.keys())}
        if cmd == "add_contact":
            cs = self.add_contact(req["pub"])
            return {"ok": True, "fp": _b64e(cs.peer_fp)}
        if cmd == "send":
            cs = self.add_contact(req["pub"])
            self.load_session(cs)
            return {"ok": True, **cs.send_text(req["text"])}
        if cmd == "history":
            return {"ok": True, "items": self.history(req["pub"],
                                                      req.get("limit", 50))}
        return {"ok": False, "error": f"unknown cmd {cmd}"}

    def serve_ipc(self, sock_path: str | None = None) -> None:
        sock_path = sock_path or str(self.state_dir / "daemon.sock")
        if os.path.exists(sock_path):
            os.unlink(sock_path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        os.chmod(sock_path, 0o600)
        srv.listen(4)
        self.log_event(f"IPC 就绪 {sock_path}")
        while not self._stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            with conn:
                data = conn.recv(65536)
                if not data:
                    continue
                try:
                    req = json.loads(data)
                    resp = self.handle_ipc(req)
                except Exception as e:
                    resp = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                conn.sendall(json.dumps(resp, ensure_ascii=False).encode())
        srv.close()

    # ---------- 生命周期 ----------

    def start(self) -> None:
        self.client.auth(self.identity, self.my_fp)
        threading.Thread(target=self.poll_loop, daemon=True).start()
        threading.Thread(target=self.serve_ipc, daemon=True).start()
        self.log_event(f"daemon 启动 fp={_b64e(self.my_fp)} relay={self.relay_url}")

    def stop(self) -> None:
        self._stop.set()
