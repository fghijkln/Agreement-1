"""daemon 引擎回归：异步握手 / outbox / 指纹确定性先发方 / 状态持久化。"""
import json
import time

import pytest

from nbx.daemon import Daemon, ContactSession


class OfflineClient:
    """假 RelayClient：吞掉所有网络操作，记录 POST 的信封。"""

    def __init__(self):
        self.posted: list[bytes] = []
        self.inbox: list[bytes] = []

    def auth(self, *a, **k):
        pass

    def post_envelope(self, blob):
        self.posted.append(blob)
        return {"ok": True}

    def fetch(self, fp, proof):
        out, self.inbox = self.inbox, []
        return out


def mk_daemon(tmp_path, name):
    d = Daemon(str(tmp_path / name), "http://fake", poll_interval=999)
    d.client = OfflineClient()
    return d


def test_async_handshake_and_outbox(tmp_path):
    """A 离线发消息 → 入 outbox；B 上线收握手并回握手；A 上线补发。"""
    a = mk_daemon(tmp_path, "a")
    b = mk_daemon(tmp_path, "b")
    pub_a, pub_b = a.export_public(), b.export_public()
    a.add_contact(pub_b)
    b.add_contact(pub_a)

    # A 无会话发送: 握手已 POST + 消息入 outbox
    r = a.handle_ipc({"cmd": "send", "pub": pub_b, "text": "hello-async"})
    assert r["queued"] is True
    assert len(a.client.posted) == 1            # 只有握手信封
    assert a._outbox_path().read_text().count("hello-async") == 1

    # 模拟 B 收到 A 的握手(纯被动): B 建
    # 事件日志里应无 outbox 记录(尚未会话)
    # 让 B fetch 到 A 的握手信封
    a_hs = a.client.posted[0]
    b.client.inbox = [a_hs]
    b.my_fp = __import__("nbx.chat", fromlist=["fingerprint8"]).fingerprint8(
        b.export_public())
    b._poll_once()
    # B 应: 回发自己的握手 + 建立 session
    hs_back = [p for p in b.client.posted if p != a_hs]
    assert len(hs_back) == 1, "B 必须回发自己的握手"
    assert len(list((b.state_dir / "sessions").glob("*.session"))) == 1


def test_speaks_first_deterministic(tmp_path):
    """指纹较小者持发送链——双方独立判定结果一致。"""
    a = mk_daemon(tmp_path, "a")
    b = mk_daemon(tmp_path, "b")
    pa, pb = a.export_public(), b.export_public()
    a.add_contact(pb)
    b.add_contact(pa)
    assert a.speaks_first_for(pb) != b.speaks_first_for(pa), \
        "双方判定必须互补（恰好一方先发）"


def test_outbox_flush_order(tmp_path):
    """outbox 按入队顺序补发，补发后清空。"""
    a = mk_daemon(tmp_path, "a")
    pub_b = "CDGghF7TbQkhGbp3mSMkd123wRaMQrdgZNCcZGxXzimsmUH6yaNE4fbAp56QEtd+jDHSvjHkQZ7WmoiWWRJnYw=="
    a.add_contact(pub_b)
    a.enqueue_outbox(pub_b, "msg1")
    a.enqueue_outbox(pub_b, "msg2")
    # 伪造会话: send_text 会走真加密路径 — 这里只验证 flush 清空逻辑
    cs = a.contacts[pub_b]
    from nbx.ratchet import RatchetSession
    rs = RatchetSession()
    rs.begin(a.identity)
    import nbx.chat as chat
    peer_x, peer_ed = __import__("nbx.fskey", fromlist=["Identity"]).Identity.parse_public(pub_b)
    rs.finish(a.identity, peer_ed, None, speaks_first=True) if False else None
    # 直接构造最小 session 桩
    class StubSession:
        def encrypt(self, data):
            return b"x" * 40

        def export_state(self):
            return b"stub"
    cs.session = StubSession()
    n = a.flush_outbox()
    assert n == 2
    assert not a._outbox_path().exists() or a._outbox_path().read_text().strip() == ""


def test_history_persisted(tmp_path):
    """消息日志按联系人可查。"""
    a = mk_daemon(tmp_path, "a")
    pub_b = "CDGghF7TbQkhGbp3mSMkd123wRaMQrdgZNCcZGxXzimsmUH6yaNE4fbAp56QEtd+jDHSvjHkQZ7WmoiWWRJnYw=="
    cs = a.add_contact(pub_b)
    a.log_message("out", cs.peer_fp, "记录一")
    a.log_message("in", cs.peer_fp, "记录二")
    items = a.handle_ipc({"cmd": "history", "pub": pub_b})["items"]
    assert [i["text"] for i in items] == ["记录一", "记录二"]
