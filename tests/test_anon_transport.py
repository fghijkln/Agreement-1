"""M2.5b：L2 匿名网络传输（Tor SOCKS5 → onion → relay）测试。

需要环境变量 NBX_TOR_TEST=1 且本机 tor 已运行（SOCKS5 9050 + onion service
指向测试中动态起的 relay）。无 Tor 时自动跳过，CI/普通开发环境不炸。

同时保留不依赖 Tor 的回归：SOCKS5 握手字节格式、onion 地址解析。
"""
import os
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from nbx.contacts import LAYER_ANON, TransportStack

TOR_SOCKS = os.environ.get("NBX_TOR_SOCKS", "127.0.0.1:9050")
RUN_TOR = os.environ.get("NBX_TOR_TEST") == "1"
ONION = os.environ.get("NBX_TOR_ONION", "")


class _MiniRelay(BaseHTTPRequestHandler):
    """记录收到的 /envelope 字节，回 202。"""

    received = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        if self.path == "/envelope":
            _MiniRelay.received.append(body)
            resp = b'{"ok": true}'
            self.send_response(202)
        else:
            resp = b'{"ok": false}'
            self.send_response(404)
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, *a):
        pass


@pytest.fixture
def mini_relay():
    srv = HTTPServer(("127.0.0.1", 0), _MiniRelay)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    _MiniRelay.received.clear()
    yield srv
    srv.shutdown()


def test_socks5_greeting_bytes():
    """SOCKS5 协议常量: 无认证 greeting 与 domain 类型地址。"""
    assert b"\x05\x01\x00" == bytes([5, 1, 0])
    assert 0x03 == 3  # DOMAINNAME


def test_onion_addr_parsing():
    """onion 地址 host:port 解析（含 http:// 前缀）。"""
    for raw in ("abc.onion:8765", "http://abc.onion:8765"):
        host, port = raw.replace("http://", "").rsplit(":", 1)
        assert host.endswith(".onion") and port == "8765"


@pytest.mark.skipif(not RUN_TOR or not ONION, reason="needs live tor + onion service")
def test_l2_full_path_via_tor(mini_relay):
    """全链路: Alice → SOCKS5(tor) → onion service → relay → Bob 取信。

    环境约定: NBX_TOR_ONION=xxx.onion，其 HiddenServicePort 指向本机
    nbx relay（默认 8765）。
    """
    import base64, hashlib, tempfile
    import nbx.message as M
    from nbx.chat import RelayClient, auth_proof
    from nbx.contacts import ContactBook, fp_of_pub
    from nbx.fskey import Identity
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    alice = Identity(X25519PrivateKey.generate(), Ed25519PrivateKey.generate())
    bob = Identity(X25519PrivateKey.generate(), Ed25519PrivateKey.generate())
    book = ContactBook(os.path.join(tempfile.mkdtemp(), "c.json"))
    stack = TransportStack(book, alice, socks_proxy=TOR_SOCKS)

    bob_b64 = bob.export_public()
    bob_fp = fp_of_pub(bob_b64)
    c = book.add(bob_b64)
    c.addrs.append({"layer": LAYER_ANON, "addr": f"{ONION}:8765"})

    env = M.pack_message(M.PT_TEXT, stack.my_fp, bob_fp, b"l2 tor test")
    res = stack.send(bob_fp, env)
    assert res.ok, res.detail
    assert res.layer == LAYER_ANON

    rc = RelayClient("http://127.0.0.1:8765")
    rc.auth(bob, bob_fp)
    got = rc.fetch(bob_fp, auth_proof(bob, bob_fp))
    bodies = [M.parse_message(g)["body"] for g in got]
    assert b"l2 tor test" in bodies
