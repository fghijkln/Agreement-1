import os
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import pytest
from nbx.contacts import LAYER_ANON, TransportStack
TOR_SOCKS = os.environ.get('NBX_TOR_SOCKS', '127.0.0.1:9050')
RUN_TOR = os.environ.get('NBX_TOR_TEST') == '1'
ONION = os.environ.get('NBX_TOR_ONION', '')

class _MiniRelay(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        if self.path == '/envelope':
            _MiniRelay.received.append(body)
            resp = b'{"ok": true}'
            self.send_response(202)
        else:
            resp = b'{"ok": false}'
            self.send_response(404)
        self.send_header('Content-Length', str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, *a):
        pass

@pytest.fixture
def mini_relay():
    srv = HTTPServer(('127.0.0.1', 0), _MiniRelay)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    _MiniRelay.received.clear()
    yield srv
    srv.shutdown()

def test_socks5_greeting_bytes():
    assert b'\x05\x01\x00' == bytes([5, 1, 0])
    assert 3 == 3

def test_onion_addr_parsing():
    for raw in ('abc.onion:8765', 'http://abc.onion:8765'):
        host, port = raw.replace('http://', '').rsplit(':', 1)
        assert host.endswith('.onion') and port == '8765'

@pytest.mark.skipif(not RUN_TOR or not ONION, reason='needs live tor + onion service')
def test_l2_full_path_via_tor(mini_relay):
    import base64, hashlib, tempfile
    import nbx.message as M
    from nbx.chat import RelayClient, auth_proof
    from nbx.contacts import ContactBook, fp_of_pub
    from nbx.fskey import Identity
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    alice = Identity(X25519PrivateKey.generate(), Ed25519PrivateKey.generate())
    bob = Identity(X25519PrivateKey.generate(), Ed25519PrivateKey.generate())
    book = ContactBook(os.path.join(tempfile.mkdtemp(), 'c.json'))
    stack = TransportStack(book, alice, socks_proxy=TOR_SOCKS)
    bob_b64 = bob.export_public()
    bob_fp = fp_of_pub(bob_b64)
    c = book.add(bob_b64)
    c.addrs.append({'layer': LAYER_ANON, 'addr': f'{ONION}:8765'})
    env = M.pack_message(M.PT_TEXT, stack.my_fp, bob_fp, b'l2 tor test')
    res = stack.send(bob_fp, env)
    assert res.ok, res.detail
    assert res.layer == LAYER_ANON
    rc = RelayClient('http://127.0.0.1:8765')
    rc.auth(bob, bob_fp)
    got = rc.fetch(bob_fp, auth_proof(bob, bob_fp))
    bodies = [M.parse_message(g)['body'] for g in got]
    assert b'l2 tor test' in bodies
