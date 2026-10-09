from __future__ import annotations
import base64
import hashlib
import json
import struct
import threading
import time
import urllib.error
import urllib.request, urllib.parse
from . import message as msg
from . import replay
from .fskey import Identity
from .ratchet import RatchetSession
AUTH_INFO = b'nbx-relay-auth-v1'
_UA = 'NBX-Client/1.0'

def _http_req(url: str, data: bytes | None=None, method: str='GET'):
    req = urllib.request.Request(url, data=data, method=method, headers={'User-Agent': _UA})
    return req

def _urlopen_retry(req, timeout: float=10, attempts: int=5):
    delay = 1.0
    scheme = urllib.parse.urlparse(req.full_url).scheme.lower()
    if scheme not in ('https', 'http'):
        raise ValueError(f'refusing non-HTTP(S) relay URL scheme: {scheme}')
    for i in range(attempts):
        try:
            return urllib.request.urlopen(req, timeout=timeout)
        except (urllib.error.URLError, ConnectionError, OSError) as e:
            if isinstance(e, urllib.error.HTTPError):
                raise
            if i == attempts - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 8.0)
    raise RuntimeError('unreachable')

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip('=')

def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

def fingerprint8(pub_b64: str) -> bytes:
    pub_raw = base64.b64decode(pub_b64 + '=' * (-len(pub_b64) % 4))
    if len(pub_raw) != 64:
        raise ValueError('public material must be 64 bytes (x||ed)')
    return hashlib.sha256(pub_raw).digest()[:8]

def raw_public(identity: Identity) -> bytes:
    from cryptography.hazmat.primitives import serialization
    x_pub = identity.x_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ed_pub = identity.ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return x_pub + ed_pub
DELIVERY_INFO = b'nbx-relay-delivery-v2'

def delivery_proof(sender_identity, envelope: bytes) -> bytes:
    import hashlib, struct as _s
    ts = _s.pack('<Q', int(time.time()))
    digest = hashlib.sha256(envelope).digest()
    return ts + sender_identity.ed_priv.sign(DELIVERY_INFO + digest + ts)

def auth_proof(identity: Identity, fp: bytes) -> bytes:
    ts = struct.pack('<Q', int(time.time()))
    return ts + identity.ed_priv.sign(AUTH_INFO + fp + ts)
RELAY_AUTH_INFO = b'nbx-relay-server-auth-v1'

class RelayClient:

    def __init__(self, base: str, pin_file: str | None=None):
        self.base = base.rstrip('/')
        self.relay_pinned_pub: bytes | None = None
        self._pin_file = pin_file
        if pin_file:
            import os
            if os.path.exists(pin_file):
                with open(pin_file, 'rb') as f:
                    self.relay_pinned_pub = f.read().strip() or None

    def post_envelope(self, blob: bytes, proof: bytes | None=None) -> dict:
        data = blob + proof if proof else blob
        req = _http_req(self.base + '/envelope', data=data, method='POST')
        with _urlopen_retry(req) as r:
            return json.loads(r.read())

    def auth(self, identity: Identity, fp: bytes) -> None:
        ts = struct.pack('<Q', int(time.time()))
        pub_material = raw_public(identity)
        body = pub_material + ts + identity.ed_priv.sign(AUTH_INFO + pub_material + ts)
        req = _http_req(self.base + '/auth', data=body, method='POST')
        with _urlopen_retry(req) as r:
            obj = json.loads(r.read())
        if not obj.get('ok'):
            raise PermissionError(f'relay auth failed: {obj}')
        if 'fp' not in obj or not obj['fp']:
            raise PermissionError('relay auth: missing fp in response')
        srv_fp = _b64d(obj['fp'])
        if srv_fp != fp:
            raise PermissionError(f'relay fp mismatch: local={fp.hex()} relay={srv_fp.hex()}')
        if 'relay_pub' not in obj or 'relay_sig' not in obj:
            raise PermissionError('relay auth: missing relay identity proof')
        relay_pub = _b64d(obj['relay_pub'])
        relay_sig = _b64d(obj['relay_sig'])
        if len(relay_pub) != 32 or len(relay_sig) != 64:
            raise PermissionError('relay auth: malformed relay identity proof')
        from cryptography.hazmat.primitives.asymmetric import ed25519
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(relay_pub).verify(relay_sig, RELAY_AUTH_INFO + fp + relay_pub + ts)
        except Exception:
            raise PermissionError('relay auth: bad relay signature')
        if self.relay_pinned_pub is None:
            self.relay_pinned_pub = relay_pub
            if self._pin_file:
                with open(self._pin_file, 'wb') as f:
                    f.write(relay_pub)
        elif self.relay_pinned_pub != relay_pub:
            raise PermissionError(f'relay identity changed (possible MITM): pinned={self.relay_pinned_pub.hex()} got={relay_pub.hex()}')

    def fetch(self, fp: bytes, proof: bytes) -> list[bytes]:
        url = f'{self.base}/inbox/{_b64e(fp)}'
        try:
            with _urlopen_retry(_http_req(url, data=proof, method='POST')) as r:
                obj = json.loads(r.read())
            return [_b64d(e) for e in obj.get('envelopes', [])]
        except urllib.error.HTTPError as e:
            if e.code == 403:
                raise PermissionError('relay rejected our auth proof')
            if e.code == 404:
                return []
            raise

class ChatSession:

    def __init__(self, identity: Identity, peer_pub_b64: str, relay_base: str, speaks_first: bool):
        self.identity = identity
        self.my_fp = fingerprint8(identity.export_public())
        self.peer_pub_b64 = peer_pub_b64
        self.peer_fp = fingerprint8(peer_pub_b64)
        self.peer_ed_pub = Identity.parse_public(peer_pub_b64)[1]
        self.client = RelayClient(relay_base)
        self.speaks_first = speaks_first
        self.session: RatchetSession | None = None
        self._pending: list[bytes] = []
        self._hs_candidate: bytes | None = None

    def connect(self):
        self.client.auth(self.identity, self.my_fp)
        hs = RatchetSession()
        payload = hs.begin(self.identity, self.my_fp, self.peer_fp)
        hs_wire = msg.pack_message(msg.PT_HANDSHAKE, self.my_fp, self.peer_fp, payload)
        self.client.post_envelope(hs_wire, delivery_proof(self.identity, hs_wire))
        peer_hs = self._wait_handshake()
        hs.finish(self.identity, self.peer_ed_pub, peer_hs, speaks_first=self.speaks_first, expect_sender_fp=self.peer_fp, expect_recv_fp=self.my_fp)
        self.session = hs

    def _wait_handshake(self, timeout: float=30.0) -> bytes:
        from .ratchet import HANDSHAKE_MAX_AGE, handshake_age
        deadline = time.time() + timeout
        while time.time() < deadline:
            for blob in self.client.fetch(self.my_fp, auth_proof(self.identity, self.my_fp)):
                m = msg.parse_message(blob)
                if m['ptype'] != msg.PT_HANDSHAKE:
                    self._pending.append(blob)
                    continue
                age = handshake_age(m['body'])
                if abs(age) > HANDSHAKE_MAX_AGE:
                    continue
                if self._hs_candidate is None or handshake_age(m['body']) < handshake_age(self._hs_candidate):
                    self._hs_candidate = m['body']
            if self._hs_candidate is not None:
                body, self._hs_candidate = (self._hs_candidate, None)
                return body
            time.sleep(1.0)
        raise TimeoutError('peer handshake not received in time')

    def send_text(self, text: str) -> bytes:
        if self.session is None:
            raise RuntimeError('not connected')
        inner = self.session.encrypt(text.encode('utf-8'), outer_aad=msg.routing_aad(msg.PT_TEXT, self.my_fp, self.peer_fp))
        wire = msg.pack_message(msg.PT_TEXT, self.my_fp, self.peer_fp, inner)
        self.client.post_envelope(wire, delivery_proof(self.identity, wire))
        return wire

    def poll_once(self) -> list[tuple[int, str]]:
        out = []
        blobs = self._pending
        self._pending = []
        blobs += self.client.fetch(self.my_fp, auth_proof(self.identity, self.my_fp))
        for blob in blobs:
            m = msg.parse_message(blob)
            if m['ptype'] == msg.PT_TEXT:
                out.append((msg.PT_TEXT, self.session.decrypt(m['body'], outer_aad=msg.routing_aad(msg.PT_TEXT, m['sender_fp'], m['recv_fp'])).decode('utf-8')))
        return out

def run_chat(identity: Identity, peer_pub_b64: str, relay_base: str, speaks_first: bool, poll: float=2.0):
    me = ChatSession(identity, peer_pub_b64, relay_base, speaks_first)
    my_fp_short = identity.fingerprint()
    print(f'[nbx chat] my fingerprint: {my_fp_short}')
    print('[nbx chat] establishing session via relay ...')
    me.connect()
    print('[nbx chat] session established. type messages, /quit to exit.')
    stop = threading.Event()

    def poller():
        while not stop.is_set():
            try:
                for ptype, text in me.poll_once():
                    print(f'\r[peer] {text}\n> ', end='', flush=True)
            except Exception as e:
                print(f'\r[poll error] {e}\n> ', end='', flush=True)
            stop.wait(poll)
    t = threading.Thread(target=poller, daemon=True)
    t.start()
    try:
        while True:
            line = input('> ')
            if line.strip() in ('/quit', '/exit'):
                break
            if line.strip():
                me.send_text(line)
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        stop.set()
        print('\n[nbx chat] bye')
