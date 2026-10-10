from __future__ import annotations
import base64
import hashlib
import json
import struct
import time
from typing import Protocol
from .message import parse_message, HEADER_SIZE
DEFAULT_TTL = 7 * 86400
DEFAULT_MAX_PER_FP = 256
MAX_ENVELOPE = 1 << 20
DEFAULT_MAX_TOTAL_BYTES = 256 * (1 << 20)
AUTH_INFO = b'nbx-relay-auth-v1'
DELIVERY_INFO = b'nbx-relay-delivery-v2'
RELAY_AUTH_INFO = b'nbx-relay-server-auth-v1'

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip('=')

def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

class RelayStore(Protocol):

    def put(self, recv_fp: bytes, envelope: bytes) -> bool:
        ...

    def pop_all(self, recv_fp: bytes) -> list[bytes]:
        ...

    def count(self, recv_fp: bytes) -> int:
        ...

class MemoryStore:

    def __init__(self, ttl: int=DEFAULT_TTL, max_per_fp: int=DEFAULT_MAX_PER_FP, max_total_bytes: int=DEFAULT_MAX_TOTAL_BYTES):
        import threading
        self.ttl = ttl
        self.max_per_fp = max_per_fp
        self.max_total_bytes = max_total_bytes
        self._q: dict[bytes, list[tuple[float, bytes]]] = {}
        self._seen: dict[bytes, float] = {}
        self._total_bytes = 0
        self._lock = threading.Lock()

    def _gc(self, fp: bytes):
        now = time.time()
        q = self._q.get(fp, [])
        kept = []
        expired = []
        for t, e in q:
            if now - t < self.ttl:
                kept.append((t, e))
            else:
                expired.append(e)
        for e in expired:
            self._total_bytes -= len(e)
        self._q[fp] = kept
        self._seen = {mid: t for mid, t in self._seen.items() if now - t < self.ttl}

    def put(self, recv_fp: bytes, envelope: bytes) -> bool:
        mid = envelope[:8] + hashlib.blake2b(envelope, digest_size=16).digest()
        with self._lock:
            self._gc(recv_fp)
            if mid in self._seen:
                return False
            if self._total_bytes + len(envelope) > self.max_total_bytes:
                raise ValueError('global envelope budget exceeded')
            q = self._q.setdefault(recv_fp, [])
            q.append((time.time(), envelope))
            self._total_bytes += len(envelope)
            self._seen[mid] = time.time()
            if len(q) > self.max_per_fp:
                dropped = q[:-self.max_per_fp]
                self._q[recv_fp] = q[-self.max_per_fp:]
                for _, e in dropped:
                    self._total_bytes -= len(e)
        return True

    def pop_all(self, recv_fp: bytes) -> list[bytes]:
        with self._lock:
            self._gc(recv_fp)
            out = [e for _, e in self._q.get(recv_fp, [])]
            for e in out:
                self._total_bytes -= len(e)
            self._q[recv_fp] = []
            return out

    def count(self, recv_fp: bytes) -> int:
        with self._lock:
            self._gc(recv_fp)
            return len(self._q.get(recv_fp, []))

def load_or_create_relay_key(path: str):
    import base64
    import os
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    if os.path.exists(path):
        with open(path, 'rb') as f:
            raw = base64.b64decode(f.read().strip())
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw)
    priv = ed25519.Ed25519PrivateKey.generate()
    raw = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    with open(path, 'wb') as f:
        f.write(base64.b64encode(raw) + b'\n')
    os.chmod(path, 384)
    return priv

class RelayLogic:

    def __init__(self, store: RelayStore, ttl: int=DEFAULT_TTL, max_per_fp: int=DEFAULT_MAX_PER_FP, max_total_bytes: int=DEFAULT_MAX_TOTAL_BYTES, relay_ed_priv=None):
        self.store = store
        self.ttl = ttl
        self.max_per_fp = max_per_fp
        self.max_total_bytes = max_total_bytes
        self._pubkeys: dict[bytes, bytes] = {}
        if relay_ed_priv is None:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            relay_ed_priv = ed25519.Ed25519PrivateKey.generate()
        self.relay_ed_priv = relay_ed_priv
        from cryptography.hazmat.primitives import serialization
        self.relay_pub = relay_ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def relay_attestation(self, client_fp: bytes, ts: bytes) -> bytes:
        return self.relay_ed_priv.sign(RELAY_AUTH_INFO + client_fp + self.relay_pub + ts)

    def verify_sender(self, blob: bytes, envelope_len: int, now_skew: int=300) -> bytes:
        sender_fp = blob[12:20]
        if envelope_len < HEADER_SIZE or len(blob) < envelope_len + 72:
            raise ValueError('missing sender proof')
        ts = blob[envelope_len:envelope_len + 8]
        sig = blob[envelope_len + 8:envelope_len + 72]
        if abs(time.time() - struct.unpack('<Q', ts)[0]) > now_skew:
            raise ValueError('sender proof timestamp out of window')
        ed_pub = self._pubkeys.get(sender_fp)
        if ed_pub is None:
            raise ValueError('sender not registered (auth first)')
        from cryptography.hazmat.primitives.asymmetric import ed25519
        import hashlib
        try:
            digest = hashlib.sha256(blob[:envelope_len]).digest()
            ed25519.Ed25519PublicKey.from_public_bytes(ed_pub).verify(sig, DELIVERY_INFO + digest + ts)
        except Exception:
            raise ValueError('bad sender proof')
        return sender_fp

    def accept(self, blob: bytes, verify: bool=True) -> dict:
        if len(blob) > MAX_ENVELOPE:
            raise ValueError('envelope too large')
        if len(blob) < HEADER_SIZE:
            raise ValueError('envelope too short')
        try:
            m = parse_message(blob[:HEADER_SIZE] + blob[HEADER_SIZE:-72] if verify else blob)
        except ValueError as e:
            raise ValueError(f'bad envelope: {e}')
        if m['ptype'] == 0:
            raise ValueError('invalid ptype')
        recv_fp = m['recv_fp']
        if recv_fp == m['sender_fp']:
            raise ValueError('self-addressed')
        if verify:
            self.verify_sender(blob, len(blob) - 72)
            blob = blob[:-72]
        if not self.store.put(recv_fp, blob):
            return {'ok': True, 'duplicate': True, 'msg_id': _b64e(m['msg_id']), 'ptype': m['ptype']}
        return {'ok': True, 'msg_id': _b64e(m['msg_id']), 'ptype': m['ptype']}

    def register_pubkey(self, pub_material: bytes) -> bytes:
        if len(pub_material) != 64:
            raise ValueError('pub material must be 64 bytes (x||ed)')
        fp = hashlib.sha256(pub_material).digest()[:8]
        ed_pub = pub_material[32:]
        if fp in self._pubkeys and self._pubkeys[fp] != ed_pub:
            raise ValueError('fingerprint already bound to another key')
        self._pubkeys[fp] = ed_pub
        return fp

    def authorize(self, fp: bytes, proof: bytes, now_skew: int=300) -> bool:
        import struct
        ed_pub = self._pubkeys.get(fp)
        if ed_pub is None or len(proof) != 64 + 8:
            return False
        ts, sig = (proof[:8], proof[8:])
        if abs(time.time() - struct.unpack('<Q', ts)[0]) > now_skew:
            return False
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(ed_pub).verify(sig, AUTH_INFO + fp + ts)
            return True
        except Exception:
            return False

    def fetch(self, fp: bytes, proof: bytes) -> list[bytes]:
        if not self.authorize(fp, proof):
            raise PermissionError('unauthorized')
        return self.store.pop_all(fp)

    def inbox_count(self, fp: bytes) -> int:
        return self.store.count(fp)

def make_handler(logic: RelayLogic):

    def handle(method: str, path: str, body: bytes) -> tuple[int, dict]:
        if method == 'GET' and path == '/health':
            return (200, {'ok': True})
        if method == 'POST' and path == '/envelope':
            try:
                return (202, logic.accept(body))
            except ValueError as e:
                return (400, {'ok': False, 'error': str(e)})
        if method == 'POST' and path == '/auth':
            if len(body) != 64 + 8 + 64:
                return (400, {'ok': False, 'error': 'bad auth payload'})
            pub_material, ts, sig = (body[:64], body[64:72], body[72:136])
            if abs(time.time() - struct.unpack('<Q', ts)[0]) > 300:
                return (400, {'ok': False, 'error': 'timestamp out of window'})
            from cryptography.hazmat.primitives.asymmetric import ed25519
            ed_pub = pub_material[32:]
            try:
                ed25519.Ed25519PublicKey.from_public_bytes(ed_pub).verify(sig, AUTH_INFO + pub_material + ts)
            except Exception:
                return (403, {'ok': False, 'error': 'bad signature'})
            try:
                fp = logic.register_pubkey(pub_material)
            except ValueError as e:
                return (409, {'ok': False, 'error': str(e)})
            return (200, {'ok': True, 'fp': _b64e(fp), 'relay_pub': _b64e(logic.relay_pub), 'relay_sig': _b64e(logic.relay_attestation(fp, ts))})
        if method == 'POST' and path.startswith('/inbox/'):
            if len(body) != 8 + 64:
                return (400, {'ok': False, 'error': 'bad proof payload'})
            fp_b64 = path.split('/inbox/', 1)[1]
            try:
                fp = _b64d(fp_b64)
            except Exception:
                return (400, {'ok': False, 'error': 'bad fingerprint'})
            if len(fp) != 8:
                return (400, {'ok': False, 'error': 'bad fingerprint'})
            ts, sig = (body[:8], body[8:72])
            if abs(time.time() - struct.unpack('<Q', ts)[0]) > 300:
                return (403, {'ok': False, 'error': 'timestamp out of window'})
            try:
                envs = logic.fetch(fp, ts + sig)
                return (200, {'ok': True, 'envelopes': [_b64e(e) for e in envs]})
            except PermissionError:
                return (403, {'ok': False, 'error': 'unauthorized'})
            except Exception:
                return (400, {'ok': False, 'error': 'bad request'})
        return (404, {'ok': False, 'error': 'not found'})
    return handle

class RelayServer:

    def __init__(self, logic: RelayLogic | None=None, port: int=8765):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        self.logic = logic or RelayLogic(MemoryStore())
        self.port = port
        handler = make_handler(self.logic)

        class H(BaseHTTPRequestHandler):

            def _run(self):
                body = b''
                if self.headers.get('Content-Length'):
                    body = self.rfile.read(int(self.headers['Content-Length']))
                status, obj = handler(self.command, self.path, body)
                data = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            do_GET = do_POST = _run

            def log_message(self, *a):
                pass
        self._httpd = HTTPServer(('127.0.0.1', port), H)

    def serve_forever(self):
        self._httpd.serve_forever()

    def serve_until_stop(self):
        self._httpd.handle_request()
