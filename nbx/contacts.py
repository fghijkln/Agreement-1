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
from . import storage
LAYER_P2P = 1
LAYER_ANON = 2
LAYER_RELAY = 3
LAYER_NAMES = {LAYER_P2P: 'p2p', LAYER_ANON: 'anon', LAYER_RELAY: 'relay'}

def fp_of_pub(pub_b64: str) -> bytes:
    pub_raw = base64.b64decode(pub_b64 + '=' * (-len(pub_b64) % 4))
    return hashlib.sha256(pub_raw).digest()[:8]

def fp_b32(fp: bytes) -> str:
    return base64.b32encode(fp).decode().rstrip('=')

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def _b64d(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except Exception:
        return base64.b64decode(s + pad)

class Contact:

    def __init__(self, pub_b64: str, session_state: bytes | None=None, addrs: list[dict] | None=None, pref: list[int] | None=None):
        self.pub_b64 = pub_b64
        self.fp = fp_of_pub(pub_b64)
        self.session_state = session_state
        self.addrs = addrs or []
        self.pref = pref or [LAYER_P2P, LAYER_ANON, LAYER_RELAY]

    def last_session_layer(self) -> int | None:
        used = [a['layer'] for a in self.addrs if a.get('last_ok')]
        return used[-1] if used else None

class ContactBook:
    """通讯录。传入 storage_key（32B，见 nbx.storage.derive_storage_key）时，
    会话状态以 AEAD 加密存为 'session_enc'；旧版明文 'session' 字段仍可读取，
    并在下一次 save() 时迁移为加密格式。文件以 0600 原子写入。"""

    def __init__(self, path: str, storage_key: bytes | None=None):
        self.path = path
        self._key = storage_key
        self._c: dict[str, Contact] = {}
        self._opaque_enc: dict[str, str] = {}
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                raw = json.load(f)
            for k, v in raw.items():
                state = v.get('session')
                enc = v.get('session_enc')
                if enc is not None:
                    if self._key is None:
                        self._opaque_enc[k] = enc
                        state = None
                    else:
                        try:
                            state = storage.open_sealed(self._key, base64.b64decode(enc), self._ctx(k)).decode('ascii')
                        except (storage.StorageError, ValueError):
                            state = None
                self._c[k] = Contact(v['pub'], state, v.get('addrs'), v.get('pref'))

    @staticmethod
    def _ctx(b32: str) -> bytes:
        return b'contact-session|' + b32.encode('ascii')

    def save(self):

        def enc(v):
            if isinstance(v, bytes):
                return _b64e(v)
            return v
        data = {}
        for c in self._c.values():
            k = fp_b32(c.fp)
            entry = {'pub': c.pub_b64, 'addrs': c.addrs, 'pref': c.pref}
            st = enc(c.session_state)
            if self._key is not None and st is not None:
                entry['session'] = None
                entry['session_enc'] = _b64e(storage.seal(self._key, st.encode('utf-8'), self._ctx(k)))
            elif st is None and k in self._opaque_enc:
                entry['session'] = None
                entry['session_enc'] = self._opaque_enc[k]
            else:
                entry['session'] = st
            data[k] = entry
        storage.atomic_write(self.path, json.dumps(data, indent=1).encode('utf-8'))

    def add(self, pub_b64: str, pref: list[int] | None=None) -> Contact:
        c = Contact(pub_b64, pref=pref)
        self._c[fp_b32(c.fp)] = c
        return c

    def get(self, fp: bytes) -> Contact | None:
        return self._c.get(fp_b32(fp))

    def get_by_b32(self, b32: str) -> Contact | None:
        return self._c.get(b32)

    def all(self) -> list[Contact]:
        return list(self._c.values())

    def store_session(self, fp: bytes, session: RatchetSession):
        c = self.get(fp)
        if c is None:
            raise KeyError(f'unknown contact fp {fp.hex()}')
        c.session_state = session.export_state().decode('ascii')

    def load_session(self, fp: bytes) -> RatchetSession | None:
        c = self.get(fp)
        if c is None or c.session_state is None:
            return None
        try:
            return RatchetSession.import_state(c.session_state)
        except (ValueError, KeyError):
            return None

class TransportResult:

    def __init__(self, layer: int, ok: bool, detail: str=''):
        self.layer = layer
        self.ok = ok
        self.detail = detail

class TransportStack:

    def __init__(self, book: ContactBook, my_identity: Identity, socks_proxy: str | None=None, pin_file: str | None=None, socks_timeout: float=10.0, io_deadline: float=30.0):
        self.book = book
        self.me = my_identity
        self.my_fp = fp_of_pub(my_identity.export_public())
        self.socks_proxy = socks_proxy
        self.socks_timeout = socks_timeout
        self.io_deadline = io_deadline
        self._relay_authed: set[bytes] = set()
        self._verified_endpoints: set[str] = set()
        self._relay_pins: dict[str, bytes] = {}
        self._pin_file = pin_file
        if pin_file and os.path.exists(pin_file):
            try:
                import base64 as _b64
                with open(pin_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) == 2:
                            self._relay_pins[_b64.b64decode(parts[0]).decode('utf-8')] = _b64.b64decode(parts[1])
            except Exception:
                pass

    @staticmethod
    def _recv_all(s: socket.socket, deadline: float, limit: int) -> bytes:
        buf = b''
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('recv deadline exceeded')
            try:
                s.settimeout(remaining)
            except OSError:
                pass
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > limit:
                break
        return buf

    @staticmethod
    def _recv_exact(s: socket.socket, n: int) -> bytes:
        buf = b''
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise ConnectionError('SOCKS5 handshake: connection closed before full reply')
            buf += chunk
        return buf

    def _http_post(self, url: str, data: bytes, proxy: str | None, timeout: float=8.0) -> tuple[int, bytes]:
        if proxy:
            s = self._socks_connect(*self._split_addr(url))
            try:
                http = f'POST {url} HTTP/1.0\r\nContent-Length: {len(data)}\r\n\r\n'.encode() + data
                s.sendall(http)
                resp = self._recv_all(s, time.monotonic() + self.io_deadline, 8 * 1024 * 1024)
            finally:
                s.close()
            status = int(resp.split(b' ')[1]) if resp else 0
            return (status, resp.split(b'\r\n\r\n', 1)[1] if b'\r\n\r\n' in resp else b'')
        handler = urllib.request.ProxyHandler({})
        opener = urllib.request.build_opener(handler)
        req = urllib.request.Request(url, data=data, method='POST')
        try:
            with opener.open(req, timeout=timeout) as r:
                return (r.status, r.read())
        except urllib.error.HTTPError as e:
            return (e.code, e.read())

    def _http_get(self, url: str, proxy: str | None, timeout: float=8.0) -> tuple[int, bytes]:
        handler = urllib.request.ProxyHandler({})
        opener = urllib.request.build_opener(handler)
        try:
            with opener.open(url, timeout=timeout) as r:
                return (r.status, r.read())
        except urllib.error.HTTPError as e:
            return (e.code, e.read())

    def _socks_opener(self, proxy: str):
        import socks
        host, port = proxy.rsplit(':', 1)
        socks.set_default_proxy(socks.SOCKS5, host, int(port))
        socket.socket = socks.socksocket
        return urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _send_via_relay(self, c: Contact, addr: str, blob: bytes) -> TransportResult:
        try:
            base = addr.rstrip('/')
            if base not in self._relay_authed:
                self._relay_auth(base)
            status, _ = self._http_post(base + '/envelope', blob + self._delivery_proof(blob), None)
            return TransportResult(LAYER_RELAY, status == 202, f'HTTP {status}')
        except Exception as e:
            return TransportResult(LAYER_RELAY, False, str(e))

    def _delivery_proof(self, blob: bytes) -> bytes:
        import hashlib, struct as _s
        ts = _s.pack('<Q', int(time.time()))
        digest = hashlib.sha256(blob).digest()
        return ts + self.me.ed_priv.sign(b'nbx-relay-delivery-v2' + digest + ts)

    def _relay_auth(self, base: str):
        import struct as _s
        ts = _s.pack('<Q', int(time.time()))
        from cryptography.hazmat.primitives import serialization
        x_pub = self.me.x_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ed_pub = self.me.ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        pub_material = x_pub + ed_pub
        sig = self.me.ed_priv.sign(b'nbx-relay-auth-v1' + pub_material + ts)
        status, resp = self._http_post(base + '/auth', pub_material + ts + sig, None)
        if status != 200:
            raise ConnectionError(f'relay auth failed: HTTP {status}')
        try:
            srv = json.loads(resp)
        except Exception:
            raise ConnectionError('relay auth: bad response')
        if not isinstance(srv, dict) or not srv.get('ok'):
            raise ConnectionError(f'relay auth failed: {srv}')
        srv_fp = _b64d(srv.get('fp', ''))
        if not srv_fp:
            raise ConnectionError('relay auth: server did not return fp')
        if srv_fp != self.my_fp:
            raise ConnectionError(f'relay fp mismatch: local={self.my_fp.hex()} relay={srv_fp.hex()}')
        relay_pub_b64, relay_sig_b64 = (srv.get('relay_pub', ''), srv.get('relay_sig', ''))
        if not relay_pub_b64 or not relay_sig_b64:
            raise ConnectionError('relay auth: missing relay identity proof')
        relay_pub = _b64d(relay_pub_b64)
        relay_sig = _b64d(relay_sig_b64)
        if len(relay_pub) != 32 or len(relay_sig) != 64:
            raise ConnectionError('relay auth: malformed relay identity proof')
        from cryptography.hazmat.primitives.asymmetric import ed25519
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(relay_pub).verify(relay_sig, b'nbx-relay-server-auth-v1' + self.my_fp + relay_pub + ts)
        except Exception:
            raise ConnectionError('relay auth: bad relay signature')
        prev = self._relay_pins.get(base)
        if prev is None:
            self._relay_pins[base] = relay_pub
            self._save_pins()
        elif prev != relay_pub:
            raise ConnectionError(f'relay identity changed (possible MITM) at {base}')
        self._relay_authed.add(base)
        self._verified_endpoints.add(base)

    def _save_pins(self) -> None:
        if not self._pin_file:
            return
        import base64 as _b64
        import tempfile
        lines = ''.join((f'{_b64.b64encode(k.encode()).decode()} {_b64.b64encode(v).decode()}\n' for k, v in sorted(self._relay_pins.items())))
        d = os.path.dirname(self._pin_file) or '.'
        fd, tmp = tempfile.mkstemp(dir=d)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(lines)
            os.replace(tmp, self._pin_file)
            os.chmod(self._pin_file, 384)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def _send_via_anon(self, c: Contact, onion_addr: str, blob: bytes) -> TransportResult:
        if not self.socks_proxy:
            return TransportResult(LAYER_ANON, False, 'no socks proxy configured')
        s = None
        try:
            host, port = onion_addr.replace('http://', '').rsplit(':', 1)
            s = self._socks_connect(host, int(port))
            data = blob + self._delivery_proof(blob)
            http = f'POST /envelope HTTP/1.0\r\nHost: {onion_addr}\r\nContent-Length: {len(data)}\r\n\r\n'.encode() + data
            s.sendall(http)
            resp = self._recv_all(s, time.monotonic() + self.io_deadline, 65536)
            ok = b' 202 ' in resp.split(b'\r\n')[0] if resp else False
            return TransportResult(LAYER_ANON, ok, resp.split(b'\r\n')[0].decode(errors='replace'))
        except Exception as e:
            return TransportResult(LAYER_ANON, False, str(e))
        finally:
            if s is not None:
                s.close()

    def _socks_connect(self, host: str, port: int) -> socket.socket:
        if not self.socks_proxy:
            raise RuntimeError('no socks proxy')
        phost, pport = self.socks_proxy.rsplit(':', 1)
        s = socket.create_connection((phost, int(pport)), timeout=self.socks_timeout)
        try:
            s.settimeout(self.socks_timeout)
            s.sendall(b'\x05\x01\x00')
            if self._recv_exact(s, 2) != b'\x05\x00':
                raise OSError('SOCKS5 handshake rejected')
            s.sendall(b'\x05\x01\x00\x03' + bytes([len(host)]) + host.encode() + struct.pack('>H', port))
            resp = self._recv_exact(s, 4)
            if resp[0] != 5:
                raise ConnectionError('SOCKS5 connect: bad reply version')
            if resp[1] != 0:
                raise ConnectionError(f'SOCKS5 connect failed: {resp[1]}')
            # 按 ATYP 读完 BND.ADDR + BND.PORT，避免残留字节混入后续 HTTP 响应
            atyp = resp[3]
            if atyp == 1:
                self._recv_exact(s, 4 + 2)
            elif atyp == 4:
                self._recv_exact(s, 16 + 2)
            elif atyp == 3:
                ln = self._recv_exact(s, 1)[0]
                self._recv_exact(s, ln + 2)
            else:
                raise ConnectionError('SOCKS5 connect: bad address type')
            return s
        except BaseException:
            try:
                s.close()
            except OSError:
                pass
            raise

    def _send_via_p2p(self, c: Contact, addr: str, blob: bytes) -> TransportResult:
        try:
            host, port = addr.rsplit(':', 1)
            data = blob + self._delivery_proof(blob)
            with socket.create_connection((host, int(port)), timeout=5) as s:
                http = f'POST /envelope HTTP/1.0\r\nHost: {host}\r\nContent-Length: {len(data)}\r\n\r\n'.encode() + data
                s.sendall(http)
                resp = s.recv(4096)
            ok = b' 202 ' in resp.split(b'\r\n')[0] if resp else False
            return TransportResult(LAYER_P2P, ok, resp.split(b'\r\n')[0].decode(errors='replace'))
        except Exception as e:
            return TransportResult(LAYER_P2P, False, str(e))

    def send(self, peer_fp: bytes, blob: bytes) -> TransportResult:
        c = self.book.get(peer_fp)
        if c is None:
            raise KeyError(f'unknown contact {peer_fp.hex()}')
        senders = {LAYER_P2P: self._send_via_p2p, LAYER_ANON: self._send_via_anon, LAYER_RELAY: self._send_via_relay}
        for layer in c.pref:
            for a in [a for a in c.addrs if a['layer'] == layer]:
                r = senders[layer](c, a['addr'], blob)
                if r.ok:
                    a['last_ok'] = time.time()
                    return r
        return TransportResult(-1, False, 'all layers failed')

    def poll(self, peer_hint: bytes | None=None) -> list[tuple[int, bytes]]:
        results: list[tuple[int, bytes]] = []
        proof = self._relay_proof()
        for c in self.book.all():
            for a in c.addrs:
                if a['layer'] == LAYER_RELAY:
                    base = a['addr'].rstrip('/')
                    if base not in self._verified_endpoints:
                        try:
                            self._relay_auth(base)
                        except Exception:
                            continue
                    try:
                        status, body = self._http_post(base + f'/inbox/{_b64e(self.my_fp)}', proof, None)
                        if status == 200:
                            for e in json.loads(body).get('envelopes', []):
                                results.append((LAYER_RELAY, _b64d(e)))
                    except Exception:
                        continue
                elif a.get('last_ok') and a['addr'] in self._verified_endpoints:
                    s = None
                    try:
                        if a['layer'] == LAYER_ANON:
                            s = self._socks_connect(*self._split_addr(a['addr']))
                        else:
                            host, port = self._split_addr(a['addr'])
                            s = socket.create_connection((host, port), timeout=5)
                        body = proof
                        http = f"POST /inbox/{_b64e(self.my_fp)} HTTP/1.0\r\nHost: {a['addr']}\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body
                        s.sendall(http)
                        resp = self._recv_all(s, time.monotonic() + self.io_deadline, 8 * 1024 * 1024)
                        if b'\r\n\r\n' in resp:
                            body = resp.split(b'\r\n\r\n', 1)[1]
                            for e in json.loads(body).get('envelopes', []):
                                results.append((a['layer'], _b64d(e)))
                    except Exception:
                        continue
                    finally:
                        if s is not None:
                            s.close()
        return results

    @staticmethod
    def _split_addr(addr: str) -> tuple[str, int]:
        a = addr.replace('http://', '')
        host, port = a.rsplit(':', 1)
        return (host, int(port))

    def _relay_proof(self) -> bytes:
        import struct as _s
        ts = _s.pack('<Q', int(time.time()))
        return ts + self.me.ed_priv.sign(b'nbx-relay-auth-v1' + self.my_fp + ts)
