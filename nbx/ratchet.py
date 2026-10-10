from __future__ import annotations
import hashlib
import hmac
import secrets
import struct
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .fskey import Identity
MAGIC_RATCHET = b'NBXRATCH1'
MAGIC_STATE = b'NBXRATCHST1'
HEADER_SIZE = 40
NONCE_SIZE = 12
MAX_SKIP = 256
HANDSHAKE_SIZE = 9 + 8 + 8 + 32 + 8 + 64
HANDSHAKE_MAX_AGE = 120.0

class HandshakeStale(Exception):
    pass

def handshake_age(hs: bytes) -> float:
    if len(hs) != HANDSHAKE_SIZE or hs[:9] != MAGIC_RATCHET:
        raise ValueError('bad handshake payload')
    return time.time() - struct.unpack('<Q', hs[57:65])[0]
INFO_ROOT = b'nbx-ratchet-root-v1'
INFO_CHAIN = b'nbx-ratchet-chain-v1'
INFO_HANDSHAKE = b'nbx-ratchet-handshake-v1'

def _kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=b'', info=INFO_CHAIN).derive(ck)
    return (okm[:32], okm[32:])

def _kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=rk, info=INFO_ROOT).derive(dh_out)
    return (okm[:32], okm[32:])

def _dh(priv: x25519.X25519PrivateKey, pub: bytes) -> bytes:
    return priv.exchange(x25519.X25519PublicKey.from_public_bytes(pub))

def _raw_pub(priv: x25519.X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def pack_header(ratchet_pub: bytes, prev_len: int, msg_no: int) -> bytes:
    return ratchet_pub + struct.pack('<II', prev_len, msg_no)

def unpack_header(hdr: bytes) -> tuple[bytes, int, int]:
    if len(hdr) != HEADER_SIZE:
        raise ValueError('bad ratchet header')
    return (hdr[:32], struct.unpack('<I', hdr[32:36])[0], struct.unpack('<I', hdr[36:40])[0])

def make_handshake(identity: Identity, eph_pub: bytes, sender_fp: bytes=b'\x00' * 8, recv_fp: bytes=b'\x00' * 8) -> bytes:
    ts = struct.pack('<Q', int(time.time()))
    sig = identity.ed_priv.sign(MAGIC_RATCHET + sender_fp + recv_fp + eph_pub + ts)
    return MAGIC_RATCHET + sender_fp + recv_fp + eph_pub + ts + sig

def verify_handshake(peer_ed_pub: bytes, hs: bytes, max_age: float=HANDSHAKE_MAX_AGE, expect_sender_fp: bytes | None=None, expect_recv_fp: bytes | None=None) -> bytes:
    if len(hs) != HANDSHAKE_SIZE or hs[:9] != MAGIC_RATCHET:
        raise ValueError('bad handshake payload')
    sender_fp, recv_fp = (hs[9:17], hs[17:25])
    eph_pub, ts, sig = (hs[25:57], hs[57:65], hs[65:129])
    if expect_sender_fp is not None and sender_fp != expect_sender_fp:
        raise ValueError('handshake sender_fp mismatch')
    if expect_recv_fp is not None and recv_fp != expect_recv_fp:
        raise ValueError('handshake recv_fp mismatch (not addressed to us)')
    ed25519.Ed25519PublicKey.from_public_bytes(peer_ed_pub).verify(sig, MAGIC_RATCHET + sender_fp + recv_fp + eph_pub + ts)
    if max_age > 0:
        age = time.time() - struct.unpack('<Q', ts)[0]
        if age > max_age or age < -max_age:
            raise HandshakeStale(f'handshake age {age:.0f}s outside ±{max_age:.0f}s')
    return eph_pub

def _state_integrity_tag(root_key: bytes, blob: bytes) -> bytes:
    return hmac.new(root_key, MAGIC_STATE + blob, hashlib.sha256).digest()[:16]

class RatchetSession:

    def __init__(self):
        self._root_key: bytes = b''
        self._send_ck: bytes | None = None
        self._recv_ck: bytes | None = None
        self._send_n = 0
        self._recv_n = 0
        self._prev_send_len = 0
        self._dh_self: x25519.X25519PrivateKey | None = None
        self._dh_remote_pub: bytes = b''
        self._skipped: dict[tuple[bytes, int], bytes] = {}
        self._established = False

    def begin(self, my_id: Identity, sender_fp: bytes | None=None, recv_fp: bytes | None=None) -> bytes:
        if sender_fp is None:
            sender_fp = b'\x00' * 8
        if recv_fp is None:
            recv_fp = b'\x00' * 8
        self._eph = x25519.X25519PrivateKey.generate()
        self._eph_pub = _raw_pub(self._eph)
        self._hs_sender_fp = sender_fp
        self._hs_recv_fp = recv_fp
        return make_handshake(my_id, self._eph_pub, sender_fp, recv_fp)

    def finish(self, my_id: Identity, peer_ed_pub: bytes, peer_hs: bytes, speaks_first: bool, expect_sender_fp: bytes | None=None, expect_recv_fp: bytes | None=None):
        peer_eph_pub = verify_handshake(peer_ed_pub, peer_hs, expect_sender_fp=expect_sender_fp, expect_recv_fp=expect_recv_fp)
        dh_shared = _dh(self._eph, peer_eph_pub)
        lo, hi = sorted((self._eph_pub, peer_eph_pub))
        sk = HKDF(algorithm=hashes.SHA256(), length=64, salt=lo + hi, info=INFO_HANDSHAKE).derive(dh_shared)
        self._root_key, ck0 = (sk[:32], sk[32:])
        self._dh_self = self._eph
        self._dh_self_pub = self._eph_pub
        self._dh_remote_pub = peer_eph_pub
        if speaks_first:
            self._send_ck, self._recv_ck = (ck0, None)
        else:
            self._send_ck, self._recv_ck = (None, ck0)
        self._established = True
        return self

    def export_state(self) -> bytes:
        import base64 as _b64
        if not self._established or self._dh_self is None:
            raise RuntimeError('session not established')

        def f(t: int, v: bytes) -> bytes:
            return bytes([t]) + struct.pack('<I', len(v)) + v
        out = MAGIC_STATE + bytes([1])
        out += f(1, self._root_key)
        out += f(2, self._send_ck or b'')
        out += f(3, self._recv_ck or b'')
        out += f(4, self._dh_self.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        out += f(5, self._dh_remote_pub)
        sk_blob = b''.join((pub + struct.pack('<I', no) + mk for (pub, no), mk in self._skipped.items()))
        out += f(6, sk_blob)
        counters = struct.pack('<III', self._prev_send_len, self._send_n, self._recv_n)
        out += f(7, counters)
        tag = _state_integrity_tag(self._root_key, out)
        out += f(8, tag)
        return _b64.b64encode(out)

    @classmethod
    def import_state(cls, blob: bytes) -> 'RatchetSession':
        import base64 as _b64
        raw = _b64.b64decode(blob)
        mlen = len(MAGIC_STATE)
        if raw[:mlen] != MAGIC_STATE or raw[mlen] != 1:
            raise ValueError('bad ratchet state blob')
        s = cls()
        off = mlen + 1
        fields = {}
        while off < len(raw):
            t = raw[off]
            ln = struct.unpack('<I', raw[off + 1:off + 5])[0]
            fields[t] = raw[off + 5:off + 5 + ln]
            off += 5 + ln
        s._root_key = fields[1]
        s._send_ck = fields[2] or None
        s._recv_ck = fields[3] or None
        s._dh_self = x25519.X25519PrivateKey.from_private_bytes(fields[4])
        s._dh_self_pub = _raw_pub(s._dh_self)
        s._dh_remote_pub = fields[5]
        sk_blob = fields[6]
        po = 0
        while po < len(sk_blob):
            pub, no = (sk_blob[po:po + 32], struct.unpack('<I', sk_blob[po + 32:po + 36])[0])
            s._skipped[pub, no] = sk_blob[po + 36:po + 68]
            po += 68
        s._prev_send_len, s._send_n, s._recv_n = struct.unpack('<III', fields[7])
        if 8 not in fields or len(fields[8]) != 16:
            raise ValueError('ratchet state missing integrity tag')
        body_end = mlen + 1
        while body_end < len(raw):
            t = raw[body_end]
            if t == 8:
                break
            ln = struct.unpack('<I', raw[body_end + 1:body_end + 5])[0]
            body_end += 5 + ln
        else:
            raise ValueError('ratchet state missing integrity tag')
        if _state_integrity_tag(s._root_key, raw[:body_end]) != fields[8]:
            raise ValueError('ratchet state integrity check failed (corrupted or foreign state file)')
        s._established = True
        return s

    def _snapshot(self) -> tuple:
        return (self._root_key, self._send_ck, self._recv_ck, self._send_n, self._recv_n, self._prev_send_len, self._dh_self, self._dh_self_pub, self._dh_remote_pub, dict(self._skipped))

    def _restore(self, snap: tuple) -> None:
        self._root_key, self._send_ck, self._recv_ck, self._send_n, self._recv_n, self._prev_send_len, self._dh_self, self._dh_self_pub, self._dh_remote_pub, self._skipped = snap

    def _recv_step(self, remote_pub: bytes, prev_len: int):
        if self._dh_self is None:
            raise RuntimeError('session not established')
        if self._recv_ck is not None and self._dh_remote_pub:
            self._skip_to(self._dh_remote_pub, prev_len)
        shared = _dh(self._dh_self, remote_pub)
        self._root_key, self._recv_ck = _kdf_rk(self._root_key, shared)
        self._recv_n = 0
        self._dh_remote_pub = remote_pub

    def _send_step(self):
        if not self._dh_remote_pub:
            raise RuntimeError('no remote ratchet key')
        self._prev_send_len = self._send_n
        self._dh_self = x25519.X25519PrivateKey.generate()
        self._dh_self_pub = _raw_pub(self._dh_self)
        shared_s = _dh(self._dh_self, self._dh_remote_pub)
        self._root_key, self._send_ck = _kdf_rk(self._root_key, shared_s)
        self._send_n = 0

    def _skip_to(self, ratchet_pub: bytes, until: int):
        if self._recv_ck is None:
            return
        if until - self._recv_n > MAX_SKIP:
            raise ValueError('too many skipped messages')
        while self._recv_n < until:
            self._recv_ck, mk = _kdf_ck(self._recv_ck)
            self._skipped[ratchet_pub, self._recv_n] = mk
            self._recv_n += 1

    def encrypt(self, plaintext: bytes, outer_aad: bytes=b'') -> bytes:
        if not self._established:
            raise RuntimeError('session not established')
        if self._send_ck is None:
            self._send_step()
        if self._send_ck is None:
            raise RuntimeError('send chain missing after ratchet step')
        self._send_ck, mk = _kdf_ck(self._send_ck)
        nonce = secrets.token_bytes(NONCE_SIZE)
        hdr = pack_header(self._dh_self_pub, self._prev_send_len, self._send_n)
        ct = ChaCha20Poly1305(mk).encrypt(nonce, plaintext, MAGIC_RATCHET + hdr + outer_aad)
        self._send_n += 1
        return hdr + nonce + ct

    def decrypt(self, blob: bytes, outer_aad: bytes=b'') -> bytes:
        if not self._established:
            raise RuntimeError('session not established')
        if len(blob) < HEADER_SIZE + NONCE_SIZE + 16:
            raise ValueError('message too short')
        hdr = blob[:HEADER_SIZE]
        nonce = blob[HEADER_SIZE:HEADER_SIZE + NONCE_SIZE]
        ct = blob[HEADER_SIZE + NONCE_SIZE:]
        ratchet_pub, prev_len, msg_no = unpack_header(hdr)
        aad = MAGIC_RATCHET + hdr + outer_aad
        snap = self._snapshot()
        try:
            skipped = dict(self._skipped)
            mk = skipped.pop((ratchet_pub, msg_no), None)
            if mk is not None:
                pt = ChaCha20Poly1305(mk).decrypt(nonce, ct, aad)
                self._skipped = skipped
                return pt
            if ratchet_pub != self._dh_remote_pub:
                self._recv_step(ratchet_pub, prev_len)
            if self._recv_ck is None:
                raise ValueError('no receiving chain')
            if msg_no < self._recv_n:
                raise ValueError('message already processed')
            if msg_no - self._recv_n > MAX_SKIP:
                raise ValueError('too many skipped messages')
            self._skip_to(ratchet_pub, msg_no)
            self._recv_ck, mk = _kdf_ck(self._recv_ck)
            self._recv_n += 1
            pt = ChaCha20Poly1305(mk).decrypt(nonce, ct, aad)
            return pt
        except Exception:
            self._restore(snap)
            raise

    @property
    def send_ratchet_pub(self) -> bytes:
        return self._dh_self_pub

    @property
    def skipped_count(self) -> int:
        return len(self._skipped)

    @property
    def recv_n(self) -> int:
        return self._recv_n

    @property
    def send_n(self) -> int:
        return self._send_n
