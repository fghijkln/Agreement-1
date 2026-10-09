from __future__ import annotations
import base64
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .. import replay
from ..vendor.kyber_py.ml_kem import ML_KEM_768
NONCE_SIZE = 12
PQ_INFO = b'nbx-pq-hybrid-session-v1'
X_PUB_SIZE = 32
KEM_CT_SIZE = 1088
SIG_SIZE = 64

def _hkdf_hybrid(x_shared: bytes, kem_shared: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=PQ_INFO).derive(x_shared + kem_shared)

class PQIdentity:

    def __init__(self, x_priv, ed_priv, kem_ek: bytes, kem_dk: bytes):
        self.x_priv = x_priv
        self.ed_priv = ed_priv
        self.kem_ek = kem_ek
        self.kem_dk = kem_dk

    @classmethod
    def generate(cls) -> 'PQIdentity':
        kem_ek, kem_dk = ML_KEM_768.keygen()
        return cls(x25519.X25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate(), bytes(kem_ek), bytes(kem_dk))

    def to_bytes(self) -> bytes:
        x = self.x_priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        ed = self.ed_priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        return x + ed + self.kem_ek + self.kem_dk

    @classmethod
    def from_bytes(cls, data: bytes) -> 'PQIdentity':
        x = x25519.X25519PrivateKey.from_private_bytes(data[:32])
        ed = ed25519.Ed25519PrivateKey.from_private_bytes(data[32:64])
        return cls(x, ed, data[64:64 + 1184], data[64 + 1184:64 + 1184 + 2400])

    def save(self, path: str):
        with open(path, 'wb') as f:
            f.write(base64.b64encode(self.to_bytes()) + b'\n')

    @classmethod
    def load(cls, path: str) -> 'PQIdentity':
        with open(path, 'rb') as f:
            return cls.from_bytes(base64.b64decode(f.read().strip()))
    MAGIC_ENC = b'NBXPQ1'

    def save_encrypted(self, path: str, passphrase: str):
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        import secrets
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        salt = secrets.token_bytes(16)
        key = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode('utf-8'))
        nonce = secrets.token_bytes(12)
        ct = ChaCha20Poly1305(key).encrypt(nonce, self.to_bytes(), None)
        blob = self.MAGIC_ENC + bytes([15, 8, 1]) + salt + nonce + ct
        with open(path, 'wb') as f:
            f.write(base64.b64encode(blob) + b'\n')

    @classmethod
    def load_encrypted(cls, path: str, passphrase: str) -> 'PQIdentity':
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        with open(path, 'rb') as f:
            blob = base64.b64decode(f.read().strip())
        if blob[:6] != cls.MAGIC_ENC:
            raise ValueError('not an encrypted identity file')
        n_exp, r_exp, p_exp = (blob[6], blob[7], blob[8])
        salt, nonce, ct = (blob[9:25], blob[25:37], blob[37:])
        key = Scrypt(salt=salt, length=32, n=1 << n_exp, r=r_exp, p=p_exp).derive(passphrase.encode('utf-8'))
        return cls.from_bytes(ChaCha20Poly1305(key).decrypt(nonce, ct, None))

    def export_public(self) -> str:
        x_pub = self.x_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ed_pub = self.ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return base64.b64encode(x_pub + ed_pub + self.kem_ek).decode()

    @staticmethod
    def parse_public(b64: str) -> tuple[bytes, bytes, bytes]:
        raw = base64.b64decode(b64)
        if len(raw) != 32 + 32 + 1184:
            raise ValueError('bad PQ public key material')
        return (raw[:32], raw[32:64], raw[64:])

    def fingerprint(self) -> str:
        import hashlib
        x_pub = self.x_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ed_pub = self.ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        d = hashlib.sha256(x_pub + ed_pub + self.kem_ek).digest()[:8]
        return base64.b32encode(d).decode().rstrip('=')

def seal_pq(data: bytes, sender: PQIdentity, rec_x_pub: bytes, rec_ed_pub: bytes, rec_kem_ek: bytes) -> bytes:
    eph = x25519.X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    x_shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(rec_x_pub))
    kem_shared, kem_ct = ML_KEM_768.encaps(rec_kem_ek)
    kem_shared, kem_ct = (bytes(kem_shared), bytes(kem_ct))
    key = _hkdf_hybrid(x_shared, kem_shared, eph_pub + rec_x_pub)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = ChaCha20Poly1305(key).encrypt(nonce, data, None)
    ts = replay.timestamp_now()
    sig = sender.ed_priv.sign(eph_pub + kem_ct + ts + rec_x_pub + ct)
    return eph_pub + kem_ct + ts + sig + nonce + ct

def open_pq(blob: bytes, recipient: PQIdentity, snd_x_pub: bytes, snd_ed_pub: bytes, cache: 'replay.ReplayCache | None'=None, max_skew: int=replay.DEFAULT_MAX_SKEW) -> bytes:
    if len(blob) < X_PUB_SIZE + KEM_CT_SIZE + 8 + SIG_SIZE + NONCE_SIZE + 16:
        raise ValueError('PQ envelope too short')
    p = 0
    eph_pub = blob[p:p + X_PUB_SIZE]
    p += X_PUB_SIZE
    kem_ct = blob[p:p + KEM_CT_SIZE]
    p += KEM_CT_SIZE
    ts = blob[p:p + 8]
    p += 8
    sig = blob[p:p + SIG_SIZE]
    p += SIG_SIZE
    nonce = blob[p:p + NONCE_SIZE]
    p += NONCE_SIZE
    ct = blob[p:]
    my_x_pub = recipient.x_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ed25519.Ed25519PublicKey.from_public_bytes(snd_ed_pub).verify(sig, eph_pub + kem_ct + ts + my_x_pub + ct)
    replay.check_timestamp(ts, max_skew)
    if cache is not None:
        cache.check_and_remember(replay.envelope_id(eph_pub + kem_ct, ct))
    x_shared = recipient.x_priv.exchange(x25519.X25519PublicKey.from_public_bytes(eph_pub))
    kem_shared = bytes(ML_KEM_768.decaps(recipient.kem_dk, kem_ct))
    key = _hkdf_hybrid(x_shared, kem_shared, eph_pub + my_x_pub)
    return ChaCha20Poly1305(key).decrypt(nonce, ct, None)
