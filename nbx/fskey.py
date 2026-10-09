from __future__ import annotations
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from . import replay
NONCE_SIZE = 12
FS_INFO = b'nbx-fs-session-key-v1'
EPH_PUB_SIZE = 32

class Identity:

    def __init__(self, x_priv: x25519.X25519PrivateKey, ed_priv: ed25519.Ed25519PrivateKey):
        self.x_priv = x_priv
        self.ed_priv = ed_priv

    def to_bytes(self) -> bytes:

        def _raw(key) -> bytes:
            return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        return _raw(self.x_priv) + _raw(self.ed_priv)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'Identity':
        return cls(x25519.X25519PrivateKey.from_private_bytes(data[:32]), ed25519.Ed25519PrivateKey.from_private_bytes(data[32:64]))

    def save(self, path: str):
        import base64
        with open(path, 'w', encoding='utf-8') as f:
            f.write(base64.b64encode(self.to_bytes()).decode() + '\n')

    @classmethod
    def load(cls, path: str) -> 'Identity':
        import base64
        with open(path, 'r', encoding='utf-8') as f:
            return cls.from_bytes(base64.b64decode(f.read().strip()))
    MAGIC_ENC = b'NBXID1'

    def save_encrypted(self, path: str, passphrase: str):
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        import base64, secrets
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        salt = secrets.token_bytes(16)
        kdf = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1)
        key = kdf.derive(passphrase.encode('utf-8'))
        nonce = secrets.token_bytes(12)
        ct = ChaCha20Poly1305(key).encrypt(nonce, self.to_bytes(), None)
        blob = self.MAGIC_ENC + bytes([15, 8, 1]) + salt + nonce + ct
        with open(path, 'wb') as f:
            f.write(base64.b64encode(blob) + b'\n')

    @classmethod
    def load_encrypted(cls, path: str, passphrase: str) -> 'Identity':
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        import base64
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        with open(path, 'rb') as f:
            blob = base64.b64decode(f.read().strip())
        if blob[:6] != cls.MAGIC_ENC:
            raise ValueError('not an encrypted identity file')
        n_exp, r_exp, p_exp = (blob[6], blob[7], blob[8])
        salt, nonce, ct = (blob[9:25], blob[25:37], blob[37:])
        kdf = Scrypt(salt=salt, length=32, n=1 << n_exp, r=r_exp, p=p_exp)
        key = kdf.derive(passphrase.encode('utf-8'))
        data = ChaCha20Poly1305(key).decrypt(nonce, ct, None)
        return cls.from_bytes(data)

    @classmethod
    def generate(cls) -> 'Identity':
        return cls(x25519.X25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate())

    def export_public(self) -> str:
        import base64
        x_pub = self.x_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ed_pub = self.ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return base64.b64encode(x_pub + ed_pub).decode()

    @staticmethod
    def parse_public(b64: str) -> tuple[bytes, bytes]:
        import base64
        raw = base64.b64decode(b64)
        if len(raw) != 64:
            raise ValueError('bad public key material')
        return (raw[:32], raw[32:])

    def fingerprint(self) -> str:
        import base64, hashlib
        x_pub = self.x_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ed_pub = self.ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        d = hashlib.sha256(x_pub + ed_pub).digest()[:8]
        return base64.b32encode(d).decode().rstrip('=')

def _session_key(shared_secret: bytes, eph_pub: bytes, static_pub: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub + static_pub, info=FS_INFO).derive(shared_secret)

def seal_envelope(data: bytes, sender: Identity, recipient_x_pub: bytes, recipient_ed_pub: bytes) -> bytes:
    eph = x25519.X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ts = replay.timestamp_now()
    shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(recipient_x_pub))
    key = _session_key(shared, eph_pub, recipient_x_pub)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = ChaCha20Poly1305(key).encrypt(nonce, data, None)
    sig = sender.ed_priv.sign(eph_pub + ts + recipient_x_pub + ct)
    return eph_pub + ts + sig + nonce + ct

def open_envelope(blob: bytes, recipient: Identity, sender_x_pub: bytes, sender_ed_pub: bytes, cache: replay.ReplayCache | None=None, max_skew: int=replay.DEFAULT_MAX_SKEW) -> bytes:
    if len(blob) < EPH_PUB_SIZE + 8 + 64 + NONCE_SIZE + 16:
        raise ValueError('envelope too short')
    eph_pub = blob[:32]
    ts = blob[32:40]
    sig = blob[40:104]
    nonce = blob[104:104 + NONCE_SIZE]
    ct = blob[104 + NONCE_SIZE:]
    ed25519.Ed25519PublicKey.from_public_bytes(sender_ed_pub).verify(sig, eph_pub + ts + recipient.x_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) + ct)
    replay.check_timestamp(ts, max_skew)
    if cache is not None:
        cache.check_and_remember(replay.envelope_id(eph_pub, ct))
    shared = recipient.x_priv.exchange(x25519.X25519PublicKey.from_public_bytes(eph_pub))
    key = _session_key(shared, eph_pub, recipient.x_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    return ChaCha20Poly1305(key).decrypt(nonce, ct, None)
