"""后量子混合密钥交换（NBX-PQ v1）。

策略（与 Chrome TLS / Signal 同类的 hybrid 思路）:
    session_secret = HKDF( X25519_shared || ML-KEM-768_shared )

- 经典侧: X25519 (ECDH) —— 今天安全，防量子攻击者靠 KEM 侧
- 量子侧: ML-KEM-768 (FIPS 203, 原Kyber) —— 抗量子，纯 Python 实现 (vendored kyber-py)
- 两侧共享秘密拼接后经 HKDF 混合: 任何一侧算法被破解，整体仍安全
  （除非两侧同时被破）。安全级别: NIST Category 1+（768 位 Kyber ≈ AES-192 级）

身份: 复用 fskey.Identity 的 X25519 + Ed25519，另加 ML-KEM 静态密钥对。
PQIdentity = X25519(static) + Ed25519(sign) + ML-KEM-768(static)

信封格式（handshake blob）:
    eph_x_pub(32) || kem_ct(1088) || sig(64) || nonce(12) || ct
    sig = Ed25519_sign(sender, eph_x_pub || kem_ct || recipient_x_pub || ct)
"""
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
PQ_INFO = b"nbx-pq-hybrid-session-v1"
X_PUB_SIZE = 32
KEM_CT_SIZE = 1088
SIG_SIZE = 64


def _hkdf_hybrid(x_shared: bytes, kem_shared: bytes,
                 salt: bytes) -> bytes:
    """混合两路共享秘密。"""
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=salt, info=PQ_INFO).derive(x_shared + kem_shared)


class PQIdentity:
    """后量子时代身份：X25519 + Ed25519 + ML-KEM-768。"""

    def __init__(self, x_priv, ed_priv, kem_ek: bytes, kem_dk: bytes):
        self.x_priv = x_priv          # cryptography X25519PrivateKey
        self.ed_priv = ed_priv        # cryptography Ed25519PrivateKey
        self.kem_ek = kem_ek          # ML-KEM encapsulation key (public)
        self.kem_dk = kem_dk          # ML-KEM decapsulation key (secret)

    # ---- 生成 / 序列化 ----
    @classmethod
    def generate(cls) -> "PQIdentity":
        kem_ek, kem_dk = ML_KEM_768.keygen()
        return cls(x25519.X25519PrivateKey.generate(),
                   ed25519.Ed25519PrivateKey.generate(),
                   bytes(kem_ek), bytes(kem_dk))

    def to_bytes(self) -> bytes:
        x = self.x_priv.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        ed = self.ed_priv.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        return x + ed + self.kem_ek + self.kem_dk

    @classmethod
    def from_bytes(cls, data: bytes) -> "PQIdentity":
        x = x25519.X25519PrivateKey.from_private_bytes(data[:32])
        ed = ed25519.Ed25519PrivateKey.from_private_bytes(data[32:64])
        return cls(x, ed, data[64:64 + 1184], data[64 + 1184:64 + 1184 + 2400])

    def save(self, path: str):
        with open(path, "wb") as f:
            f.write(base64.b64encode(self.to_bytes()) + b"\n")

    @classmethod
    def load(cls, path: str) -> "PQIdentity":
        with open(path, "rb") as f:
            return cls.from_bytes(base64.b64decode(f.read().strip()))

    # ---- 公钥导出（X25519 pub + Ed25519 pub + KEM ek，全部定长拼接） ----
    def export_public(self) -> str:
        x_pub = self.x_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ed_pub = self.ed_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return base64.b64encode(x_pub + ed_pub + self.kem_ek).decode()

    @staticmethod
    def parse_public(b64: str) -> tuple[bytes, bytes, bytes]:
        raw = base64.b64decode(b64)
        if len(raw) != 32 + 32 + 1184:
            raise ValueError("bad PQ public key material")
        return raw[:32], raw[32:64], raw[64:]

    def fingerprint(self) -> str:
        import hashlib
        x_pub = self.x_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ed_pub = self.ed_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        d = hashlib.sha256(x_pub + ed_pub + self.kem_ek).digest()[:8]
        return base64.b32encode(d).decode().rstrip("=")


def seal_pq(data: bytes, sender: PQIdentity,
            rec_x_pub: bytes, rec_ed_pub: bytes, rec_kem_ek: bytes) -> bytes:
    """混合后量子信封:
    eph_x_pub(32) || kem_ct(1088) || sig(64) || nonce(12) || ct
    """
    # 经典侧
    eph = x25519.X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    x_shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(rec_x_pub))
    # 量子侧
    kem_shared, kem_ct = ML_KEM_768.encaps(rec_kem_ek)
    kem_shared, kem_ct = bytes(kem_shared), bytes(kem_ct)
    # 混合
    key = _hkdf_hybrid(x_shared, kem_shared, eph_pub + rec_x_pub)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = ChaCha20Poly1305(key).encrypt(nonce, data, None)
    ts = replay.timestamp_now()
    sig = sender.ed_priv.sign(eph_pub + kem_ct + ts + rec_x_pub + ct)
    return eph_pub + kem_ct + ts + sig + nonce + ct


def open_pq(blob: bytes, recipient: PQIdentity,
            snd_x_pub: bytes, snd_ed_pub: bytes,
            cache: "replay.ReplayCache | None" = None,
            max_skew: int = replay.DEFAULT_MAX_SKEW) -> bytes:
    """解封并验签：验签 → 时间窗 → 重放缓存 → 解密。"""
    if len(blob) < X_PUB_SIZE + KEM_CT_SIZE + 8 + SIG_SIZE + NONCE_SIZE + 16:
        raise ValueError("PQ envelope too short")
    p = 0
    eph_pub = blob[p:p + X_PUB_SIZE]; p += X_PUB_SIZE
    kem_ct = blob[p:p + KEM_CT_SIZE]; p += KEM_CT_SIZE
    ts = blob[p:p + 8]; p += 8
    sig = blob[p:p + SIG_SIZE]; p += SIG_SIZE
    nonce = blob[p:p + NONCE_SIZE]; p += NONCE_SIZE
    ct = blob[p:]
    # 验签（发送方 Ed25519，绑定全部握手材料含时间戳）
    my_x_pub = recipient.x_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ed25519.Ed25519PublicKey.from_public_bytes(snd_ed_pub).verify(
        sig, eph_pub + kem_ct + ts + my_x_pub + ct)
    # 重放防护
    replay.check_timestamp(ts, max_skew)
    if cache is not None:
        cache.check_and_remember(replay.envelope_id(eph_pub + kem_ct, ct))
    # 经典侧
    x_shared = recipient.x_priv.exchange(
        x25519.X25519PublicKey.from_public_bytes(eph_pub))
    # 量子侧
    kem_shared = bytes(ML_KEM_768.decaps(recipient.kem_dk, kem_ct))
    key = _hkdf_hybrid(x_shared, kem_shared, eph_pub + my_x_pub)
    return ChaCha20Poly1305(key).decrypt(nonce, ct, None)
