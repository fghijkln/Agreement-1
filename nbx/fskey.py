"""前向保密会话密钥协商（NBX-FS v1）。

设计：
- 每个身份持有长期的 X25519 静态密钥对（身份密钥）+ Ed25519 签名密钥对
- 每次发送：
    1. 生成一次性 X25519 临时密钥对 (ephemeral)
    2. 共享秘密 = X25519(ephemeral_priv, recipient_static_pub)
       （接收端同样算出 X25519(static_priv, ephemeral_pub)）
    3. HKDF(shared_secret, salt=both_pubkeys) -> 会话密钥
    4. 发送方用 Ed25519 对 (ephemeral_pub || ciphertext 相关信息) 签名，
       接收端用发送方公钥验签 → 认证 + 防 MITM
- 前向保密来源：临时私钥用后即焚。若日后静态身份密钥泄露，
  过去的会话密钥也无法恢复（差一个已销毁的临时私钥）。

信封格式（sealed envelope, 常量长度头便于解析）:
  eph_pub(32) || nonce(12) || ct  →  外面再套 Ed25519 签名
"""
from __future__ import annotations

import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import replay

NONCE_SIZE = 12
FS_INFO = b"nbx-fs-session-key-v1"
EPH_PUB_SIZE = 32


# ---------- 身份密钥对（长期） ----------

class Identity:
    """一对 X25519(密钥协商) + Ed25519(签名) 静态身份密钥。"""

    def __init__(self, x_priv: x25519.X25519PrivateKey,
                 ed_priv: ed25519.Ed25519PrivateKey):
        self.x_priv = x_priv
        self.ed_priv = ed_priv

    # ---- 序列化（存文件用） ----
    def to_bytes(self) -> bytes:
        def _raw(key) -> bytes:
            return key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption())
        return _raw(self.x_priv) + _raw(self.ed_priv)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Identity":
        return cls(x25519.X25519PrivateKey.from_private_bytes(data[:32]),
                   ed25519.Ed25519PrivateKey.from_private_bytes(data[32:64]))

    def save(self, path: str):
        import base64
        with open(path, "w", encoding="utf-8") as f:
            f.write(base64.b64encode(self.to_bytes()).decode() + "\n")

    @classmethod
    def load(cls, path: str) -> "Identity":
        import base64
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_bytes(base64.b64decode(f.read().strip()))

    @classmethod
    def generate(cls) -> "Identity":
        return cls(x25519.X25519PrivateKey.generate(),
                   ed25519.Ed25519PrivateKey.generate())

    # ---- 公钥导出（分发给对方，Base64） ----
    def export_public(self) -> str:
        import base64
        x_pub = self.x_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ed_pub = self.ed_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return base64.b64encode(x_pub + ed_pub).decode()

    @staticmethod
    def parse_public(b64: str) -> tuple[bytes, bytes]:
        import base64
        raw = base64.b64decode(b64)
        if len(raw) != 64:
            raise ValueError("bad public key material")
        return raw[:32], raw[32:]

    # ---- 身份指纹（方便人工核对防 MITM） ----
    def fingerprint(self) -> str:
        import base64, hashlib
        x_pub = self.x_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ed_pub = self.ed_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        d = hashlib.sha256(x_pub + ed_pub).digest()[:8]
        return base64.b32encode(d).decode().rstrip("=")


# ---------- 信封加密 / 解密 ----------

def _session_key(shared_secret: bytes, eph_pub: bytes, static_pub: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=eph_pub + static_pub, info=FS_INFO).derive(shared_secret)


def seal_envelope(data: bytes, sender: Identity,
                  recipient_x_pub: bytes, recipient_ed_pub: bytes) -> bytes:
    """加密成前向保密信封（含重放防护）:
    返回 eph_pub(32) || ts(8) || sig(64) || nonce(12) || ct
    sig = Ed25519_sign(sender, eph_pub || ts || recipient_x_pub || ct)
    """
    eph = x25519.X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ts = replay.timestamp_now()
    shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(recipient_x_pub))
    key = _session_key(shared, eph_pub, recipient_x_pub)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = ChaCha20Poly1305(key).encrypt(nonce, data, None)
    sig = sender.ed_priv.sign(eph_pub + ts + recipient_x_pub + ct)
    return eph_pub + ts + sig + nonce + ct

def open_envelope(blob: bytes, recipient: Identity,
                  sender_x_pub: bytes, sender_ed_pub: bytes,
                  cache: replay.ReplayCache | None = None,
                  max_skew: int = replay.DEFAULT_MAX_SKEW) -> bytes:
    """解密信封：验签 → 时间窗 → 重放缓存 → 解密。任一不过即拒绝。"""
    if len(blob) < EPH_PUB_SIZE + 8 + 64 + NONCE_SIZE + 16:
        raise ValueError("envelope too short")
    eph_pub = blob[:32]
    ts = blob[32:40]
    sig = blob[40:104]
    nonce = blob[104:104 + NONCE_SIZE]
    ct = blob[104 + NONCE_SIZE:]
    # 验签：必须由持有 sender_ed 私钥的人签发（绑定 eph_pub + 时间戳 + 收件人公钥 + 密文）
    ed25519.Ed25519PublicKey.from_public_bytes(sender_ed_pub).verify(
        sig, eph_pub + ts + recipient.x_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw) + ct)
    # 重放防护：时间窗 + 缓存
    replay.check_timestamp(ts, max_skew)
    if cache is not None:
        cache.check_and_remember(replay.envelope_id(eph_pub, ct))
    shared = recipient.x_priv.exchange(
        x25519.X25519PublicKey.from_public_bytes(eph_pub))
    # salt 必须与加密端一致: eph_pub + 接收方静态公钥
    key = _session_key(shared, eph_pub,
                       recipient.x_priv.public_key().public_bytes(
                           serialization.Encoding.Raw,
                           serialization.PublicFormat.Raw))
    return ChaCha20Poly1305(key).decrypt(nonce, ct, None)
