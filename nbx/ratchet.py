"""NBX Double Ratchet v1（nbx/ratchet.py）— IM 会话加密核心。

参考 Signal Double Ratchet。关键组件：

- 根链 RK：HKDF 迭代，KDF_RK(rk, dh_out) = HKDF(ikm=dh_out, salt=rk)。
- 发送/接收链 CK：每发/收一条消息推进一次
  KDF_CK(ck) -> (next_ck, message_key)，消息密钥用后即焚 → 逐消息前向保密。
- DH ratchet：每次发现对方换了 ratchet 公钥，用新的 DH 输出更新根链并开新链
  → 被攻破链的恢复（post-compromise security）。

会话建立（对称双临时密钥）：
  Alice 生成 E_a，Bob 生成 E_b，双方交换（需经认证信道，外壳用 FS 信封）。
  SK = HKDF(DH(E_a,E_b), salt=E_a_pub||E_b_pub, info=NBX_RATCHET_V1, 64B)
  RK=SK[:32]；初始链 CK0=SK[32:]
  Alice: DHs=E_a, DHr=E_b, send_ck=CK0
  Bob:   DHs=E_b, DHr=E_a, recv_ck=CK0
  → Alice 首条消息头部 ratchet_pub=E_a_pub，与 Bob 的 DHr 相同，不触发 step；
    Bob 首次回信才真正做 DH ratchet（换新 DHs），此后交替。

头部（40B，明文可见、作 AEAD 的 AAD）：
  ratchet_pub(32) || prev_chain_len(4) || msg_no(4)
  prev_chain_len：上一条链发了多少条，供收方补齐 skipped keys。

报文：header(40) || nonce(12) || ChaCha20-Poly1305 密文（AAD = MAGIC||header）。

安全性质：逐消息前向保密、收到新 ratchet 公钥即恢复、乱序容忍（skipped 键上限）。
已知边界（见 SPEC）：初始认证靠 Ed25519 签名 + TOFU 指纹核对；DH step 用 X25519，
不含 PQ（PQ 会话在信封层叠加）。
"""
from __future__ import annotations

import secrets
import struct
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .fskey import Identity

MAGIC_RATCHET = b"NBXRATCH1"
MAGIC_STATE = b"NBXRATCHST1"
HEADER_SIZE = 40
NONCE_SIZE = 12
MAX_SKIP = 256
HANDSHAKE_SIZE = 9 + 8 + 8 + 32 + 8 + 64   # magic + sender_fp + recv_fp + eph_pub + ts + sig
HANDSHAKE_MAX_AGE = 120.0          # 握手时效（秒）：超龄=上一代会话残留，拒绝


class HandshakeStale(Exception):
    """握手信封超出时效窗口——上一代会话的残留，须丢弃并继续等待最新握手。"""


def handshake_age(hs: bytes) -> float:
    """握手载荷的时间戳距今秒数（负数=来自未来，允许时钟小偏差）。"""
    if len(hs) != HANDSHAKE_SIZE or hs[:9] != MAGIC_RATCHET:
        raise ValueError("bad handshake payload")
    return time.time() - struct.unpack("<Q", hs[57:65])[0]

INFO_ROOT = b"nbx-ratchet-root-v1"
INFO_CHAIN = b"nbx-ratchet-chain-v1"
INFO_HANDSHAKE = b"nbx-ratchet-handshake-v1"


def _kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    """链密钥推进: ck -> (next_ck, message_key)。"""
    okm = HKDF(algorithm=hashes.SHA256(), length=64,
               salt=b"", info=INFO_CHAIN).derive(ck)
    return okm[:32], okm[32:]


def _kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """根链推进: (rk, dh_out) -> (new_rk, chain_key)。"""
    okm = HKDF(algorithm=hashes.SHA256(), length=64,
               salt=rk, info=INFO_ROOT).derive(dh_out)
    return okm[:32], okm[32:]


def _dh(priv: x25519.X25519PrivateKey, pub: bytes) -> bytes:
    return priv.exchange(x25519.X25519PublicKey.from_public_bytes(pub))


def _raw_pub(priv: x25519.X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def pack_header(ratchet_pub: bytes, prev_len: int, msg_no: int) -> bytes:
    return ratchet_pub + struct.pack("<II", prev_len, msg_no)


def unpack_header(hdr: bytes) -> tuple[bytes, int, int]:
    if len(hdr) != HEADER_SIZE:
        raise ValueError("bad ratchet header")
    return hdr[:32], struct.unpack("<I", hdr[32:36])[0], struct.unpack("<I", hdr[36:40])[0]


def make_handshake(identity: Identity, eph_pub: bytes,
                   sender_fp: bytes = b"\x00" * 8,
                   recv_fp: bytes = b"\x00" * 8) -> bytes:
    """握手 v2（audit R-05）：签名绑定路由头。

    MAGIC || sender_fp(8) || recv_fp(8) || eph_pub || ts(8) || sig，
    sig = Ed25519_sign(MAGIC || sender_fp || recv_fp || eph_pub || ts)。
    绑定收发双方指纹后，"Bob→Carol 的合法握手被投给 Alice"的反射
    攻击不再成立：Alice 校验 recv_fp==自己 即拒收。
    """
    ts = struct.pack("<Q", int(time.time()))
    sig = identity.ed_priv.sign(
        MAGIC_RATCHET + sender_fp + recv_fp + eph_pub + ts)
    return MAGIC_RATCHET + sender_fp + recv_fp + eph_pub + ts + sig


def verify_handshake(peer_ed_pub: bytes, hs: bytes,
                     max_age: float = HANDSHAKE_MAX_AGE,
                     expect_sender_fp: bytes | None = None,
                     expect_recv_fp: bytes | None = None) -> bytes:
    """验签并返回对端临时公钥；签名绑定路由指纹 + eph_pub + 时间戳。

    expect_sender_fp/expect_recv_fp（audit R-05）：提供时校验载荷中的
    路由指纹——接收端必须确认"这条握手是发给我的、来自我认识的对方"，
    否则不同会话的握手可被反射/重定向到任意桶。
    max_age：握手时间戳的最大有效期（秒）。0 表示不做时效检查（仅测试）。
    """
    if len(hs) != HANDSHAKE_SIZE or hs[:9] != MAGIC_RATCHET:
        raise ValueError("bad handshake payload")
    sender_fp, recv_fp = hs[9:17], hs[17:25]
    eph_pub, ts, sig = hs[25:57], hs[57:65], hs[65:129]
    if expect_sender_fp is not None and sender_fp != expect_sender_fp:
        raise ValueError("handshake sender_fp mismatch")
    if expect_recv_fp is not None and recv_fp != expect_recv_fp:
        raise ValueError("handshake recv_fp mismatch (not addressed to us)")
    ed25519.Ed25519PublicKey.from_public_bytes(peer_ed_pub).verify(
        sig, MAGIC_RATCHET + sender_fp + recv_fp + eph_pub + ts)
    if max_age > 0:
        age = time.time() - struct.unpack("<Q", ts)[0]
        if age > max_age or age < -max_age:      # 过龄或来自过远的未来都拒
            raise HandshakeStale(f"handshake age {age:.0f}s outside ±{max_age:.0f}s")
    return eph_pub


def _state_integrity_tag(root_key: bytes, blob: bytes) -> bytes:
    """状态序列化的完整性标签（非机密性）。

    HKDF(ikm=root_key, info=MAGIC_STATE) 派生 16B tag 绑定整个 TLV
    序列：检测落盘损坏、截断与"拿错会话状态文件"。root_key 本身是
    秘密，tag 不新增攻击面。防恶意回滚需外部单调 epoch 存储（daemon 层）。
    """
    return HKDF(algorithm=hashes.SHA256(), length=16, salt=None,
                info=MAGIC_STATE + b"state-integrity").derive(root_key)


class RatchetSession:
    """一条双向加密会话。"""

    def __init__(self):
        self._root_key: bytes = b""
        self._send_ck: bytes | None = None
        self._recv_ck: bytes | None = None
        self._send_n = 0
        self._recv_n = 0
        self._prev_send_len = 0
        self._dh_self: x25519.X25519PrivateKey | None = None
        self._dh_remote_pub: bytes = b""
        self._skipped: dict[tuple[bytes, int], bytes] = {}
        self._established = False

    # ---------- 建立（两阶段，双方交换临时密钥） ----------

    def begin(self, my_id: Identity, sender_fp: bytes | None = None,
              recv_fp: bytes | None = None) -> bytes:
        """阶段一：生成本方临时密钥并返回握手载荷。双方都调用。

        sender_fp/recv_fp（audit R-05）：路由指纹绑进签名。缺省为
        8 字节零值（格式固定 129B，兼容无指纹上下文的裸 ratchet 测试）；
        正式通道必须显式传入真实指纹。
        """
        if sender_fp is None:
            sender_fp = b"\x00" * 8
        if recv_fp is None:
            recv_fp = b"\x00" * 8
        self._eph = x25519.X25519PrivateKey.generate()
        self._eph_pub = _raw_pub(self._eph)
        self._hs_sender_fp = sender_fp
        self._hs_recv_fp = recv_fp
        return make_handshake(my_id, self._eph_pub, sender_fp, recv_fp)

    def finish(self, my_id: Identity, peer_ed_pub: bytes, peer_hs: bytes,
               speaks_first: bool, expect_sender_fp: bytes | None = None,
               expect_recv_fp: bytes | None = None):
        """阶段二：验对方载荷 → 派生 SK → 初始化链。

        speaks_first：本方是否先发消息。两方必须恰好一方为 True——
        初始链 CK0 只能单向使用（避免同一链密钥双向密钥重用），
        先发方持发送链，后发方持接收链；后发方首次发送时 DH ratchet 换新链。
        expect_sender_fp/expect_recv_fp（audit R-05）：校验握手路由头，
        确认握手来自预期对端且是发给本方的。
        """
        peer_eph_pub = verify_handshake(peer_ed_pub, peer_hs,
                                        expect_sender_fp=expect_sender_fp,
                                        expect_recv_fp=expect_recv_fp)
        dh_shared = _dh(self._eph, peer_eph_pub)
        # salt 按字典序拼接，保证双方派生出同一 SK
        lo, hi = sorted((self._eph_pub, peer_eph_pub))
        sk = HKDF(algorithm=hashes.SHA256(), length=64,
                  salt=lo + hi,
                  info=INFO_HANDSHAKE).derive(dh_shared)
        self._root_key, ck0 = sk[:32], sk[32:]
        # 初始 ratchet 公钥用各自临时密钥，保证首条消息不触发多余 step
        self._dh_self = self._eph
        self._dh_self_pub = self._eph_pub
        self._dh_remote_pub = peer_eph_pub
        if speaks_first:
            self._send_ck, self._recv_ck = ck0, None
        else:
            self._send_ck, self._recv_ck = None, ck0
        self._established = True
        return self

    # ---------- 会话状态持久化（M2.5a：通讯录/会话简历的地基） ----------

    def export_state(self) -> bytes:
        """序列化会话状态（敏感！等同长期私钥，落盘须加密，如 anon包装）。

        格式: MAGIC_STATE(12) || ver(1) || fields TLV:
          1 root_key(32)  2 send_ck(32 或空)  3 recv_ck(32 或空)
          4 dh_self_priv(32)  5 dh_remote_pub(32)  6 skipped entries
          7 counters(prev_send_len, send_n, recv_n 各 4B LE)
        skipped entry: ratchet_pub(32) || msg_no(4) || mk(32)
        """
        import base64 as _b64
        if not self._established or self._dh_self is None:
            raise RuntimeError("session not established")
        def f(t: int, v: bytes) -> bytes:
            return bytes([t]) + struct.pack("<I", len(v)) + v
        out = MAGIC_STATE + bytes([1])   # magic 11B + ver
        out += f(1, self._root_key)
        out += f(2, self._send_ck or b"")
        out += f(3, self._recv_ck or b"")
        out += f(4, self._dh_self.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()))
        out += f(5, self._dh_remote_pub)
        sk_blob = b"".join(
            pub + struct.pack("<I", no) + mk
            for (pub, no), mk in self._skipped.items())
        out += f(6, sk_blob)
        counters = struct.pack("<III", self._prev_send_len, self._send_n, self._recv_n)
        out += f(7, counters)
        # 完整性校验（audit ⑤ 防篡改/损坏）：HKDF 以 root_key 为输入信息
        # 派生 tag——不是 MAC 密钥，不增加安全性，但能检测落盘损坏/
        # 意外混入的其他会话状态。真正的防回滚需要持久化 epoch 序号
        # + 单调存储（M3 daemon 层处理）。
        tag = _state_integrity_tag(self._root_key, out)
        out += f(8, tag)
        return _b64.b64encode(out)

    @classmethod
    def import_state(cls, blob: bytes) -> "RatchetSession":
        """从 export_state 恢复会话。"""
        import base64 as _b64
        raw = _b64.b64decode(blob)
        mlen = len(MAGIC_STATE)
        if raw[:mlen] != MAGIC_STATE or raw[mlen] != 1:
            raise ValueError("bad ratchet state blob")
        s = cls()
        off = mlen + 1
        fields = {}
        while off < len(raw):
            t = raw[off]
            ln = struct.unpack("<I", raw[off + 1:off + 5])[0]
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
            pub, no = sk_blob[po:po + 32], struct.unpack("<I", sk_blob[po + 32:po + 36])[0]
            s._skipped[(pub, no)] = sk_blob[po + 36:po + 68]
            po += 68
        s._prev_send_len, s._send_n, s._recv_n = struct.unpack("<III", fields[7])
        # 完整性校验（audit ⑤）：tag 必须与 root_key 绑定的 TLV 序列一致
        if 8 not in fields or len(fields[8]) != 16:
            raise ValueError("ratchet state missing integrity tag")
        body = raw[:raw.rfind(bytes([8]) + struct.pack("<I", 16))]
        if _state_integrity_tag(s._root_key, body) != fields[8]:
            raise ValueError("ratchet state integrity check failed "
                             "(corrupted or foreign state file)")
        s._established = True
        return s

    # ---------- 收发 ----------

    def _snapshot(self) -> tuple:
        """捕获可变状态（供认证失败时回滚）。

        安全要求（Signal spec）：任何未经认证的输入都不得永久改变
        会话状态——否则攻击者一个垃圾包即可 DoS（状态被污染后，
        对端合法消息再也解不开）。decrypt 先在快照上推进，AEAD 成功
        才提交。
        """
        return (self._root_key, self._send_ck, self._recv_ck,
                self._send_n, self._recv_n, self._prev_send_len,
                self._dh_self, self._dh_self_pub, self._dh_remote_pub,
                dict(self._skipped))

    def _restore(self, snap: tuple) -> None:
        (self._root_key, self._send_ck, self._recv_ck,
         self._send_n, self._recv_n, self._prev_send_len,
         self._dh_self, self._dh_self_pub, self._dh_remote_pub,
         self._skipped) = snap

    def _recv_step(self, remote_pub: bytes, prev_len: int):
        """收到对方新 ratchet 公钥：接收链 DH step。"""
        assert self._dh_self is not None, "session not established"
        if self._recv_ck is not None and self._dh_remote_pub:
            self._skip_to(self._dh_remote_pub, prev_len)
        shared = _dh(self._dh_self, remote_pub)
        self._root_key, self._recv_ck = _kdf_rk(self._root_key, shared)
        self._recv_n = 0
        self._dh_remote_pub = remote_pub

    def _send_step(self):
        """发送侧 DH step：生成本方新 ratchet 密钥并派生新发送链。"""
        assert self._dh_remote_pub, "no remote ratchet key"
        self._prev_send_len = self._send_n
        self._dh_self = x25519.X25519PrivateKey.generate()
        self._dh_self_pub = _raw_pub(self._dh_self)
        shared_s = _dh(self._dh_self, self._dh_remote_pub)
        self._root_key, self._send_ck = _kdf_rk(self._root_key, shared_s)
        self._send_n = 0

    def _skip_to(self, ratchet_pub: bytes, until: int):
        """推进收链到 until，中间消息密钥存入 skipped。

        上限 MAX_SKIP：until 来自报文头（未认证的 uint32），必须与
        msg_no 跳跃同样受限，否则攻击者可构造 prev_len=0xffffffff
        诱发数十亿次 KDF（资源耗尽 DoS）。
        """
        if self._recv_ck is None:
            return
        if until - self._recv_n > MAX_SKIP:
            raise ValueError("too many skipped messages")
        while self._recv_n < until:
            self._recv_ck, mk = _kdf_ck(self._recv_ck)
            self._skipped[(ratchet_pub, self._recv_n)] = mk
            self._recv_n += 1

    def encrypt(self, plaintext: bytes, outer_aad: bytes = b"") -> bytes:
        """加密一条消息 → header(40) || nonce(12) || ct。

        outer_aad（audit 补充项）：外层消息信封的路由头，与本层
        ratchet 头一起纳入 AEAD 认证——防止密文被搬到不同路由头的
        信封里重放（头本身明文，不认证则可被中继/攻击者重写）。
        """
        if not self._established:
            raise RuntimeError("session not established")
        if self._send_ck is None:
            # 后发言方首次发送：只做发送侧 DH step（其接收链 CK0 不动）
            self._send_step()
        assert self._send_ck is not None
        self._send_ck, mk = _kdf_ck(self._send_ck)
        nonce = secrets.token_bytes(NONCE_SIZE)
        hdr = pack_header(self._dh_self_pub, self._prev_send_len, self._send_n)
        ct = ChaCha20Poly1305(mk).encrypt(
            nonce, plaintext, MAGIC_RATCHET + hdr + outer_aad)
        self._send_n += 1
        return hdr + nonce + ct

    def decrypt(self, blob: bytes, outer_aad: bytes = b"") -> bytes:
        """解密一条消息（容忍乱序，skipped 键上限 MAX_SKIP）。

        outer_aad：外层信封路由头，须与加密时一致（audit 补充项）。
        事务式状态更新（Signal spec："如果消息认证失败，对 state 的
        修改必须被丢弃"）：ratchet 推进全部发生在快照上，AEAD 认证
        成功才提交；失败则回滚——攻击者伪造/篡改的报文无法污染会话
        状态，后续合法消息不受影响。
        """
        if not self._established:
            raise RuntimeError("session not established")
        if len(blob) < HEADER_SIZE + NONCE_SIZE + 16:
            raise ValueError("message too short")
        hdr = blob[:HEADER_SIZE]
        nonce = blob[HEADER_SIZE:HEADER_SIZE + NONCE_SIZE]
        ct = blob[HEADER_SIZE + NONCE_SIZE:]
        ratchet_pub, prev_len, msg_no = unpack_header(hdr)
        aad = MAGIC_RATCHET + hdr + outer_aad

        snap = self._snapshot()
        try:
            # 1) skipped 命中（乱序补上）——pop 只发生在快照副本上，
            #    认证失败时副本丢弃，密钥不丢：篡改的乱序消息无法
            #    永久毁掉真正的消息（④ 的修复）
            skipped = dict(self._skipped)
            mk = skipped.pop((ratchet_pub, msg_no), None)
            if mk is not None:
                pt = ChaCha20Poly1305(mk).decrypt(nonce, ct, aad)
                self._skipped = skipped
                return pt

            # 2) 对方换了 ratchet 公钥 → 接收链 DH step
            if ratchet_pub != self._dh_remote_pub:
                self._recv_step(ratchet_pub, prev_len)

            # 3) 推进收链到 msg_no，中间密钥记为 skipped
            if self._recv_ck is None:
                raise ValueError("no receiving chain")
            if msg_no < self._recv_n:
                raise ValueError("message already processed")
            if msg_no - self._recv_n > MAX_SKIP:
                raise ValueError("too many skipped messages")
            self._skip_to(ratchet_pub, msg_no)
            self._recv_ck, mk = _kdf_ck(self._recv_ck)
            self._recv_n += 1
            pt = ChaCha20Poly1305(mk).decrypt(nonce, ct, aad)
            return pt
        except Exception:
            self._restore(snap)      # 认证失败：状态原子回滚（①③ 的修复）
            raise

    @property
    def send_ratchet_pub(self) -> bytes:
        return self._dh_self_pub

    @property
    def skipped_count(self) -> int:
        return len(self._skipped)
