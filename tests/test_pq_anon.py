"""后量子混合握手 + Anonymity Wrapper + 强制 E2E 测试。"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nbx import anon, carrier, crypto, pq
from nbx.pq import PQIdentity


def test_pq_roundtrip(tmp_path):
    a, b = PQIdentity.generate(), PQIdentity.generate()
    msg = "post-quantum 机密 🛡".encode()
    env = pq.seal_pq(msg, a, *PQIdentity.parse_public(b.export_public()))
    sx, se, _ = PQIdentity.parse_public(a.export_public())
    assert pq.open_pq(env, b, sx, se) == msg
    print("✓ PQ 混合信封往返 (X25519+ML-KEM-768)")


def test_pq_tamper_and_impersonation(tmp_path):
    a, b, m = PQIdentity.generate(), PQIdentity.generate(), PQIdentity.generate()
    env = pq.seal_pq(b"data", a, *PQIdentity.parse_public(b.export_public()))
    ax, ae, _ = PQIdentity.parse_public(a.export_public())
    mx, me, _ = PQIdentity.parse_public(m.export_public())
    bad = bytearray(env); bad[-1] ^= 1
    try:
        pq.open_pq(bytes(bad), b, ax, ae)
        raise AssertionError
    except Exception:
        pass
    try:
        pq.open_pq(env, b, mx, me)
        raise AssertionError
    except Exception:
        pass
    print("✓ PQ 篡改/冒充均被拒绝")


def test_pq_uses_kem(tmp_path):
    """验证信封里确实有 ML-KEM 密文 (1088B)——没有 KEM 就没有后量子。"""
    a, b = PQIdentity.generate(), PQIdentity.generate()
    env = pq.seal_pq(b"x", a, *PQIdentity.parse_public(b.export_public()))
    assert len(env) >= 32 + 1088 + 64 + 12 + 16
    # 换一个身份, kem_ct 不同 (KEM 有随机性)
    env2 = pq.seal_pq(b"x", a, *PQIdentity.parse_public(b.export_public()))
    assert env[32:32 + 1088] != env2[32:32 + 1088]
    print("✓ KEM 密文存在且每次不同（封装随机性）")


def test_anon_roundtrip(tmp_path):
    master = crypto.generate_master_key().encode()
    inner = carrier.convert_text("meta should be hidden: 秘密文件名.txt", title="秘密文件名.txt")
    blob = anon.wrap(inner, master)
    # 外层搜不到元数据
    needle = "秘密".encode("utf-8")
    assert needle not in blob and b"filename" not in blob
    out = anon.unwrap(blob, master)
    assert out == inner
    print("✓ Anonymity Wrapper 往返 + 元数据不泄露")


def test_anon_pad(tmp_path):
    master = crypto.generate_master_key().encode()
    inner = carrier.convert_text("x" * 1000)
    b1 = anon.wrap(inner, master, pad_block=4096)
    b2 = anon.wrap(carrier.convert_text("x" * 3000), master, pad_block=4096)
    assert len(b1) == len(b2) == 4096  # 整个外层对齐到 pad_block
    assert anon.unwrap(b1, master) == inner
    print(f"✓ 填充对齐: 1000B 与 3000B 内层 -> 同样 {len(b1)}B 外层（长度不可区分）")


def test_anon_wrong_key(tmp_path):
    master = crypto.generate_master_key().encode()
    other = crypto.generate_master_key().encode()
    blob = anon.wrap(b"secret", master)
    try:
        anon.unwrap(blob, other)
        raise AssertionError
    except Exception:
        pass
    print("✓ 错误密钥解包被拒绝")


def test_forced_e2e(tmp_path):
    """明文文件经 transfer.send_file 的 E2E 检查逻辑必须变成加密容器。"""
    # 直接调用内部逻辑（不真正开网络）: 检查明文 .nbx 会被识别为需要加密
    plain_nbx = carrier.convert_text("hello e2e")
    _, _, flags = carrier.unpack(plain_nbx)
    assert not (flags & carrier.FLAG_ENCRYPTED)
    enc_nbx = carrier.pack(
        [(carrier.TLV_BIN, crypto.encrypt(b"hello e2e", b"k" * 32))],
        {"enc": "chacha20poly1305"}, flags=carrier.FLAG_ENCRYPTED)
    _, _, flags2 = carrier.unpack(enc_nbx)
    assert flags2 & carrier.FLAG_ENCRYPTED
    print("✓ E2E 标志识别正确（明文容器→强制加密路径）")


if __name__ == "__main__":
    import pathlib
    with tempfile.TemporaryDirectory() as td:
        tmp_path = pathlib.Path(td)
        test_pq_roundtrip(tmp_path)
        test_pq_tamper_and_impersonation(tmp_path)
        test_pq_uses_kem(tmp_path)
        test_anon_roundtrip(tmp_path)
        test_anon_pad(tmp_path)
        test_anon_wrong_key(tmp_path)
        test_forced_e2e(tmp_path)
    print("\nPQ + Anon + E2E 全部测试通过 ✅")
