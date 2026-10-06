"""NBX v2 通用载体转换器测试。"""
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nbx import carrier, crypto


def test_text_roundtrip():
    blob = carrier.convert_text("你好，世界！Hello NBX v2 中文测试 🚀\n", title="hello.txt")
    meta, streams, flags = carrier.unpack(blob)
    assert meta["type"] == "text"
    assert streams[0][1].decode("utf-8") == "你好，世界！Hello NBX v2 中文测试 🚀\n"
    assert flags & carrier.FLAG_MULTIPART == 0
    print("✓ 文本 roundtrip")


def test_file_conversion(tmp):
    # 纯文本
    f = tmp / "note.txt"; f.write_text("plain note", encoding="utf-8")
    meta, streams, _ = carrier.unpack(carrier.convert(f))
    assert meta["type"] == "text" and streams[0][1] == b"plain note"
    # HTML
    f = tmp / "page.html"; f.write_text("<h1>Hi</h1>", encoding="utf-8")
    meta, _, _ = carrier.unpack(carrier.convert(f))
    assert meta["type"] == "html"
    # PNG 魔数
    f = tmp / "img.png"; f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    meta, _, _ = carrier.unpack(carrier.convert(f))
    assert meta["type"] == "binary" and meta["mime"] == "image/png"
    # 未知二进制
    f = tmp / "data.bin"; f.write_bytes(bytes(range(256)))
    meta, _, _ = carrier.unpack(carrier.convert(f))
    assert meta["type"] == "binary" and meta["mime"] == "application/octet-stream"
    print("✓ 文件类型嗅探 (txt/html/png/bin)")


def test_extract_lossless(tmp):
    src = tmp / "orig.md"
    src.write_text("# 标题\n\n内容 body。\n", encoding="utf-8")
    blob = carrier.convert(src)
    (name, content), = carrier.extract(blob)
    assert name == "orig.md"
    assert content == src.read_bytes()  # 无损
    print("✓ 无损还原")


def test_bundle(tmp):
    a = tmp / "a.txt"; a.write_text("file a")
    b = tmp / "b.png"; b.write_bytes(b"\x89PNG\r\n\x1a\nIMGDATA")
    blob = carrier.convert_bundle([a, b], main_name="pack.nbx")
    meta, streams, flags = carrier.unpack(blob)
    assert meta["type"] == "bundle" and flags & carrier.FLAG_MULTIPART
    assert len(streams) == 2
    restored = carrier.extract(blob)
    assert restored[0] == ("a.txt", b"file a")
    assert restored[1] == ("b.png", b"\x89PNG\r\n\x1a\nIMGDATA")
    print("✓ 多文件 bundle")


def test_encrypted_carrier(tmp):
    master = crypto.generate_master_key().encode()
    secret = tmp / "secret.txt"
    secret.write_text("top secret 内容", encoding="utf-8")
    blob = carrier.convert(str(secret))
    meta, streams, flags = carrier.unpack(blob)
    enc = crypto.encrypt(carrier._build_payload(streams), master)
    meta["enc"] = "chacha20poly1305"
    enc_blob = carrier.pack([(carrier.TLV_BIN, enc)], meta, flags=carrier.FLAG_ENCRYPTED)
    # 密文中搜不到明文
    assert b"top secret" not in enc_blob
    # 解密还原
    m2, s2, f2 = carrier.unpack(enc_blob)
    assert f2 & carrier.FLAG_ENCRYPTED
    payload = crypto.decrypt(s2[0][1], master)
    assert b"top secret" in payload
    print("✓ 加密载体（密文无明文泄露 + 可解密还原）")


def test_corruption():
    blob = bytearray(carrier.convert_text("integrity"))
    blob[-1] ^= 0xFF  # 破坏校验和
    try:
        carrier.unpack(bytes(blob))
        raise AssertionError("should have raised")
    except carrier.NBXError as e:
        assert "checksum" in str(e)
    print("✓ 篡改检测")


if __name__ == "__main__":
    import pathlib
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        test_text_roundtrip()
        test_file_conversion(tmp)
        test_extract_lossless(tmp)
        test_bundle(tmp)
        test_encrypted_carrier(tmp)
        test_corruption()
    print("\n全部测试通过 ✅")
