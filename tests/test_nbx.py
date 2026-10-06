import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(*args, cwd=ROOT):
    return subprocess.run(
        [sys.executable, "-m", "nbx.cli", *args],
        cwd=cwd, capture_output=True, text=True, timeout=30,
    )


def test_roundtrip(tmp_path):
    keyfile = tmp_path / "k.key"
    src = tmp_path / "secret.txt"
    packed = tmp_path / "secret.nbx"
    out = tmp_path / "out.txt"
    src.write_bytes(b"top secret \xe4\xb8\xad\xe6\x96\x87 payload" * 100)

    r = run("keygen", "--out", str(keyfile))
    assert r.returncode == 0, r.stderr

    r = run("pack", str(src), str(packed), "--keyfile", str(keyfile),
            '--meta={"title":"demo"}')
    assert r.returncode == 0, r.stderr
    blob = packed.read_bytes()
    assert blob[:8] == b"NBXFILE\x01"          # 魔数
    assert b"top secret" not in blob           # 内容确实被加密

    r = run("unpack", str(packed), str(out), "--keyfile", str(keyfile))
    assert r.returncode == 0, r.stderr
    assert out.read_bytes() == src.read_bytes()  # 还原一致

    # 错误密钥必须解密失败
    bad = tmp_path / "bad.key"
    run("keygen", "--out", str(bad))
    r = run("unpack", str(packed), str(tmp_path / "x"), "--keyfile", str(bad))
    assert r.returncode != 0


def test_network_transfer(tmp_path):
    """v2: convert -> send(自动E2E) -> 接收 -> extract 还原。"""
    keyfile = tmp_path / "k.key"
    src = tmp_path / "file.nbx"
    outdir = tmp_path / "recv"
    run("keygen", "--out", str(keyfile))
    r = run("convert", str(Path(__file__)), str(src), "--encrypt",
            "--keyfile", str(keyfile))
    assert r.returncode == 0, r.stderr

    server = subprocess.Popen(
        [sys.executable, "-m", "nbx.cli", "listen", "9377",
         "--outdir", str(outdir), "--keyfile", str(keyfile)],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        time.sleep(1.0)
        r = run("send", str(src), "127.0.0.1", "9377", "--keyfile", str(keyfile))
        assert r.returncode == 0, r.stderr
        deadline = time.time() + 5
        while time.time() < deadline:
            received = list(outdir.glob("*.nbx"))
            if received:
                restored = tmp_path / "restored"
                r2 = run("extract", str(received[0]), "--outdir", str(restored),
                         "--keyfile", str(keyfile))
                if r2.returncode != 0:
                    time.sleep(0.3)
                    continue
                got = list(restored.iterdir())[0].read_bytes()
                assert got == Path(__file__).read_bytes()
                break
            time.sleep(0.2)
        else:
            raise AssertionError("encrypted file not received")
    finally:
        server.terminate()
        server.wait(timeout=5)
