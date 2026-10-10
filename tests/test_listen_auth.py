import base64
import hashlib
import secrets
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from nbx import protocol, transfer
from nbx.transfer import AUTH_NONCE_SIZE, _auth_mac

def _write_keyfile(tmp_path: Path, secret: bytes=b'server-master-key-material-01') -> Path:
    p = tmp_path / 'nbx.key'
    p.write_text(base64.b64encode(secret).decode('ascii'), encoding='utf-8')
    return p

def _read_master(keyfile: Path) -> bytes:
    return base64.b64decode(keyfile.read_text(encoding='utf-8').strip())

def _free_port() -> int:
    s = socket.socket()
    try:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]
    finally:
        s.close()

def _start_listener(outdir: Path, keyfile: Path | None, port: int) -> threading.Thread:
    t = threading.Thread(target=transfer.listen, args=(port, str(outdir), None if keyfile is None else str(keyfile)), daemon=True)
    t.start()
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            socket.create_connection(('127.0.0.1', port), timeout=0.2).close()
            return t
        except OSError:
            threading.Event().wait(0.02)
    raise AssertionError('listener did not come up')

def _empty(d: Path) -> bool:
    return not list(d.glob('*')) if d.exists() else True

def _hello(sock, master: bytes | None) -> tuple:
    """raw 客户端：hello → 收挑战 → 回 MAC（master=None 时回垃圾）"""
    sock.sendall(protocol.hello())
    ftype, challenge = protocol.recv_frame(sock)
    assert ftype == protocol.T_AUTH, f'expected auth challenge, got {ftype}'
    assert len(challenge) == AUTH_NONCE_SIZE
    mac = secrets.token_bytes(32) if master is None else _auth_mac(master, challenge)
    sock.sendall(protocol.frame(protocol.T_AUTH, mac))
    return protocol.recv_frame(sock)

def _decrypt_payload(blob: bytes, master: bytes) -> bytes:
    from nbx import carrier, crypto
    meta, streams, flags = carrier.unpack(blob)
    assert flags & carrier.FLAG_ENCRYPTED, '明文应被主密钥自动加密'
    return crypto.decrypt(streams[0][1], master)

def test_normal_roundtrip_encrypted_and_verified(tmp_path):
    port = _free_port()
    keyfile = _write_keyfile(tmp_path)
    outdir = tmp_path / 'out'
    srv = _start_listener(outdir, keyfile, port)
    src = tmp_path / 'report.txt'
    payload = b'top secret transfer payload\n' * 20
    src.write_bytes(payload)
    result = transfer.send_file(str(src), '127.0.0.1', port, str(keyfile))
    assert 'sent report.txt.nbx' in result
    got = outdir / 'report.txt.nbx'
    assert got.exists(), '服务端应已写入文件'
    assert _decrypt_payload(got.read_bytes(), _read_master(keyfile)) == payload
    assert srv.is_alive()

def test_listener_without_key_refuses_to_start(tmp_path, monkeypatch):
    monkeypatch.delenv('NBX_MASTER_KEY', raising=False)
    port = _free_port()
    outdir = tmp_path / 'out'
    with pytest.raises(SystemExit):
        transfer.listen(port, str(outdir), None)
    s = socket.socket()
    try:
        s.bind(('127.0.0.1', port))
    finally:
        s.close()

def test_wrong_key_is_rejected_and_listener_survives(tmp_path):
    port = _free_port()
    keyfile = _write_keyfile(tmp_path)
    wrong = tmp_path / 'wrong.key'
    wrong.write_text(base64.b64encode(b'attacker-guess').decode('ascii'), encoding='utf-8')
    outdir = tmp_path / 'out'
    srv = _start_listener(outdir, keyfile, port)
    src = tmp_path / 'x.txt'
    src.write_bytes(b'hello')
    with pytest.raises(protocol.ProtocolError, match='not authenticated'):
        transfer.send_file(str(src), '127.0.0.1', port, str(wrong))
    assert not list(outdir.glob('*')) if outdir.exists() else True, '错误密钥不得写入任何文件'
    transfer.send_file(str(src), '127.0.0.1', port, str(keyfile))
    assert (outdir / 'x.txt.nbx').exists()
    assert srv.is_alive(), '认证失败不得打死监听循环'

def test_client_without_key_cannot_authenticate(tmp_path, monkeypatch):
    monkeypatch.delenv('NBX_MASTER_KEY', raising=False)
    port = _free_port()
    keyfile = _write_keyfile(tmp_path)
    srv = _start_listener(tmp_path / 'out', keyfile, port)
    src = tmp_path / 'x.txt'
    src.write_bytes(b'hello')
    with pytest.raises(SystemExit):
        transfer.send_file(str(src), '127.0.0.1', port, None)
    transfer.send_file(str(src), '127.0.0.1', port, str(keyfile))
    assert srv.is_alive()

def test_hello_without_auth_gets_no_go(tmp_path):
    port = _free_port()
    keyfile = _write_keyfile(tmp_path)
    srv = _start_listener(tmp_path / 'out', keyfile, port)
    with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
        sock.sendall(protocol.hello())
        ftype, challenge = protocol.recv_frame(sock)
        assert ftype == protocol.T_AUTH
        sock.sendall(protocol.begin_frame('evil.txt', 3, 65536, 1))
        ftype, payload = protocol.recv_frame(sock)
        assert ftype == protocol.T_ACK and payload != b'GO'
    assert srv.is_alive()

def test_bad_mac_rejected(tmp_path):
    port = _free_port()
    keyfile = _write_keyfile(tmp_path)
    outdir = tmp_path / 'out'
    srv = _start_listener(outdir, keyfile, port)
    with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
        ftype, payload = _hello(sock, None)
        assert payload == b'AUTH FAILED', payload
    assert srv.is_alive()
    assert not list(outdir.glob('*')) if outdir.exists() else True

def test_path_traversal_filename_rejected(tmp_path):
    port = _free_port()
    keyfile = _write_keyfile(tmp_path)
    outdir = tmp_path / 'out'
    srv = _start_listener(outdir, keyfile, port)
    master = _read_master(keyfile)
    with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
        ftype, payload = _hello(sock, master)
        assert payload == b'READY', payload
        sock.sendall(protocol.begin_frame('../../etc/passwd', 4, 65536, 1))
        ftype, payload = protocol.recv_frame(sock)
        assert ftype == protocol.T_ACK
        assert b'REJECTED' in payload, payload
    assert not Path('/etc/passwd').read_bytes() == b'pwned', '不得写出 outdir'
    assert not list(outdir.glob('*')), '拒绝后不得留下空文件'
    assert srv.is_alive(), '拒绝穿越文件名不得打死监听循环'

def test_absolute_and_backslash_filenames_rejected(tmp_path):
    port = _free_port()
    keyfile = _write_keyfile(tmp_path)
    outdir = tmp_path / 'out'
    _start_listener(outdir, keyfile, port)
    master = _read_master(keyfile)
    for bad in ('/etc/cron.d/nbx', 'C:\\Windows\\system32\\evil', '..', '.'):
        with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
            ftype, payload = _hello(sock, master)
            assert payload == b'READY', payload
            sock.sendall(protocol.begin_frame(bad, 4, 65536, 1))
            ftype, payload = protocol.recv_frame(sock)
            assert ftype == protocol.T_ACK and b'REJECTED' in payload, (bad, payload)
    assert not list(outdir.glob('*'))

def test_existing_target_not_overwritten(tmp_path):
    port = _free_port()
    keyfile = _write_keyfile(tmp_path)
    outdir = tmp_path / 'out'
    outdir.mkdir(parents=True)
    victim = outdir / 'dup.txt.nbx'
    victim.write_bytes(b'PRECIOUS DATA (do not clobber)')
    _start_listener(outdir, keyfile, port)
    master = _read_master(keyfile)
    with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
        ftype, payload = _hello(sock, master)
        assert payload == b'READY', payload
        sock.sendall(protocol.begin_frame('dup.txt.nbx', 4, 65536, 1))
        ftype, payload = protocol.recv_frame(sock)
        assert ftype == protocol.T_ACK and b'REJECTED' in payload, payload
    assert victim.read_bytes() == b'PRECIOUS DATA (do not clobber)'

def test_bad_frame_does_not_kill_listener(tmp_path):
    port = _free_port()
    keyfile = _write_keyfile(tmp_path)
    outdir = tmp_path / 'out'
    srv = _start_listener(outdir, keyfile, port)
    master = _read_master(keyfile)
    with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
        ftype, payload = _hello(sock, master)
        assert payload == b'READY', payload
        sock.sendall(b'XX' + b'\x00\x00\x00')
    with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
        ftype, payload = _hello(sock, master)
        assert payload == b'READY', payload
        sock.sendall(protocol.begin_frame('after.txt.nbx', 3, 65536, 1))
        ftype, payload = protocol.recv_frame(sock)
        assert payload == b'GO', payload
        data = b'abc'
        sock.sendall(protocol.chunk_frame(0, data))
        sock.sendall(protocol.end_frame(hashlib.sha256(b'abc').digest()))
        ftype, payload = protocol.recv_frame(sock)
        assert payload == b'VERIFIED', payload
        sock.sendall(protocol.bye())
    assert (outdir / 'after.txt.nbx').read_bytes() == b'abc'
    assert srv.is_alive(), '坏帧后监听循环必须继续'

def test_out_of_order_chunk_does_not_kill_listener(tmp_path):
    port = _free_port()
    keyfile = _write_keyfile(tmp_path)
    outdir = tmp_path / 'out'
    srv = _start_listener(outdir, keyfile, port)
    master = _read_master(keyfile)
    with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
        ftype, payload = _hello(sock, master)
        sock.sendall(protocol.begin_frame('oo.txt.nbx', 2, 65536, 1))
        ftype, payload = protocol.recv_frame(sock)
        assert payload == b'GO', payload
        sock.sendall(protocol.chunk_frame(7, b'ab'))
        # 等服务端处理完并关闭连接（清理半途文件发生在关闭连接之前），消除竞态
        sock.settimeout(5)
        try:
            while sock.recv(4096):
                pass
        except OSError:
            pass
    assert not list(outdir.glob('*')), '序号错乱的半途文件不得残留'
    assert srv.is_alive()
    with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
        ftype, payload = _hello(sock, master)
        assert payload == b'READY', payload
