from __future__ import annotations
import base64
import hashlib
import hmac
import os
import secrets
import socket
import time
from . import protocol
CHUNK = protocol.DEFAULT_CHUNK
AUTH_NONCE_SIZE = 32
AUTH_MAC_SIZE = 32

def _load_master_key(keyfile: str | None) -> bytes:
    env = os.environ.get('NBX_MASTER_KEY')
    if keyfile:
        with open(keyfile, 'r', encoding='utf-8') as f:
            return base64.b64decode(f.read().strip())
    if env:
        return base64.b64decode(env)
    raise SystemExit('no master key: use --keyfile or NBX_MASTER_KEY')

def _auth_mac(master: bytes, nonce: bytes) -> bytes:
    return hmac.new(master, nonce, hashlib.sha256).digest()

def _safe_target(outdir: str, name: str) -> str:
    if not name or name in ('.', '..') or '/' in name or '\\' in name or os.path.isabs(name):
        raise protocol.ProtocolError(f'unsafe filename rejected: {name!r}')
    path = os.path.join(outdir, name)
    if os.path.exists(path):
        raise protocol.ProtocolError(f'target exists, refusing to overwrite: {path}')
    return path

def _serve_transfer(conn, addr, outdir: str, master: bytes) -> None:
    ftype, payload = protocol.recv_frame(conn)
    if ftype != protocol.T_HELLO or payload != protocol.PROTO_NAME:
        conn.sendall(protocol.ack('BAD HELLO'))
        return
    nonce = secrets.token_bytes(AUTH_NONCE_SIZE)
    conn.sendall(protocol.frame(protocol.T_AUTH, nonce))
    ftype, payload = protocol.recv_frame(conn)
    if ftype != protocol.T_AUTH or len(payload) != AUTH_MAC_SIZE:
        conn.sendall(protocol.ack('BAD AUTH'))
        return
    if not hmac.compare_digest(payload, _auth_mac(master, nonce)):
        conn.sendall(protocol.ack('AUTH FAILED'))
        return
    conn.sendall(protocol.ack('READY'))
    ftype, payload = protocol.recv_frame(conn)
    if ftype != protocol.T_BEGIN:
        conn.sendall(protocol.ack('EXPECTED BEGIN'))
        return
    name, total, chunk_size, total_chunks = protocol.parse_begin(payload)
    try:
        path = _safe_target(outdir, name)
    except protocol.ProtocolError as e:
        conn.sendall(protocol.ack(f'REJECTED: {e}'))
        return
    conn.sendall(protocol.ack('GO'))
    h = hashlib.sha256()
    received = 0
    t0 = time.time()
    try:
        with open(path, 'wb') as out:
            seq_expect = 0
            while True:
                ftype, payload = protocol.recv_frame(conn)
                if ftype == protocol.T_CHUNK:
                    seq, data = protocol.parse_chunk(payload)
                    if seq != seq_expect:
                        raise protocol.ProtocolError(f'chunk out of order: got {seq}, want {seq_expect}')
                    seq_expect += 1
                    out.write(data)
                    h.update(data)
                    received += len(data)
                    pct = received * 100 // total if total else 100
                    print(f'\r[nbx] {addr[0]} -> {name} {pct}% ({received}/{total})', end='', flush=True)
                elif ftype == protocol.T_END:
                    break
                else:
                    raise protocol.ProtocolError(f'unexpected frame {ftype}')
    except BaseException:
        try:
            os.remove(path)
        except OSError:
            pass
        print(f'\n[nbx] aborted from {addr}, discarded partial {name}')
        raise
    if h.digest() != payload:
        conn.sendall(protocol.ack('CHECKSUM FAIL'))
        os.remove(path)
        print(f'\n[nbx] checksum FAILED from {addr}, discarded {name}')
        return
    dt = time.time() - t0
    conn.sendall(protocol.ack('VERIFIED'))
    speed = total / dt / 1024 if dt > 0 else 0
    print(f'\n[nbx] OK {name} verified ({total}B, {dt:.2f}s, {speed:.0f} KB/s)')
    protocol.recv_frame(conn)

def send_file(path: str, host: str, port: int, keyfile: str | None=None) -> str:
    from . import anon, carrier, crypto, format
    master = _load_master_key(keyfile)
    with open(path, 'rb') as f:
        data = f.read()
    e2e = False
    if carrier.MAGIC[:7] == data[:7] == b'NBXFILE':
        try:
            _, _, flags = carrier.unpack(data)
            e2e = bool(flags & carrier.FLAG_ENCRYPTED)
        except carrier.NBXError:
            e2e = False
    elif anon.is_wrapper(data):
        e2e = True
    elif len(data) > 108 and data[:8] not in (b'NBXFILE\x02',):
        pass
    if not e2e:
        meta = {'type': 'binary', 'mime': 'application/octet-stream', 'filename': os.path.basename(path), 'enc': 'chacha20poly1305', 'auto': True}
        inner = crypto.encrypt(data, master)
        data = carrier.pack([(carrier.TLV_BIN, inner)], meta, flags=carrier.FLAG_ENCRYPTED)
        name = os.path.basename(path) + '.nbx'
        print(f'[nbx] plaintext detected -> auto-encrypted for transfer ({len(data)}B)')
    else:
        name = os.path.basename(path)
    total = len(data)
    digest = hashlib.sha256(data).digest()
    chunks = [data[i:i + CHUNK] for i in range(0, total, CHUNK)] or [b'']
    t0 = time.time()
    with socket.create_connection((host, port), timeout=15) as sock:
        sock.sendall(protocol.hello())
        ftype, payload = protocol.recv_frame(sock)
        if ftype != protocol.T_AUTH or not payload:
            raise protocol.ProtocolError(f'handshake refused: {payload!r}')
        sock.sendall(protocol.frame(protocol.T_AUTH, _auth_mac(master, payload)))
        ftype, payload = protocol.recv_frame(sock)
        if ftype != protocol.T_ACK or payload != b'READY':
            raise protocol.ProtocolError(f'not authenticated: {payload!r}')
        sock.sendall(protocol.begin_frame(name, total, CHUNK, len(chunks)))
        ftype, payload = protocol.recv_frame(sock)
        if ftype != protocol.T_ACK or payload != b'GO':
            raise protocol.ProtocolError(f'receiver refused transfer: {payload!r}')
        for seq, chunk in enumerate(chunks):
            sock.sendall(protocol.chunk_frame(seq, chunk))
        sock.sendall(protocol.end_frame(digest))
        ftype, payload = protocol.recv_frame(sock)
        if ftype != protocol.T_ACK or payload != b'VERIFIED':
            raise protocol.ProtocolError(f'receiver verification failed: {payload!r}')
        sock.sendall(protocol.bye())
    dt = time.time() - t0
    speed = total / dt / 1024 if dt > 0 else 0
    return f'sent {name} ({total} bytes, {len(chunks)} chunks) in {dt:.2f}s ({speed:.0f} KB/s)'

def listen(port: int, outdir: str, keyfile: str | None=None,
           host: str='127.0.0.1') -> None:
    master = _load_master_key(keyfile)
    os.makedirs(outdir, exist_ok=True)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    print(f'[nbx] listening on {host}:{port} (challenge-response authenticated)')
    while True:
        try:
            conn, addr = srv.accept()
            with conn:
                try:
                    _serve_transfer(conn, addr, outdir, master)
                except Exception as e:
                    print(f'\n[nbx] error from {addr}: {type(e).__name__}: {e}')
        except KeyboardInterrupt:
            print('\n[nbx] shutting down')
            break
