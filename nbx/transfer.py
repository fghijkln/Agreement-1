"""NBX 协议收发两端（v2: 分块流式传输 + 端到端校验）。"""
from __future__ import annotations

import base64
import hashlib
import os
import socket
import time

from . import protocol


CHUNK = protocol.DEFAULT_CHUNK


def _load_master_key(keyfile: str | None) -> bytes:
    env = os.environ.get("NBX_MASTER_KEY")
    if keyfile:
        with open(keyfile, "r", encoding="utf-8") as f:
            return base64.b64decode(f.read().strip())
    if env:
        return base64.b64decode(env)
    raise SystemExit("no master key: use --keyfile or NBX_MASTER_KEY")


def send_file(path: str, host: str, port: int, keyfile: str | None = None) -> str:
    """分块流式发送文件。强制 E2E: 明文 .nbx / 普通文件在发送前自动加密。"""
    from . import anon, carrier, crypto, format
    with open(path, "rb") as f:
        data = f.read()

    # ---- 强制 E2E 检查 ----
    e2e = False
    if carrier.MAGIC[:7] == data[:7] == b"NBXFILE":  # NBX 容器
        try:
            _, _, flags = carrier.unpack(data)
            e2e = bool(flags & carrier.FLAG_ENCRYPTED)
        except carrier.NBXError:
            e2e = False
    elif anon.is_wrapper(data):
        e2e = True  # 匿名包装内层必有加密
    elif len(data) > 108 and data[:8] not in (b"NBXFILE\x02",):
        # 可能是 FS/PQ 信封（无公开魔数, 全随机）——交给用户判断
        pass
    if not e2e:
        # 明文内容: 自动用主密钥加密成 NBX 容器再传
        master = _load_master_key(keyfile)
        meta = {"type": "binary", "mime": "application/octet-stream",
                "filename": os.path.basename(path),
                "enc": "chacha20poly1305", "auto": True}
        inner = crypto.encrypt(data, master)
        data = carrier.pack([(carrier.TLV_BIN, inner)], meta,
                            flags=carrier.FLAG_ENCRYPTED)
        name = os.path.basename(path) + ".nbx"
        print(f"[nbx] plaintext detected -> auto-encrypted for transfer ({len(data)}B)")
    else:
        name = os.path.basename(path)

    total = len(data)
    digest = hashlib.sha256(data).digest()
    chunks = [data[i:i + CHUNK] for i in range(0, total, CHUNK)] or [b""]

    t0 = time.time()
    with socket.create_connection((host, port), timeout=15) as sock:
        sock.sendall(protocol.hello())
        ftype, payload = protocol.recv_frame(sock)
        if ftype != protocol.T_ACK:
            raise protocol.ProtocolError("handshake refused")
        sock.sendall(protocol.begin_frame(name, total, CHUNK, len(chunks)))
        ftype, payload = protocol.recv_frame(sock)
        if ftype != protocol.T_ACK:
            raise protocol.ProtocolError("receiver refused transfer")
        for seq, chunk in enumerate(chunks):
            sock.sendall(protocol.chunk_frame(seq, chunk))
        sock.sendall(protocol.end_frame(digest))
        ftype, payload = protocol.recv_frame(sock)
        if ftype != protocol.T_ACK or payload != b"VERIFIED":
            raise protocol.ProtocolError(f"receiver verification failed: {payload!r}")
        sock.sendall(protocol.bye())
    dt = time.time() - t0
    speed = total / dt / 1024 if dt > 0 else 0
    return f"sent {name} ({total} bytes, {len(chunks)} chunks) in {dt:.2f}s ({speed:.0f} KB/s)"


def listen(port: int, outdir: str, keyfile: str | None = None) -> None:
    """接收端：握手 → 分块接收 → SHA-256 校验 → 落盘。"""
    os.makedirs(outdir, exist_ok=True)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    print(f"[nbx] listening on 0.0.0.0:{port}")
    while True:
        conn, addr = srv.accept()
        try:
            with conn:
                ftype, payload = protocol.recv_frame(conn)
                if ftype != protocol.T_HELLO or payload != protocol.PROTO_NAME:
                    conn.sendall(protocol.ack("BAD HELLO"))
                    continue
                conn.sendall(protocol.ack("READY"))
                ftype, payload = protocol.recv_frame(conn)
                if ftype != protocol.T_BEGIN:
                    conn.sendall(protocol.ack("EXPECTED BEGIN"))
                    continue
                name, total, chunk_size, total_chunks = protocol.parse_begin(payload)
                conn.sendall(protocol.ack("GO"))
                # 流式接收：边收边写边算哈希
                h = hashlib.sha256()
                path = os.path.join(outdir, os.path.basename(name))
                received = 0
                t0 = time.time()
                with open(path, "wb") as out:
                    seq_expect = 0
                    while True:
                        ftype, payload = protocol.recv_frame(conn)
                        if ftype == protocol.T_CHUNK:
                            seq, data = protocol.parse_chunk(payload)
                            if seq != seq_expect:
                                raise protocol.ProtocolError(
                                    f"chunk out of order: got {seq}, want {seq_expect}")
                            seq_expect += 1
                            out.write(data)
                            h.update(data)
                            received += len(data)
                            pct = received * 100 // total if total else 100
                            print(f"\r[nbx] {addr[0]} -> {name} {pct}% ({received}/{total})",
                                  end="", flush=True)
                        elif ftype == protocol.T_END:
                            break
                        else:
                            raise protocol.ProtocolError(f"unexpected frame {ftype}")
                if h.digest() != payload:
                    conn.sendall(protocol.ack("CHECKSUM FAIL"))
                    os.remove(path)
                    print(f"\n[nbx] checksum FAILED from {addr}, discarded {name}")
                    continue
                dt = time.time() - t0
                conn.sendall(protocol.ack("VERIFIED"))
                speed = total / dt / 1024 if dt > 0 else 0
                print(f"\n[nbx] OK {name} verified ({total}B, {dt:.2f}s, {speed:.0f} KB/s)")
                protocol.recv_frame(conn)  # BYE
        except protocol.ProtocolError as e:
            print(f"\n[nbx] error from {addr}: {e}")
        except KeyboardInterrupt:
            print("\n[nbx] shutting down")
            break
