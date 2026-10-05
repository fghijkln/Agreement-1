"""NBX 协议收发两端。"""
from __future__ import annotations

import os
import socket

from . import crypto, format, protocol


def _load_master_key(keyfile: str | None) -> bytes:
    env = os.environ.get("NBX_MASTER_KEY")
    if keyfile:
        with open(keyfile, "r", encoding="utf-8") as f:
            return base64_decode(f.read().strip())
    if env:
        return base64_decode(env)
    raise SystemExit("no master key: use --keyfile or NBX_MASTER_KEY")


def base64_decode(s: str) -> bytes:
    import base64

    return base64.b64decode(s)


def send_file(path: str, host: str, port: int, keyfile: str | None = None) -> str:
    master = _load_master_key(keyfile)
    meta_raw, _ = format.unpack(open(path, "rb").read()) if False else (None, None)
    with open(path, "rb") as f:
        encrypted_blob = f.read()
    # 若文件尚未加密，先加密
    try:
        meta, inner = format.unpack(encrypted_blob)
        if meta.get("enc") != "chacha20p1305":
            raise format.NBXError("not encrypted")
    except format.NBXError:
        raise SystemExit("input is not an encrypted .nbx file (pack it first)")

    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(protocol.hello())
        ftype, payload = protocol.recv_frame(sock)
        if ftype != protocol.T_ACK:
            raise protocol.ProtocolError("handshake refused")
        sock.sendall(protocol.file_frame(os.path.basename(path), encrypted_blob))
        ftype, payload = protocol.recv_frame(sock)
        if ftype != protocol.T_ACK:
            raise protocol.ProtocolError("receiver rejected file")
        sock.sendall(protocol.bye())
    return "sent"


def listen(port: int, outdir: str, keyfile: str | None = None) -> None:
    master = _load_master_key(keyfile)
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
                if ftype != protocol.T_FILE:
                    conn.sendall(protocol.ack("EXPECTED FILE"))
                    continue
                name, blob = protocol.parse_file(payload)
                conn.sendall(protocol.ack("OK"))
                ftype, _ = protocol.recv_frame(conn)  # BYE (optional)
                path = os.path.join(outdir, os.path.basename(name))
                with open(path, "wb") as f:
                    f.write(blob)
                try:
                    meta, inner_enc = format.unpack(blob)
                    plain = crypto.decrypt(inner_enc, master)
                    out = os.path.join(outdir, "decrypted_" + os.path.basename(name))
                    with open(out, "wb") as f:
                        f.write(plain)
                    print(f"[nbx] {addr[0]} -> {path} (decrypted: {out}, meta={meta})")
                except Exception as e:  # 密钥不符或文件损坏
                    print(f"[nbx] {addr[0]} -> {path} saved, but decrypt failed: {e}")
        except protocol.ProtocolError as e:
            print(f"[nbx] error from {addr}: {e}")
