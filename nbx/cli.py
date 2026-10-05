"""NBX 命令行工具。"""
from __future__ import annotations

import argparse
import base64
import json
import sys

from . import crypto, format, transfer


def main(argv=None):
    p = argparse.ArgumentParser(prog="nbx", description="Nebula Transfer Protocol")
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="生成独一无二的主密钥")
    k.add_argument("--out", default="nbx.key")

    pk = sub.add_parser("pack", help="加密并打包 .nbx 文件")
    pk.add_argument("infile")
    pk.add_argument("outfile")
    pk.add_argument("--meta", default="{}")
    pk.add_argument("--keyfile", default="nbx.key")

    up = sub.add_parser("unpack", help="解密并还原 .nbx 文件")
    up.add_argument("infile")
    up.add_argument("outfile")
    up.add_argument("--keyfile", default="nbx.key")

    s = sub.add_parser("send", help="发送 .nbx 文件")
    s.add_argument("file")
    s.add_argument("host")
    s.add_argument("port", type=int)
    s.add_argument("--keyfile", default="nbx.key")

    l = sub.add_parser("listen", help="接收 .nbx 文件")
    l.add_argument("port", type=int)
    l.add_argument("--outdir", default="received")
    l.add_argument("--keyfile", default="nbx.key")

    args = p.parse_args(argv)

    if args.cmd == "keygen":
        key = crypto.generate_master_key()
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(key + "\n")
        print(f"master key written to {args.out} (keep it secret!)")

    elif args.cmd == "pack":
        master = _read_key(args.keyfile)
        with open(args.infile, "rb") as f:
            data = f.read()
        meta = json.loads(args.meta)
        meta["enc"] = "chacha20p1305"
        blob = format.pack(crypto.encrypt(data, master), meta)
        with open(args.outfile, "wb") as f:
            f.write(blob)
        print(f"packed {args.infile} -> {args.outfile} ({len(blob)} bytes)")

    elif args.cmd == "unpack":
        master = _read_key(args.keyfile)
        with open(args.infile, "rb") as f:
            meta, inner = format.unpack(f.read())
        plain = crypto.decrypt(inner, master)
        with open(args.outfile, "wb") as f:
            f.write(plain)
        print(f"unpacked -> {args.outfile} (meta: {json.dumps(meta, ensure_ascii=False)})")

    elif args.cmd == "send":
        print(transfer.send_file(args.file, args.host, args.port, args.keyfile))

    elif args.cmd == "listen":
        transfer.listen(args.port, args.outdir, args.keyfile)


def _read_key(path: str) -> bytes:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return base64.b64decode(f.read().strip())
    except FileNotFoundError:
        sys.exit(f"key file not found: {path} (run 'nbx keygen' first)")


if __name__ == "__main__":
    main()
