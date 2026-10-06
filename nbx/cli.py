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

    cv = sub.add_parser("convert", help="把任意文件转成 .nbx 通用载体")
    cv.add_argument("infile")
    cv.add_argument("outfile")
    cv.add_argument("--encrypt", action="store_true", help="同时加密")
    cv.add_argument("--compress", action="store_true", help="流级 LZMA 压缩")
    cv.add_argument("--keyfile", default="nbx.key")

    ex = sub.add_parser("extract", help="从 .nbx 无损还原原文件")
    ex.add_argument("infile")
    ex.add_argument("--outdir", default=".")
    ex.add_argument("--keyfile", default="nbx.key")

    vw = sub.add_parser("view", help="终端直接查看 .nbx（不落盘）")
    vw.add_argument("infile")
    vw.add_argument("--keyfile", default="nbx.key")
    vw.add_argument("--image", action="store_true", help="图片输出 base64 预览")

    bdl = sub.add_parser("bundle", help="把多个文件打成一个 .nbx")
    bdl.add_argument("outfile")
    bdl.add_argument("infiles", nargs="+")

    idn = sub.add_parser("identity", help="前向保密身份密钥管理")
    idn.add_argument("action", choices=["new", "show", "pubout"])
    idn.add_argument("idfile", nargs="?", default="nbx_id.key")
    idn.add_argument("--out", default=None, help="pubout 时导出公钥到的文件")

    fs = sub.add_parser("seal", help="前向保密加密（X25519+Ed25519 信封）")
    fs.add_argument("infile")
    fs.add_argument("outfile")
    fs.add_argument("--my-id", default="nbx_id.key")
    fs.add_argument("--to-pub", required=True, help="接收方身份公钥文件(Base64)")

    un = sub.add_parser("unseal", help="解密前向保密信封")
    un.add_argument("infile")
    un.add_argument("outfile")
    un.add_argument("--my-id", default="nbx_id.key")
    un.add_argument("--from-pub", required=True, help="发送方身份公钥文件(Base64)")

    an = sub.add_parser("anon", help="Anonymity Wrapper: 元数据加密外层")
    an.add_argument("action", choices=["pack", "unpack"])
    an.add_argument("infile")
    an.add_argument("outfile")
    an.add_argument("--keyfile", default="nbx.key")
    an.add_argument("--pad", type=int, default=0, help="长度填充块大小(如4096)")

    pqc = sub.add_parser("pqseal", help="后量子混合信封 (X25519+ML-KEM-768)")
    pqc.add_argument("infile")
    pqc.add_argument("outfile")
    pqc.add_argument("--my-id", default="nbx_id.key")
    pqc.add_argument("--to-pub", required=True)

    pqu = sub.add_parser("pqunseal", help="解封后量子信封")
    pqu.add_argument("infile")
    pqu.add_argument("outfile")
    pqu.add_argument("--my-id", default="nbx_id.key")
    pqu.add_argument("--from-pub", required=True)

    rl = sub.add_parser("relay", help="启动中继服务器（密文搬运工）")
    rl.add_argument("--port", type=int, default=8765)

    ch = sub.add_parser("chat", help="经中继的加密会话客户端")
    ch.add_argument("--relay", default="http://127.0.0.1:8765")
    ch.add_argument("--my-id", required=True)
    ch.add_argument("--to-pub", required=True, help="对方身份公钥（Base64）")
    ch.add_argument("--poll", type=float, default=2.0, help="取信轮询秒数")

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

    elif args.cmd == "convert":
        from . import carrier
        blob = carrier.convert(args.infile)
        if args.compress:
            meta, streams, flags = carrier.unpack(blob)
            blob = carrier.pack(streams, meta, flags=flags, compress=True)
        if args.encrypt:
            master = _read_key(args.keyfile)
            meta, streams, flags = carrier.unpack(blob)
            enc = crypto.encrypt(carrier._build_payload(streams), master)
            meta["enc"] = "chacha20poly1305"
            blob = carrier.pack([(carrier.TLV_BIN, enc)], meta,
                                flags=carrier.FLAG_ENCRYPTED)
        with open(args.outfile, "wb") as f:
            f.write(blob)
        print(f"converted {args.infile} -> {args.outfile} ({len(blob)} bytes)")

    elif args.cmd == "extract":
        from . import carrier
        with open(args.infile, "rb") as f:
            blob = f.read()
        meta, streams, flags = carrier.unpack(blob)
        if flags & carrier.FLAG_ENCRYPTED:
            master = _read_key(args.keyfile)
            payload = crypto.decrypt(streams[0][1], master)
            # 重新解析内层 TLV
            p, inner = 0, []
            while p < len(payload):
                stype, slen = carrier.TLV.unpack_from(payload, p)
                p += carrier.TLV.size
                inner.append((stype, payload[p:p + slen]))
                p += slen
            streams = inner
        import os
        os.makedirs(args.outdir, exist_ok=True)
        ctype = meta.get("type")
        if ctype == "bundle" and "parts" in meta:
            for part, (stype, content) in zip(meta["parts"], streams):
                out = os.path.join(args.outdir, part.get("name", "part"))
                with open(out, "wb") as f:
                    f.write(content)
                print(f"extracted -> {out} ({len(content)} bytes)")
        else:
            name = meta.get("filename", "untitled")
            out = os.path.join(args.outdir, name)
            with open(out, "wb") as f:
                f.write(streams[0][1])
            print(f"extracted -> {out} ({len(streams[0][1])} bytes, type={ctype})")

    elif args.cmd == "view":
        from . import viewer
        with open(args.infile, "rb") as f:
            blob = f.read()
        master = None
        try:
            master = _read_key(args.keyfile)
        except SystemExit:
            pass
        print(viewer.view(blob, master_key=master, image_preview=args.image))

    elif args.cmd == "bundle":
        from . import carrier
        blob = carrier.convert_bundle(args.infiles)
        with open(args.outfile, "wb") as f:
            f.write(blob)
        print(f"bundled {len(args.infiles)} files -> {args.outfile} ({len(blob)} bytes)")

    elif args.cmd == "identity":
        from . import fskey
        import os
        if args.action == "new":
            if os.path.exists(args.idfile):
                sys.exit(f"refusing to overwrite existing identity: {args.idfile}")
            ident = fskey.Identity.generate()
            ident.save(args.idfile)
            print(f"identity created: {args.idfile}")
            print(f"fingerprint: {ident.fingerprint()}")
            print(f"public key:\n{ident.export_public()}")
        elif args.action == "show":
            ident = fskey.Identity.load(args.idfile)
            print(f"fingerprint: {ident.fingerprint()}")
            print(f"public key:\n{ident.export_public()}")
        elif args.action == "pubout":
            ident = fskey.Identity.load(args.idfile)
            out = args.out or (args.idfile + ".pub")
            with open(out, "w", encoding="utf-8") as f:
                f.write(ident.export_public() + "\n")
            print(f"public key written to {out}")

    elif args.cmd == "seal":
        from . import fskey
        ident = fskey.Identity.load(args.my_id)
        to_x, to_ed = fskey.Identity.parse_public(open(args.to_pub).read().strip())
        data = open(args.infile, "rb").read()
        env = fskey.seal_envelope(data, ident, to_x, to_ed)
        with open(args.outfile, "wb") as f:
            f.write(env)
        print(f"sealed {args.infile} -> {args.outfile} ({len(env)} bytes, forward-secure, replay-protected)")

    elif args.cmd == "unseal":
        from . import fskey, replay
        ident = fskey.Identity.load(args.my_id)
        from_x, from_ed = fskey.Identity.parse_public(open(args.from_pub).read().strip())
        env = open(args.infile, "rb").read()
        cache = replay.ReplayCache()
        try:
            plain = fskey.open_envelope(env, ident, from_x, from_ed, cache=cache)
        except ValueError as e:
            sys.exit(f"unseal failed: {e}")
        except Exception as e:
            sys.exit(f"unseal failed (wrong key or tampered): {e}")
        with open(args.outfile, "wb") as f:
            f.write(plain)
        print(f"unsealed -> {args.outfile} ({len(plain)} bytes, signature+replay verified)")

    elif args.cmd == "anon":
        from . import anon
        master = _read_key(args.keyfile)
        data = open(args.infile, "rb").read()
        if args.action == "pack":
            blob = anon.wrap(data, master, pad_block=args.pad)
            with open(args.outfile, "wb") as f:
                f.write(blob)
            print(f"anon-wrapped -> {args.outfile} ({len(data)}B inner -> {len(blob)}B outer,"
                  f" pad_block={args.pad or 'off'})")
        else:
            try:
                inner = anon.unwrap(data, master)
            except Exception as e:
                sys.exit(f"unwrap failed: {e}")
            with open(args.outfile, "wb") as f:
                f.write(inner)
            print(f"unwrapped -> {args.outfile} ({len(inner)}B)")

    elif args.cmd == "pqseal":
        from . import pq
        ident = pq.PQIdentity.load(args.my_id)
        rec = pq.PQIdentity.parse_public(open(args.to_pub).read().strip())
        data = open(args.infile, "rb").read()
        env = pq.seal_pq(data, ident, *rec)
        with open(args.outfile, "wb") as f:
            f.write(env)
        print(f"pq-sealed {args.infile} -> {args.outfile} ({len(env)}B, X25519+ML-KEM-768, replay-protected)")

    elif args.cmd == "pqunseal":
        from . import pq, replay
        ident = pq.PQIdentity.load(args.my_id)
        snd = pq.PQIdentity.parse_public(open(args.from_pub).read().strip())
        env = open(args.infile, "rb").read()
        cache = replay.ReplayCache()
        try:
            plain = pq.open_pq(env, ident, snd[0], snd[1], cache=cache)
        except ValueError as e:
            sys.exit(f"pq-unseal failed: {e}")
        except Exception as e:
            sys.exit(f"pq-unseal failed: {e}")
        with open(args.outfile, "wb") as f:
            f.write(plain)
        print(f"pq-unsealed -> {args.outfile} ({len(plain)}B, signature+replay verified)")

    elif args.cmd == "send":
        print(transfer.send_file(args.file, args.host, args.port, args.keyfile))

    elif args.cmd == "listen":
        transfer.listen(args.port, args.outdir, args.keyfile)

    elif args.cmd == "relay":
        from .relay import RelayLogic, MemoryStore, RelayServer
        logic = RelayLogic(MemoryStore())
        srv = RelayServer(logic, port=args.port)
        print(f"[nbx relay] listening on 127.0.0.1:{args.port} (Ctrl+C to stop)")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\n[nbx relay] stopped")

    elif args.cmd == "chat":
        from .chat import run_chat
        from .fskey import Identity
        ident = Identity.load(args.my_id)
        run_chat(ident, args.to_pub, args.relay, speaks_first=False,
                 poll=args.poll)


def _read_key(path: str) -> bytes:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return base64.b64decode(f.read().strip())
    except FileNotFoundError:
        sys.exit(f"key file not found: {path} (run 'nbx keygen' first)")


if __name__ == "__main__":
    main()
