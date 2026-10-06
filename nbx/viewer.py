"""NBX 查看器：不落盘直接在终端呈现 .nbx 内容。

- text/markdown/html: 终端渲染（markdown 做轻量格式化，html 剥标签）
- image: 打印尺寸信息 + 可选 base64 预览
- binary: hexdump 头部 + 元信息
- 加密容器: 需提供密钥，失败则只显示元信息
"""
from __future__ import annotations

import base64
import json
import re

from . import carrier


class View:
    """收集终端输出行。"""

    def __init__(self):
        self.lines: list[str] = []

    def add(self, s: str = ""):
        self.lines.append(s)

    def text(self) -> str:
        return "\n".join(self.lines)


# ---- 轻量 markdown / html 终端渲染（无第三方依赖） ----

_MD_RULES = [
    (re.compile(r"^#{1,6}\s+(.*)$", re.M), lambda m: "\033[1m◆ " + m.group(1) + "\033[0m"),
    (re.compile(r"\*\*(.+?)\*\*"), lambda m: "\033[1m" + m.group(1) + "\033[0m"),
    (re.compile(r"\*(.+?)\*"), lambda m: "\033[3m" + m.group(1) + "\033[0m"),
    (re.compile(r"`(.+?)`"), lambda m: "\033[7m" + m.group(1) + "\033[0m"),
    (re.compile(r"^\s*[-*]\s+(.*)$", re.M), lambda m: "  • " + m.group(1)),
    (re.compile(r"^\s*\d+\.\s+(.*)$", re.M), lambda m: "  ⇒ " + m.group(1)),
]

_TAG = re.compile(r"<[^>]+>")

def render_markdown(text: str) -> str:
    out = text
    for pat, repl in _MD_RULES:
        out = pat.sub(repl, out)
    return out


def render_html(text: str) -> str:
    t = re.sub(r"<(script|style)[\s\S]*?</\1>", "", text, flags=re.I)
    t = _TAG.sub("", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()


def hexdump(data: bytes, limit: int = 96) -> str:
    lines = []
    for i in range(0, min(len(data), limit), 16):
        chunk = data[i:i + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:08x}  {hexpart:<47}  |{asc}|")
    if len(data) > limit:
        lines.append(f"  ... ({len(data)} bytes total)")
    return "\n".join(lines)


def view(blob: bytes, master_key: bytes | None = None,
         image_preview: bool = False) -> str:
    """返回可直接打印的终端视图字符串。"""
    v = View()
    # ---- 解析容器（可能需先解密） ----
    try:
        meta, streams, flags = carrier.unpack(blob)
    except carrier.NBXError as e:
        if "checksum" in str(e):
            return f"⚠️ 完整性校验失败: {e}"
        return f"无法解析: {e}"

    encrypted = bool(flags & carrier.FLAG_ENCRYPTED)
    ctype = meta.get("type", "?")
    filename = meta.get("filename", "?")

    # ---- 元信息头 ----
    v.add("┌─ NBX ─────────────────────────────")
    v.add(f"│ 文件: {filename}")
    v.add(f"│ 类型: {ctype}   MIME: {meta.get('mime', '-')}"
          f"   加密: {'是' if encrypted else '否'}"
          f"   压缩: {'是' if flags & carrier.FLAG_COMPRESSED else '否'}")
    parts = meta.get("parts", [])
    if len(parts) > 1:
        v.add(f"│ 流数: {len(parts)}")
        for i, p in enumerate(parts):
            nm = p.get("name", f"stream{i}")
            v.add(f"│   [{i}] {nm}  {p.get('type', '')} {p.get('len', '')}B")
    v.add("└───────────────────────────────────")

    # ---- 加密容器：尝试解密 ----
    if encrypted:
        if master_key is None:
            v.add("🔒 此容器已加密。提供密钥以查看内容 (--keyfile)。")
            return v.text()
        try:
            from . import crypto
            payload = crypto.decrypt(streams[0][1], master_key)
            p, inner = 0, []
            while p < len(payload):
                stype, slen = carrier.TLV.unpack_from(payload, p)
                p += carrier.TLV.size
                inner.append((stype, payload[p:p + slen]))
                p += slen
            streams = inner
        except Exception:
            v.add("❌ 密钥错误，无法解密内容。")
            return v.text()

    # ---- 内容呈现 ----
    def content_of(stype: int, data: bytes) -> str:
        if stype == carrier.TLV_TEXT:
            text = data.decode("utf-8", errors="replace")
            if ctype == "markdown":
                return render_markdown(text)
            if ctype == "html":
                return render_html(text)
            return text
        # 二进制
        head = "二进制流"
        if meta.get("mime", "").startswith("image/"):
            try:
                w = h = "?"
                if meta.get("mime") == "image/png" and data[:24][:8] == b"\x89PNG\r\n\x1a\n":
                    import struct as _s
                    w, h = _s.unpack(">II", data[16:24])
                head = f"图片 {meta['mime']} 尺寸 {w}x{h}"
            except Exception:
                pass
            if image_preview:
                b64 = base64.b64encode(data).decode()
                v.add(f"[IMAGE:{b64}]")
        return head + "\n" + hexdump(data)

    for i, (stype, data) in enumerate(streams):
        if len(streams) > 1:
            name = parts[i].get("name", f"stream{i}") if i < len(parts) else f"stream{i}"
            v.add(f"\n── {name} " + "─" * max(0, 30 - len(name)))
        v.add(content_of(stype, data))
    return v.text()
