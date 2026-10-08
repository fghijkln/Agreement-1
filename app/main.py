"""NBX Messenger — Android/Linux 端点 App（Flet GUI + nbx daemon 引擎）。

M3 功能集（用户拍板：注册/加联系人/文字聊天/通知，预留扩展接口）：
  · 首启自动生成本机身份（状态目录持久化）
  · 粘贴对方公钥加联系人
  · 文字聊天（经 daemon 异步握手 + ratchet）
  · 预留接口：
      - MESSAGE_TYPES: 未来多媒体/文件消息在此扩展（ptype 层已预留）
      - daemon.handle_ipc: 新命令直接在引擎层加，UI 无需改协议
      - EXTENSION_HOOKS: 文件传输/语音入口挂点
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

import flet as ft

from nbx.daemon import Daemon

# ---------- 平台状态目录 ----------
def app_state_dir() -> str:
    if sys.platform == "android" or "ANDROID_DATA" in os.environ:
        return "/data/data/com.nebula.nbxmessenger/files/state"
    xdg = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(xdg, "nbx-messenger")


DEFAULT_RELAY = "https://sgstfsr4575dfse.redhdyd545.kdns.fr"

# ---------- 预留扩展接口 ----------
MESSAGE_TYPES = {"text": 1}          # 未来: {"image": 2, "file": 3, ...}
EXTENSION_HOOKS: dict[str, callable] = {}   # 注册自定义消息处理器: hooks[name] = fn(daemon, cs, payload)


class MessengerApp:
    def __init__(self):
        self.state_dir = app_state_dir()
        self.relay = os.environ.get("NBX_RELAY", DEFAULT_RELAY)
        self.daemon = Daemon(self.state_dir, self.relay, poll_interval=3)
        self.daemon.start()
        self.peer_pub: str | None = None
        self.page: ft.Page | None = None

    # ---------- IPC（本进程内直调；跨进程时走 unix socket 同一 handle_ipc） ----------

    def ipc(self, req: dict) -> dict:
        return self.daemon.handle_ipc(req)

    # ---------- UI ----------

    def main(self, page: ft.Page):
        self.page = page
        page.title = "NBX Messenger"
        page.theme_mode = ft.ThemeMode.DARK

        self.me_fp = ft.Text(selectable=True, size=12, opacity=0.7)
        self.pub_input = ft.TextField(label="对方公钥 (base64)", multiline=True,
                                      min_lines=2, max_lines=3, expand=True)
        self.chat_list = ft.ListView(expand=True, spacing=8, auto_scroll=True)
        self.msg_input = ft.TextField(label="消息", expand=True,
                                      on_submit=self.on_send)
        self.status = ft.Text(size=12, opacity=0.7)

        page.add(
            ft.Column([
                ft.Row([ft.Text("NBX", size=22, weight=ft.FontWeight.BOLD),
                        ft.Icon(ft.Icons.LOCK, color=ft.Colors.GREEN)],),
                ft.Row([ft.Text("我的指纹:"), self.me_fp]),
                ft.Divider(height=4),
                self.pub_input,
                ft.Row([ft.ElevatedButton("添加联系人", on_click=self.on_add),
                        ft.ElevatedButton("粘贴", on_click=self.on_paste)]),
                self.status,
                ft.Divider(height=4),
                self.chat_list,
                ft.Row([self.msg_input,
                        ft.IconButton(ft.Icons.SEND, on_click=self.on_send)]),
            ], expand=True),
        )
        self.refresh_me()
        threading.Thread(target=self.poll_loop, daemon=True).start()

    def refresh_me(self):
        st = self.ipc({"cmd": "status"})
        self.me_fp.value = st["fp"]

    def on_paste(self, e):
        if self.page:
            data = self.page.clipboard
            # flet 1.0: page.clipboard.get_text 需 await；桌面可用 pyperclip 替代
            try:
                import pyperclip
                self.pub_input.value = pyperclip.paste()
                self.page.update()
            except Exception:
                self.status.value = "剪贴板不可用，请手动粘贴"
                self.page.update()

    def on_add(self, e):
        pub = (self.pub_input.value or "").strip()
        if not pub:
            self.status.value = "请先粘贴对方公钥"
            self.page.update()
            return
        r = self.ipc({"cmd": "add_contact", "pub": pub})
        self.peer_pub = pub
        self.status.value = f"已添加联系人 fp={r['fp']}"
        self.msg_input.disabled = False
        self.chat_list.controls.clear()
        self.page.update()
        self.refresh_history()

    def refresh_history(self):
        if not self.peer_pub:
            return
        r = self.ipc({"cmd": "history", "pub": self.peer_pub, "limit": 100})
        self.chat_list.controls.clear()
        for item in r["items"]:
            mine = item["dir"] == "out"
            self.chat_list.controls.append(
                ft.Row([
                    ft.Container(
                        ft.Text(item["text"], selectable=True,
                                color=ft.Colors.WHITE if mine else None),
                        bgcolor=ft.Colors.BLUE_GREY_700 if mine else ft.Colors.BLUE_GREY_900,
                        padding=10, border_radius=12,
                    )
                ], alignment=ft.MainAxisAlignment.END if mine else ft.MainAxisAlignment.START)
            )
        self.page.update()

    def on_send(self, e=None):
        text = (self.msg_input.value or "").strip()
        if not text or not self.peer_pub:
            return
        self.msg_input.value = ""
        r = self.ipc({"cmd": "send", "pub": self.peer_pub, "text": text})
        if not r.get("queued"):
            self.refresh_history()
        else:
            self.status.value = r.get("note", "queued")
        self.page.update()

    def poll_loop(self):
        """UI 侧刷新线程：收新消息 + 刷新历史。"""
        last_count = 0
        while True:
            time.sleep(2)
            try:
                if self.peer_pub and self.page:
                    r = self.ipc({"cmd": "history", "pub": self.peer_pub, "limit": 100})
                    if len(r["items"]) != last_count:
                        last_count = len(r["items"])
                        self.refresh_history()
            except Exception:
                pass


def main():
    app = MessengerApp()
    # flet 1.0+: ft.app 已改名 ft.run
    run = getattr(ft, "run", None) or getattr(ft, "app")
    run(app.main)


if __name__ == "__main__":
    main()
