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

def app_state_dir() -> str:
    if sys.platform == 'android' or 'ANDROID_DATA' in os.environ:
        return '/data/data/com.nebula.nbxmessenger/files/state'
    xdg = os.environ.get('XDG_DATA_HOME') or os.path.expanduser('~/.local/share')
    return os.path.join(xdg, 'nbx-messenger')
DEFAULT_RELAY = 'https://sgstfsr4575dfse.redhdyd545.kdns.fr'
MESSAGE_TYPES = {'text': 1}
EXTENSION_HOOKS: dict[str, callable] = {}

class MessengerApp:

    def __init__(self):
        self.state_dir = app_state_dir()
        self.relay = os.environ.get('NBX_RELAY', DEFAULT_RELAY)
        self.daemon = Daemon(self.state_dir, self.relay, poll_interval=3)
        self.daemon.start()
        self.peer_pub: str | None = None
        self.page: ft.Page | None = None

    def ipc(self, req: dict) -> dict:
        return self.daemon.handle_ipc(req)

    def main(self, page: ft.Page):
        self.page = page
        page.title = 'NBX Messenger'
        page.theme_mode = ft.ThemeMode.DARK
        self.me_fp = ft.Text(selectable=True, size=12, opacity=0.7)
        self.me_pub = ft.Text(selectable=True, size=10, opacity=0.7, max_lines=3)
        self.pub_input = ft.TextField(label='对方公钥 (base64)', multiline=True, min_lines=2, max_lines=3, expand=True)
        self.chat_list = ft.ListView(expand=True, spacing=8, auto_scroll=True)
        self.msg_input = ft.TextField(label='消息', expand=True, on_submit=self.on_send)
        self.status = ft.Text(size=12, opacity=0.7)
        page.add(ft.Column([ft.Row([ft.Text('NBX', size=22, weight=ft.FontWeight.BOLD), ft.Icon(ft.Icons.LOCK, color=ft.Colors.GREEN)]), ft.Row([ft.Text('我的指纹:'), self.me_fp, ft.FilledButton('复制我的公钥', on_click=self.on_copy_pub)]), self.me_pub, ft.Divider(height=4), self.pub_input, ft.Row([ft.FilledButton('添加联系人', on_click=self.on_add), ft.FilledButton('粘贴', on_click=self.on_paste)]), self.status, ft.Divider(height=4), self.chat_list, ft.Row([self.msg_input, ft.IconButton(ft.Icons.SEND, on_click=self.on_send)])], expand=True))
        self.refresh_me()
        threading.Thread(target=self.poll_loop, daemon=True).start()

    def refresh_me(self):
        st = self.ipc({'cmd': 'status'})
        self.me_fp.value = st['fp']
        self.me_pub.value = self.daemon.export_public()

    def on_copy_pub(self, e):
        import asyncio, threading
        pub = self.daemon.export_public()

        async def _set():
            from flet import Clipboard
            clip = next((x for x in self.page.services if isinstance(x, Clipboard)), None)
            if clip is None:
                clip = Clipboard()
                self.page.services.append(clip)
            await clip.set(pub)

        def _run():
            try:
                asyncio.run(_set())
                self.status.value = '公钥已复制，发给对方即可添加你'
            except Exception:
                self.status.value = '复制失败，请长按公钥文本手动复制'
            if self.page:
                self.page.update()
        threading.Thread(target=_run, daemon=True).start()

    def on_paste(self, e):
        import asyncio

        async def _get():
            from flet import Clipboard
            clip = next((x for x in self.page.services if isinstance(x, Clipboard)), None)
            if clip is None:
                clip = Clipboard()
                self.page.services.append(clip)
            return await clip.get()

        def _done():
            try:
                val = asyncio.run(_get())
            except Exception:
                val = None
            if val:
                self.pub_input.value = val
            else:
                self.status.value = '剪贴板不可用，请手动粘贴'
            if self.page:
                self.page.update()
        if self.page:
            import threading
            threading.Thread(target=_done, daemon=True).start()

    def on_add(self, e):
        pub = (self.pub_input.value or '').strip()
        if not pub:
            self.status.value = '请先粘贴对方公钥'
            self.page.update()
            return
        r = self.ipc({'cmd': 'add_contact', 'pub': pub})
        self.peer_pub = pub
        self.status.value = f"已添加联系人 fp={r['fp']}"
        self.msg_input.disabled = False
        self.chat_list.controls.clear()
        self.page.update()
        self.refresh_history()

    def refresh_history(self):
        if not self.peer_pub:
            return
        r = self.ipc({'cmd': 'history', 'pub': self.peer_pub, 'limit': 100})
        self.chat_list.controls.clear()
        for item in r['items']:
            mine = item['dir'] == 'out'
            self.chat_list.controls.append(ft.Row([ft.Container(ft.Text(item['text'], selectable=True, color=ft.Colors.WHITE if mine else None), bgcolor=ft.Colors.BLUE_GREY_700 if mine else ft.Colors.BLUE_GREY_900, padding=10, border_radius=12)], alignment=ft.MainAxisAlignment.END if mine else ft.MainAxisAlignment.START))
        self.page.update()

    def on_send(self, e=None):
        text = (self.msg_input.value or '').strip()
        if not text or not self.peer_pub:
            return
        self.msg_input.value = ''
        r = self.ipc({'cmd': 'send', 'pub': self.peer_pub, 'text': text})
        if not r.get('queued'):
            self.refresh_history()
        else:
            self.status.value = r.get('note', 'queued')
        self.page.update()

    def poll_loop(self):
        last_count = 0
        while True:
            time.sleep(2)
            try:
                if self.peer_pub and self.page:
                    r = self.ipc({'cmd': 'history', 'pub': self.peer_pub, 'limit': 100})
                    if len(r['items']) != last_count:
                        last_count = len(r['items'])
                        self.refresh_history()
            except Exception:
                pass

def main():
    app = MessengerApp()
    run = getattr(ft, 'run', None) or getattr(ft, 'app')
    run(app.main)
if __name__ == '__main__':
    main()
