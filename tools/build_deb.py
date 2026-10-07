#!/usr/bin/env python3
"""构建 nbx 的 deb 包：CLI + relay + daemon + systemd 服务。"""
import os, shutil, subprocess, textwrap, sys

REPO = os.environ.get("NBX_REPO", os.getcwd())
BUILD = "/tmp/debbuild/nbx_0.1.0"
DEB_OUT = "/home/agentuser/nebula-protocol/dist/nbx_0.1.0_all.deb"

# 清理
shutil.rmtree("/tmp/debbuild", ignore_errors=True)
pkg = BUILD
dirs = [f"{pkg}/DEBIAN", f"{pkg}/usr/bin", f"{pkg}/usr/lib/nbx",
        f"{pkg}/usr/share/doc/nbx", f"{pkg}/lib/systemd/system",
        f"{pkg}/etc/nbx"]
for d in dirs:
    os.makedirs(d, exist_ok=True)

# 1. 纯 Python 源码打包进 /usr/lib/nbx（vendor 含纯 py KEM, 全平台兼容）
shutil.copytree(f"{REPO}/nbx", f"{pkg}/usr/lib/nbx/nbx",
                ignore=shutil.ignore_patterns("__pycache__"))
# 源仓库目录是 700，copytree 会保留；打成 deb 必须对所有人可读
for root, dirs_, files_ in os.walk(f"{pkg}/usr/lib/nbx"):
    os.chmod(root, 0o755)
    for f_ in files_:
        os.chmod(os.path.join(root, f_), 0o644)

# 2. 启动器脚本
launchers = {
    "nbx": '''#!/usr/bin/python3
import sys
sys.path.insert(0, "/usr/lib/nbx")
from nbx.cli import main
main()
''',
    "nbx-relayd": '''#!/usr/bin/python3
import sys
sys.path.insert(0, "/usr/lib/nbx")
from nbx.cli import main
sys.argv = ["nbx", "relay"] + sys.argv[1:]
main()
''',
    "nbx-daemon": '''#!/usr/bin/python3
import sys, os
sys.path.insert(0, "/usr/lib/nbx")
from nbx.daemon import Daemon
import signal

state = os.environ.get("NBX_STATE", "/var/lib/nbx")
relay = open("/etc/nbx/relay").read().strip() if os.path.exists("/etc/nbx/relay") else "http://127.0.0.1:8765"
d = Daemon(state, relay, poll_interval=3)
d.start()
print("nbx-daemon: fp=%s relay=%s" % (d.my_fp.hex(), relay), flush=True)
signal.pause()
''',
}
for name, body in launchers.items():
    p = f"{pkg}/usr/bin/{name}"
    open(p, "w").write(body)
    os.chmod(p, 0o755)

# 3. systemd 单元
open(f"{pkg}/lib/systemd/system/nbx-daemon@.service", "w").write(textwrap.dedent('''\
    [Unit]
    Description=NBX Messenger Daemon (E2E encrypted IM engine)
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=simple
    User=%i
    StateDirectory=nbx
    ExecStart=/usr/bin/nbx-daemon
    Restart=on-failure
    RestartSec=5

    [Install]
    WantedBy=multi-user.target
'''))

# 4. 配置 + 文档
open(f"{pkg}/etc/nbx/relay", "w").write("https://sgstfsr4575dfse.redhdyd545.kdns.fr\n")
readme = f"""NBX Messenger (deb) — 端到端加密即时通讯
协议与代码: https://github.com/fghijkln/Agreement-1

组件:
  /usr/bin/nbx          CLI (seal/unseal/relay/identity/...)
  /usr/bin/nbx-relayd   中继服务器 (默认 :8765)
  /usr/bin/nbx-daemon   常驻会话引擎 (IPC: ~/.local/state/nbx/daemon.sock 或 /var/lib/nbx)
  /lib/systemd/system/nbx-daemon@.service

用法:
  sudo systemctl enable --now nbx-daemon@$USER
  # 状态目录: /var/lib/nbx (含 identity.key, sessions/, messages/)
"""
open(f"{pkg}/usr/share/doc/nbx/README.txt", "w").write(readme)

# 5. 控制文件
open(f"{pkg}/DEBIAN/control", "w").write(textwrap.dedent('''\
    Package: nbx
    Version: 0.1.0
    Section: net
    Priority: optional
    Architecture: all
    Depends: python3 (>= 3.10), python3-cryptography
    Maintainer: fghijkln <fghijkln@users.noreply.github.com>
    Description: NBX end-to-end encrypted messenger (CLI, relay, daemon)
     Nebula Transfer Protocol endpoint suite: .nbx container CLI,
     relay server, resident messaging daemon with double-ratchet
     sessions. Relay never sees plaintext; keys never leave the device.
'''))

# 6. conffiles (配置保留)
open(f"{pkg}/DEBIAN/conffiles", "w").write("/etc/nbx/relay\n")

# 7. 构建
os.makedirs("/home/agentuser/nebula-protocol/dist", exist_ok=True)
subprocess.run(["dpkg-deb", "--build", "--root-owner-group", pkg, DEB_OUT], check=True)
info = subprocess.run(["dpkg-deb", "--info", DEB_OUT], capture_output=True, text=True)
print(info.stdout[:600])
print("DEB:", DEB_OUT, os.path.getsize(DEB_OUT), "bytes")
