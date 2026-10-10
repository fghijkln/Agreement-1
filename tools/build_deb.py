import os, shutil, subprocess, textwrap, sys
REPO = os.environ.get('NBX_REPO', os.getcwd())
BUILD = '/tmp/debbuild/nbx_0.2.0'
DEB_OUT = '/home/agentuser/nebula-protocol/dist/nbx_0.2.0_all.deb'
shutil.rmtree('/tmp/debbuild', ignore_errors=True)
pkg = BUILD
dirs = [f'{pkg}/DEBIAN', f'{pkg}/usr/bin', f'{pkg}/usr/lib/nbx', f'{pkg}/usr/share/doc/nbx', f'{pkg}/lib/systemd/system', f'{pkg}/etc/nbx']
for d in dirs:
    os.makedirs(d, exist_ok=True)
shutil.copytree(f'{REPO}/nbx', f'{pkg}/usr/lib/nbx/nbx', ignore=shutil.ignore_patterns('__pycache__'))
for root, dirs_, files_ in os.walk(f'{pkg}/usr/lib/nbx'):
    os.chmod(root, 493)
    for f_ in files_:
        os.chmod(os.path.join(root, f_), 420)
launchers = {'nbx': '#!/usr/bin/python3\nimport sys\nsys.path.insert(0, "/usr/lib/nbx")\nfrom nbx.cli import main\nmain()\n', 'nbx-relayd': '#!/usr/bin/python3\nimport sys\nsys.path.insert(0, "/usr/lib/nbx")\nfrom nbx.cli import main\nsys.argv = ["nbx", "relay"] + sys.argv[1:]\nmain()\n', 'nbx-daemon': '#!/usr/bin/python3\nimport sys, os\nsys.path.insert(0, "/usr/lib/nbx")\nfrom nbx.daemon import Daemon\nimport signal\n\nstate = os.environ.get("NBX_STATE", "/var/lib/nbx")\nrelay = open("/etc/nbx/relay").read().strip() if os.path.exists("/etc/nbx/relay") else "http://127.0.0.1:8765"\nd = Daemon(state, relay, poll_interval=3)\nd.start()\nprint("nbx-daemon: fp=%s relay=%s" % (d.my_fp.hex(), relay), flush=True)\nsignal.pause()\n'}
for name, body in launchers.items():
    p = f'{pkg}/usr/bin/{name}'
    open(p, 'w').write(body)
    os.chmod(p, 493)
open(f'{pkg}/lib/systemd/system/nbx-daemon@.service', 'w').write(textwrap.dedent('    [Unit]\n    Description=NBX Messenger Daemon (E2E encrypted IM engine)\n    After=network-online.target\n    Wants=network-online.target\n\n    [Service]\n    Type=simple\n    User=%i\n    StateDirectory=nbx\n    ExecStart=/usr/bin/nbx-daemon\n    Restart=on-failure\n    RestartSec=5\n\n    [Install]\n    WantedBy=multi-user.target\n'))
open(f'{pkg}/etc/nbx/relay', 'w').write('https://sgstfsr4575dfse.redhdyd545.kdns.fr\n')
readme = f'NBX Messenger (deb) — 端到端加密即时通讯\n协议与代码: https://github.com/fghijkln/Agreement-1\n\n组件:\n  /usr/bin/nbx          CLI (seal/unseal/relay/identity/...)\n  /usr/bin/nbx-relayd   中继服务器 (默认 :8765)\n  /usr/bin/nbx-daemon   常驻会话引擎 (IPC: ~/.local/state/nbx/daemon.sock 或 /var/lib/nbx)\n  /lib/systemd/system/nbx-daemon@.service\n\n用法:\n  sudo systemctl enable --now nbx-daemon@$USER\n  # 状态目录: /var/lib/nbx (含 identity.key, sessions/, messages/)\n'
open(f'{pkg}/usr/share/doc/nbx/README.txt', 'w').write(readme)
open(f'{pkg}/DEBIAN/control', 'w').write(textwrap.dedent('    Package: nbx\n    Version: 0.2.0\n    Section: net\n    Priority: optional\n    Architecture: all\n    Depends: python3 (>= 3.10), python3-cryptography\n    Maintainer: fghijkln <fghijkln@users.noreply.github.com>\n    Description: NBX end-to-end encrypted messenger (CLI, relay, daemon)\n     Nebula Transfer Protocol endpoint suite: .nbx container CLI,\n     relay server, resident messaging daemon with double-ratchet\n     sessions. Relay never sees plaintext; keys never leave the device.\n'))
open(f'{pkg}/DEBIAN/conffiles', 'w').write('/etc/nbx/relay\n')
os.makedirs('/home/agentuser/nebula-protocol/dist', exist_ok=True)
subprocess.run(['dpkg-deb', '--build', '--root-owner-group', pkg, DEB_OUT], check=True)
info = subprocess.run(['dpkg-deb', '--info', DEB_OUT], capture_output=True, text=True)
print(info.stdout[:600])
print('DEB:', DEB_OUT, os.path.getsize(DEB_OUT), 'bytes')
