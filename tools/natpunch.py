from __future__ import annotations
import argparse
import os
import socket
import struct
import sys
import time
STUN_SERVERS = [('stun.l.google.com', 19302), ('stun1.l.google.com', 19302), ('stun.cloudflare.com', 3478)]
MAGIC_COOKIE = 554869826

def stun_query(sock: socket.socket, server: str, port: int, timeout: float=4.0):
    tid = os.urandom(12)
    pkt = struct.pack('>HHI', 1, 0, MAGIC_COOKIE) + tid
    try:
        sock.sendto(pkt, (server, port))
    except OSError:
        return None
    deadline = time.time() + timeout
    while time.time() < deadline:
        sock.settimeout(max(0.1, deadline - time.time()))
        try:
            data, _ = sock.recvfrom(2048)
        except socket.timeout:
            return None
        except OSError:
            return None
        if len(data) < 20:
            continue
        if struct.unpack('>H', data[:2])[0] != 257:
            continue
        if struct.unpack('>I', data[4:8])[0] != MAGIC_COOKIE:
            continue
        i = 20
        while i + 4 <= len(data):
            t, ln = struct.unpack('>HH', data[i:i + 4])
            val = data[i + 4:i + 4 + ln]
            if t == 32 and len(val) >= 8:
                port_v = struct.unpack('>H', val[2:4])[0] ^ 8466
                ip = bytes((b ^ m for b, m in zip(val[4:8], struct.pack('>I', MAGIC_COOKIE))))
                return (socket.inet_ntoa(ip), port_v)
            if t == 1 and len(val) >= 8:
                port_v = struct.unpack('>H', val[2:4])[0]
                return (socket.inet_ntoa(val[4:8]), port_v)
            i += 4 + ln + (4 - ln % 4) % 4
    return None

def discover(sock: socket.socket) -> dict:
    print('探测公网映射（同一 socket，逐个 STUN 服务器）…')
    results = []
    for host, port in STUN_SERVERS:
        try:
            r = stun_query(sock, host, port)
        except Exception as e:
            r = None
            print(f'  {host}:{port}  失败: {e}')
        else:
            print(f'  {host}:{port}  ->  {r}')
        results.append((host, port, r))
    ok = [r for _, _, r in results if r]
    if not ok:
        print('\n[!] 所有 STUN 都失败：UDP 出站可能被封。无法自动探测。')
        print('    可手工填入映射，或用 --peer 直接打洞试试。')
        return {'mapping': None, 'nat': 'unknown'}
    mapping = ok[0]
    ips = {r[0] for r in ok}
    ports = {r[1] for r in ok}
    if len(ports) == 1:
        nat = 'cone'
    else:
        nat = 'symmetric'
    print(f'\n  MY MAPPING: {mapping[0]}:{mapping[1]}')
    print(f"  映射端口跨 {len(ok)} 个目标: {('一致 → 锥型 NAT（可打洞）' if nat == 'cone' else '变化 → 对称 NAT（打洞难）')}")
    return {'mapping': mapping, 'nat': nat}

def punch(sock: socket.socket, peer_ip: str, peer_port: int, seconds: float=25.0) -> dict:
    peer = (peer_ip, int(peer_port))
    sock.settimeout(0.25)
    t0 = time.time()
    sent = 0
    inbound = 0
    first_in = None
    success = False
    print(f'开始打洞 -> {peer}，持续 {seconds:.0f}s（对端须同时在打）…')
    while time.time() - t0 < seconds:
        try:
            sock.sendto(b'NBX_PUNCH', peer)
            sent += 1
        except OSError:
            pass
        while True:
            try:
                data, addr = sock.recvfrom(2048)
            except (socket.timeout, OSError):
                break
            if addr[0] != peer_ip:
                continue
            if data.startswith(b'NBX_PUNCH'):
                try:
                    sock.sendto(b'NBX_PONG', addr)
                except OSError:
                    pass
                inbound += 1
                if not success:
                    success = True
                    first_in = time.time() - t0
                    print(f'\n[+] 收到对端入站包 from {addr[0]}:{addr[1]} （第 {sent} 次发送后，{first_in:.2f}s）→ 打洞成功')
            elif data.startswith(b'NBX_PONG'):
                inbound += 1
                if not success:
                    success = True
                    first_in = time.time() - t0
                    print(f'\n[+] 收到对端 PONG（{first_in:.2f}s）→ 双向直连成功')
        time.sleep(0.05)
    if not success:
        print(f'\n[-] 打洞失败：发出 {sent} 包，收到 0 入站包。')
        print('    常见原因：对端是对称 NAT / 未同时开始 / 运营商封 UDP。')
    return {'success': success, 'sent': sent, 'inbound': inbound, 'first_inbound_s': round(first_in, 2) if first_in else None}

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description='NBX UDP 打洞实测')
    ap.add_argument('--peer', help='对端映射 IP:PORT（打洞模式）')
    ap.add_argument('--port', type=int, default=0, help='绑定本地端口（默认随机）')
    ap.add_argument('--seconds', type=float, default=25.0, help='打洞持续秒数')
    ap.add_argument('--no-stun', action='store_true', help='跳过 STUN 探测')
    args = ap.parse_args(argv)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', args.port))
    local = sock.getsockname()
    print(f'本地 UDP 端口: {local[1]}')
    if not args.no_stun:
        info = discover(sock)
        if info['mapping'] is None and (not args.peer):
            print('\n没有可用映射，退出。')
            sock.close()
            return 1
    if not args.peer:
        print('\n下一步：把上面 MY MAPPING 这一行发给对端，')
        print('拿到对方的后运行：')
        print(f'  python3 {sys.argv[0]} --peer <对方IP>:<对方端口>')
        sock.close()
        return 0
    host, _, port = args.peer.rpartition(':')
    if not host:
        print(f'--peer 格式应为 IP:PORT，收到 {args.peer!r}')
        sock.close()
        return 2
    res = punch(sock, host, int(port), seconds=args.seconds)
    sock.close()
    return 0 if res['success'] else 1
if __name__ == '__main__':
    raise SystemExit(main())
