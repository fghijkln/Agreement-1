from __future__ import annotations
import base64
import json
import os
import socket
import threading
import time
from pathlib import Path
from .fskey import Identity
from .chat import RelayClient, auth_proof, fingerprint8, _urlopen_retry, delivery_proof
from .ratchet import RatchetSession, HandshakeStale, handshake_age
from . import message as msg
from . import storage
DAEMON_MAGIC = b'NBXDAEMON1'
IPC_VERSION = 1

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip('=')

def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

class ContactSession:

    def __init__(self, daemon: 'Daemon', peer_pub_b64: str):
        self.daemon = daemon
        self.peer_pub = peer_pub_b64
        self.peer_fp = fingerprint8(peer_pub_b64)
        self.session: RatchetSession | None = None
        self.handshake_sent_at = 0.0
        self.speaks_first_flag: bool | None = None

    def ensure_handshake(self) -> None:
        if self.session is not None:
            return
        now = time.time()
        if now - self.handshake_sent_at < 300:
            return
        self.handshake_sent_at = now
        hs = RatchetSession()
        payload = hs.begin(self.daemon.identity, self.daemon.my_fp, self.peer_fp)
        self.daemon._pending_hs[self.peer_fp] = hs
        wire = msg.pack_message(msg.PT_HANDSHAKE, self.daemon.my_fp, self.peer_fp, payload)
        self.daemon.client.post_envelope(wire, delivery_proof(self.daemon.identity, wire))
        self.daemon.log_event(f'握手已发 → {self.peer_fp.hex()}')

    def finish_handshake(self, peer_hs: bytes) -> None:
        hs = self.daemon._pending_hs.pop(self.peer_fp, None)
        if hs is None:
            hs = RatchetSession()
            payload = hs.begin(self.daemon.identity, self.daemon.my_fp, self.peer_fp)
            wire = msg.pack_message(msg.PT_HANDSHAKE, self.daemon.my_fp, self.peer_fp, payload)
            self.daemon.client.post_envelope(wire, delivery_proof(self.daemon.identity, wire))
        hs.finish(self.daemon.identity, self.daemon._peer_ed_pub(self.peer_pub), peer_hs, speaks_first=self.daemon.speaks_first_for(self.peer_pub), expect_sender_fp=self.peer_fp, expect_recv_fp=self.daemon.my_fp)
        self.session = hs
        self.daemon.save_session(self)
        self.daemon.log_event(f'会话建立 ✓ {self.peer_fp.hex()}')
        self.daemon.flush_outbox()

    def send_text(self, text: str) -> dict:
        if self.session is None:
            self.ensure_handshake()
            self.daemon.enqueue_outbox(self.peer_pub, text)
            return {'queued': True, 'note': '无活跃会话：已发握手，消息入 outbox 待自动补发'}
        wire = msg.pack_message(msg.PT_TEXT, self.daemon.my_fp, self.peer_fp, self.session.encrypt(text.encode(), outer_aad=msg.routing_aad(msg.PT_TEXT, self.daemon.my_fp, self.peer_fp)))
        self.daemon.client.post_envelope(wire, delivery_proof(self.daemon.identity, wire))
        self.daemon.log_message('out', self.peer_fp, text)
        self.daemon.save_session(self)
        return {'queued': False}

    def decrypt_incoming(self, body: bytes, sender_fp: bytes=b'', recv_fp: bytes=b'') -> str:
        if self.session is None:
            raise RuntimeError('no active session')
        aad = msg.routing_aad(msg.PT_TEXT, sender_fp, recv_fp) if sender_fp and recv_fp else b''
        text = self.session.decrypt(body, outer_aad=aad).decode('utf-8')
        self.daemon.save_session(self)
        return text

def _progress_of(session) -> tuple[int, int]:
    recv_n = int(getattr(session, 'recv_n', 0) or 0)
    send_n = int(getattr(session, 'send_n', 0) or 0)
    return (recv_n, send_n)

R2_06_BOUNDARY = ("sessions 目录整体回滚(含 epoch log)不受本机制保护, 需外部锚点",)


class Daemon:

    def __init__(self, state_dir: str, relay_url: str, poll_interval: float=3.0, passphrase: str | None=None, storage_secret: bytes | None=None):
        self.state_dir = Path(state_dir).expanduser()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        (self.state_dir / 'messages').mkdir(exist_ok=True)
        (self.state_dir / 'sessions').mkdir(exist_ok=True)
        self.relay_url = relay_url
        self.poll_interval = poll_interval
        id_path = self.state_dir / 'identity.key'
        enc_path = self.state_dir / 'identity.key.enc'
        if enc_path.exists() and passphrase:
            self.identity = Identity.load_encrypted(str(enc_path), passphrase)
        elif id_path.exists():
            self.identity = Identity.load(str(id_path))
            if passphrase:
                self.identity.save_encrypted(str(enc_path), passphrase)
                os.chmod(enc_path, 384)
                id_path.unlink()
        else:
            self.identity = Identity.generate()
            if passphrase:
                self.identity.save_encrypted(str(enc_path), passphrase)
                os.chmod(enc_path, 384)
            else:
                self.identity.save(str(id_path))
                os.chmod(id_path, 384)
        self.my_fp = fingerprint8(self.identity.export_public())
        # 静态加密密钥：默认由身份私钥经 HKDF 域分离派生（身份文件用 passphrase
        # 加密时，状态目录被整体拷走也无法解出会话/历史）；也可显式传入
        # storage_secret（如 keyfile 主密钥）。
        self._migrated: set[Path] = set()
        self._storage_key = storage.derive_storage_key(storage_secret or self.identity.to_bytes(), b'daemon-state')
        self._migrate_at_rest()
        self.client = RelayClient(relay_url)
        self.contacts: dict[str, ContactSession] = {}
        self._pending_hs: dict[bytes, RatchetSession] = {}
        self._pending_texts: dict[bytes, list[bytes]] = {}
        self._stop = threading.Event()
        self._lock = threading.Lock()

    def export_public(self) -> str:
        return self.identity.export_public()

    def add_contact(self, peer_pub_b64: str, speaks_first: bool | None=None) -> ContactSession:
        if peer_pub_b64 not in self.contacts:
            self.contacts[peer_pub_b64] = ContactSession(self, peer_pub_b64)
        if speaks_first is not None:
            self.contacts[peer_pub_b64].speaks_first_flag = speaks_first
        return self.contacts[peer_pub_b64]

    def speaks_first_for(self, peer_pub_b64: str) -> bool:
        cs = self.contacts.get(peer_pub_b64)
        if cs is not None and getattr(cs, 'speaks_first_flag', None) is not None:
            return bool(cs.speaks_first_flag)
        return self.my_fp < fingerprint8(peer_pub_b64)

    def _peer_ed_pub(self, peer_pub_b64: str) -> bytes:
        _, ed = Identity.parse_public(peer_pub_b64)
        return ed

    def _session_path(self, cs: ContactSession) -> Path:
        return self.state_dir / 'sessions' / f'{_b64e(cs.peer_fp)}.session'

    def _epoch_log_path(self, peer_fp: bytes) -> Path:
        return self.state_dir / 'sessions' / f'{_b64e(peer_fp)}.epoch'

    @staticmethod
    def _parse_epoch_lines(text: str) -> list[tuple[int, tuple[int, int]]]:
        out = []
        for line in text.splitlines():
            parts = line.split()
            if len(parts) == 3:
                try:
                    out.append((int(parts[0]), (int(parts[1]), int(parts[2]))))
                except ValueError:
                    continue
        return out

    def save_session(self, cs: ContactSession) -> None:
        if cs.session is None:
            return
        blob = cs.session.export_state()
        sealed = storage.seal(self._storage_key, blob, self._session_ctx(cs.peer_fp))
        storage.atomic_write(self._session_path(cs), sealed)
        recv_n, send_n = _progress_of(cs.session)
        ep = self._epoch_log_path(cs.peer_fp)
        with open(ep, 'a') as f:
            f.write(f'{int(time.time())} {recv_n} {send_n}\n')
        os.chmod(ep, 384)
        with open(ep) as f:
            entries = self._parse_epoch_lines(f.read())
        if len(entries) >= 64:
            last_ts, (lr, ls) = max(entries, key=lambda e: (e[1], e[0]))
            tmp = ep.with_suffix('.tmp')
            tmp.write_text(f'{last_ts} {lr} {ls}\n')
            os.replace(tmp, ep)
            os.chmod(ep, 384)

    def load_session(self, cs: ContactSession) -> None:
        p = self._session_path(cs)
        if not p.exists() or cs.session is not None:
            return
        raw = p.read_bytes()
        if storage.is_sealed(raw):
            raw = storage.open_sealed(self._storage_key, raw, self._session_ctx(cs.peer_fp))
        # else: 旧版明文状态，照常导入；下次 save_session 以加密格式覆盖（迁移）
        rs = RatchetSession.import_state(raw)
        ep = self._epoch_log_path(cs.peer_fp)
        if ep.exists():
            with open(ep) as f:
                entries = self._parse_epoch_lines(f.read())
            if entries:
                _, last = max(entries, key=lambda e: (e[1], e[0]))
                progress = _progress_of(rs)
                if progress < last:
                    raise RuntimeError(f'session state rollback detected for peer {_b64e(cs.peer_fp)}: state progress {progress} < epoch log {last} — refusing to load (possible restore attack; delete BOTH files to reset)')
        cs.session = rs

    @staticmethod
    def _session_ctx(peer_fp: bytes) -> bytes:
        return b'session|' + peer_fp

    @staticmethod
    def _jsonl_ctx(path: Path) -> bytes:
        return b'jsonl|' + path.name.encode('utf-8')

    def _read_jsonl(self, path: Path) -> list[tuple[dict, str]]:
        """读取 jsonl：兼容旧明文行与新加密行；认证失败的行丢弃并记事件。"""
        out = []
        ctx = self._jsonl_ctx(path)
        bad = 0
        for line in path.read_text(encoding='utf-8').splitlines():
            if not line.strip():
                continue
            try:
                if storage.is_sealed_line(line):
                    out.append((json.loads(storage.open_line(self._storage_key, line, ctx)), line))
                else:
                    out.append((json.loads(line), storage.seal_line(self._storage_key, line, ctx)))
            except (storage.StorageError, ValueError):
                bad += 1
        if bad:
            self.log_event(f'{path.name}: {bad} 条记录认证失败已忽略')
        return out

    def _migrate_jsonl(self, path: Path) -> None:
        if path in self._migrated or not path.exists():
            return
        lines = path.read_text(encoding='utf-8').splitlines()
        if all(storage.is_sealed_line(l) or not l.strip() for l in lines):
            os.chmod(path, 0o600)
        else:
            ctx = self._jsonl_ctx(path)
            new = [l if storage.is_sealed_line(l) else storage.seal_line(self._storage_key, l, ctx) for l in lines if l.strip()]
            storage.atomic_write(path, ''.join(l + '\n' for l in new).encode('utf-8'))
        self._migrated.add(path)

    def _migrate_at_rest(self) -> None:
        """把旧版明文的消息历史 / outbox / 会话状态迁移为加密格式。"""
        for f in sorted((self.state_dir / 'messages').glob('*.jsonl')):
            self._migrate_jsonl(f)
        self._migrate_jsonl(self._outbox_path())
        for f in sorted((self.state_dir / 'sessions').glob('*.session')):
            raw = f.read_bytes()
            if storage.is_sealed(raw):
                continue
            try:
                peer_fp = _b64d(f.stem)
                RatchetSession.import_state(raw)
            except Exception:
                continue  # 损坏的旧文件原样保留，由 load_session 报错
            storage.atomic_write(f, storage.seal(self._storage_key, raw, self._session_ctx(peer_fp)))

    def _append_sealed(self, path: Path, record: dict) -> None:
        self._migrate_jsonl(path)
        line = storage.seal_line(self._storage_key, json.dumps(record, ensure_ascii=False), self._jsonl_ctx(path))
        storage.append_line(path, line)

    def log_message(self, direction: str, peer_fp: bytes, text: str) -> None:
        day = time.strftime('%Y-%m-%d')
        entry = {'ts': time.time(), 'dir': direction, 'peer': _b64e(peer_fp), 'text': text}
        self._append_sealed(self.state_dir / 'messages' / f'{day}.jsonl', entry)

    def log_event(self, text: str) -> None:
        day = time.strftime('%Y-%m-%d')
        entry = {'ts': time.time(), 'event': text}
        with open(self.state_dir / 'events.log', 'a') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')

    def _outbox_path(self) -> Path:
        return self.state_dir / 'outbox.jsonl'

    def enqueue_outbox(self, peer_pub: str, text: str) -> None:
        entry = {'ts': time.time(), 'pub': peer_pub, 'text': text}
        self._append_sealed(self._outbox_path(), entry)

    def flush_outbox(self) -> int:
        p = self._outbox_path()
        if not p.exists():
            return 0
        remain = []
        sent = 0
        for e, sealed_line in self._read_jsonl(p):
            cs = self.contacts.get(e['pub'])
            if cs is not None and cs.session is not None:
                cs.send_text(e['text'])
                sent += 1
            else:
                remain.append(sealed_line)
        storage.atomic_write(p, ''.join(l + '\n' for l in remain).encode('utf-8'))
        if sent:
            self.log_event(f'outbox 补发 {sent} 条')
        return sent

    def history(self, peer_pub_b64: str, limit: int=50) -> list[dict]:
        cs = self.contacts.get(peer_pub_b64)
        if cs is None:
            return []
        want = _b64e(cs.peer_fp)
        out = []
        for day_file in sorted((self.state_dir / 'messages').glob('*.jsonl'), reverse=True):
            for e, _ in reversed(self._read_jsonl(day_file)):
                if e.get('peer') == want:
                    out.append(e)
                    if len(out) >= limit:
                        return list(reversed(out))
        return list(reversed(out))

    def _poll_once(self) -> None:
        try:
            blobs = self.client.fetch(self.my_fp, auth_proof(self.identity, self.my_fp))
        except Exception as e:
            self.log_event(f'poll 失败: {type(e).__name__}')
            return
        for blob in blobs:
            try:
                self._handle_envelope(blob)
            except Exception as e:
                self.log_event(f'信封处理失败: {type(e).__name__}: {e}')

    def _handle_envelope(self, blob: bytes) -> None:
        m = msg.parse_message(blob)
        peer_fp = m['sender_fp']
        cs = None
        for c in self.contacts.values():
            if c.peer_fp == peer_fp:
                cs = c
                break
        if cs is None:
            self.log_event(f'未知发件人 {peer_fp.hex()}，信封丢弃')
            return
        self.load_session(cs)
        if m['ptype'] == msg.PT_HANDSHAKE:
            try:
                handshake_age(m['body'])
            except HandshakeStale:
                self.log_event(f'丢弃过期握手 from {peer_fp.hex()}')
                return
            cs.finish_handshake(m['body'])
            return
        if m['ptype'] == msg.PT_TEXT:
            if cs.session is None:
                self._pending_texts.setdefault(peer_fp, []).append(blob)
                self.log_event(f'TEXT 先于握手，暂缓 {peer_fp.hex()}')
                return
            try:
                text = cs.decrypt_incoming(m['body'], m['sender_fp'], m['recv_fp'])
            except Exception:
                self.log_event(f'TEXT 解密失败 from {peer_fp.hex()}（旧代残留?）')
                return
            self.log_message('in', peer_fp, text)
            self._on_message(cs, text)

    def _on_message(self, cs: ContactSession, text: str) -> None:
        pass

    def poll_loop(self) -> None:
        while not self._stop.is_set():
            self._poll_once()
            self._stop.wait(self.poll_interval)

    def handle_ipc(self, req: dict) -> dict:
        cmd = req.get('cmd')
        if cmd == 'status':
            return {'ok': True, 'fp': _b64e(self.my_fp), 'relay': self.relay_url, 'contacts': list(self.contacts.keys())}
        if cmd == 'add_contact':
            cs = self.add_contact(req['pub'])
            return {'ok': True, 'fp': _b64e(cs.peer_fp)}
        if cmd == 'send':
            cs = self.add_contact(req['pub'])
            self.load_session(cs)
            return {'ok': True, **cs.send_text(req['text'])}
        if cmd == 'history':
            return {'ok': True, 'items': self.history(req['pub'], req.get('limit', 50))}
        return {'ok': False, 'error': f'unknown cmd {cmd}'}

    def serve_ipc(self, sock_path: str | None=None) -> None:
        sock_path = sock_path or str(self.state_dir / 'daemon.sock')
        if os.path.exists(sock_path):
            os.unlink(sock_path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        os.chmod(sock_path, 384)
        srv.listen(4)
        self.log_event(f'IPC 就绪 {sock_path}')
        while not self._stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            with conn:
                data = conn.recv(65536)
                if not data:
                    continue
                try:
                    req = json.loads(data)
                    resp = self.handle_ipc(req)
                except Exception as e:
                    resp = {'ok': False, 'error': f'{type(e).__name__}: {e}'}
                conn.sendall(json.dumps(resp, ensure_ascii=False).encode())
        srv.close()

    def start(self) -> None:
        self.client.auth(self.identity, self.my_fp)
        threading.Thread(target=self.poll_loop, daemon=True).start()
        threading.Thread(target=self.serve_ipc, daemon=True).start()
        self.log_event(f'daemon 启动 fp={_b64e(self.my_fp)} relay={self.relay_url}')

    def stop(self) -> None:
        self._stop.set()
