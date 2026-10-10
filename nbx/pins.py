from __future__ import annotations
import base64
import binascii
import hashlib
import json
import os
import sys
import tempfile

PINS_ENV = 'NBX_SENDER_PINS'
DEFAULT_PINS_FILE = os.path.join(os.path.expanduser('~'), '.nbx_sender_pins.json')


def default_pins_path() -> str:
    return os.environ.get(PINS_ENV) or os.path.join(os.path.expanduser('~'), '.nbx_sender_pins.json')


def pubkey_fingerprint(pub_text: str) -> str:
    raw = base64.b64decode(''.join(pub_text.split()), validate=True)
    if not raw:
        raise ValueError('empty public key material')
    return hashlib.sha256(raw).digest()[:8].hex()


def _normalize_fp(fp: str) -> str:
    return ''.join(fp.split()).replace(':', '').lower()


class PinStore:
    def __init__(self, path: str | None = None):
        self.path = path or default_pins_path()
        self.pins = self._load()

    def _load(self) -> dict:
        try:
            with open(self.path, 'r', encoding='utf-8') as f:
                raw = f.read()
        except FileNotFoundError:
            return {}
        except OSError as e:
            raise ValueError(f'cannot read sender pin file {self.path}: {e}')
        if not raw.strip():
            return {}
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f'corrupt sender pin file {self.path} (refusing to overwrite): {e}')
        if not isinstance(data, dict):
            raise ValueError(f'corrupt sender pin file {self.path} (expected JSON object)')
        clean = {}
        for name, fp in data.items():
            if isinstance(name, str) and isinstance(fp, str):
                clean[name] = _normalize_fp(fp)
        return clean

    def _save(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path)) or '.'
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix='.nbx_pins_', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(self.pins, f, ensure_ascii=False, sort_keys=True)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
            os.chmod(self.path, 0o600)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def trust(self, name: str, fp: str) -> None:
        fp = _normalize_fp(fp)
        existing = self.pins.get(name)
        if existing is None:
            self.pins[name] = fp
            self._save()
            print(f'[nbx] 首次信任发送方 {name}，指纹={fp}，请带外核对', file=sys.stderr)
            return
        if existing != fp:
            raise ValueError(
                f'发送方 {name} 指纹不一致：期望={existing} 实际={fp}。'
                f'若对方确实轮换了密钥，请带外核对后用 --from-fp 显式指定，'
                f'或删除 pin 文件 {self.path} 以重新信任')
