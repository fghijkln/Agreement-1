"""静态加密（at-rest encryption）工具：棘轮会话状态、消息历史、outbox 落盘加密。

格式（版本头 + AEAD）::

    MAGIC(8) = b'NBXSEAL1' | VER(1) = 0x01 | NONCE(12) | ChaCha20-Poly1305(ct||tag)

AAD = MAGIC + VER + context，context 由调用方给出（例如 b'session|' + peer_fp），
把密文绑定到用途/位置，防止把一个文件的密文挪到另一个位置复用。

密钥由调用方的长期秘密（daemon 身份私钥 / keyfile 主密钥）经 HKDF-SHA256 派生，
与传输层密钥做域分离（info=b'nbx-at-rest-v1|' + purpose）。

兼容：`is_sealed()` 判断是否为新格式；不是则调用方按旧明文读取，并在下次写入时
以新格式落盘（迁移）。
"""
from __future__ import annotations

import base64
import os
import secrets
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b'NBXSEAL1'
VERSION = 1
NONCE_SIZE = 12
HEADER_SIZE = len(MAGIC) + 1 + NONCE_SIZE
# 文本行格式前缀（jsonl 中逐行加密时使用）
LINE_PREFIX = 'nbxseal1:'


class StorageError(ValueError):
    """静态加密数据无法解开（篡改、密钥不对、版本不支持）。"""


def derive_storage_key(secret: bytes, purpose: bytes = b'state') -> bytes:
    if not secret:
        raise ValueError('empty secret for storage key derivation')
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b'nbx-at-rest-v1|' + purpose).derive(secret)


def is_sealed(blob: bytes) -> bool:
    return blob[:len(MAGIC)] == MAGIC


def seal(key: bytes, data: bytes, context: bytes = b'') -> bytes:
    header = MAGIC + bytes([VERSION])
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = ChaCha20Poly1305(key).encrypt(nonce, data, header + context)
    return header + nonce + ct


def open_sealed(key: bytes, blob: bytes, context: bytes = b'') -> bytes:
    if not is_sealed(blob):
        raise StorageError('not a sealed blob')
    if len(blob) < HEADER_SIZE + 16:
        raise StorageError('sealed blob truncated')
    ver = blob[len(MAGIC)]
    if ver != VERSION:
        raise StorageError(f'unsupported sealed blob version {ver}')
    header = blob[:len(MAGIC) + 1]
    nonce = blob[len(MAGIC) + 1:HEADER_SIZE]
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, blob[HEADER_SIZE:], header + context)
    except InvalidTag:
        raise StorageError('sealed blob authentication failed (tampered or wrong key)') from None


def seal_line(key: bytes, text: str, context: bytes = b'') -> str:
    return LINE_PREFIX + base64.b64encode(seal(key, text.encode('utf-8'), context)).decode('ascii')


def is_sealed_line(line: str) -> bool:
    return line.startswith(LINE_PREFIX)


def open_line(key: bytes, line: str, context: bytes = b'') -> str:
    if not is_sealed_line(line):
        raise StorageError('not a sealed line')
    try:
        blob = base64.b64decode(line[len(LINE_PREFIX):], validate=True)
    except (ValueError, TypeError):
        raise StorageError('sealed line not valid base64') from None
    return open_sealed(key, blob, context).decode('utf-8')


def atomic_write(path, data: bytes, mode: int = 0o600) -> None:
    """同目录临时文件 + fsync + os.replace；临时文件创建即为 0600。"""
    path = os.fspath(path)
    directory = os.path.dirname(os.path.abspath(path)) or '.'
    fd, tmp = tempfile.mkstemp(dir=directory, prefix='.nbx_', suffix='.tmp')
    try:
        if hasattr(os, 'fchmod'):
            os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        os.chmod(path, mode)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def append_line(path, line: str, mode: int = 0o600) -> None:
    """以 0600 创建/追加一行（单次 write，O_APPEND）。"""
    path = os.fspath(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, mode)
    try:
        os.write(fd, (line + '\n').encode('utf-8'))
    finally:
        os.close(fd)
    os.chmod(path, mode)
