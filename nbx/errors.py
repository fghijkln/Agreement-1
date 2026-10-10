"""对外错误文案统一化（审计 T4 信息级：日志/错误信息泄露内部细节）。

规则：
- 用户可见 / 对端可见 / 落盘事件日志 只给 **固定文案 + 粗分类**，不含异常原文、堆栈、
  密钥材料、文件路径、地址。
- 详细信息（异常类型、原文、堆栈）只在 logging DEBUG 级别输出到 logger 'nbx'。
  设置环境变量 NBX_DEBUG=1（或调用 enable_debug()）可在 stderr 看到。
"""
from __future__ import annotations

import logging
import os
import socket

from cryptography.exceptions import InvalidSignature, InvalidTag

logger = logging.getLogger('nbx')

CATEGORY_AUTH = 'authentication or integrity check failed'
CATEGORY_TIMEOUT = 'timed out'
CATEGORY_NETWORK = 'network error'
CATEGORY_FORMAT = 'malformed input'
CATEGORY_STATE = 'local state error'
CATEGORY_INTERNAL = 'internal error'


def classify(exc: BaseException) -> str:
    if isinstance(exc, (InvalidTag, InvalidSignature)):
        return CATEGORY_AUTH
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return CATEGORY_TIMEOUT
    if isinstance(exc, (ConnectionError, OSError)):
        # FileNotFoundError/PermissionError 等也是 OSError：归为本地状态
        if isinstance(exc, (FileNotFoundError, PermissionError, IsADirectoryError)):
            return CATEGORY_STATE
        return CATEGORY_NETWORK
    if isinstance(exc, (ValueError, KeyError, IndexError, UnicodeError)):
        return CATEGORY_FORMAT
    if isinstance(exc, RuntimeError):
        return CATEGORY_STATE
    return CATEGORY_INTERNAL


def public_message(context: str, exc: BaseException) -> str:
    """返回可对外展示的固定文案；把细节写到 DEBUG 日志。"""
    logger.debug('%s: %s: %s', context, type(exc).__name__, exc, exc_info=exc)
    return f'{context}: {classify(exc)}'


def enable_debug() -> None:
    if not logger.handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter('[nbx debug] %(message)s'))
        logger.addHandler(h)
    logger.setLevel(logging.DEBUG)


def maybe_enable_debug_from_env() -> None:
    if os.environ.get('NBX_DEBUG', '').strip() not in ('', '0', 'false', 'no'):
        enable_debug()
