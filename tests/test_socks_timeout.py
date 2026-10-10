import socket
import threading
import time

import pytest

from nbx.contacts import ContactBook, TransportStack
from nbx.fskey import Identity


def _serve_once(handler):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            handler(conn)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            try:
                srv.close()
            except OSError:
                pass

    threading.Thread(target=run, daemon=True).start()
    return port


def _stack(tmp_path, port, **kwargs):
    book = ContactBook(str(tmp_path / 'c.json'))
    stack = TransportStack(book, Identity.generate(), socks_proxy=f'127.0.0.1:{port}', **kwargs)
    return book, stack


def _blackhole(conn):
    time.sleep(30)


def _socks_ok_then_silent(conn):
    conn.recv(3)
    conn.sendall(b'\x05\x00')
    conn.recv(32)
    conn.sendall(b'\x05\x00\x00\x01' + b'\x00' * 6)
    time.sleep(30)


def _one_byte_then_close(conn):
    conn.recv(3)
    conn.sendall(b'\x05')


def test_socks_connect_blackhole_times_out(tmp_path):
    port = _serve_once(_blackhole)
    _, stack = _stack(tmp_path, port, socks_timeout=0.5)
    start = time.monotonic()
    with pytest.raises((OSError, TimeoutError, ConnectionError)):
        stack._socks_connect('x.onion', 80)
    assert time.monotonic() - start < 3


def test_send_via_anon_blackhole_returns_false(tmp_path):
    port = _serve_once(_blackhole)
    book, stack = _stack(tmp_path, port, socks_timeout=0.5)
    contact = book.add(Identity.generate().export_public())
    start = time.monotonic()
    result = stack._send_via_anon(contact, 'x.onion:80', b'blob')
    assert result.ok is False
    assert time.monotonic() - start < 3


def test_send_via_anon_post_connect_silence_deadline(tmp_path):
    port = _serve_once(_socks_ok_then_silent)
    book, stack = _stack(tmp_path, port, socks_timeout=0.5, io_deadline=1.0)
    contact = book.add(Identity.generate().export_public())
    start = time.monotonic()
    result = stack._send_via_anon(contact, 'x.onion:80', b'blob')
    assert result.ok is False
    assert time.monotonic() - start < 3


def test_short_socks_reply_raises_connection_error(tmp_path):
    port = _serve_once(_one_byte_then_close)
    _, stack = _stack(tmp_path, port, socks_timeout=0.5)
    with pytest.raises(ConnectionError):
        stack._socks_connect('x.onion', 80)


def _socks_domain_reply_then_http(conn):
    conn.recv(3)
    conn.sendall(b'\x05\x00')
    conn.recv(64)
    conn.sendall(b'\x05\x00\x00\x03' + bytes([7]) + b'x.onion' + b'\x00\x50')
    conn.recv(65536)
    conn.sendall(b'HTTP/1.0 202 Accepted\r\n\r\n')


def test_socks_domain_reply_fully_consumed(tmp_path):
    """ATYP=domain 的回复长度可变：必须读完，不能把残留字节当成 HTTP 状态行。"""
    port = _serve_once(_socks_domain_reply_then_http)
    book, stack = _stack(tmp_path, port, socks_timeout=2, io_deadline=3)
    contact = book.add(Identity.generate().export_public())
    result = stack._send_via_anon(contact, 'x.onion:80', b'blob')
    assert result.ok is True, result.detail


def test_timeouts_default_and_configurable(tmp_path):
    book = ContactBook(str(tmp_path / 'c.json'))
    st = TransportStack(book, Identity.generate())
    assert st.socks_timeout == 10.0 and st.io_deadline == 30.0
