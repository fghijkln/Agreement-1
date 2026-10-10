"""审计 T4（信息级）：对外/用户可见错误不含异常原文、堆栈、密钥材料、路径；细节仅 DEBUG。"""
import json
import logging

import pytest
from cryptography.exceptions import InvalidTag

from nbx import cli, errors, fskey
from nbx.daemon import Daemon

SECRET = 'SECRET-KEY-MATERIAL-/home/user/.nbx/identity.key'


def test_public_message_fixed_text_and_debug_detail(caplog):
    with caplog.at_level(logging.DEBUG, logger='nbx'):
        msg = errors.public_message('ctx', ValueError(SECRET))
    assert msg == 'ctx: ' + errors.CATEGORY_FORMAT
    assert SECRET not in msg and 'Traceback' not in msg
    assert any(SECRET in r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG)


def test_public_message_silent_at_info(caplog):
    with caplog.at_level(logging.INFO, logger='nbx'):
        errors.public_message('ctx', ValueError(SECRET))
    assert not any(SECRET in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize('exc,cat', [
    (InvalidTag(), errors.CATEGORY_AUTH),
    (TimeoutError('x'), errors.CATEGORY_TIMEOUT),
    (ConnectionRefusedError('x'), errors.CATEGORY_NETWORK),
    (FileNotFoundError('/etc/x'), errors.CATEGORY_STATE),
    (KeyError('k'), errors.CATEGORY_FORMAT),
    (Exception('x'), errors.CATEGORY_INTERNAL),
])
def test_classify(exc, cat):
    assert errors.classify(exc) == cat


class _BoomClient:
    def auth(self, *a, **k):
        pass

    def post_envelope(self, *a, **k):
        return {'ok': True}

    def fetch(self, fp, proof):
        raise ConnectionError(SECRET)


def test_daemon_events_log_has_no_exception_detail(tmp_path):
    d = Daemon(str(tmp_path / 'd'), 'http://fake')
    d.client = _BoomClient()
    d._poll_once()

    class _C(_BoomClient):
        def fetch(self, fp, proof):
            return [b'\x00garbage' + SECRET.encode()]
    d.client = _C()
    d._poll_once()
    log = (d.state_dir / 'events.log').read_text(encoding='utf-8')
    assert SECRET not in log
    assert 'Traceback' not in log
    events = [json.loads(l)['event'] for l in log.splitlines()]
    assert any(e.startswith('poll 失败: ') for e in events)
    assert any(e.startswith('信封处理失败: ') for e in events)


def test_daemon_ipc_error_has_no_exception_detail(tmp_path):
    d = Daemon(str(tmp_path / 'd'), 'http://fake')

    def boom(req):
        raise ValueError(SECRET)
    d.handle_ipc = boom
    resp = d._ipc_dispatch(b'{"cmd": "status"}')
    assert resp['ok'] is False
    assert SECRET not in resp['error'] and 'ValueError' not in resp['error']
    bad = d._ipc_dispatch(b'not json ' + SECRET.encode())
    assert bad['ok'] is False and SECRET not in bad['error']


def test_cli_unseal_error_is_generic(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.delenv('NBX_REPLAY_CACHE', raising=False)
    monkeypatch.delenv('NBX_DEBUG', raising=False)
    snd, rec = fskey.Identity.generate(), fskey.Identity.generate()
    rec.save(str(tmp_path / 'r.key'))
    (tmp_path / 's.pub').write_text(snd.export_public())
    (tmp_path / 'env').write_bytes(b'\x00' * 200)  # 垃圾信封
    with pytest.raises(SystemExit) as ei:
        cli.main(['unseal', str(tmp_path / 'env'), str(tmp_path / 'o'), '--my-id', str(tmp_path / 'r.key'),
                  '--from-pub', str(tmp_path / 's.pub'), '--pins', str(tmp_path / 'p.json')])
    msg = str(ei.value)
    assert msg == 'unseal failed: wrong key, tampered, replayed or expired envelope'
    assert 'Invalid' not in msg and str(tmp_path) not in msg
    assert 'Traceback' not in capsys.readouterr().err


def test_transport_detail_has_no_exception_text(tmp_path):
    from nbx.contacts import ContactBook, TransportStack
    book = ContactBook(str(tmp_path / 'c.json'))
    st = TransportStack(book, fskey.Identity.generate())
    c = book.add(fskey.Identity.generate().export_public())
    r = st._send_via_p2p(c, '127.0.0.1:1', b'x')
    assert r.ok is False
    assert r.detail.startswith('p2p send: ')
    assert '127.0.0.1' not in r.detail and 'Errno' not in r.detail
