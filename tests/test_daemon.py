import json
import time
import pytest
from nbx.daemon import Daemon, ContactSession

class OfflineClient:

    def __init__(self):
        self.posted: list[bytes] = []
        self.inbox: list[bytes] = []

    def auth(self, *a, **k):
        pass

    def post_envelope(self, blob, proof=None):
        self.posted.append(blob)
        return {'ok': True}

    def fetch(self, fp, proof):
        out, self.inbox = (self.inbox, [])
        return out

def mk_daemon(tmp_path, name):
    d = Daemon(str(tmp_path / name), 'http://fake', poll_interval=999)
    d.client = OfflineClient()
    return d

def test_async_handshake_and_outbox(tmp_path):
    a = mk_daemon(tmp_path, 'a')
    b = mk_daemon(tmp_path, 'b')
    pub_a, pub_b = (a.export_public(), b.export_public())
    a.add_contact(pub_b)
    b.add_contact(pub_a)
    r = a.handle_ipc({'cmd': 'send', 'pub': pub_b, 'text': 'hello-async'})
    assert r['queued'] is True
    assert len(a.client.posted) == 1
    assert a._outbox_path().read_text().count('hello-async') == 1
    a_hs = a.client.posted[0]
    b.client.inbox = [a_hs]
    b.my_fp = __import__('nbx.chat', fromlist=['fingerprint8']).fingerprint8(b.export_public())
    b._poll_once()
    hs_back = [p for p in b.client.posted if p != a_hs]
    assert len(hs_back) == 1, 'B 必须回发自己的握手'
    assert len(list((b.state_dir / 'sessions').glob('*.session'))) == 1

def test_speaks_first_deterministic(tmp_path):
    a = mk_daemon(tmp_path, 'a')
    b = mk_daemon(tmp_path, 'b')
    pa, pb = (a.export_public(), b.export_public())
    a.add_contact(pb)
    b.add_contact(pa)
    assert a.speaks_first_for(pb) != b.speaks_first_for(pa), '双方判定必须互补（恰好一方先发）'

def test_outbox_flush_order(tmp_path):
    a = mk_daemon(tmp_path, 'a')
    pub_b = 'CDGghF7TbQkhGbp3mSMkd123wRaMQrdgZNCcZGxXzimsmUH6yaNE4fbAp56QEtd+jDHSvjHkQZ7WmoiWWRJnYw=='
    a.add_contact(pub_b)
    a.enqueue_outbox(pub_b, 'msg1')
    a.enqueue_outbox(pub_b, 'msg2')
    cs = a.contacts[pub_b]
    from nbx.ratchet import RatchetSession
    rs = RatchetSession()
    rs.begin(a.identity)
    import nbx.chat as chat
    peer_x, peer_ed = __import__('nbx.fskey', fromlist=['Identity']).Identity.parse_public(pub_b)

    class StubSession:

        def encrypt(self, data, outer_aad=b''):
            return b'x' * 40

        def export_state(self):
            return b'stub'
    cs.session = StubSession()
    n = a.flush_outbox()
    assert n == 2
    assert not a._outbox_path().exists() or a._outbox_path().read_text().strip() == ''

def test_history_persisted(tmp_path):
    a = mk_daemon(tmp_path, 'a')
    pub_b = 'CDGghF7TbQkhGbp3mSMkd123wRaMQrdgZNCcZGxXzimsmUH6yaNE4fbAp56QEtd+jDHSvjHkQZ7WmoiWWRJnYw=='
    cs = a.add_contact(pub_b)
    a.log_message('out', cs.peer_fp, '记录一')
    a.log_message('in', cs.peer_fp, '记录二')
    items = a.handle_ipc({'cmd': 'history', 'pub': pub_b})['items']
    assert [i['text'] for i in items] == ['记录一', '记录二']
