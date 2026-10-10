from nbx.daemon import Daemon


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


def test_pending_texts_is_instance_state(tmp_path):
    a = mk_daemon(tmp_path, 'a')
    b = mk_daemon(tmp_path, 'b')

    assert '_pending_texts' not in Daemon.__dict__, '不得再是类属性'
    assert not hasattr(Daemon, '_pending_texts')
    assert isinstance(a._pending_texts, dict)
    assert isinstance(b._pending_texts, dict)
    assert a._pending_texts is not b._pending_texts

    a._pending_texts[b'peer' * 2] = [b'blob']
    assert a._pending_texts.get(b'peer' * 2) == [b'blob']
    assert b._pending_texts.get(b'peer' * 2) is None
    assert b._pending_texts == {}
