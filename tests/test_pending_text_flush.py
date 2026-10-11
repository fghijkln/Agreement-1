from nbx import message as msg
from nbx.daemon import Daemon


class OfflineClient:
    def __init__(self):
        self.posted = []
        self.inbox = []

    def post_envelope(self, blob, proof=None):
        self.posted.append(blob)
        return {'ok': True}

    def fetch(self, fp, proof):
        out, self.inbox = self.inbox, []
        return out


def _mk_daemon(tmp_path, name):
    daemon = Daemon(str(tmp_path / name), 'http://fake', poll_interval=999)
    daemon.client = OfflineClient()
    return daemon


def test_text_received_before_handshake_is_processed_before_outbox_flush(tmp_path):
    a = _mk_daemon(tmp_path, 'a')
    b = _mk_daemon(tmp_path, 'b')
    pub_a, pub_b = a.export_public(), b.export_public()
    a_cs, b_cs = a.add_contact(pub_b), b.add_contact(pub_a)

    # 两边先各自发出握手；确定由哪边先发首条 ratchet 消息。
    a_cs.ensure_handshake()
    b_cs.ensure_handshake()
    a_hs, b_hs = a.client.posted[0], b.client.posted[0]
    if a.speaks_first_for(pub_b):
        sender, receiver = a, b
        sender_cs, receiver_cs = a_cs, b_cs
        sender_hs, receiver_hs = a_hs, b_hs
        sender_pub = pub_a
    else:
        sender, receiver = b, a
        sender_cs, receiver_cs = b_cs, a_cs
        sender_hs, receiver_hs = b_hs, a_hs
        sender_pub = pub_b

    sender_cs.finish_handshake(msg.parse_message(receiver_hs)['body'])
    sender_cs.send_text('pre-handshake text')
    text_wire = sender.client.posted[-1]

    # 收件方已有一条待发消息；若先 flush outbox，会推进 ratchet，导致先到 TEXT 无法解密。
    receiver.enqueue_outbox(sender_pub, 'queued reply')
    received = []
    receiver._on_message = lambda cs, text: received.append(text)
    receiver._handle_envelope(text_wire)
    assert receiver._pending_texts[receiver_cs.peer_fp] == [text_wire]
    assert received == []

    receiver._handle_envelope(sender_hs)

    assert received == ['pre-handshake text']
    assert receiver_cs.peer_fp not in receiver._pending_texts
    reply_wire = receiver.client.posted[-1]
    assert msg.parse_message(reply_wire)['ptype'] == msg.PT_TEXT

    replies = []
    sender._on_message = lambda cs, text: replies.append(text)
    sender._handle_envelope(reply_wire)
    assert replies == ['queued reply']
