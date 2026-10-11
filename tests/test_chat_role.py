from nbx import cli
from nbx.chat import ChatSession, fingerprint8
from nbx.fskey import Identity


def test_chat_sessions_choose_deterministic_complementary_first_speakers():
    alice, bob = Identity.generate(), Identity.generate()

    alice_session = ChatSession(alice, bob.export_public(), 'http://fake')
    bob_session = ChatSession(bob, alice.export_public(), 'http://fake')

    expected_alice = fingerprint8(alice.export_public()) < fingerprint8(bob.export_public())
    assert alice_session.speaks_first is expected_alice
    assert bob_session.speaks_first is (not expected_alice)
    assert alice_session.speaks_first != bob_session.speaks_first


def test_cli_chat_uses_identity_derived_role(monkeypatch, tmp_path):
    local = Identity.generate()
    peer = Identity.generate()
    local_path = tmp_path / 'local.key'
    local.save(str(local_path))
    observed = []

    def capture_chat(identity, peer_pub_b64, relay_base, *, poll):
        observed.append(ChatSession(identity, peer_pub_b64, relay_base))

    monkeypatch.setattr('nbx.chat.run_chat', capture_chat)
    cli.main(['chat', '--my-id', str(local_path), '--to-pub', peer.export_public()])

    assert len(observed) == 1
    assert observed[0].speaks_first == (
        fingerprint8(local.export_public()) < fingerprint8(peer.export_public())
    )
