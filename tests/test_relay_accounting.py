import pytest
import nbx.relay as relay
from nbx.relay import MemoryStore


def _env(tag: int, size: int) -> bytes:
    head = tag.to_bytes(4, 'big', signed=False)
    return head + bytes(((tag + i) % 251 for i in range(size - 4)))


def test_repeated_put_pop_all_returns_to_zero():
    store = MemoryStore(ttl=10 ** 9)
    fp = b'A' * 8
    for i in range(50):
        env = _env(i, 37)
        assert store.put(fp, env) is True
        assert store._total_bytes == len(env)
        popped = store.pop_all(fp)
        assert popped == [env]
        assert store._total_bytes == 0
    assert store.count(fp) == 0


def test_pop_all_restores_global_budget():
    store = MemoryStore(max_total_bytes=300, ttl=10 ** 9)
    fp = b'B' * 8
    accepted = []
    for i in range(10):
        env = _env(i, 100)
        try:
            store.put(fp, env)
        except ValueError:
            break
        accepted.append(env)
    assert len(accepted) == 3
    assert store._total_bytes == 300
    with pytest.raises(ValueError, match='global envelope budget exceeded'):
        store.put(fp, _env(99, 100))
    popped = store.pop_all(fp)
    assert popped == accepted
    assert store._total_bytes == 0
    assert store.put(fp, _env(98, 100)) is True
    assert store._total_bytes == 100


def test_ttl_expiry_deducts_expired_entry_sizes(monkeypatch):
    store = MemoryStore(ttl=100, max_total_bytes=10 ** 9)
    fp = b'C' * 8
    fake = {'now': 1000.0}
    monkeypatch.setattr(relay.time, 'time', lambda: fake['now'])

    old = _env(1, 50)
    assert store.put(fp, old) is True
    assert store._total_bytes == 50

    fake['now'] = 1150.0
    new = _env(2, 200)
    assert store.put(fp, new) is True
    assert store._total_bytes == 200
    assert store.count(fp) == 1
    assert store.pop_all(fp) == [new]
    assert store._total_bytes == 0


def test_count_and_pop_all_are_locked():
    store = MemoryStore(ttl=10 ** 9)
    assert hasattr(store._lock, 'acquire') and hasattr(store._lock, 'release')
    assert not store._lock.locked()
    store.put(b'D' * 8, _env(1, 20))
    assert not store._lock.locked()
    store.count(b'D' * 8)
    assert not store._lock.locked()
    store.pop_all(b'D' * 8)
    assert not store._lock.locked()
