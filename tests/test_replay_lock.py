import json
import multiprocessing as mp
import time

import pytest

from nbx import replay


def _remember_worker(path, ids, barrier):
    cache = replay.ReplayCache(path)
    barrier.wait()
    for raw in ids:
        cache.check_and_remember(raw)


def _same_id_worker(path, raw, barrier, counter, lock):
    cache = replay.ReplayCache(path)
    barrier.wait()
    try:
        cache.check_and_remember(raw)
    except ValueError:
        return
    with lock:
        counter.value += 1


def _ctx():
    try:
        return mp.get_context('fork')
    except ValueError:  # pragma: no cover - platforms without fork
        return mp.get_context()


def test_concurrent_distinct_ids_all_persisted(tmp_path):
    path = str(tmp_path / 'conc.json')
    ctx = _ctx()
    procs_count = 4
    per = 25
    barrier = ctx.Barrier(procs_count)
    procs = []
    for p in range(procs_count):
        ids = [(p * 1000 + i).to_bytes(16, 'big') for i in range(per)]
        pr = ctx.Process(target=_remember_worker, args=(path, ids, barrier))
        pr.start()
        procs.append((pr, ids))
    for pr, _ids in procs:
        pr.join(60)
        assert pr.exitcode == 0, pr.exitcode

    cache = replay.ReplayCache(path)
    for _pr, ids in procs:
        for raw in ids:
            assert raw.hex() in cache._mem, raw.hex()
    assert len(cache._mem) == procs_count * per


def test_concurrent_same_id_single_success(tmp_path):
    path = str(tmp_path / 'same.json')
    ctx = _ctx()
    raw = b'\xab' * 16
    barrier = ctx.Barrier(4)
    counter = ctx.Value('i', 0)
    lock = ctx.Lock()
    procs = [ctx.Process(target=_same_id_worker, args=(path, raw, barrier, counter, lock))
             for _ in range(4)]
    for pr in procs:
        pr.start()
    for pr in procs:
        pr.join(60)
        assert pr.exitcode == 0, pr.exitcode

    assert counter.value == 1
    assert raw.hex() in replay.ReplayCache(path)._mem


def test_max_entries_evicts_oldest(tmp_path):
    path = str(tmp_path / 'max.json')
    now = int(time.time())
    cache = replay.ReplayCache(path, max_entries=3)
    for i in range(5):
        cache._mem[f'{i:032x}'] = now - (10 - i)
    assert cache._evict() is True
    cache._save()

    reloaded = replay.ReplayCache(path, max_entries=3)
    assert set(reloaded._mem) == {f'{2:032x}', f'{3:032x}', f'{4:032x}'}


def test_check_and_remember_respects_max_entries(tmp_path, monkeypatch):
    path = str(tmp_path / 'max2.json')

    class _FakeTime:
        t = 1000

        @staticmethod
        def time():
            return _FakeTime.t

    monkeypatch.setattr(replay, 'time', _FakeTime)
    cache = replay.ReplayCache(path, max_entries=3)
    for i in range(5):
        _FakeTime.t = 1000 + i
        cache.check_and_remember(i.to_bytes(16, 'big'))

    reloaded = replay.ReplayCache(path, max_entries=3)
    assert set(reloaded._mem) == {
        (2).to_bytes(16, 'big').hex(),
        (3).to_bytes(16, 'big').hex(),
        (4).to_bytes(16, 'big').hex(),
    }


def test_oversized_file_does_not_crash_or_clear(tmp_path):
    path = tmp_path / 'huge.json'
    path.write_bytes(b'x' * (replay.MAX_FILE_BYTES + 1024))
    original_size = path.stat().st_size

    cache = replay.ReplayCache(str(path))
    assert cache._mem == {}
    cache.check_and_remember(b'\x01' * 16)
    assert b'\x01' * 16 and (b'\x01' * 16).hex() in cache._mem
    assert path.stat().st_size == original_size, '损坏/超大文件不得被覆盖清空'


def test_malformed_json_does_not_crash(tmp_path):
    path = tmp_path / 'bad.json'
    path.write_text('{ this is not valid json')
    cache = replay.ReplayCache(str(path))
    assert cache._mem == {}


def test_invalid_entries_ignored(tmp_path):
    path = tmp_path / 'mix.json'
    now = int(time.time())
    data = {
        'nothex': now,
        'abc': now,
        'ab': 'not-int',
        'cd': 12.5,
        'ef': True,
        'aa' * 16: now,
        'bb' * 16: now - 10 * 86400,
    }
    path.write_text(json.dumps(data))
    cache = replay.ReplayCache(str(path))
    assert cache._mem == {'aa' * 16: now}
