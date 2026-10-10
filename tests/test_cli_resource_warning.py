"""审计 5.1：cli 中 open() 必须用 with（防 ResourceWarning）。pytest 配置已把 ResourceWarning 设为 error。"""
import ast
import gc
import warnings
from pathlib import Path

from nbx import cli, fskey, pins

CLI_SRC = Path(cli.__file__).read_text(encoding='utf-8')


def _bare_open_calls(src: str) -> list[int]:
    """返回不在 with 语句头里的 open(...) 调用行号。"""
    tree = ast.parse(src)
    in_with = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                in_with.add(id(item.context_expr))
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'open':
            if id(node) not in in_with:
                bad.append(node.lineno)
    return bad


def test_cli_has_no_bare_open():
    assert _bare_open_calls(CLI_SRC) == []


def test_detector_catches_bare_open():
    assert _bare_open_calls("x = open('f').read()\nwith open('g') as f:\n    pass\n") == [1]


def test_seal_unseal_flow_emits_no_resource_warning(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.delenv('NBX_REPLAY_CACHE', raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter('error', ResourceWarning)
        snd, rec = tmp_path / 's.key', tmp_path / 'r.key'
        cli.main(['identity', 'new', str(snd)])
        cli.main(['identity', 'new', str(rec)])
        cli.main(['identity', 'pubout', str(snd), '--out', str(tmp_path / 's.pub')])
        cli.main(['identity', 'pubout', str(rec), '--out', str(tmp_path / 'r.pub')])
        src = tmp_path / 'm.txt'
        src.write_bytes(b'resource-check')
        env = tmp_path / 'm.env'
        cli.main(['seal', str(src), str(env), '--my-id', str(snd), '--to-pub', str(tmp_path / 'r.pub')])
        fp = pins.pubkey_fingerprint((tmp_path / 's.pub').read_text())
        out = tmp_path / 'o.txt'
        cli.main(['unseal', str(env), str(out), '--my-id', str(rec), '--from-pub', str(tmp_path / 's.pub'),
                  '--from-fp', fp, '--pins', str(tmp_path / 'pins.json')])
        gc.collect()
    assert out.read_bytes() == b'resource-check'
