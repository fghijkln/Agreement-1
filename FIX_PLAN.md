# FIX_PLAN：审计修复清单（Agreement-1 / NBX）

## 背景

- 依据：审计报告 `OPENCODE_REPORT.md`（只读静态审计 + 全量测试 + 针对性验证）。
- 基线提交：`ac9cf81`（审计时点）。
- 修复分支：`fix/audit-regressions`。
- 修复范围：按审计报告的第 3 部分安全问题清单（T1–T4）、第 5.1 代码质量、第 5.2 测试缺口、第 5.3 CI 缺口逐项处理。
- 本文件按 `git log --reverse --oneline ac9cf81..HEAD` 的提交顺序记录每一项修复：提交哈希+标题、对应审计项、改动内容、原因（引用审计发现）、涉及文件、对应测试。

以下所有 diff 均通过 `git show <hash>` 实际阅读，文件清单通过 `git show --stat <hash>` 获取，测试用例名通过 `git show <hash>` 阅读测试源码得到。

---

## 1. `33bedcc` fix(ratchet): state integrity tag covers full blob + regression tests

- 提交：`33bedcc0b77a22431452b83dd572a078e9d88ddc`
- 审计项：**T1（高）**——ratchet 状态完整性标签形同虚设，会话回滚攻击可行；同时覆盖 5.2 缺口第 4 条（状态标签无篡改测试）。
- 改动内容：
  - `nbx/ratchet.py` 的 `_state_integrity_tag(root_key, blob)` 由原来的
    `HKDF(...).derive(root_key)`（`blob` 参数被完全忽略）改为
    `hmac.new(root_key, MAGIC_STATE + blob, hashlib.sha256).digest()[:16]`，
    即标签真正绑定整段状态 blob；新增 `import hashlib`、`import hmac`。
  - `export_state` / `import_state` 的字段布局与校验顺序未变（导入仍先验 tag 再解析字段），因此兼容既有导出格式，但任何字段被篡改都会导致 tag 校验失败。
  - 新增 `tests/test_state_integrity.py`：手工解析/重建状态 TLV，逐字段篡改（recv_n、send_n、root_key、send_ck、DH 私钥、skipped 条目）验证 `import_state` 必须抛 `ValueError(match='integrity')`。
- 原因：审计报告 T1 指出 `ratchet.py:72-73` 的 `blob` 参数未被使用，tag 只取决于 root_key，而 root_key 就在同一被保护文件里 ⇒ 改任何字段再算一遍（甚至不重算）都能通过 `import_state`，直接摧毁回滚防护。审计原文建议改为 `HMAC-SHA256(key=root_key, msg=blob)` 并补“篡改任意 state 字段必须导入失败”的测试。
- 涉及文件（`git show --stat`）：
  - `nbx/ratchet.py`（4 行，1 增 1 删 + import）
  - `tests/test_state_integrity.py`（新增，142 行）
- 对应测试（`tests/test_state_integrity.py`）：
  - `test_untampered_state_roundtrips`
  - `test_untampered_state_with_skipped_entries_roundtrips`
  - `test_tampered_recv_n_rejected`
  - `test_tampered_send_n_rejected`
  - `test_tampered_root_key_rejected`
  - `test_tampered_send_ck_rejected`
  - `test_tampered_dh_private_key_rejected`
  - `test_tampered_skipped_entries_rejected`
  - `test_tag_binds_blob_not_just_root_key`

---

## 2. `9aed2b0` fix(transfer): authenticate listen + harden filenames + regression tests

- 提交：`9aed2b04a468e0d384922bbe2a9cc3cce1d10464`
- 审计项：**T2（高）**——`nbx listen` 无认证 + 可被诱导覆盖任意同基名文件 + 单帧异常可打死监听循环；覆盖 5.2 缺口第 3 条（路径穿越无回归测试）与第 5.1 条（`transfer.listen` 的 `keyfile` 收了不用、异常面过窄）。
- 改动内容：
  - `nbx/protocol.py`：新增帧类型常量 `T_AUTH = 8`（与既有 T_HELLO/T_BEGIN/T_CHUNK/T_END 并列）。
  - `nbx/transfer.py`：
    - 新增常量 `AUTH_NONCE_SIZE = 32`、`AUTH_MAC_SIZE = 32` 与 `_auth_mac(master, nonce) = HMAC-SHA256(master, nonce)`，基于主密钥（`--keyfile` / `NBX_MASTER_KEY`）做挑战—应答。
    - `send_file`：先 `_load_master_key`，握手改为收取服务端下发的 `T_AUTH` nonce → 回发 `HMAC(master, nonce)`；只有收到 `ACK=b'READY'` 才继续，`ACK=b'GO'` 才发数据（原来是裸 `T_ACK`）。
    - 新增 `_safe_target(outdir, name)`：拒绝空名、`.`、`..`、含 `/` 或 `\`、绝对路径，并拒绝覆盖已存在文件（`os.path.exists`）。
    - 新增 `_serve_transfer(conn, addr, outdir, master)`：把单连接处理抽出；先校验 hello，再校验 MAC（`hmac.compare_digest`），失败回 `AUTH FAILED`；`parse_begin` 后经 `_safe_target` 校验文件名，拒绝则回 `REJECTED: ...`；传输中用 `try/except BaseException` 清理半途文件；校验和不匹配回 `CHECKSUM FAIL` 并删除文件。
    - `listen`：启动即 `_load_master_key`（无密钥直接 `SystemExit`，修掉 `keyfile` 未用问题）；accept 循环用 `except Exception` 兜底（原来是 `except protocol.ProtocolError`），单连接异常不再打死监听进程；打印文案加 “(challenge-response authenticated)”。
  - 新增 `tests/test_listen_auth.py`：真实起监听线程 + 裸 socket 客户端，覆盖正常往返、错钥拒绝、无钥、坏 MAC、路径穿越、绝对/反斜杠名、已存在目标不覆盖、坏帧后监听存活、乱序 chunk 后监听存活。
- 原因：审计报告 T2 指出 hello 帧只需字面量 `NBXPROTO\x01`、无任何身份验证；`os.path.join(outdir, os.path.basename(name))` 可覆盖任意同基名文件；`..`/空名会触发 `IsADirectoryError`/`FileNotFoundError`，而循环只捕 `ProtocolError`。修复建议为 hello 后加 `--keyfile` 挑战应答、拒绝绝对路径/`.`/`..`/已存在目标、`except Exception` 兜底并实现或移除 `keyfile`。
- 涉及文件（`git show --stat`）：
  - `nbx/protocol.py`（1 行新增）
  - `nbx/transfer.py`（149 行改动）
  - `tests/test_listen_auth.py`（新增，232 行）
- 对应测试（`tests/test_listen_auth.py`）：
  - `test_normal_roundtrip_encrypted_and_verified`
  - `test_listener_without_key_refuses_to_start`
  - `test_wrong_key_is_rejected_and_listener_survives`
  - `test_client_without_key_cannot_authenticate`
  - `test_hello_without_auth_gets_no_go`
  - `test_bad_mac_rejected`
  - `test_path_traversal_filename_rejected`（对应 5.2 缺口第 3 条）
  - `test_absolute_and_backslash_filenames_rejected`
  - `test_existing_target_not_overwritten`
  - `test_bad_frame_does_not_kill_listener`
  - `test_out_of_order_chunk_does_not_kill_listener`（后于 `3486ef3` 消除竞态）

---

## 3. `233d52e` fix(relay): MemoryStore 正确扣减 _total_bytes + 加锁 + 回归测试

- 提交：`233d52e82922b1c2e267ce68e0b2f0e4ce2119f5`
- 审计项：**T3（中）**——`MemoryStore._gc` 有界性失效导致中继内存可按指纹缓慢耗尽（`_total_bytes` 不减、`_seen` 无上限）；以及 `pop_all`/`count` 未加锁。
- 改动内容：
  - `nbx/relay.py` `MemoryStore._gc`：由原来 `kept = [...]; for _, e in q[len(kept):]` 的按位置截断，改为显式把 `expired` 单独收集后逐条 `self._total_bytes -= len(e)`，避免 GC 时记账遗漏/错位。
  - `pop_all` / `count` 全程加 `with self._lock:`，与 `put` 的临界区一致，消除并发下的记账竞态。
  - 新增 `tests/test_relay_accounting.py`：反复 put/pop 同一 fp 后 `_total_bytes` 归零、`pop_all` 恢复全局预算、TTL 过期扣减过期条目体积、锁状态检查。
- 原因：审计报告 T3 指出 `pop_all` 只减队列部分导致 `_total_bytes` 虚高、`max_total_bytes` 触顶即永久拒绝服务；`tests/test_relay.py:266-280` 只测“拒绝”没测“恢复”。修复建议为在 `pop_all` 同步扣减 `_total_bytes` 并参照 `tests/test_relay.py:305-316` 扩展。
- 涉及文件（`git show --stat`）：
  - `nbx/relay.py`（28 行改动）
  - `tests/test_relay_accounting.py`（新增，74 行）
- 对应测试（`tests/test_relay_accounting.py`）：
  - `test_repeated_put_pop_all_returns_to_zero`
  - `test_pop_all_restores_global_budget`
  - `test_ttl_expiry_deducts_expired_entry_sizes`
  - `test_count_and_pop_all_are_locked`

---

## 4. `0265886` test(r2x): 修复恒真断言，真实检验 MemoryStore 预算

- 提交：`0265886c4e06050202d064afba46e788dd145cb0`
- 审计项：**5.2 测试缺口第 1 条**——`tests/test_r2x.py:58-67` 是恒真死测试（用 3 个参数调用 2 参的 `MemoryStore.put`，必然 `TypeError`；`MemoryStore` 也无 `total_bytes()` 方法），正是 `.coderabbit.yaml` 明令禁止的模式。同时呼应 T3 记账问题。
- 改动内容：
  - `tests/test_r2x.py` 的 `test_r2_08_python_memory_store_budget_unchanged` 重写：改用正确的两参 `put(fp, env)`，构造 `max_total_bytes=1024`、`ttl=10**9`；循环写入直至捕获 `ValueError('global envelope budget exceeded')`，断言确实抛出、`_total_bytes <= 1024`、`accepted == 10`、`count(fp) == accepted`。删除了原 `st.total_bytes()` 这个不存在的方法调用与恒真的 `ok is False or ...`。
- 原因：审计报告 5.2 指出该测试必然 `TypeError` 却因 `except Exception` + `or` 恒真而永远“通过”，属死断言；修复建议为改成真实断言（第 6 部分第 5 条）。
- 涉及文件（`git show --stat`）：
  - `tests/test_r2x.py`（25 行改动，17 增 8 删）
- 对应测试：`tests/test_r2x.py::test_r2_08_python_memory_store_budget_unchanged`（修复后真实生效）。

---

## 5. `e7ed969` fix(cli): pack 的 enc 字段拼写 chacha20poly1305 + 测试

- 提交：`e7ed969ffbfd54a3676dfe7c5368486ef773d595`
- 审计项：**5.1 代码质量**——一致性：`cli.py:100` 写 `'chacha20p1305'`（p 后缺 o），`:123` 写 `'chacha20poly1305'`，同一字段两种拼写。
- 改动内容：
  - `nbx/cli.py` 的 `pack` 分支把 `meta['enc']` 由 `'chacha20p1305'` 改为 `'chacha20poly1305'`，与 `transfer.py` 等处的写法统一。
  - 新增 `tests/test_cli_pack_enc.py`：真实走 `keygen → pack → format.unpack → unpack` 全链路，断言 `meta['enc'] == 'chacha20poly1305'` 且解包内容与原文一致。
- 原因：审计报告 5.1 明确列出该拼写不一致；属低风险但会造成下游按 `enc` 分支判断时行为不一致。
- 涉及文件（`git show --stat`）：
  - `nbx/cli.py`（2 行，1 增 1 删）
  - `tests/test_cli_pack_enc.py`（新增，19 行）
- 对应测试：`tests/test_cli_pack_enc.py::test_pack_enc_field_and_unpack_roundtrip`

---

## 6. `aef17b3` fix(daemon): _pending_texts 改为实例属性 + 测试

- 提交：`aef17b3835cacf1b7d92a41a85b5fc1304614b1c`
- 审计项：**T4（低）**——`daemon.py` 的 `_pending_texts` 是类属性字典 ⇒ 跨实例状态共享（`daemon.py:297` 定义在类体、`:287`）。
- 改动内容：
  - `nbx/daemon.py` `Daemon.__init__` 新增 `self._pending_texts: dict[bytes, list[bytes]] = {}`。
  - 删除类体中 `_pending_texts: dict[bytes, list[bytes]] = {}` 的类属性定义。
  - 新增 `tests/test_daemon_pending_texts.py`：断言 `_pending_texts` 不再是类属性（`'_pending_texts' not in Daemon.__dict__`、`not hasattr(Daemon, '_pending_texts')`），且两个实例的字典互相独立。
- 原因：审计报告 T4 指出该字典挂在类上，多 daemon 实例会串数据；修复建议为移到 `__init__`。
- 涉及文件（`git show --stat`）：
  - `nbx/daemon.py`（2 行，1 增 1 删）
  - `tests/test_daemon_pending_texts.py`（新增，41 行）
- 对应测试：`tests/test_daemon_pending_texts.py::test_pending_texts_is_instance_state`

---

## 7. `7bb72d5` test(relay): live HTTP 测试绕开环境代理

- 提交：`7bb72d5b495c95ff3be87034fc813b75dd63416a`
- 审计项：**5.2 测试缺口第 2 条**——`tests/test_relay.py::test_http_server_live` 未绕过代理，在设了 `HTTP_PROXY`/`HTTPS_PROXY` 的 CI/开发机上会假失败（第 0 节）。
- 改动内容：
  - `tests/test_relay.py` 的 `test_http_server_live` 改用 `urllib.request.build_opener(urllib.request.ProxyHandler({}))`，并用 `opener.open(...)` 替代裸 `urllib.request.urlopen(...)`，使本机 `127.0.0.1:18765` 请求不经过环境代理。
- 原因：审计报告第 0 节与 5.2 第 2 条指出该测试因代理返回 404 而 `assert e.code == 400` 失败，属测试自身健壮性问题；产品代码中 `contacts.py:144` 等处已正确使用 `ProxyHandler({})`，故仅需修测试。
- 涉及文件（`git show --stat`）：
  - `tests/test_relay.py`（5 行，3 增 2 删）
- 对应测试：`tests/test_relay.py::test_http_server_live`

---

## 8. `1028e69` fix(cli): --from-pub 指纹 TOFU pin 与 --from-fp 显式校验 + 测试

- 提交：`1028e69209bd2a5f381e3616c8c1fb6d46835cef`
- 审计项：**T3（中高）**——`open_pq`/`open_envelope` 把“发送方公钥”当调用方输入，公钥轮换/伪造文件即冒充；对应第 6 部分第 3 条（把 `Identity.fingerprint()` 接入信任确认）。
- 改动内容：
  - 新增 `nbx/pins.py`：
    - `pubkey_fingerprint(pub_text)`：对 Base64 公钥原始字节做 `sha256(...).digest()[:8].hex()`（16 位 hex / 8 字节）。
    - `PinStore`：从 pin 文件（默认 `~/.nbx_sender_pins.json`，可用 `NBX_SENDER_PINS` 覆盖）加载 name→fp；`_load` 对损坏/非对象 JSON 抛 `ValueError`（拒绝覆盖清空），并清洗为规范化 hex；`_save` 用 `tempfile.mkstemp` + `os.replace` 原子写并 `chmod 0600`；`trust(name, fp)` 首次信任写入并打印提示，已有不同 fp 则抛 `ValueError`（拒绝）。
  - `nbx/cli.py`：
    - `unseal` / `pqunseal` 新增 `--from-fp`、`--from-name`、`--pins` 参数及说明 `description`。
    - 新增 `_verify_from_pub(args, pub_text)`：解析指纹失败即 `sys.exit`；给定 `--from-fp` 时与之显式比对，不一致 `sys.exit`（不写 outfile）；否则按 `--from-name`（默认 `--from-pub` 绝对路径）走 `PinStore.trust` 的 TOFU。
    - `unseal` / `pqunseal` 分支在 `parse_public` 之前调用 `_verify_from_pub`。
  - 新增 `tests/test_from_pub_pin.py`：参数化 `fs`/`pq` 两套信封，覆盖首次信任写 pin（0600）、同名换钥拒绝、`--from-fp` 正确接受/错误拒绝、损坏 pin 文件拒绝、`NBX_SENDER_PINS` 覆盖。
- 原因：审计报告 T3 指出验签用的是 `--from-pub` 文件里的公钥，攻击者替换该文件即可冒充；建议 CLI 至少校验指纹并首次提示，参照 `chat.py:111-117` 的 relay pin 模式做 pinning。
- 涉及文件（`git show --stat`）：
  - `nbx/cli.py`（43 行改动）
  - `nbx/pins.py`（新增，85 行）
  - `tests/test_from_pub_pin.py`（新增，143 行）
- 对应测试（`tests/test_from_pub_pin.py`，参数化 `fs`/`pq`）：
  - `test_tofu_first_trust_writes_pin`
  - `test_tofu_same_name_swapped_key_rejected`
  - `test_explicit_fp_accepts_correct`
  - `test_explicit_fp_rejects_wrong`
  - `test_corrupt_pin_file_rejected`
  - `test_pin_env_override`

---

## 9. `1b483e6` fix(replay): ReplayCache 跨进程文件锁 + 条目上限淘汰 + 测试

- 提交：`1b483e64d93e385f1c3081f991752a121f8c401e`
- 审计项：**T3（中）**——`ReplayCache` 同主机多会话互相干扰 + 明文落盘 + 启动期无文件锁（`replay.py:8/41-48/58-64`）；对应第 6 部分第 4 条。
- 改动内容：
  - `nbx/replay.py`：
    - 新增 `DEFAULT_MAX_ENTRIES = 100000`、`MAX_FILE_BYTES = 16 * 1024 * 1024`、`REPLAY_CACHE_ENV = 'NBX_REPLAY_CACHE'`、`default_cache_path()`（默认仍 `~/.nbx_replay_cache.json`，可被环境变量覆盖）。
    - 导入 `fcntl`（非 POSIX 缺失则 `fcntl = None`）与 `msvcrt`（非 Windows 缺失则 `None`）；新增 `_is_hex_key`。
    - `ReplayCache.__init__` 支持 `path=None` 走 `default_cache_path()`、`max_entries`；新增 `_corrupt` 标志。
    - `_load`：先 `os.stat`，文件 > `MAX_FILE_BYTES` 或 JSON 损坏/非 dict ⇒ 置 `_corrupt=True` 并返回 `{}`（不清空原文件）；正常时走 `_sanitize`（只保留 hex 键 + int 值 + ttl 内条目，超 `max_entries` 按时间戳保留最新）。
    - `_save`：`_corrupt` 时直接返回（不覆盖损坏文件）；写盘改为 `os.open(..., 0o600)` 后 `json.dump` 再 `os.replace`。
    - 新增 `_locked()` 上下文管理器：在 `path + '.lock'` 上 `fcntl.flock(LOCK_EX)`（Windows 降级 `msvcrt.locking`，二者不可用则无锁不报错）。
    - `_drop_stale()` / `_evict()`：分别淘汰过期条目与超上限的最旧条目。
    - `seen` / `remember` / `check_and_remember` 全部在 `_locked()` 内**重新从磁盘加载最新内容**再判定/写入，避免多进程基于旧快照互相覆盖；`check_and_remember` 在锁内完成“查重 + 写入 + 淘汰 + 保存”原子序列。
  - 新增 `tests/test_replay_lock.py`：多进程并发写不同 id 全部持久化、并发写同一 id 仅一次成功、`max_entries` 淘汰最旧、`check_and_remember` 尊重上限、超大文件不崩溃不覆盖、坏 JSON 不崩溃、非法条目被忽略。
- 原因：审计报告 T3 指出 `_save` 无锁导致多进程并发 `check_and_remember` 互相覆盖丢记忆、放大重放窗口；`_load` 无大小上限，可被巨型 JSON 放大内存。修复建议为按 fp 分文件 + `fcntl.flock`（或 sqlite）、限制大小并只载入 ttl 内键。
- 涉及文件（`git show --stat`）：
  - `nbx/replay.py`（170 行改动）
  - `tests/test_replay_lock.py`（新增，147 行）
- 对应测试（`tests/test_replay_lock.py`）：
  - `test_concurrent_distinct_ids_all_persisted`
  - `test_concurrent_same_id_single_success`
  - `test_max_entries_evicts_oldest`
  - `test_check_and_remember_respects_max_entries`
  - `test_oversized_file_does_not_crash_or_clear`
  - `test_malformed_json_does_not_crash`
  - `test_invalid_entries_ignored`

---

## 10. `f42875f` ci: Python 3.10–3.13 矩阵 + Workers relay vitest job + 全量回归

- 提交：`f42875fbe1f8f45ee321b88e907406416f1ab77e`
- 审计项：**5.3 CI**——`.github/workflows/tests.yml` 仅 Python 3.11，版本矩阵缺失；`workers-relay/`（5 个 vitest）没有任何 CI 工作流。
- 改动内容：
  - `.github/workflows/tests.yml`：
    - 触发条件扩展：`push.branches` 增加 `'fix/**'`，新增 `workflow_dispatch`。
    - `pytest` job 引入 `strategy.matrix.python-version = ['3.10','3.11','3.12','3.13']`，`fail-fast: false`；`setup-python` 用矩阵版本并开启 `cache: pip`；依赖改为 `pytest 'cryptography>=42'`；测试命令加 `-ra`。
    - 新增 `workers-relay` job：`working-directory: workers-relay`，用 `pnpm/action-setup@v4` 指定 `version: 9`、`setup-node@v4`（Node 22，`cache: pnpm`，`cache-dependency-path: workers-relay/pnpm-lock.yaml`），执行 `pnpm install --frozen-lockfile` 与 `pnpm test`。
- 原因：审计报告 5.3 指出 Python 版本矩阵缺失，且“`workers-relay/` 含 5 个 vitest 却没有任何 CI 工作流——中继端 300 行 TS 零自动化回归，是最明显的 CI 缺口”。第 6 部分第 5 条要求补 vitest 工作流与版本矩阵。
- 涉及文件（`git show --stat`）：
  - `.github/workflows/tests.yml`（36 行改动，31 增 5 删）
- 对应测试：CI 层，无新增 pytest/vitest 文件；该 job 会运行既有 `workers-relay` 的 5 个 vitest 文件（17 用例）与 Python 3.10–3.13 全量回归。

---

## 11. `3486ef3` test(transfer): 消除 test_out_of_order_chunk_does_not_kill_listener 的竞态

- 提交：`3486ef3deaf1b08477c13fc5cf4f2e8660c84231`
- 审计项：修复 `9aed2b0` 新增测试自身的竞态（测试可靠性，呼应 5.2 的测试纪律）。
- 改动内容：
  - `tests/test_listen_auth.py` 的 `test_out_of_order_chunk_does_not_kill_listener` 在发送乱序 chunk 后，`settimeout(5)` 并循环 `sock.recv(4096)` 直到服务端关闭连接（清理半途文件发生在关闭连接之前），再断言 `outdir` 无残留文件。消除原来“断言时服务端可能尚未清理完”的时序竞态。
- 原因：`9aed2b0` 的该用例在服务端处理乱序 chunk 后立即断言目录为空，存在竞态可能偶发失败；本提交在保持断言强度不变的前提下同步等待服务端关闭连接。
- 涉及文件（`git show --stat`）：
  - `tests/test_listen_auth.py`（7 行新增）
- 对应测试：`tests/test_listen_auth.py::test_out_of_order_chunk_does_not_kill_listener`

---

## 12. `336e391` ci: setup-python pip 缓存指定 cache-dependency-path=pyproject.toml

- 提交：`336e391e948cf633b447194885cea2620b208e70`
- 审计项：**5.3 CI** 的收尾修复（`f42875f` 引入 `cache: pip` 后，仓库无 `requirements.txt` 会令缓存报错）。
- 改动内容：
  - `.github/workflows/tests.yml` 的 `setup-python` 步骤补 `cache-dependency-path: pyproject.toml`，显式指定依赖清单路径。
- 原因：`f42875f` 开启 pip 缓存后，`actions/setup-python` 默认查找 `requirements.txt` 不存在会失败；仓库依赖声明在 `pyproject.toml`。
- 涉及文件（`git show --stat`）：
  - `.github/workflows/tests.yml`（1 行新增）
- 对应测试：CI 配置层，无新增测试。

---

## 汇总表

| 提交 | 标题 | 审计项 | 文件 | 测试 |
|---|---|---|---|---|
| `33bedcc` | fix(ratchet): state integrity tag covers full blob | T1；5.2-4 | `nbx/ratchet.py`、`tests/test_state_integrity.py` | `test_tampered_*_rejected`、`test_tag_binds_blob_not_just_root_key` 等 9 项 |
| `9aed2b0` | fix(transfer): authenticate listen + harden filenames | T2；5.1；5.2-3 | `nbx/protocol.py`、`nbx/transfer.py`、`tests/test_listen_auth.py` | `test_path_traversal_filename_rejected`、`test_bad_mac_rejected` 等 11 项 |
| `233d52e` | fix(relay): MemoryStore 正确扣减 _total_bytes + 加锁 | T3（MemoryStore） | `nbx/relay.py`、`tests/test_relay_accounting.py` | 4 项，含 `test_pop_all_restores_global_budget` |
| `0265886` | test(r2x): 修复恒真断言 | 5.2-1 | `tests/test_r2x.py` | `test_r2_08_python_memory_store_budget_unchanged`（重写） |
| `e7ed969` | fix(cli): pack 的 enc 字段拼写 | 5.1 | `nbx/cli.py`、`tests/test_cli_pack_enc.py` | `test_pack_enc_field_and_unpack_roundtrip` |
| `aef17b3` | fix(daemon): _pending_texts 改为实例属性 | T4（daemon） | `nbx/daemon.py`、`tests/test_daemon_pending_texts.py` | `test_pending_texts_is_instance_state` |
| `7bb72d5` | test(relay): live HTTP 测试绕开环境代理 | 5.2-2 | `tests/test_relay.py` | `test_http_server_live` |
| `1028e69` | fix(cli): --from-pub TOFU pin + --from-fp 校验 | T3（from-pub） | `nbx/cli.py`、`nbx/pins.py`、`tests/test_from_pub_pin.py` | 6 项（fs/pq 参数化） |
| `1b483e6` | fix(replay): ReplayCache 文件锁 + 条目上限淘汰 | T3（ReplayCache） | `nbx/replay.py`、`tests/test_replay_lock.py` | 7 项，含 `test_concurrent_same_id_single_success` |
| `f42875f` | ci: Python 3.10–3.13 矩阵 + Workers relay vitest job | 5.3 | `.github/workflows/tests.yml` | CI（运行既有 5 vitest 文件 17 用例 + Python 矩阵） |
| `3486ef3` | test(transfer): 消除乱序用例竞态 | 5.2（测试可靠性） | `tests/test_listen_auth.py` | `test_out_of_order_chunk_does_not_kill_listener` |
| `336e391` | ci: setup-python pip 缓存指定路径 | 5.3 | `.github/workflows/tests.yml` | CI 配置 |

---

## 验证结果

### Python 测试套件

实际运行命令与结果：

```
.venv/bin/python -m pytest -q
```

输出尾部：

```
162 passed, 1 skipped, 8 warnings in 3.72s
```

- 相对审计基线（`116 passed, 1 skipped, 1 failed`）新增大量回归用例；唯一 skip 仍是 `tests/test_anon_transport.py::test_l2_full_path_via_tor`（需要真实 Tor + onion 地址，属合理 skip）。
- `8 warnings` 全部为 `tests/test_replay_lock.py` 中多进程 `fork()` 的 `DeprecationWarning`（Python 3.12 对多线程进程 fork 的提示），不影响结果。
- 本地运行环境为 Python 3.12。

### Workers relay

本地已用 pnpm 9.15.9 执行：

```
pnpm install --frozen-lockfile && pnpm test
```

结果：**Test Files 5 passed (5)，Tests 17 passed (17)**。

注意：pnpm 10+ 不读取 `package.json` 的 `pnpm.overrides` 字段，`--frozen-lockfile` 安装会报 overrides 不匹配，因此 CI 固定 pnpm 9（`.github/workflows/tests.yml` 中 `pnpm/action-setup@v4` 指定 `version: 9`）。

---

## 残留风险 / 未做事项

1. **棘轮会话状态与消息历史仍明文落盘（仅 0600）**：T1 修复只让状态标签真正绑定内容并拒绝篡改，但 `ratchet.export_state` 导出的 root/chain/DH 私钥、`daemon.save_session` 的会话状态、`contacts.py` 的 `session_state` 与消息历史仍是明文 JSON，仅靠 0600 文件权限保护。备份泄露/同 uid 读取仍可绕过 FS。审计 T4 与 2.2 节建议的“口令 scrypt 封装会话状态”“消息历史加密或不落盘选项”未实现。
2. **Carrier 元数据无完整性（T4）**：`.nbx` v2 的 `parts`/`type`/`filename` 仍未认证；bundle 部分数与实际流不一致时 `zip` 静默截断、二进制流可被标 `type=text` 走 `decode('utf-8')`，审计建议的 `len(parts)==len(streams)` 与逐部分校验和未加入。
3. **`contacts.py` SOCKS/Tor 分支超时（T4）**：`recv` 仍可能无限阻塞、`poll` 对黑洞 endpoint 无总超时与退避，审计建议的统一 deadline / 失败退避未实现。
4. **日志泄露细节（T4）**：`daemon.py` 仍把异常类型与地址写入 `events.log`，`cli.py` 仍将异常细节 `sys.exit` 打印，未统一固定错误文案 + 细分仅进 debug。
5. **bandit 仍 `|| true` 不门禁**：`.github/workflows/bandit.yml` 失败不阻断 CI，本次未改为门禁。
6. **TOFU pin 的固有局限**：`nbx/pins.py` 在首次信任时（解密前）即写入 pin——若首次即遭冒充，攻击者公钥会被 pin；且指纹为 `sha256(...).digest()[:8]`，仅 64 位截断。这两点是设计取舍，未做更长的指纹或带外强制核对（`--from-fp` 提供显式核对路径）。
7. **ReplayCache 的 fail-open 与无锁降级**：文件损坏或超过 `MAX_FILE_BYTES` 时 `_corrupt=True`，`_save` 直接返回不再写盘（持久化层面 fail-open，本进程内存内仍去重）；非 POSIX/非 Windows 环境无 `fcntl`/`msvcrt` 时退化为无锁，跨进程防护失效。本次未改为 sqlite 或强制失败关闭。
8. **CI 版本覆盖**：Python 3.10/3.11/3.13 仅在 CI 运行，本地仅验证 3.12；Workers relay 的 vitest CI 依赖 pnpm 9（见上）。
9. **本 FIX_PLAN 提交本身**：本次仅新增 `FIX_PLAN.md` 并本地提交，`OPENCODE_REPORT.md` 与 `opencode.json` 保持未跟踪、未被 `git add`，也未执行 push。

---

## 提交

```
docs: FIX_PLAN.md 审计修复清单
```
