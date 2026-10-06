# NBX 协议规范

版本：v2.1（2026-10）
状态：实现中，本文档描述 `nbx/` 代码的实际字节布局。任何字段变更须先改本文档。

多字节整数一律小端（LE）。所有长度字段是字节数。

## 0. 分层总览

```
层级 5  Anonymity Wrapper   元数据加密外层（可选）
层级 4  加密信封            主密钥 / FS / PQ 混合（三选一，或明文）
层级 3  NBX v2 容器         TLV 多流 + SHA-256
层级 2  传输分块            BEGIN / CHUNK / END
层级 1  线路帧              NX 魔数 + 类型 + 长度
```

接收方自下而上逐层剥开。层级 4 与 5 可以叠加（先信封后包装）。

## 1. 线路帧（nbx/protocol.py）

```
偏移  大小  字段
0     2    魔数 "NX"
2     1    帧类型
3     4    载荷长度 (LE u32)
7     N    载荷
```

帧类型：

| 值 | 名称 | 载荷 |
|----|------|------|
| 0x01 | HELLO | 协议名 `NBXPROTO\x01`（8 字节） |
| 0x02 | FILE | 已废弃（v1 遗留，见第 6 节） |
| 0x03 | ACK | UTF-8 消息（OK / READY / GO / VERIFIED / 错误描述） |
| 0x04 | BYE | 空 |
| 0x05 | BEGIN | 见 2.1 |
| 0x06 | CHUNK | 见 2.2 |
| 0x07 | END | 见 2.3 |

载荷长度上限 2^30。接收方读到未知帧类型应断开连接。

## 2. 分块传输

一次传输的完整序列：

```
发送方                          接收方
  HELLO ──────────────────────▶
  ◀────────────────────────── ACK "READY"
  BEGIN(文件名,总大小,块大小,块数) ─▶
  ◀────────────────────────── ACK "GO"
  CHUNK(seq=0) ───────────────▶
  CHUNK(seq=1) ───────────────▶
  ...
  END(SHA-256) ───────────────▶
  ◀────────────────────────── ACK "VERIFIED"
  BYE ────────────────────────▶
```

### 2.1 BEGIN 载荷

```
0     2    文件名长度 (LE u16)
2     N    文件名 (UTF-8)
2+N   8    总大小 (LE u64)
10+N  4    块大小 (LE u32)
14+N  4    总块数 (LE u32)
```

### 2.2 CHUNK 载荷

```
0     4    序号 (LE u32，从 0 起)
4     N    数据（最后一块可以小于块大小）
```

接收方强制 `seq == expected`，乱序即断开。块大小默认 64 KiB。

### 2.3 END 载荷

整个文件的 SHA-256（32 字节）。接收方边收边算，末尾比对：

- 一致 → ACK `VERIFIED`，保留文件
- 不符 → ACK `CHECKSUM FAIL`，删除已落盘文件

## 3. NBX v2 容器（nbx/carrier.py）

文件后缀 `.nbx`。

```
偏移  大小  字段
0     8    魔数 "NBXFILE\x02"
8     1    版本 = 2
9     1    标志位
10    2    元数据长度 M (LE u16)
12    M    元数据 (JSON, UTF-8, ensure_ascii=False)
12+M  4    载荷长度 P (LE u32)
16+M  P    载荷 = TLV 流序列
16+M+P 32  SHA-256(载荷)
```

标志位：

| bit | 含义 |
|-----|------|
| 0 | 已加密（层级 4 在载荷内） |
| 1 | 已压缩（每条流独立 LZMA，preset 6） |
| 2 | 多流（载荷含不止一条 TLV） |

### 3.1 TLV 流

```
1B  流类型
4B  流长度 (LE u32)
N   流内容
```

| 类型 | 名称 | 内容 |
|------|------|------|
| 1 | TEXT | UTF-8 文本（正文/markdown/html） |
| 2 | BINARY | 原始字节 |
| 3 | SUBMETA | 附属描述 JSON（预留） |

压缩作用于单条流：pack 时压缩后若没有变小则放弃压缩。unpack 看到标志位 1 时逐流解压，调用方拿到的永远是原始字节。

### 3.2 元数据 JSON 字段

| 字段 | 必有 | 说明 |
|------|------|------|
| type | 是 | text / html / markdown / image / audio / video / binary / bundle |
| mime | 是 | 原始 MIME |
| filename | 是 | 原始文件名 |
| size | 否 | 原始字节数 |
| parts | 多流时 | 流清单：`[{name, type, mime, len}, ...]`，与 TLV 顺序一一对应 |
| enc | 加密时 | `chacha20poly1305` |
| comp | 压缩时 | `lzma` |
| auto | 否 | 传输层自动加密时置 true |

### 3.3 类型嗅探顺序

1. 扩展名命中 `KNOWN_TEXT_EXT`（.txt/.md/.html/.py 等 25 种）→ 文本类
2. 文件头魔数命中 `MAGIC_SNIFF`（PNG/JPEG/PDF/MP4 等 14 种）→ binary + 具体 MIME
3. 整段可 UTF-8 解码 → text
4. 其余 → binary / application/octet-stream

### 3.4 完整性

SHA-256 覆盖整个载荷（含 TLV 头）。校验失败必须拒绝解析，不做部分恢复。

## 4. 加密信封（层级 4）

三种模式共用 ChaCha20-Poly1305（12 字节 nonce）做 AEAD，区别在密钥来源。

### 4.1 主密钥模式（nbx/crypto.py）

密钥材料：32 字节主密钥（Base64 存文件或 `NBX_MASTER_KEY` 环境变量）。

```
加密: salt(16) || nonce(12) || ct
密钥: HKDF-SHA256(master, salt=salt, info="nbx-file-key-v1")
```

无前向保密。适合单机自加密。

### 4.2 FS 信封（nbx/fskey.py）— 前向保密

身份 = X25519 静态（协商）+ Ed25519 静态（签名），序列化为 raw 64 字节 Base64。

```
信封: eph_pub(32) || ts(8) || sig(64) || nonce(12) || ct
shared = X25519(eph_priv, 静态收方公钥)
key    = HKDF-SHA256(shared, salt=eph_pub || 收方公钥, info="nbx-fs-session-key-v1")
sig    = Ed25519_sign(发送方, eph_pub || ts || 收方公钥 || ct)
```

开销恒定 116 字节（含 8B 重放防护时间戳）。发送后临时私钥销毁；长期私钥日后泄露也无法解出旧会话。收方先验签后解密。

重放防护（FS 与 PQ 共用，见 5.1）：解封前校验时间窗（默认 ±300 秒）并查信封 ID 缓存。

### 4.3 PQ 混合信封（nbx/pq/）— 抗量子

在 FS 基础上增加 ML-KEM-768（FIPS 203，Kyber；vendored 纯 Python 实现）。

身份 = X25519 静态 + Ed25519 静态 + ML-KEM-768 静态（ek 1184B / dk 2400B）。

```
信封: eph_x_pub(32) || kem_ct(1088) || ts(8) || sig(64) || nonce(12) || ct
x_shared   = X25519(eph_priv, 收方 X25519 公钥)
kem_shared = ML-KEM-768.encaps(收方 ek).shared
key        = HKDF-SHA256(x_shared || kem_shared, salt=eph_pub || 收方公钥,
                         info="nbx-pq-hybrid-session-v1")
sig        = Ed25519_sign(发送方, eph_pub || kem_ct || ts || 收方公钥 || ct)
```

开销恒定 1220 字节（含 8B 重放防护时间戳）。两路共享秘密拼接后经 HKDF 混合：X25519 与 ML-KEM 需同时被破才威胁会话密钥。量子攻击者破解 X25519 后仍被 KEM 侧挡住。

安全级别：NIST Category 1（ML-KEM-768 ≈ AES-128 级，实现取 AES-192 参考点）。

### 4.4 签名绑定

FS 与 PQ 信封的签名都覆盖「临时公钥 + 时间戳 + 接收方公钥 + 密文」。改任何一项都会导致验签失败，冒充第三方身份同样失败。

### 4.5 重放防护（nbx/replay.py）

两级机制，解封顺序：验签 → 时间窗 → 缓存 → 解密。

1. 时间窗：信封内 8 字节 Unix 时间戳（LE u64），解封方校验 `|now - ts| <= max_skew`（默认 300 秒）。过期/超前信封直接拒绝——即使签名合法。发送方时钟偏差超过窗口会导致合法信封被拒，部署时需 NTP 对时。
2. 信封 ID 缓存：`SHA-256(eph_pub [|| kem_ct] || ct)` 前 16 字节。解封成功后记入缓存（默认 `~/.nbx_replay_cache.json`，TTL 86400 秒，原子写入）。有效期内重复 ID 拒绝。ephemeral 密钥每次随机生成，正常通信不会撞 ID。

边界：时间窗内的重放若发生在缓存写入前的并发场景（多进程同时解封同一信封）存在竞态；时钟回拨超窗口的发送方需重发。

## 5. Anonymity Wrapper（nbx/anon.py，层级 5，可选）

目标：外层观察者拿不到文件名、类型、大小、时间戳。

```
偏移  大小  字段
0     8    魔数 "NBAW\x01\x00\x00\x01"
8     2    标志位 (bit0 = 有填充)
10    2    填充块大小 (LE u16，0 = 关闭)
12    16   salt
28    12   nonce
40    N    ct（内层完整容器，加密进密文）
```

```
key = HKDF-SHA256(master, salt=salt, info="nbx-anonymity-wrapper-v1")
```

填充模式：加密前把明文预填充——明文 = 真实长度前缀(4B) + 内层容器 + 随机填充字节，使外层总长恰为块大小的整数倍。填充在密文内，外层观察者看不到；unwrap 单次 AEAD 解密后按前缀截断，无需猜测填充长度。两个不同大小的内层（如 1000B 与 3000B）在 4096 块下产生完全相同的 4096B 外层。填充用随机字节而非零字节，避免长度指纹。

外层字节中搜不到 NBX 魔数、文件名、任何元数据。

## 6. v1 遗留（nbx/format.py）

v1 容器（魔数 `NBXFILE\x01`）单流、无 TLV，仅保留代码供读取旧文件，不再生成。帧类型 0x02 FILE 同理，已被 BEGIN/CHUNK/END 取代。

## 7. Double Ratchet 会话（nbx/ratchet.py，IM 层）

文件信封（第 4 节）解决"一条消息的安全投递"，本节解决"一个会话的连续对话"：每条消息独立密钥、被攻破的链在下一次轮换后自愈、消息乱序仍可解。

### 9.1 会话建立（对称双临时密钥）

1. 双方各生成临时 X25519 密钥对：Alice 持 E_a，Bob 持 E_b。
2. 交换握手载荷（经 FS 信封等认证信道）：

```
握手: MAGIC(9) || eph_pub(32) || ts(8) || sig(64)      共 113 字节
sig  = Ed25519_sign(发送方, "NBXRATCH1" || eph_pub || ts)
```

3. 双方各自派生共享密钥——salt 按字典序拼接，保证两端输入相同：

```
SK = HKDF-SHA256(DH(E_a, E_b), salt=sorted(E_a_pub, E_b_pub) 拼接,
                 info="nbx-ratchet-handshake-v1", 64B)
RK = SK[:32]          根链
CK0 = SK[32:64]       初始链（单向，只能一方发送用）
```

4. 角色分配：先发言方持发送链（send_ck = CK0），后发言方持接收链（recv_ck = CK0）。两方必须恰好一方先发——同一链密钥双向使用会密钥重用。后发言方首次发送时做发送侧 DH step 换新链。

### 9.2 消息格式

```
报文: header(40) || nonce(12) || ct
header: ratchet_pub(32) || prev_chain_len(4, LE u32) || msg_no(4, LE u32)
AAD = "NBXRATCH1" || header
ct   = ChaCha20-Poly1305(message_key, nonce, AAD, plaintext)
```

头部明文可见（服务器无需解密即可读），但被 AAD 绑定——篡改任何字节解密即失败。`ratchet_pub` 是发送方当前 ratchet 公钥；`prev_chain_len` 是上一条链发出的消息数，供收方补齐 skipped keys；`msg_no` 是本链内序号。

### 9.3 链的推进与轮换

```
KDF_CK(ck) = HKDF-SHA256(ikm=ck, info="nbx-ratchet-chain-v1", 64B)
             → (next_ck, message_key)        每发/收一条消息推进一次
KDF_RK(rk, dh_out) = HKDF-SHA256(ikm=dh_out, salt=rk,
                 info="nbx-ratchet-root-v1", 64B)
             → (new_rk, new_chain_key)       每次 DH 轮换调用
```

- **发送**：推进 send 链，message_key 加密后即焚。
- **接收**：`ratchet_pub` 与已知的相同 → 推进 recv 链到 msg_no；不同 → 先做接收侧 DH step（KDF_RK(rk, DH(dh_self, 新公钥))）开新接收链。
- **发送侧轮换**：每方在收到对方新 ratchet 公钥后的首次发送（或后发言方首次发送）生成新的 ratchet 密钥对，send 链 = KDF_RK(rk, DH(新私钥, 对方当前公钥))。此后双方 ratchet 公钥交替换新。

### 9.4 乱序与重放

- 乱序：消息 5 先于 3、4 到达时，接收链推进过程中跳过的 message_key 存入缓存，键为 `(ratchet_pub, msg_no)`，上限 MAX_SKIP=256。3、4 后到时从缓存取出解密（命中即焚）。超过上限拒绝。
- 重放：同一条密文第二次到达时 msg_no 已被推进且 skipped 缓存无此键 → `message already processed` 拒绝。消息级重放防护不依赖时间窗（与 4.5 的信封级防护独立并存）。

### 9.5 安全性质与边界

- 逐消息前向保密：攻破当前链密钥推不出已焚的 message_key。
- 恢复性（PCS）：某条链被攻破后，双方下一次 DH 轮换引入新鲜 DH 输出，链自愈。
- 初始认证：握手签名绑定 eph_pub + 时间戳，防 MITM 篡改临时公钥；身份真实性靠 TOFU 指纹核对（与 4.2 同源）。
- 已知边界：DH step 用 X25519，不含 PQ——PQ 混合在信封层（4.3），ratchet 层的 PQ 化（KEM 替代 DH step）留待后续版本；会话状态仅存内存，进程重启即失效，需重新握手。

## 8. 消息信封（nbx/message.py，IM 层）

IM 消息 = 明文头（服务器路由所需的最小元数据）+ 加密体（9 节的 ratchet 报文）。正文、文件名、时间戳全部在加密体内，服务器不可见。

### 10.1 明文头（48 字节）

```
偏移  大小  字段
0     8    魔数 "NBXMSG\x01\x00"
8     1    版本 (1)
9     1    负载类型 ptype
10    1    标志位 (预留)
11    1    保留 (0)
12    8    发送方指纹 (SHA-256(身份公钥材料) 前 8 字节)
20    8    接收方指纹
28    16   msg_id（随机，去重/已读回执引用）
44    4    body 长度 (LE u32)
48    N    加密体（ratchet 报文）
```

头部无校验和：它是明文路由元数据，完整性由加密体 AEAD 与长度校验（body 长度不符即拒）兜底。篡改指纹只会送错人，不会骗过收方解密。

### 10.2 负载类型

| ptype | 名称 | 用途 |
|-------|------|------|
| 0x01 | TEXT | 文本消息 |
| 0x02 | FILE_OFFER | 文件提供（加密体内：文件名+大小+SHA-256，等 ACK） |
| 0x03 | FILE_CHUNK | 文件分块（加密体内：offset+数据，支持乱序重组） |
| 0x04 | FILE_ACK | 文件确认 |
| 0x05 | TYPING | 正在输入 |
| 0x06 | READ | 已读回执（加密体内：已读到的 msg_id） |
| 0x07 | HANDSHAKE | ratchet 握手载荷（FS 信封外壳） |
| 0x08 | PING | 存活探测 |
| 0x09 | PONG | 存活应答 |

### 10.3 加密体内的字段编码

TEXT/READ/FILE_* 的明文用小型 TLV：`type(1, LE u8) || len(4, LE u32) || value`。

| type | 字段 |
|------|------|
| 1 | 文本 / 分块数据 |
| 2 | msg_id 引用（已读回执） |
| 3 | 文件名 |
| 4 | 文件大小 (LE u64) |
| 5 | SHA-256 (32B) |
| 6 | 分块偏移 (LE u64) |

## 9. 中继服务器（nbx/relay.py, workers-relay/）

IM 消息的离线投递通道。服务器是密文搬运工：只解析明文头（10.1 的 48 字节）做路由，正文永远不可见，取走即清、不留历史。

### 9.1 双部署形态

| | Python（nbx/relay.py） | Workers（workers-relay/） |
|---|---|---|
| 运行环境 | 任意 VPS / 本机，stdlib http.server | Cloudflare Workers + Durable Objects |
| 存储 | MemoryStore（可换 SQLite） | 每 指纹一个 DO 实例（idFromName），强一致 |
| 验签 | cryptography Ed25519 | WebCrypto crypto.subtle Ed25519（原生，无需 WASM） |
| 部署 | `python -m nbx.cli relay --port 8765` | `cd workers-relay && npx wrangler deploy` |

两形态共享同一字节协议，客户端可混用（Python 端点连 Workers 中继已互操作实测）。DO 侧对同一指纹的并发读写串行化，规避 4.5 节提到的缓存竞态。

### 9.2 参数（两形态一致）

| 参数 | 值 | 说明 |
|------|-----|------|
| 信封 TTL | 7 天（604800s） | 入队时打时间戳，超时清理 |
| 每指纹队列上限 | 256 条 | 满则丢最旧 |
| 单信封上限 | 1 MiB | 大文件走 FILE_OFFER + 分块，多信封传 |
| 时间窗 | ±300s | /auth 与取信 proof 共用 |

### 9.3 端点

```
POST /envelope          body = 完整消息信封（明文头 + 加密体）
  校验: 长度 ≤ 1MiB、魔数、版本、body 长度一致、ptype ≠ 0、sender_fp ≠ recv_fp
  202 {ok, msg_id(b64url)}   400 {ok:false, error}

POST /auth              body = fp(8) || ts(8, LE u64) || ed_pub(32) || sig(64)
  sig = Ed25519_sign(ed_pub 私钥, "nbx-relay-auth-v1" || fp || ts)
  TOFU：指纹首次登记绑定公钥；重复登记同钥 200，换绑 409
  200 / 400（长度、时间窗）/ 403（坏签名）/ 409（换绑）

GET /inbox/<fp_b64url>?proof=<b64url>
  proof = ts(8) || sig(64)，sig = Ed25519_sign(登记的私钥, AUTH_INFO || fp || ts)
  授权通过 → 取走该指纹全部信封并清空（取走即清）
  200 {ok, envelopes:[b64url]}   403（未登记/错钥/超窗）   400

GET /health             200 {ok:true}
```

### 9.4 服务器威胁模型边界

- 服务器可见：收发双方指纹、消息类型、投递时间、信封大小、频率。想隐藏大小用 5 节 AW 填充；想隐藏与服务器的关系用 10 节 L2。
- 服务器不可见：正文、文件名、会话上下文、ratchet 状态。
- 恶意服务器：可以丢信（可用性攻击，协议无法防）、延迟投递；不能篡改（AEAD）、不能重放成功（4.5 + 7.4 双层）、不能伪造发件人（Ed25519）。
- 信任模型：TOFU。/auth 首次绑定后换绑被拒（409），但首次绑定时若中间人抢先登记，服务器无法区分——身份真实性最终靠带外指纹核对（4.2）。

## 10. 会话持久化与三层传输栈（nbx/contacts.py）

### 10.1 ratchet 会话状态序列化

```
blob = base64( MAGIC_STATE(11, "NBXRATCHST1") || ver(1) || TLV fields )
TLV: type(1) || len(4, LE u32) || value
  1 root_key(32)       2 send_ck(32 或空)   3 recv_ck(32 或空)
  4 dh_self_priv(32)   5 dh_remote_pub(32)  6 skipped entries
  7 counters: prev_send_len(4) || send_n(4) || recv_n(4)，各 LE u32
skipped entry: ratchet_pub(32) || msg_no(4, LE) || message_key(32)
```

恢复后通信无缝继续，含乱序场景：skipped 键跨进程保留，"消息 2 已解、重启、消息 1 后到"仍可解（实测）。状态含 ratchet 私钥，敏感级别等同身份私钥，落盘必须加密（可用 5 节 AW）。

### 10.2 通讯录

联系人 = 身份公钥材料（Base64）+ 最近会话状态 + 候选地址表 + 降级顺序：

```json
{ "<fp_b32>": {
    "pub": "<b64 身份公钥>",
    "session": "<ratchet export_state>",
    "addrs": [{"layer": 1, "addr": "192.168.1.5:8765", "ts": 0},
              {"layer": 2, "addr": "xxx.onion:8765"},
              {"layer": 3, "addr": "https://relay.example"}],
    "pref": [1, 2, 3] } }
```

`pref` 可配：隐私优先 `[2,3]`（永不经 L1 直连，防真实 IP 关联）；延迟优先 `[1,3]`。地址表由握手消息交换（M2.5c 起自动填 L1 候选），成功投递的地址记录 `last_ok` 时间。

### 10.3 三层传输

```
应用层 → TransportStack.send(fp, blob)
  L1 P2P 直连    TCP 直连对端 mini-relay（同 relay 协议）；UDP 打洞在 M2.5c
  L2 匿名网络    SOCKS5（Tor 9050）→ onion:port 上的 relay 协议；I2P 同构
  L3 中继        relay HTTP（9.3），首次自动 /auth
按 pref 顺序逐层逐地址尝试，成功即返回 (layer, result) 并记录；全部失败返回 -1。
poll() 反向：从所有标记 last_ok 的地址取自己的桶。
```

三层跑的是同一个应用层协议（8 节消息信封），区别只在把字节塞进哪个管道。部署推论：一台 onion 服务或一个 Workers 实例都是"L3 的一种地址"，客户端无需区分对待。

边界：L1 的 P2P 直连地址会暴露本机网络位置（NAT 后的局域网地址无害，公网映射地址敏感）；L2 依赖本机 Tor/I2P 进程，等于把匿名性外包给覆盖网络的规模与配置；三层都不防本机被入侵。

## 11. 威胁模型与边界

| 对手 | 防护 |
|------|------|
| 窃听线路 | 层级 4 全部模式（传输强制 E2E，明文在发送前自动加密） |
| 篡改密文 | AEAD tag + SHA-256 + 签名，任何一处不过即拒绝 |
| 冒充发送方 | Ed25519 验签（需要收方持有发送方公钥并核对指纹） |
| 量子计算机（未来存档攻击） | PQ 混合信封 |
| 元数据采集 | Anonymity Wrapper（需显式开启） |
| 已长期掌握的私钥泄露 | FS / PQ 模式保护过去的会话；主密钥模式无此性质 |
| 收方主动泄露 | 无法防护 |
| 重放（重发旧信封） | 信封级：时间窗（±300s）+ 信封 ID 缓存（4.5 节）；消息级：链序号 + skipped 缓存（7.4 节） |
| 会话链被攻破 | Double Ratchet：下一次 DH 轮换引入新鲜 DH 输出，链自愈（7.5 节） |
| 网络审查 / 隐藏服务器位置 | L2 匿名网络：onion/destination 地址不可关联真实 IP（10.3 节） |
| 中继作恶（丢信/拖延） | 可用性攻击，协议无法防；可换中继或走 L1/L2 |
| 中继作恶（篡改/伪造/重放） | AEAD + Ed25519 + 双层重放防护，服务器无法绕过（9.4 节） |

已知边界：TLS 层缺失——帧层裸奔在 TCP 上，依赖层级 4 提供机密性；时序侧信道——ML-KEM-768 使用 vendored 纯 Python 实现（kyber-py），非常时实现，解封耗时可能侧漏信息，本协议按"无物理旁路、非实时"对手建模，高对抗部署应换用常时（constant-time）KEM 实现或 liboqs；会话密钥协商层（7 节 Double Ratchet）的 DH step 仍为 X25519，不含后量子成分，抗量子的存档攻击需在信封层（4.3 PQ 混合）实现；ratchet 会话状态含 ratchet 私钥，导出/落盘时敏感级别等同身份私钥，必须加密存储（10.1 节）；中继服务器可丢弃信封（可用性攻击，9.4 节）；会话状态仅在内存时进程重启丢失，持久化依赖 10.1 节且落盘须加密。

## 12. CLI 一览

```
nbx keygen / pack / unpack          主密钥模式
nbx convert / extract / bundle      万物转换 + 无损还原
nbx view                            终端查看（不落盘）
nbx identity new|show|pubout        FS 身份
nbx seal / unseal                   FS 信封
nbx pqseal / pqunseal               PQ 混合信封
nbx anon pack|unpack                匿名包装
nbx send / listen                   分块传输（强制 E2E）
nbx relay --port                    启动中继服务器
nbx chat --my-id --to-pub           经中继的加密会话客户端
workers-relay/ (npx wrangler deploy)  Cloudflare Workers 版中继
```
