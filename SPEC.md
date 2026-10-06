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
信封: eph_pub(32) || sig(64) || nonce(12) || ct
shared = X25519(eph_priv, 静态收方公钥)
key    = HKDF-SHA256(shared, salt=eph_pub || 收方公钥, info="nbx-fs-session-key-v1")
sig    = Ed25519_sign(发送方, eph_pub || 收方公钥 || ct)
```

开销恒定 108 字节。发送后临时私钥销毁；长期私钥日后泄露也无法解出旧会话。收方先验签后解密。

### 4.3 PQ 混合信封（nbx/pq/）— 抗量子

在 FS 基础上增加 ML-KEM-768（FIPS 203，Kyber；vendored 纯 Python 实现）。

身份 = X25519 静态 + Ed25519 静态 + ML-KEM-768 静态（ek 1184B / dk 2400B）。

```
信封: eph_x_pub(32) || kem_ct(1088) || sig(64) || nonce(12) || ct
x_shared   = X25519(eph_priv, 收方 X25519 公钥)
kem_shared = ML-KEM-768.encaps(收方 ek).shared
key        = HKDF-SHA256(x_shared || kem_shared, salt=eph_pub || 收方公钥,
                         info="nbx-pq-hybrid-session-v1")
sig        = Ed25519_sign(发送方, eph_pub || kem_ct || 收方公钥 || ct)
```

开销恒定 1212 字节。两路共享秘密拼接后经 HKDF 混合：X25519 与 ML-KEM 需同时被破才威胁会话密钥。量子攻击者破解 X25519 后仍被 KEM 侧挡住。

安全级别：NIST Category 1（ML-KEM-768 ≈ AES-128 级，实现取 AES-192 参考点）。

### 4.4 签名绑定

FS 与 PQ 信封的签名都覆盖「临时公钥 + 接收方公钥 + 密文」。改任何一项都会导致验签失败，冒充第三方身份同样失败。

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

填充模式：密文前加 4 字节真实长度，尾部用随机字节补齐到块大小的整数倍。两个不同大小的内层（如 1000B 与 3000B）在 4096 块下产生完全相同的 4136B 外层。填充用随机字节而非零字节，避免长度指纹。

外层字节中搜不到 NBX 魔数、文件名、任何元数据。

## 6. v1 遗留（nbx/format.py）

v1 容器（魔数 `NBXFILE\x01`）单流、无 TLV，仅保留代码供读取旧文件，不再生成。帧类型 0x02 FILE 同理，已被 BEGIN/CHUNK/END 取代。

## 7. 威胁模型与边界

| 对手 | 防护 |
|------|------|
| 窃听线路 | 层级 4 全部模式（传输强制 E2E，明文在发送前自动加密） |
| 篡改密文 | AEAD tag + SHA-256 + 签名，任何一处不过即拒绝 |
| 冒充发送方 | Ed25519 验签（需要收方持有发送方公钥并核对指纹） |
| 量子计算机（未来存档攻击） | PQ 混合信封 |
| 元数据采集 | Anonymity Wrapper（需显式开启） |
| 已长期掌握的私钥泄露 | FS / PQ 模式保护过去的会话；主密钥模式无此性质 |
| 收方主动泄露 | 无法防护 |

已知边界：TLS 层缺失——帧层裸奔在 TCP 上，依赖层级 4 提供机密性；不含重放保护，同一信封可被重放（时间戳字段未纳入签名绑定）；时序侧信道——ML-KEM-768 使用 vendored 纯 Python 实现（kyber-py），非常时实现，解封耗时可能侧漏信息，本协议按"无物理旁路、非实时"对手建模，高对抗部署应换用常时（constant-time）KEM 实现或 liboqs。

## 8. CLI 一览

```
nbx keygen / pack / unpack          主密钥模式
nbx convert / extract / bundle      万物转换 + 无损还原
nbx view                            终端查看（不落盘）
nbx identity new|show|pubout        FS 身份
nbx seal / unseal                   FS 信封
nbx pqseal / pqunseal               PQ 混合信封
nbx anon pack|unpack                匿名包装
nbx send / listen                   分块传输（强制 E2E）
```
