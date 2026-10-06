# Nebula Transfer Protocol (NBX)

私有加密文件传输协议。任何文件（文本、markdown、html、图片、任意二进制）转成 `.nbx` 容器，经端到端加密后在自有的 TCP 协议上分块传输。三种加密模式可选，其中一种抗量子。

协议字节级规范见 [SPEC.md](SPEC.md)。

## 快速上手

```bash
# 生成主密钥
python -m nbx.cli keygen --out my.key

# 任意文件 → .nbx
python -m nbx.cli convert photo.jpg photo.nbx
python -m nbx.cli convert notes.md notes.nbx --compress --encrypt --keyfile my.key

# 不落盘直接看内容（markdown 会渲染，加密文件需 --keyfile）
python -m nbx.cli view notes.nbx --keyfile my.key

# 无损还原（逐字节一致）
python -m nbx.cli extract photo.nbx --outdir ./

# 多个文件打成一个 .nbx
python -m nbx.cli bundle pack.nbx a.txt b.png c.pdf

# 传输（接收端拿到的永远是密文）
python -m nbx.cli listen 9000 --outdir ./received --keyfile my.key
python -m nbx.cli send notes.nbx 127.0.0.1 9000 --keyfile my.key
```

发送普通明文文件时协议会自动加密再上线，日志会提示 `plaintext detected -> auto-encrypted`。

## 三种加密模式

| 模式 | 命令 | 前向保密 | 抗量子 | 依赖 |
|------|------|:---:|:---:|------|
| 主密钥 | `pack --encrypt` | ✗ | ✗ | 密钥文件或 `NBX_MASTER_KEY` |
| FS 信封 | `seal` / `unseal` | ✓ | ✗ | 双方互换公钥 |
| PQ 混合信封 | `pqseal` / `pqunseal` | ✓ | ✓ | 双方互换 PQ 公钥 |

FS / PQ 身份管理：

```bash
python -m nbx.cli identity new alice.id     # 生成身份 + 指纹
python -m nbx.cli identity pubout alice.id  # 导出公钥发给对方
python -m nbx.cli pqseal plan.txt plan.pq --my-id alice.id --to-pub bob.id.pub
python -m nbx.cli pqunseal plan.pq out.txt --my-id bob.id --from-pub alice.id.pub
```

PQ 模式用 X25519 + ML-KEM-768（FIPS 203）双路密钥交换，HKDF 混合。两套算法需同时被破才威胁会话密钥，存档数据不怕未来的量子计算机。信封开销 1212 字节。

指纹（如 `JXFPLLIX2GEUS`）用于人工核对双方公钥，防中间人。

## Anonymity Wrapper（可选）

容器元数据（文件名、类型、大小）默认明文可读。加上匿名外层后全部进密文：

```bash
python -m nbx.cli anon pack secret.nbx secret.aw --keyfile my.key --pad 4096
python -m nbx.cli anon unpack secret.aw secret.nbx --keyfile my.key
```

`--pad 4096` 在加密前把明文预填充到 4 KiB 倍数（随机字节，填充随密文一起加密）。1000 字节和 3000 字节的内层产生相同的 4096 字节外层，长度不可区分；解密单次 AEAD 完成。外层搜不到 NBX 魔数和任何元数据。

## 代码结构

```
nbx/
├── carrier.py     v2 容器：TLV 多流、类型嗅探、LZMA、SHA-256
├── crypto.py      主密钥模式：HKDF → ChaCha20-Poly1305
├── fskey.py       FS 信封：X25519 临时 + Ed25519 签名
├── pq/            PQ 混合信封：+ ML-KEM-768（vendored kyber-py）
├── anon.py        Anonymity Wrapper：元数据加密 + 长度填充
├── relay.py       中继服务器：分桶队列/TTL/取走即清/TOFU 授权
├── contacts.py    通讯录 + 三层传输栈（P2P/匿名网络/中继）
├── chat.py        经中继的加密会话客户端
├── replay.py      重放防护：时间窗 + 信封 ID 持久缓存
├── ratchet.py     Double Ratchet 会话：逐消息前向保密、DH 轮换、乱序容忍
├── message.py     IM 消息信封：9 种负载类型，正文全在加密体
├── protocol.py    线路帧：HELLO/ACK/BYE/BEGIN/CHUNK/END
├── transfer.py    收发两端：64 KiB 分块、流式 SHA-256 校验
├── viewer.py      终端渲染（markdown/html/hexdump，解密在内存）
└── cli.py         全部子命令
```

测试：

```bash
python3 tests/test_carrier.py    # 容器 roundtrip、嗅探、bundle、加密、篡改检测
python3 tests/test_fskey.py      # FS：冒充拒绝、篡改拒绝、前向保密性质
python3 tests/test_pq_anon.py    # PQ 混合、KEM 随机性、匿名包装、E2E 强制
python3 tests/test_replay.py     # 重放防护：时间窗、缓存持久化、旧攻击面回归
python3 tests/test_ratchet.py    # ratchet：前向保密、乱序、重放、文件分块、FS 完整栈
python3 tests/test_relay.py      # 中继：投递校验、TTL、TOFU、HTTP、端到端
python3 tests/test_transport.py  # 传输栈：会话持久化、降级、通讯录
```

## 中继服务器与三种部署形态

IM 消息的离线投递由中继完成——服务器只看 48 字节明文路由头，正文永远在加密体里，取走即清不留历史。同一协议三种跑法：

```bash
python -m nbx.cli relay --port 8765           # 自建（VPS/本机）
cd workers-relay && npx wrangler deploy       # Cloudflare Workers + Durable Objects
tor onion service 指向任意上述实例             # 匿名部署，地址不可关联真实 IP
```

参数一致：信封保存 7 天、每收件人队列上限 256、单信封 1 MiB、时间窗 ±300s。Python 客户端连 Workers 中继已互操作实测（正式账号部署：`https://nbx-relay.sctdjohn.workers.dev`）。

Workers 部署注意：需 `CLOUDFLARE_API_TOKEN`（模板 "Edit Cloudflare Workers" 即可）；`workers.dev` 前置的 Cloudflare 防护会 403 拦截无 User-Agent 的请求，客户端须带 UA（`nbx.chat` 已内置 `NBX-Client/1.0`）。

## 三层传输栈

```
应用层 → TransportStack.send(联系人, 消息)
  L1  P2P 直连     局域网/打洞后的直连（最低延迟）
  L2  匿名网络     Tor/I2P 上的中继（无公网 IP 也可收发，IP 不可关联）— 已实测
  L3  中继服务器   自建或 Workers（保底，永远可达）
```

按每个联系人的偏好顺序自动降级（隐私优先 `[2,3]`、延迟优先 `[1,3]`），成功层自动记录。会话状态可导出恢复——重启后不用重新握手，乱序消息跨重启仍可解。

## IM 会话（Double Ratchet）

文件信封之上的会话层，面向即时通讯：每条消息独立密钥（用后即焚），收到对方新 ratchet 公钥即轮换链（被攻破的链自愈），消息乱序仍可解（skipped keys 缓存，上限 256）。握手双方各出临时 X25519 密钥，Ed25519 签名绑定，经 FS 信封交换。消息信封明文头只含路由元数据（收发方指纹 + msg_id + 类型），正文、文件名、已读回执全在加密体内。字节级布局见 SPEC.md 第 7、8 节。

## 安全边界

防：线路窃听、密文篡改、身份冒充、未来量子解密（PQ 模式）、元数据采集（AW 模式）、信封重放（时间窗 ±300s + 信封 ID 持久缓存）、消息重放（链序号 + skipped 缓存）。

不防：接收方主动泄露；帧层未接入 TLS，机密性完全依赖加密信封；时序侧信道——ML-KEM-768 为 vendored 纯 Python 实现（kyber-py，非常时实现），高对抗场景下解封操作的时间可能泄露信息，当前按非实时、无物理旁路对手建模；ratchet 的 DH 轮换仍为 X25519，不含后量子成分，抗量子存档攻击依赖信封层的 PQ 混合。细节见 SPEC.md 第 9 节。
