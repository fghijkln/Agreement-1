# Nebula Transfer Protocol (NTP-X)

独属于自己的加密传输协议：只能传输自定义的 `.nbx` 专属文件格式，
使用独一无二的密钥进行端到端加密。

## 架构

```
nbx/
├── format.py    # .nbx 专属文件容器格式（编解码）
├── crypto.py    # 密钥派生 + AEAD 端到端加密
├── protocol.py  # 自定义传输协议帧（握手/清单/数据/结束）
├── client.py    # 收发两端实现
└── cli.py       # 命令行工具
```

## 文件格式 .nbx

```
偏移   大小  字段
0      8    魔数 "NBXFILE\x01"
8      1    版本
9      1    标志位
10     2    元数据区长度 (LE)
12     M    元数据 (JSON, UTF-8)
12+M   4    数据区长度 (LE)
16+M   N    数据
16+M+N 32   SHA-256 校验
```

## 加密方案

- 主密钥：32 字节（Base64 存储），环境变量 `NBX_MASTER_KEY` 或密钥文件
- 每文件：HKDF-SHA256 派生独立子密钥 + 随机 24 字节 nonce
- 算法：ChaCha20-Poly1305 认证加密

## 用法

```bash
# 生成密钥
python -m nbx.cli keygen --out my.key

# 打包 .nbx 文件
python -m nbx.cli pack secret.txt secret.nbx --meta '{"title":"demo"}'

# 发送
python -m nbx.cli send secret.nbx 127.0.0.1 9000

# 接收
python -m nbx.cli listen 9000 --outdir ./received
```
