/**
 * NbxFpDurableObject — 每个收件人指纹一个实例（idFromName(fp)）。
 * 状态全部存 instance storage：信封队列 + 登记的 Ed25519 公钥。
 * 强一致：同一指纹的并发读写都在同一个 DO 上串行化。
 */
const TTL_MS = 7 * 86400 * 1000;
const MAX_PER_FP = 256;
const MAX_REGISTERED = 10000;            // audit R-10: 全局登记公钥上限
const SEND_QUOTA_WINDOW_MS = 3600 * 1000;// audit R-10: per-sender 投递配额窗口
const SEND_QUOTA_MAX = 600;              // 每发送者每小时最多投递数
// audit R2-08: 收件人维度资源预算 —— sender quota 限速不限规模，
// 伪造 recv_fp 可以无限创建 DO/持久化存储，必须在 RegistryDo 做
// 收件人准入。三个闸门:
const MAX_ACTIVE_RECIPIENTS = 50000;     // 存活收件人 fp 数上限
const MAX_TOTAL_QUEUED_BYTES = 512 * 1024 * 1024; // 全局队列字节预算 (512 MiB)
const RECIPIENT_DECAY_MS = 7 * 86400 * 1000;      // 收件人记账 TTL(与信封 TTL 同步)
const MAGIC_MSG = new Uint8Array([0x4e, 0x42, 0x58, 0x4d, 0x53, 0x47, 0x01, 0x00]);

function b64urlEncode(buf: Uint8Array): string {
  let s = "";
  for (const c of buf) s += String.fromCharCode(c);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function concat(...arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

function json(status: number, obj: unknown): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

interface StoredEnvelope {
  at: number;          // 入队 epoch ms
  env: string;         // b64url(信封字节)
}

export class NbxFpDurableObject {
  private state: DurableObjectState;

  constructor(state: DurableObjectState, _env: unknown) {
    this.state = state;
  }

  private async gc(): Promise<void> {
    const q = ((await this.state.storage.get<StoredEnvelope[]>("q")) ?? [])
      .filter((e) => Date.now() - e.at < TTL_MS);
    await this.state.storage.put("q", q);
  }

  async fetch(req: Request): Promise<Response> {
    const path = new URL(req.url).pathname;

    if (req.method === "PUT" && path === "/pubkey") {
      const pubRaw = new Uint8Array(await req.arrayBuffer());
      if (pubRaw.length !== 32) return json(400, { ok: false, error: "bad pubkey length" });
      const existing = await this.state.storage.get<Uint8Array>("pubkey");
      if (existing) {
        const old = b64urlEncode(existing);
        const neu = b64urlEncode(pubRaw);
        if (old !== neu) return json(409, { ok: false, error: "fingerprint already bound to another key" });
        return json(200, { ok: true });
      }
      // audit R-10: 全局登记上限由 worker 侧 REGISTRY DO 把关（见 index.ts /auth）
      await this.state.storage.put("pubkey", pubRaw);
      return json(200, { ok: true });
    }

    // audit R-10: per-sender 投递配额（滑动窗口计数）
    if (req.method === "POST" && path === "/send_quota") {
      const now = Date.now();
      const times = ((await this.state.storage.get<number[]>("send_times")) ?? [])
        .filter((t) => now - t < SEND_QUOTA_WINDOW_MS);
      if (times.length >= SEND_QUOTA_MAX)
        return json(429, { ok: false, error: "sender quota exceeded" });
      times.push(now);
      await this.state.storage.put("send_times", times);
      return json(200, { ok: true });
    }

    if (req.method === "GET" && path === "/pubkey") {
      const pub = await this.state.storage.get<Uint8Array>("pubkey");
      if (!pub) return new Response("not found", { status: 404 });
      return new Response(pub as unknown as BodyInit, {
        status: 200,
        headers: { "Content-Type": "application/octet-stream" },
      });
    }

    if (req.method === "POST" && path === "/push") {
      await this.gc();
      const blob = new Uint8Array(await req.arrayBuffer());
      // 基本校验（ DO 内再验一次，防绕过 worker 直连）
      if (blob.length < 48) return json(400, { ok: false, error: "bad envelope" });
      for (let i = 0; i < 8; i++) if (blob[i] !== MAGIC_MSG[i]) return json(400, { ok: false, error: "bad envelope" });
      const q = (await this.state.storage.get<StoredEnvelope[]>("q")) ?? [];
      q.push({ at: Date.now(), env: b64urlEncode(blob) });
      // 满则丢最旧
      const trimmed = q.length > MAX_PER_FP ? q.slice(q.length - MAX_PER_FP) : q;
      await this.state.storage.put("q", trimmed);
      const msgId = b64urlEncode(blob.slice(28, 44));
      return json(202, { ok: true, msg_id: msgId });
    }

    if (req.method === "GET" && path === "/pop") {
      await this.gc();
      const q = (await this.state.storage.get<StoredEnvelope[]>("q")) ?? [];
      await this.state.storage.put("q", []);       // 取走即清
      return json(200, { ok: true, envelopes: q.map((e) => e.env) });
    }

    return json(404, { ok: false, error: "not found" });
  }
}

/**
 * RegistryDo — 全局单例（idFromName("registry")），audit R-10 的登记闸门。
 * 记录已登记 fp 集合；超过 MAX_REGISTERED 拒绝新登记（幂等：已存在的 fp 放行）。
 * 存储为分片 map（fp -> 1），数量 = keys 数（DO 单实例强一致）。
 */
export class RegistryDo {
  private state: DurableObjectState;

  constructor(state: DurableObjectState, _env: unknown) {
    this.state = state;
  }

  async fetch(req: Request): Promise<Response> {
    const path = new URL(req.url).pathname;
    if (req.method === "POST" && path === "/claim") {
      const fp = new Uint8Array(await req.arrayBuffer()).toString();
      const existing = await this.state.storage.get<number>("fp:" + fp);
      if (existing) return json(200, { ok: true, existing: true });
      const count = (await this.state.storage.get<number>("count")) ?? 0;
      if (count >= MAX_REGISTERED) return json(429, { ok: false, error: "registration quota exhausted" });
      await this.state.storage.put("fp:" + fp, 1);
      await this.state.storage.put("count", count + 1);
      return json(200, { ok: true, existing: false });
    }
    // audit R2-08: 收件人准入闸门。body = recv_fp(8) || env_len(4 LE)。
    // 已知收件人放行（记字节账）；新收件人受 MAX_ACTIVE_RECIPIENTS 限制。
    // 返回 {ok:true} 准入 / 429 拒绝。信封 TTL 过期由 /decay 清账。
    if (req.method === "POST" && path === "/recipient_admit") {
      const body = new Uint8Array(await req.arrayBuffer());
      if (body.length !== 12) return json(400, { ok: false, error: "bad admit payload" });
      const fp = new Uint8Array(body.slice(0, 8)).toString();
      const envLen = new DataView(body.buffer, body.byteOffset + 8, 4).getUint32(0, true);
      const existing = await this.state.storage.get<number>("rcp:" + fp);
      if (existing !== undefined) {
        const total = ((await this.state.storage.get<number>("total_bytes")) ?? 0) + envLen;
        if (total > MAX_TOTAL_QUEUED_BYTES)
          return json(429, { ok: false, error: "global queue budget exceeded" });
        await this.state.storage.put("total_bytes", total);
        await this.state.storage.put("rcp:" + fp, existing + envLen);
        // audit R2-12: 活动时间戳每次投递刷新——decay 判据是"最后投递
        // 距今超过 TTL"，不是"创建距今"。否则活跃收件人会被误清账，
        // 造成账本与真实 DO 队列脱钩。
        await this.state.storage.put("rcp_at:" + fp, Date.now());
        return json(200, { ok: true });
      }
      const count = (await this.state.storage.get<number>("recip_count")) ?? 0;
      if (count >= MAX_ACTIVE_RECIPIENTS)
        return json(429, { ok: false, error: "recipient budget exhausted" });
      const total0 = ((await this.state.storage.get<number>("total_bytes")) ?? 0) + envLen;
      if (total0 > MAX_TOTAL_QUEUED_BYTES)
        return json(429, { ok: false, error: "global queue budget exceeded" });
      await this.state.storage.put("recip_count", count + 1);
      await this.state.storage.put("total_bytes", total0);
      await this.state.storage.put("rcp:" + fp, envLen);
      await this.state.storage.put("rcp_at:" + fp, Date.now());
      // audit R2-11: 保证 decay 循环被调度(alarm 不存在时设置)
      if (!(await this.state.storage.getAlarm())) {
        await this.state.storage.setAlarm(Date.now() + RECIPIENT_DECAY_CHECK_MS);
      }
      return json(200, { ok: true, new: true });
    }
    // audit R2-08: /pop 后归还额度（信封离开队列，字节账相应减少）。
    // body = recv_fp(8) || bytes_freed(4 LE)。
    if (req.method === "POST" && path === "/recipient_release") {
      const body = new Uint8Array(await req.arrayBuffer());
      if (body.length !== 12) return json(400, { ok: false, error: "bad release payload" });
      const fp = new Uint8Array(body.slice(0, 8)).toString();
      const freed = new DataView(body.buffer, body.byteOffset + 8, 4).getUint32(0, true);
      const cur = await this.state.storage.get<number>("rcp:" + fp);
      if (cur !== undefined) {
        const total = Math.max(0, ((await this.state.storage.get<number>("total_bytes")) ?? 0) - freed);
        const left = Math.max(0, cur - freed);
        await this.state.storage.put("total_bytes", total);
        if (left === 0) {
          // audit R2-11: 收件人账目清零 = 不再占用名额, 释放 recip_count。
          // 否则 count 只增不减, 50k 个一次性收件人即永久锁死新收件人。
          await this.state.storage.delete("rcp:" + fp);
          await this.state.storage.delete("rcp_at:" + fp);
          const count = (await this.state.storage.get<number>("recip_count")) ?? 0;
          await this.state.storage.put("recip_count", Math.max(0, count - 1));
        } else {
          await this.state.storage.put("rcp:" + fp, left);
        }
      }
      return json(200, { ok: true });
    }
    // audit R2-08/R2-11: TTL 清账 —— 由 DO alarm 定期自动调用(见 alarm()),
    // 清理"最后投递距今超过 TTL"的收件人账目。R2-12: 判据是 rcp_at(每次
    // 投递刷新)而非创建时间; 账目清零的条目已在 release 即时释放。
    // 注意: 本端点只清 RegistryDo 的账; 收件人 DO 的真实队列由其自身
    // TTL GC(StoredEnvelope.at)逐条过期——账本条目仅在"最后活动超 TTL"
    // 时删除, 此时其对应 DO 内信封必然也已全部过期(TTL 相同), 账实一致。
    if (req.method === "POST" && path === "/decay") {
      const now = Date.now();
      let count = (await this.state.storage.get<number>("recip_count")) ?? 0;
      let total = (await this.state.storage.get<number>("total_bytes")) ?? 0;
      const dels: string[] = [];
      const atMap = await this.state.storage.list({ prefix: "rcp_at:" });
      atMap.forEach((v, k) => {
        if (now - (v as number) > RECIPIENT_DECAY_MS) dels.push(k);
      });
      for (const k of dels) {
        const fp = k.slice("rcp_at:".length);
        const bytes = (await this.state.storage.get<number>("rcp:" + fp)) ?? 0;
        total -= bytes;
        count -= 1;
        await this.state.storage.delete("rcp_at:" + fp);
        await this.state.storage.delete("rcp:" + fp);
      }
      if (dels.length) {
        await this.state.storage.put("recip_count", Math.max(0, count));
        await this.state.storage.put("total_bytes", Math.max(0, total));
      }
      return json(200, { ok: true, decayed: dels.length });
    }
    // audit R2-11: 账本观测端点(运维/回归测试用)。返回当前资源账目。
    if (req.method === "GET" && path === "/stats") {
      return json(200, {
        ok: true,
        registered: (await this.state.storage.get<number>("count")) ?? 0,
        recip_count: (await this.state.storage.get<number>("recip_count")) ?? 0,
        total_bytes: (await this.state.storage.get<number>("total_bytes")) ?? 0,
      });
    }
    // audit R2-01: 中继身份签名。body = client_fp(8) || ts(8)。
    // 私钥 seed 首次生成并持久化于本单例 DO；签名覆盖
    // RELAY_AUTH_INFO || client_fp || relay_pub || ts。
    if (req.method === "POST" && path === "/relay_sign") {
      const body = new Uint8Array(await req.arrayBuffer());
      if (body.length !== 16) return json(400, { ok: false, error: "bad sign payload" });
      const clientFp = body.slice(0, 8);
      const ts = body.slice(8, 16);
      let seed = await this.state.storage.get<Uint8Array>("relay_seed");
      if (!seed || seed.length !== 32) {
        // 首次生成：同时存下公钥（WebCrypto 无法从私钥导出公钥）
        const kp = await crypto.subtle.generateKey(
          { name: "Ed25519" } as AlgorithmIdentifier, true, ["sign", "verify"]) as CryptoKeyPair;
        const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
        seed = pkcs8.slice(pkcs8.length - 32);          // 末 32B 即 seed
        const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
        await this.state.storage.put("relay_seed", seed);
        await this.state.storage.put("relay_pub", rawPub);
      }
      const pubRaw = (await this.state.storage.get<Uint8Array>("relay_pub"))!;
      const priv = await crypto.subtle.importKey(
        "pkcs8", ed25519SeedToPkcs8(seed) as BufferSource,
        { name: "Ed25519" } as AlgorithmIdentifier, false, ["sign"]);
      const msg = concat(new TextEncoder().encode(RELAY_AUTH_INFO), clientFp,
        pubRaw, ts);
      const sig = await crypto.subtle.sign(
        { name: "Ed25519" } as AlgorithmIdentifier, priv, msg as BufferSource);
      return json(200, {
        ok: true,
        relay_pub: b64urlEncode(pubRaw),
        relay_sig: b64urlEncode(new Uint8Array(sig)),
      });
    }
    return json(404, { ok: false, error: "not found" });
  }

  // audit R2-11: alarm 自调度——每 24h 自动 /decay, 保证收件人名额
  // 与字节预算可回收。首次 alarm 在首个收件人登记时设置。
  async alarm(): Promise<void> {
    const count = (await this.state.storage.get<number>("recip_count")) ?? 0;
    if (count > 0) {
      const req = new Request("https://do/decay", { method: "POST" });
      await this.fetch(req);
    }
    await this.state.storage.setAlarm(Date.now() + RECIPIENT_DECAY_CHECK_MS);
  }
}

const RELAY_AUTH_INFO = "nbx-relay-server-auth-v1";
const RECIPIENT_DECAY_CHECK_MS = 86400 * 1000;   // alarm 周期: 每天扫一次

/** 把 32B Ed25519 seed 包成 PKCS#8（WebCrypto importKey 需要容器格式）。 */
function ed25519SeedToPkcs8(seed: Uint8Array): Uint8Array {
  // PKCS#8 Ed25519 前缀（RFC 8410）：48 字节容器，最后 32 字节是 seed
  const pkcs8 = new Uint8Array(48);
  pkcs8.set([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b,
             0x65, 0x70, 0x04, 0x22, 0x04, 0x20], 0);
  pkcs8.set(seed, 16);
  return pkcs8;
}
