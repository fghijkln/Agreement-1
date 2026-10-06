/**
 * NbxFpDurableObject — 每个收件人指纹一个实例（idFromName(fp)）。
 * 状态全部存 instance storage：信封队列 + 登记的 Ed25519 公钥。
 * 强一致：同一指纹的并发读写都在同一个 DO 上串行化。
 */
const TTL_MS = 7 * 86400 * 1000;
const MAX_PER_FP = 256;
const MAGIC_MSG = new Uint8Array([0x4e, 0x42, 0x58, 0x4d, 0x53, 0x47, 0x01, 0x00]);

function b64urlEncode(buf: Uint8Array): string {
  let s = "";
  for (const c of buf) s += String.fromCharCode(c);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
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
      await this.state.storage.put("pubkey", pubRaw);
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
