// R2-15 回归: 跨 DO pop/release 故障一致性。
// 场景: release 失败 → /inbox 返回 503 → 信封仍在 pending(不丢)
// → 客户端重试 /inbox → /pop 重发同批 → release 幂等(去重集)
// → ack 提交删除 → 再取为空 → Registry 账本归位(不重复退账)。
import { env, SELF } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";

const AUTH_INFO = "nbx-relay-auth-v1";
const DELIVERY_INFO = "nbx-relay-delivery-v2";
const MAGIC = new Uint8Array([0x4e, 0x42, 0x58, 0x4d, 0x53, 0x47, 0x01, 0x00]);
const concat = (...arrs: Uint8Array[]): Uint8Array => {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total); let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
};
const b64u = (b: Uint8Array): string =>
  btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const sign = async (priv: CryptoKey, data: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" } as AlgorithmIdentifier, priv, data as BufferSource));
const tNow = (): Uint8Array => {
  const t = new Uint8Array(8);
  new DataView(t.buffer).setBigUint64(0, BigInt(Math.floor(Date.now() / 1000)), true);
  return t;
};
async function genKey(): Promise<{ pub: Uint8Array; priv: CryptoKey }> {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" } as AlgorithmIdentifier, true, ["sign", "verify"]) as CryptoKeyPair;
  const ed = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { pub: concat(crypto.getRandomValues(new Uint8Array(32)), ed), priv: kp.privateKey };
}
const fpOf = async (keys: { pub: Uint8Array }): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", keys.pub as BufferSource)).slice(0, 8);
const authBody = async (k: { pub: Uint8Array; priv: CryptoKey }) =>
  concat(k.pub, tNow(), await sign(k.priv, concat(new TextEncoder().encode(AUTH_INFO), k.pub, tNow())));
const authProof = async (k: { priv: CryptoKey }, fp: Uint8Array) =>
  concat(tNow(), await sign(k.priv, concat(new TextEncoder().encode(AUTH_INFO), fp, tNow())));
const deliveryProof = async (k: { priv: CryptoKey }, env_: Uint8Array) => {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", env_ as BufferSource));
  return concat(tNow(), await sign(k.priv, concat(new TextEncoder().encode(DELIVERY_INFO), d, tNow())));
};
function packMessage(pt: number, sfp: Uint8Array, rfp: Uint8Array, body: Uint8Array): Uint8Array {
  const hdr = new Uint8Array(48);
  hdr.set(MAGIC, 0); hdr[8] = 1; hdr[9] = pt;
  new DataView(hdr.buffer).setUint32(44, body.length, true);
  hdr.set(sfp, 12); hdr.set(rfp, 20);
  return concat(hdr, body);
}
async function stats() {
  const stub = env.NBX_REGISTRY.get(env.NBX_REGISTRY.idFromName("registry"));
  return (await (await stub.fetch("https://do/stats")).json()) as
    { registered: number; recip_count: number; total_bytes: number };
}

describe("R2-15: 跨 DO 故障一致性", () => {
  it("release 失败→503→消息保留→重试成功→账本归位", async () => {
    const before = await stats();
    const bob = await genKey(); const alice = await genKey();
    const bobFp = await fpOf(bob); const aliceFp = await fpOf(alice);
    await SELF.fetch("https://example.com/auth", { method: "POST", body: await authBody(bob) as unknown as BodyInit });
    await SELF.fetch("https://example.com/auth", { method: "POST", body: await authBody(alice) as unknown as BodyInit });

    const envBytes = packMessage(1, aliceFp, bobFp, new TextEncoder().encode("r2-15"));
    expect(envBytes.length).toBe(53);
    const dr = await SELF.fetch("https://example.com/envelope", {
      method: "POST", body: concat(envBytes, await deliveryProof(alice, envBytes)) as unknown as BodyInit,
    });
    expect(dr.status).toBe(202);
    const afterPush = await stats();
    expect(afterPush.total_bytes).toBe(before.total_bytes + 53);

    // 模拟 release 失败: 让 RegistryDo /recipient_release 抛异常
    const regGet = env.NBX_REGISTRY.get.bind(env.NBX_REGISTRY);
    const realStub = regGet(env.NBX_REGISTRY.idFromName("registry"));
    const broken = new Proxy(realStub, {
      get(target, prop) {
        if (prop === "fetch") {
          return async (_url: unknown, init?: RequestInit) => {
            const u = String(_url);
            if (u.includes("recipient_release")) throw new Error("simulated cross-DO failure");
            return (target as any).fetch(_url as RequestInfo, init);
          };
        }
        return (target as any)[prop];
      },
    }) as DurableObjectStub;
    (env.NBX_REGISTRY as any).get = () => broken;

    const r1 = await SELF.fetch("https://example.com/inbox/" + b64u(bobFp), {
      method: "POST", body: await authProof(bob, bobFp) as unknown as BodyInit,
    });
    expect(r1.status).toBe(503);   // release 失败 → 可重试, 不清 pending

    // 恢复正常 DO
    (env.NBX_REGISTRY as any).get = regGet;

    // 重试 /inbox: /pop 重发同批(消息未丢!), release 幂等, ack 提交
    const r2 = await SELF.fetch("https://example.com/inbox/" + b64u(bobFp), {
      method: "POST", body: await authProof(bob, bobFp) as unknown as BodyInit,
    });
    expect(r2.status).toBe(200);
    const j2 = (await r2.json()) as { envelopes: string[]; popped_bytes: number };
    expect(j2.envelopes.length).toBe(1);
    const got = atob(j2.envelopes[0].replace(/-/g, "+").replace(/_/g, "/"));
    const gotBytes = new Uint8Array(got.length);
    for (let i = 0; i < got.length; i++) gotBytes[i] = got.charCodeAt(i);
    expect(b64u(gotBytes)).toBe(b64u(envBytes));

    // 第三次取信: 空(ack 已真正提交删除)
    const r3 = await SELF.fetch("https://example.com/inbox/" + b64u(bobFp), {
      method: "POST", body: await authProof(bob, bobFp) as unknown as BodyInit,
    });
    expect(((await r3.json()) as { envelopes: string[] }).envelopes.length).toBe(0);

    // 账本归位: 只退了一次账(幂等去重), 名额释放
    const after = await stats();
    expect(after.total_bytes).toBe(before.total_bytes);
    expect(after.recip_count).toBe(before.recip_count);
  });
});
