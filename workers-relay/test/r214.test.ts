// R2-14 回归: 完整生产调用链账实一致性。
// /envelope → recipient_admit → DO /push → /inbox/<fp> → DO /pop → release
// 断言: 取信后 recip_count / total_bytes 完全归位(账本==现实)。
// 此前 R2-13 测试绕过 /inbox 手动 release, 盖住了 release 被
// popped_bytes===undefined 分支吞掉的真实缺陷——本测试直接走 SELF.fetch
// 公网入口, 不再允许任何手动补偿。
import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const AUTH_INFO = "nbx-relay-auth-v1";
const DELIVERY_INFO = "nbx-relay-delivery-v2";
const MAGIC = new Uint8Array([0x4e, 0x42, 0x58, 0x4d, 0x53, 0x47, 0x01, 0x00]);

const concat = (...arrs: Uint8Array[]): Uint8Array => {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
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
  const x = crypto.getRandomValues(new Uint8Array(32));
  return { pub: concat(x, ed), priv: kp.privateKey };
}
const fpOf = async (keys: { pub: Uint8Array }): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", keys.pub as BufferSource)).slice(0, 8);
const authBody = async (keys: { pub: Uint8Array; priv: CryptoKey }): Promise<Uint8Array> =>
  concat(keys.pub, tNow(), await sign(keys.priv, concat(new TextEncoder().encode(AUTH_INFO), keys.pub, tNow())));
const authProof = async (keys: { priv: CryptoKey }, fp: Uint8Array): Promise<Uint8Array> =>
  concat(tNow(), await sign(keys.priv, concat(new TextEncoder().encode(AUTH_INFO), fp, tNow())));
const deliveryProof = async (keys: { priv: CryptoKey }, envelope: Uint8Array): Promise<Uint8Array> => {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", envelope as BufferSource));
  return concat(tNow(), await sign(keys.priv, concat(new TextEncoder().encode(DELIVERY_INFO), digest, tNow())));
};
function packMessage(ptype: number, sfp: Uint8Array, rfp: Uint8Array, body: Uint8Array): Uint8Array {
  const hdr = new Uint8Array(48);
  hdr.set(MAGIC, 0);
  hdr[8] = 1; hdr[9] = ptype;
  new DataView(hdr.buffer).setUint32(44, body.length, true);
  hdr.set(sfp, 12); hdr.set(rfp, 20);
  hdr.set(new Uint8Array(16).map((_, i) => i), 28);
  return concat(hdr, body);
}

async function stats() {
  const stub = env.NBX_REGISTRY.get(env.NBX_REGISTRY.idFromName("registry"));
  return (await (await stub.fetch("https://do/stats")).json()) as
    { registered: number; recip_count: number; total_bytes: number };
}

describe("R2-14: /inbox 生产链路退账", () => {
  it("投递→正常取信→账本完全归位", async () => {
    const before = await stats();
    const bob = await genKey();
    const alice = await genKey();
    const bobFp = await fpOf(bob);
    const aliceFp = await fpOf(alice);
    await SELF.fetch("https://example.com/auth", { method: "POST", body: await authBody(bob) as unknown as BodyInit });
    await SELF.fetch("https://example.com/auth", { method: "POST", body: await authBody(alice) as unknown as BodyInit });
    const r = await stats();
    expect(r.registered).toBe(before.registered + 2);

    // 投递 3 条(每条 48+7=55B 信封)
    for (let i = 0; i < 3; i++) {
      const env = packMessage(1, aliceFp, bobFp, new TextEncoder().encode("r2-14-" + i));
      expect(env.length).toBe(55);
      const dr = await SELF.fetch("https://example.com/envelope", {
        method: "POST", body: concat(env, await deliveryProof(alice, env)) as unknown as BodyInit,
      });
      expect(dr.status).toBe(202);
    }
    const afterPush = await stats();
    expect(afterPush.total_bytes).toBe(before.total_bytes + 3 * 55);
    expect(afterPush.recip_count).toBe(before.recip_count + 1);

    // 生产取信路径 /inbox —— R2-14 前: release 被吞, 账本不退
    const ir = await SELF.fetch("https://example.com/inbox/" + b64u(bobFp), {
      method: "POST", body: await authProof(bob, bobFp) as unknown as BodyInit,
    });
    expect(ir.status).toBe(200);
    const ip = (await ir.json()) as { envelopes: string[]; popped_bytes: number };
    expect(ip.envelopes.length).toBe(3);
    expect(ip.popped_bytes).toBe(3 * 55);

    // 关键断言: 账本完全归位(R2-14 修复前这里差 3*64B 且名额不释放)
    const after = await stats();
    expect(after.total_bytes).toBe(before.total_bytes);
    expect(after.recip_count).toBe(before.recip_count);
  });
});
