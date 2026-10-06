/**
 * Workers 中继测试（vitest + @cloudflare/vitest-pool-workers，真实 Workers runtime）。
 * 用 WebCrypto 生成 Ed25519 密钥对，走与 Python 客户端完全相同的字节布局。
 * 与 R-03/04/06/10 后协议同步：
 *   /auth      body = pub_material(64=x||ed) + ts(8) + sig(64)，fp 服务器算
 *   /inbox     POST，body = ts(8) + sig(64)
 *   /envelope  明文头(48) + 密文体 + 投递签名后缀(72=ts+sig)，发送者须已登记
 */
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const AUTH_INFO = "nbx-relay-auth-v1";
const MAGIC = new Uint8Array([0x4e, 0x42, 0x58, 0x4d, 0x53, 0x47, 0x01, 0x00]);

function concat(...arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

function b64u(b: Uint8Array): string {
  let s = "";
  for (const c of b) s += String.fromCharCode(c);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64uDecode(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** 身份：ed25519 签名密钥 + 32B 随机 x25519 部分。pub_material = x||ed (64B)。 */
async function genKey(): Promise<{ pub: Uint8Array; priv: CryptoKey }> {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" } as AlgorithmIdentifier, true, ["sign", "verify"]);
  const ed = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const x = crypto.getRandomValues(new Uint8Array(32));
  return { pub: concat(x, ed), priv: kp.privateKey };
}

async function fpOf(keys: { pub: Uint8Array }): Promise<Uint8Array> {
  const d = await crypto.subtle.digest("SHA-256", keys.pub as BufferSource);
  return new Uint8Array(d).slice(0, 8);
}

async function sign(priv: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" } as AlgorithmIdentifier, priv, data as BufferSource));
}

function tsBytes(tsS = Math.floor(Date.now() / 1000)): Uint8Array {
  const t = new Uint8Array(8);
  new DataView(t.buffer).setBigUint64(0, BigInt(tsS), true);
  return t;
}

/** R-03 后 /auth body: pub_material(64) || ts(8) || sig(64) */
async function authBody(keys: { pub: Uint8Array; priv: CryptoKey },
                        tsS = Math.floor(Date.now() / 1000)): Promise<Uint8Array> {
  const t = tsBytes(tsS);
  const sig = await sign(keys.priv, concat(new TextEncoder().encode(AUTH_INFO), keys.pub, t));
  return concat(keys.pub, t, sig);
}

/** 取信 proof: ts(8) || sig(64)，sig 覆盖 AUTH_INFO||fp||ts */
async function authProof(keys: { priv: CryptoKey }, fp: Uint8Array): Promise<Uint8Array> {
  const t = tsBytes();
  const sig = await sign(keys.priv, concat(new TextEncoder().encode(AUTH_INFO), fp, t));
  return concat(t, sig);
}

/** 投递签名后缀: ts(8) || sig(64)，sig 覆盖 AUTH_INFO||明文头(48)||ts */
async function deliveryProof(keys: { priv: CryptoKey }, header: Uint8Array): Promise<Uint8Array> {
  const t = tsBytes();
  const sig = await sign(keys.priv, concat(new TextEncoder().encode(AUTH_INFO), header, t));
  return concat(t, sig);
}

function packMessage(ptype: number, sfp: Uint8Array, rfp: Uint8Array, body: Uint8Array): Uint8Array {
  const hdr = new Uint8Array(48);
  hdr.set(MAGIC, 0);
  hdr[8] = 1;                 // version
  hdr[9] = ptype;
  const dv = new DataView(hdr.buffer);
  dv.setUint32(44, body.length, true);
  hdr.set(sfp, 12); hdr.set(rfp, 20);
  hdr.set(new Uint8Array(16).map((_, i) => i), 28);   // msg_id
  return concat(hdr, body);
}

describe("nbx workers relay", () => {
  it("health", async () => {
    const r = await SELF.fetch("https://example.com/health");
    expect(r.status).toBe(200);
    expect((await r.json()).ok).toBe(true);
  });

  it("auth: register then authorized fetch (R-03/R-04/R-06)", async () => {
    const bob = await genKey();
    const alice = await genKey();
    const bobFp = await fpOf(bob);
    const aliceFp = await fpOf(alice);

    // 登记 Bob（服务器按公钥算 fp，客户端不自报）
    let r = await SELF.fetch("https://example.com/auth", {
      method: "POST", body: await authBody(bob) as unknown as BodyInit,
    });
    expect(r.status).toBe(200);
    expect((await r.json()).fp).toBe(b64u(bobFp));

    // 登记 Alice（R-06：发送者须先 AUTH）
    r = await SELF.fetch("https://example.com/auth", {
      method: "POST", body: await authBody(alice) as unknown as BodyInit,
    });
    expect(r.status).toBe(200);

    // R-04：取信是 POST，GET 不再有路由 → 404
    r = await SELF.fetch(`https://example.com/inbox/${b64u(bobFp)}`);
    expect(r.status).toBe(404);

    const env = packMessage(1, aliceFp, bobFp, new TextEncoder().encode("ciphertext"));

    // R-06：无投递签名 → 400
    r = await SELF.fetch("https://example.com/envelope", {
      method: "POST", body: env as unknown as BodyInit,
    });
    expect(r.status).toBe(400);

    // 带投递签名 → 202（签名只覆盖 48B 明文头）
    r = await SELF.fetch("https://example.com/envelope", {
      method: "POST",
      body: concat(env, await deliveryProof(alice, env.slice(0, 48))) as unknown as BodyInit,
    });
    expect(r.status).toBe(202);

    // Bob POST 取信 → 200 + 1 封（裸信封，签名后缀已剥）
    r = await SELF.fetch(`https://example.com/inbox/${b64u(bobFp)}`, {
      method: "POST", body: await authProof(bob, bobFp) as unknown as BodyInit,
    });
    expect(r.status).toBe(200);
    const obj = await r.json();
    expect(obj.envelopes.length).toBe(1);
    expect(b64u(b64uDecode(obj.envelopes[0]))).toBe(b64u(env));

    // 取走即清
    r = await SELF.fetch(`https://example.com/inbox/${b64u(bobFp)}`, {
      method: "POST", body: await authProof(bob, bobFp) as unknown as BodyInit,
    });
    expect((await r.json()).envelopes.length).toBe(0);
  });

  it("R-06: unregistered sender's envelope rejected", async () => {
    const bob = await genKey();
    const mallory = await genKey();
    const bobFp = await fpOf(bob);
    const malloryFp = await fpOf(mallory);
    await SELF.fetch("https://example.com/auth", {
      method: "POST", body: await authBody(bob) as unknown as BodyInit,
    });
    const env = packMessage(1, malloryFp, bobFp, new TextEncoder().encode("spam"));
    const r = await SELF.fetch("https://example.com/envelope", {
      method: "POST",
      body: concat(env, await deliveryProof(mallory, env.slice(0, 48))) as unknown as BodyInit,
    });
    expect(r.status).toBe(403);            // 未登记发送者不得投递
  });

  it("envelope validation: bad magic / self-addressed / short", async () => {
    const fp = new Uint8Array(8).fill(1);
    let r = await SELF.fetch("https://example.com/envelope", {
      method: "POST", body: new Uint8Array(10) as unknown as BodyInit,
    });
    expect(r.status).toBe(400);

    const selfEnv = packMessage(1, fp, fp, new Uint8Array(4));
    r = await SELF.fetch("https://example.com/envelope", {
      method: "POST", body: concat(selfEnv, new Uint8Array(72)) as unknown as BodyInit,
    });
    expect(r.status).toBe(400);
  });

  it("auth: tampered signature rejected", async () => {
    const keys = await genKey();
    const body = await authBody(keys);
    body[100] ^= 1;                       // 破坏签名区
    const r = await SELF.fetch("https://example.com/auth", {
      method: "POST", body: body as unknown as BodyInit,
    });
    expect(r.status).toBe(403);
  });

  it("auth: same key re-register is idempotent (R-03/R-10)", async () => {
    const k1 = await genKey();
    let r = await SELF.fetch("https://example.com/auth", {
      method: "POST", body: await authBody(k1) as unknown as BodyInit,
    });
    expect(r.status).toBe(200);
    const fp1 = (await r.json()).fp;
    // 同一公钥重放：fp 由服务器算，必须返回同一 fp 且不占新名额
    r = await SELF.fetch("https://example.com/auth", {
      method: "POST", body: await authBody(k1) as unknown as BodyInit,
    });
    expect(r.status).toBe(200);
    expect((await r.json()).fp).toBe(fp1);
  });
});
