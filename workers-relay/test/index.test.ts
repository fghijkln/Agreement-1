/**
 * Workers 中继测试（vitest + @cloudflare/vitest-pool-workers，真实 Workers runtime）。
 * 用 WebCrypto 生成 Ed25519 密钥对，走与 Python 客户端完全相同的字节布局。
 */
import { SELF, createExecutionContext, env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../src/index";

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

async function genKey(): Promise<{ pub: Uint8Array; priv: CryptoKey }> {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" } as AlgorithmIdentifier, true, ["sign", "verify"]);
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { pub, priv: kp.privateKey };
}

async function sign(priv: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" } as AlgorithmIdentifier, priv, data as BufferSource));
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

async function authBody(keys: { pub: Uint8Array; priv: CryptoKey }, fp: Uint8Array, tsS = Math.floor(Date.now() / 1000)): Promise<Uint8Array> {
  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigUint64(0, BigInt(tsS), true);
  const sig = await sign(keys.priv, concat(new TextEncoder().encode(AUTH_INFO), fp, ts));
  return concat(fp, ts, keys.pub, sig);
}

function authProof(keys: { priv: CryptoKey }, fp: Uint8Array): Promise<Uint8Array> {
  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigUint64(0, BigInt(Math.floor(Date.now() / 1000)), true);
  return sign(keys.priv, concat(new TextEncoder().encode(AUTH_INFO), fp, ts))
    .then((sig) => concat(ts, sig));
}

describe("nbx workers relay", () => {
  it("health", async () => {
    const r = await SELF.fetch("https://example.com/health");
    expect(r.status).toBe(200);
    expect((await r.json()).ok).toBe(true);
  });

  it("auth: register then unauthorized fetch then authorized fetch", async () => {
    const bob = await genKey();
    const alice = await genKey();
    const bobFp = new Uint8Array(8).map((_, i) => 0xb0 + i);
    const aliceFp = new Uint8Array(8).map((_, i) => 0xa0 + i);

    // 登记 Bob 公钥
    let r = await SELF.fetch("https://example.com/auth", {
      method: "POST",
      body: await authBody(bob, bobFp) as unknown as BodyInit,
    });
    expect(r.status).toBe(200);

    // 未授权取信 → 403
    r = await SELF.fetch(`https://example.com/inbox/${b64u(bobFp)}`);
    expect(r.status).toBe(403);

    // Alice 投递给 Bob
    const env = packMessage(1, aliceFp, bobFp, new TextEncoder().encode("ciphertext"));
    r = await SELF.fetch("https://example.com/envelope", {
      method: "POST", body: env as unknown as BodyInit,
    });
    expect(r.status).toBe(202);

    // Bob 授权取信 → 200 + 1 封
    const proof = await authProof(bob, bobFp);
    r = await SELF.fetch(`https://example.com/inbox/${b64u(bobFp)}?proof=${b64u(proof)}`);
    expect(r.status).toBe(200);
    const obj = await r.json();
    expect(obj.envelopes.length).toBe(1);
    const gotBytes = b64uDecode(obj.envelopes[0]);
    expect(gotBytes.length).toBe(env.length);
    expect(b64u(gotBytes)).toBe(b64u(env));

    // 取走即清
    const proof2 = await authProof(bob, bobFp);
    r = await SELF.fetch(`https://example.com/inbox/${b64u(bobFp)}?proof=${b64u(proof2)}`);
    expect((await r.json()).envelopes.length).toBe(0);
  });

  it("envelope validation: bad magic / self-addressed / short", async () => {
    const fp = new Uint8Array(8).fill(1);
    let r = await SELF.fetch("https://example.com/envelope", {
      method: "POST", body: new Uint8Array(10) as unknown as BodyInit,
    });
    expect(r.status).toBe(400);

    const selfEnv = packMessage(1, fp, fp, new Uint8Array(4));
    r = await SELF.fetch("https://example.com/envelope", {
      method: "POST", body: selfEnv as unknown as BodyInit,
    });
    expect(r.status).toBe(400);
  });

  it("auth: tampered signature rejected", async () => {
    const keys = await genKey();
    const fp = new Uint8Array(8).fill(7);
    const body = await authBody(keys, fp);
    body[100] ^= 1;                       // 破坏签名
    const r = await SELF.fetch("https://example.com/auth", {
      method: "POST", body: body as unknown as BodyInit,
    });
    expect(r.status).toBe(403);
  });

  it("auth: TOFU rebinding rejected", async () => {
    const k1 = await genKey();
    const k2 = await genKey();
    const fp = new Uint8Array(8).fill(9);
    await SELF.fetch("https://example.com/auth", {
      method: "POST", body: await authBody(k1, fp) as unknown as BodyInit,
    });
    const r = await SELF.fetch("https://example.com/auth", {
      method: "POST", body: await authBody(k2, fp) as unknown as BodyInit,
    });
    expect(r.status).toBe(409);
  });
});

function b64uDecode(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
