import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
const AUTH_INFO = "nbx-relay-auth-v1";
const MAGIC = new Uint8Array([0x4e, 0x42, 0x58, 0x4d, 0x53, 0x47, 0x01, 0x00]);
function concat(...arrs) {
    const total = arrs.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrs) {
        out.set(a, off);
        off += a.length;
    }
    return out;
}
function b64u(b) {
    let s = "";
    for (const c of b)
        s += String.fromCharCode(c);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64uDecode(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4)
        s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++)
        out[i] = bin.charCodeAt(i);
    return out;
}
async function genKey() {
    const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const ed = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    const x = crypto.getRandomValues(new Uint8Array(32));
    return { pub: concat(x, ed), priv: kp.privateKey };
}
async function fpOf(keys) {
    const d = await crypto.subtle.digest("SHA-256", keys.pub);
    return new Uint8Array(d).slice(0, 8);
}
async function sign(priv, data) {
    return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, priv, data));
}
function tsBytes(tsS = Math.floor(Date.now() / 1000)) {
    const t = new Uint8Array(8);
    new DataView(t.buffer).setBigUint64(0, BigInt(tsS), true);
    return t;
}
async function authBody(keys, tsS = Math.floor(Date.now() / 1000)) {
    const t = tsBytes(tsS);
    const sig = await sign(keys.priv, concat(new TextEncoder().encode(AUTH_INFO), keys.pub, t));
    return concat(keys.pub, t, sig);
}
async function authProof(keys, fp) {
    const t = tsBytes();
    const sig = await sign(keys.priv, concat(new TextEncoder().encode(AUTH_INFO), fp, t));
    return concat(t, sig);
}
async function deliveryProof(keys, envelope) {
    const t = tsBytes();
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", envelope));
    const sig = await sign(keys.priv, concat(new TextEncoder().encode("nbx-relay-delivery-v2"), digest, t));
    return concat(t, sig);
}
function packMessage(ptype, sfp, rfp, body) {
    const hdr = new Uint8Array(48);
    hdr.set(MAGIC, 0);
    hdr[8] = 1;
    hdr[9] = ptype;
    const dv = new DataView(hdr.buffer);
    dv.setUint32(44, body.length, true);
    hdr.set(sfp, 12);
    hdr.set(rfp, 20);
    hdr.set(new Uint8Array(16).map((_, i) => i), 28);
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
        let r = await SELF.fetch("https://example.com/auth", {
            method: "POST", body: await authBody(bob),
        });
        expect(r.status).toBe(200);
        expect((await r.json()).fp).toBe(b64u(bobFp));
        r = await SELF.fetch("https://example.com/auth", {
            method: "POST", body: await authBody(alice),
        });
        expect(r.status).toBe(200);
        r = await SELF.fetch(`https://example.com/inbox/${b64u(bobFp)}`);
        expect(r.status).toBe(404);
        const env = packMessage(1, aliceFp, bobFp, new TextEncoder().encode("ciphertext"));
        r = await SELF.fetch("https://example.com/envelope", {
            method: "POST", body: env,
        });
        expect(r.status).toBe(400);
        r = await SELF.fetch("https://example.com/envelope", {
            method: "POST",
            body: concat(env, await deliveryProof(alice, env)),
        });
        expect(r.status).toBe(202);
        r = await SELF.fetch(`https://example.com/inbox/${b64u(bobFp)}`, {
            method: "POST", body: await authProof(bob, bobFp),
        });
        expect(r.status).toBe(200);
        const obj = await r.json();
        expect(obj.envelopes.length).toBe(1);
        expect(b64u(b64uDecode(obj.envelopes[0]))).toBe(b64u(env));
        r = await SELF.fetch(`https://example.com/inbox/${b64u(bobFp)}`, {
            method: "POST", body: await authProof(bob, bobFp),
        });
        expect((await r.json()).envelopes.length).toBe(0);
    });
    it("R-06: unregistered sender's envelope rejected", async () => {
        const bob = await genKey();
        const mallory = await genKey();
        const bobFp = await fpOf(bob);
        const malloryFp = await fpOf(mallory);
        await SELF.fetch("https://example.com/auth", {
            method: "POST", body: await authBody(bob),
        });
        const env = packMessage(1, malloryFp, bobFp, new TextEncoder().encode("spam"));
        const r = await SELF.fetch("https://example.com/envelope", {
            method: "POST",
            body: concat(env, await deliveryProof(mallory, env)),
        });
        expect(r.status).toBe(403);
    });
    it("envelope validation: bad magic / self-addressed / short", async () => {
        const fp = new Uint8Array(8).fill(1);
        let r = await SELF.fetch("https://example.com/envelope", {
            method: "POST", body: new Uint8Array(10),
        });
        expect(r.status).toBe(400);
        const selfEnv = packMessage(1, fp, fp, new Uint8Array(4));
        r = await SELF.fetch("https://example.com/envelope", {
            method: "POST", body: concat(selfEnv, new Uint8Array(72)),
        });
        expect(r.status).toBe(400);
    });
    it("auth: tampered signature rejected", async () => {
        const keys = await genKey();
        const body = await authBody(keys);
        body[100] ^= 1;
        const r = await SELF.fetch("https://example.com/auth", {
            method: "POST", body: body,
        });
        expect(r.status).toBe(403);
    });
    it("R2-08: normal delivery still works with recipient admission", async () => {
        const bob = await genKey();
        const alice = await genKey();
        const bobFp = await fpOf(bob);
        const aliceFp = await fpOf(alice);
        await SELF.fetch("https://example.com/auth", { method: "POST", body: await authBody(bob) });
        await SELF.fetch("https://example.com/auth", { method: "POST", body: await authBody(alice) });
        const env = packMessage(1, aliceFp, bobFp, new TextEncoder().encode("r2-08-ok"));
        const r = await SELF.fetch("https://example.com/envelope", {
            method: "POST",
            body: concat(env, await deliveryProof(alice, env)),
        });
        expect(r.status).toBe(202);
    });
    it("R2-08: fake recipients are budget-accounted", async () => {
        const alice = await genKey();
        const aliceFp = await fpOf(alice);
        await SELF.fetch("https://example.com/auth", { method: "POST", body: await authBody(alice) });
        for (let i = 0; i < 3; i++) {
            const fakeRecv = new Uint8Array(8).fill(i + 10);
            const env = packMessage(1, aliceFp, fakeRecv, new Uint8Array(8));
            const r = await SELF.fetch("https://example.com/envelope", {
                method: "POST",
                body: concat(env, await deliveryProof(alice, env)),
            });
            expect(r.status).toBe(202);
        }
    });
    it("auth: same key re-register is idempotent (R-03/R-10)", async () => {
        const k1 = await genKey();
        let r = await SELF.fetch("https://example.com/auth", {
            method: "POST", body: await authBody(k1),
        });
        expect(r.status).toBe(200);
        const fp1 = (await r.json()).fp;
        r = await SELF.fetch("https://example.com/auth", {
            method: "POST", body: await authBody(k1),
        });
        expect(r.status).toBe(200);
        expect((await r.json()).fp).toBe(fp1);
    });
});
