import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
const AUTH_INFO = "nbx-relay-auth-v1";
const DELIVERY_INFO = "nbx-relay-delivery-v2";
const MAGIC = new Uint8Array([0x4e, 0x42, 0x58, 0x4d, 0x53, 0x47, 0x01, 0x00]);
const concat = (...arrs) => {
    const total = arrs.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrs) {
        out.set(a, off);
        off += a.length;
    }
    return out;
};
const b64u = (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const sign = async (priv, data) => new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, priv, data));
const tNow = () => {
    const t = new Uint8Array(8);
    new DataView(t.buffer).setBigUint64(0, BigInt(Math.floor(Date.now() / 1000)), true);
    return t;
};
async function genKey() {
    const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const ed = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    return { pub: concat(crypto.getRandomValues(new Uint8Array(32)), ed), priv: kp.privateKey };
}
const fpOf = async (keys) => new Uint8Array(await crypto.subtle.digest("SHA-256", keys.pub)).slice(0, 8);
const authBody = async (k) => concat(k.pub, tNow(), await sign(k.priv, concat(new TextEncoder().encode(AUTH_INFO), k.pub, tNow())));
const authProof = async (k, fp) => concat(tNow(), await sign(k.priv, concat(new TextEncoder().encode(AUTH_INFO), fp, tNow())));
const deliveryProof = async (k, env_) => {
    const d = new Uint8Array(await crypto.subtle.digest("SHA-256", env_));
    return concat(tNow(), await sign(k.priv, concat(new TextEncoder().encode(DELIVERY_INFO), d, tNow())));
};
function packMessage(pt, sfp, rfp, body) {
    const hdr = new Uint8Array(48);
    hdr.set(MAGIC, 0);
    hdr[8] = 1;
    hdr[9] = pt;
    new DataView(hdr.buffer).setUint32(44, body.length, true);
    hdr.set(sfp, 12);
    hdr.set(rfp, 20);
    return concat(hdr, body);
}
async function stats() {
    const stub = env.NBX_REGISTRY.get(env.NBX_REGISTRY.idFromName("registry"));
    return (await (await stub.fetch("https://do/stats")).json());
}
describe("R2-15: 跨 DO 故障一致性", () => {
    it("release 失败→503→消息保留→重试成功→账本归位", async () => {
        const before = await stats();
        const bob = await genKey();
        const alice = await genKey();
        const bobFp = await fpOf(bob);
        const aliceFp = await fpOf(alice);
        await SELF.fetch("https://example.com/auth", { method: "POST", body: await authBody(bob) });
        await SELF.fetch("https://example.com/auth", { method: "POST", body: await authBody(alice) });
        const envBytes = packMessage(1, aliceFp, bobFp, new TextEncoder().encode("r2-15"));
        expect(envBytes.length).toBe(53);
        const dr = await SELF.fetch("https://example.com/envelope", {
            method: "POST", body: concat(envBytes, await deliveryProof(alice, envBytes)),
        });
        expect(dr.status).toBe(202);
        const afterPush = await stats();
        expect(afterPush.total_bytes).toBe(before.total_bytes + 53);
        const regGet = env.NBX_REGISTRY.get.bind(env.NBX_REGISTRY);
        const realStub = regGet(env.NBX_REGISTRY.idFromName("registry"));
        const broken = new Proxy(realStub, {
            get(target, prop) {
                if (prop === "fetch") {
                    return async (_url, init) => {
                        const u = String(_url);
                        if (u.includes("recipient_release"))
                            throw new Error("simulated cross-DO failure");
                        return target.fetch(_url, init);
                    };
                }
                return target[prop];
            },
        });
        env.NBX_REGISTRY.get = () => broken;
        const r1 = await SELF.fetch("https://example.com/inbox/" + b64u(bobFp), {
            method: "POST", body: await authProof(bob, bobFp),
        });
        expect(r1.status).toBe(503);
        env.NBX_REGISTRY.get = regGet;
        const r2 = await SELF.fetch("https://example.com/inbox/" + b64u(bobFp), {
            method: "POST", body: await authProof(bob, bobFp),
        });
        expect(r2.status).toBe(200);
        const j2 = (await r2.json());
        expect(j2.envelopes.length).toBe(1);
        const got = atob(j2.envelopes[0].replace(/-/g, "+").replace(/_/g, "/"));
        const gotBytes = new Uint8Array(got.length);
        for (let i = 0; i < got.length; i++)
            gotBytes[i] = got.charCodeAt(i);
        expect(b64u(gotBytes)).toBe(b64u(envBytes));
        const r3 = await SELF.fetch("https://example.com/inbox/" + b64u(bobFp), {
            method: "POST", body: await authProof(bob, bobFp),
        });
        expect((await r3.json()).envelopes.length).toBe(0);
        const after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes);
        expect(after.recip_count).toBe(before.recip_count);
    });
});
