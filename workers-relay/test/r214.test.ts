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
    const x = crypto.getRandomValues(new Uint8Array(32));
    return { pub: concat(x, ed), priv: kp.privateKey };
}
const fpOf = async (keys) => new Uint8Array(await crypto.subtle.digest("SHA-256", keys.pub)).slice(0, 8);
const authBody = async (keys) => concat(keys.pub, tNow(), await sign(keys.priv, concat(new TextEncoder().encode(AUTH_INFO), keys.pub, tNow())));
const authProof = async (keys, fp) => concat(tNow(), await sign(keys.priv, concat(new TextEncoder().encode(AUTH_INFO), fp, tNow())));
const deliveryProof = async (keys, envelope) => {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", envelope));
    return concat(tNow(), await sign(keys.priv, concat(new TextEncoder().encode(DELIVERY_INFO), digest, tNow())));
};
function packMessage(ptype, sfp, rfp, body) {
    const hdr = new Uint8Array(48);
    hdr.set(MAGIC, 0);
    hdr[8] = 1;
    hdr[9] = ptype;
    new DataView(hdr.buffer).setUint32(44, body.length, true);
    hdr.set(sfp, 12);
    hdr.set(rfp, 20);
    hdr.set(new Uint8Array(16).map((_, i) => i), 28);
    return concat(hdr, body);
}
async function stats() {
    const stub = env.NBX_REGISTRY.get(env.NBX_REGISTRY.idFromName("registry"));
    return (await (await stub.fetch("https://do/stats")).json());
}
describe("R2-14: /inbox 生产链路退账", () => {
    it("投递→正常取信→账本完全归位", async () => {
        const before = await stats();
        const bob = await genKey();
        const alice = await genKey();
        const bobFp = await fpOf(bob);
        const aliceFp = await fpOf(alice);
        await SELF.fetch("https://example.com/auth", { method: "POST", body: await authBody(bob) });
        await SELF.fetch("https://example.com/auth", { method: "POST", body: await authBody(alice) });
        const r = await stats();
        expect(r.registered).toBe(before.registered + 2);
        for (let i = 0; i < 3; i++) {
            const env = packMessage(1, aliceFp, bobFp, new TextEncoder().encode("r2-14-" + i));
            expect(env.length).toBe(55);
            const dr = await SELF.fetch("https://example.com/envelope", {
                method: "POST", body: concat(env, await deliveryProof(alice, env)),
            });
            expect(dr.status).toBe(202);
        }
        const afterPush = await stats();
        expect(afterPush.total_bytes).toBe(before.total_bytes + 3 * 55);
        expect(afterPush.recip_count).toBe(before.recip_count + 1);
        const ir = await SELF.fetch("https://example.com/inbox/" + b64u(bobFp), {
            method: "POST", body: await authProof(bob, bobFp),
        });
        expect(ir.status).toBe(200);
        const ip = (await ir.json());
        expect(ip.envelopes.length).toBe(3);
        expect(ip.popped_bytes).toBe(3 * 55);
        const after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes);
        expect(after.recip_count).toBe(before.recip_count);
    });
});
