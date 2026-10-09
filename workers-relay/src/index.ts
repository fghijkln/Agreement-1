import { NbxFpDurableObject, RegistryDo } from "./do";
export { NbxFpDurableObject, RegistryDo };
const TTL_MS = 7 * 86400 * 1000;
const MAX_PER_FP = 256;
const MAX_ENVELOPE = 1 << 20;
const AUTH_SKEW_S = 300;
const AUTH_INFO = "nbx-relay-auth-v1";
const DELIVERY_INFO = "nbx-relay-delivery-v2";
function b64urlEncode(buf) {
    const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = "";
    for (const c of b)
        s += String.fromCharCode(c);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4)
        s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++)
        out[i] = bin.charCodeAt(i);
    return out;
}
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
const MAGIC_MSG = new Uint8Array([0x4e, 0x42, 0x58, 0x4d, 0x53, 0x47, 0x01, 0x00]);
const HEADER_SIZE = 48;
function parseHeader(blob) {
    if (blob.length < HEADER_SIZE)
        return null;
    for (let i = 0; i < 8; i++)
        if (blob[i] !== MAGIC_MSG[i])
            return null;
    const ver = blob[8];
    if (ver !== 1)
        return null;
    const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
    const bodyLen = dv.getUint32(44, true);
    if (blob.length !== HEADER_SIZE + bodyLen)
        return null;
    return {
        ptype: blob[9],
        senderFp: blob.slice(12, 20),
        recvFp: blob.slice(20, 28),
        msgId: blob.slice(28, 44),
        body: blob.slice(HEADER_SIZE),
    };
}
async function ed25519Verify(pubRaw, sig, data) {
    const key = await crypto.subtle.importKey("raw", pubRaw, { name: "Ed25519" }, false, ["verify"]);
    return crypto.subtle.verify({ name: "Ed25519" }, key, sig, data);
}
async function authorize(env, fp, proof) {
    if (proof.length !== 72)
        return false;
    const ts = new DataView(proof.buffer, 0, 8).getBigUint64(0, true);
    const nowS = BigInt(Math.floor(Date.now() / 1000));
    if (ts > nowS + BigInt(AUTH_SKEW_S) || ts < nowS - BigInt(AUTH_SKEW_S))
        return false;
    const pub = await env.NBX_FP.idFromName(b64urlEncode(fp));
    const stub = env.NBX_FP.get(pub);
    const resp = await stub.fetch("https://do/pubkey");
    if (!resp.ok)
        return false;
    const pubRaw = new Uint8Array(await resp.arrayBuffer());
    if (pubRaw.length !== 32)
        return false;
    const msg = concat(new TextEncoder().encode(AUTH_INFO), fp, proof.slice(0, 8));
    return ed25519Verify(pubRaw, proof.slice(8), msg);
}
export default {
    async fetch(req, env) {
        const url = new URL(req.url);
        const json = (status, obj) => new Response(JSON.stringify(obj), {
            status,
            headers: { "Content-Type": "application/json" },
        });
        if (url.pathname === "/health")
            return json(200, { ok: true });
        if (req.method === "POST" && url.pathname === "/auth") {
            const body = new Uint8Array(await req.arrayBuffer());
            if (body.length !== 64 + 8 + 64)
                return json(400, { ok: false, error: "bad auth payload" });
            const pubMaterial = body.slice(0, 64);
            const tsBytes = body.slice(64, 72);
            const sig = body.slice(72, 136);
            const ts = new DataView(tsBytes.buffer, tsBytes.byteOffset, 8).getBigUint64(0, true);
            const nowS = BigInt(Math.floor(Date.now() / 1000));
            if (ts > nowS + BigInt(AUTH_SKEW_S) || ts < nowS - BigInt(AUTH_SKEW_S))
                return json(400, { ok: false, error: "timestamp out of window" });
            const edPub = pubMaterial.slice(32, 64);
            const ok = await ed25519Verify(edPub, sig, concat(new TextEncoder().encode(AUTH_INFO), pubMaterial, tsBytes));
            if (!ok)
                return json(403, { ok: false, error: "bad signature" });
            const fp = new Uint8Array(await crypto.subtle.digest("SHA-256", pubMaterial)).slice(0, 8);
            {
                const regStub = env.NBX_REGISTRY.get(env.NBX_REGISTRY.idFromName("registry"));
                const regResp = await regStub.fetch("https://registry/claim", {
                    method: "POST", body: b64urlEncode(fp),
                });
                if (!regResp.ok)
                    return json(429, { ok: false, error: "registration quota exhausted" });
            }
            let relayPubB64 = "", relaySigB64 = "";
            {
                const regStub = env.NBX_REGISTRY.get(env.NBX_REGISTRY.idFromName("registry"));
                const idResp = await regStub.fetch("https://registry/relay_sign", {
                    method: "POST",
                    body: concat(fp, tsBytes.slice(0)),
                });
                if (idResp.ok) {
                    const idObj = await idResp.json();
                    relayPubB64 = idObj.relay_pub;
                    relaySigB64 = idObj.relay_sig;
                }
            }
            const id = env.NBX_FP.idFromName(b64urlEncode(fp));
            const stub = env.NBX_FP.get(id);
            const resp = await stub.fetch("https://do/pubkey", {
                method: "PUT", body: edPub,
            });
            if (resp.status === 409)
                return json(409, { ok: false, error: "fingerprint already bound to another key" });
            return json(200, { ok: true, fp: b64urlEncode(fp),
                relay_pub: relayPubB64, relay_sig: relaySigB64 });
        }
        if (req.method === "POST" && url.pathname === "/envelope") {
            const body = new Uint8Array(await req.arrayBuffer());
            if (body.length > MAX_ENVELOPE)
                return json(400, { ok: false, error: "envelope too large" });
            if (body.length < 48 + 72)
                return json(400, { ok: false, error: "missing sender proof" });
            const envLen = body.length - 72;
            const hdr = parseHeader(body.slice(0, envLen));
            if (!hdr)
                return json(400, { ok: false, error: "bad envelope" });
            if (hdr.ptype === 0)
                return json(400, { ok: false, error: "invalid ptype" });
            if (b64urlEncode(hdr.senderFp) === b64urlEncode(hdr.recvFp))
                return json(400, { ok: false, error: "self-addressed" });
            {
                const senderFpB64 = b64urlEncode(hdr.senderFp);
                const senderId = env.NBX_FP.idFromName(senderFpB64);
                const senderStub = env.NBX_FP.get(senderId);
                const pubResp = await senderStub.fetch("https://do/pubkey");
                if (!pubResp.ok)
                    return json(403, { ok: false, error: "sender not registered (auth first)" });
                const senderEd = new Uint8Array(await pubResp.arrayBuffer());
                if (senderEd.length !== 32)
                    return json(403, { ok: false, error: "sender not registered" });
                const tsBytes = body.slice(envLen, envLen + 8);
                const sigBytes = body.slice(envLen + 8);
                const ts = new DataView(tsBytes.buffer, tsBytes.byteOffset, 8).getBigUint64(0, true);
                const nowS = BigInt(Math.floor(Date.now() / 1000));
                if (ts > nowS + BigInt(AUTH_SKEW_S) || ts < nowS - BigInt(AUTH_SKEW_S))
                    return json(403, { ok: false, error: "sender proof timestamp out of window" });
                const envDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", body.slice(0, envLen)));
                const msgBytes = concat(new TextEncoder().encode(DELIVERY_INFO), envDigest, tsBytes);
                if (!await ed25519Verify(senderEd, sigBytes, msgBytes))
                    return json(403, { ok: false, error: "bad sender proof" });
                const quotaResp = await senderStub.fetch("https://do/send_quota", { method: "POST" });
                if (!quotaResp.ok)
                    return json(429, { ok: false, error: "sender quota exceeded" });
            }
            {
                const admit = new Uint8Array(12);
                admit.set(hdr.recvFp, 0);
                new DataView(admit.buffer).setUint32(8, envLen, true);
                const regStub = env.NBX_REGISTRY.get(env.NBX_REGISTRY.idFromName("registry"));
                const admitResp = await regStub.fetch("https://do/recipient_admit", {
                    method: "POST", body: admit,
                });
                if (!admitResp.ok) {
                    const err = await admitResp.json();
                    return json(429, { ok: false, error: err.error ?? "recipient admission denied" });
                }
            }
            const id = env.NBX_FP.idFromName(b64urlEncode(hdr.recvFp));
            const stub = env.NBX_FP.get(id);
            const resp = await stub.fetch("https://do/push", {
                method: "POST", body: body.slice(0, envLen),
            });
            const pushPayload = await resp.json();
            const regStub = env.NBX_REGISTRY.get(env.NBX_REGISTRY.idFromName("registry"));
            if (resp.status === 202 && pushPayload.ok) {
                const evicted = pushPayload.evicted_bytes ?? 0;
                if (evicted > 0) {
                    const rel = new Uint8Array(12);
                    rel.set(hdr.recvFp, 0);
                    new DataView(rel.buffer).setUint32(8, evicted, true);
                    await regStub.fetch("https://do/recipient_release", {
                        method: "POST", body: rel,
                    });
                }
            }
            else {
                const rel = new Uint8Array(12);
                rel.set(hdr.recvFp, 0);
                new DataView(rel.buffer).setUint32(8, envLen, true);
                await regStub.fetch("https://do/recipient_release", {
                    method: "POST", body: rel,
                });
                return json(400, { ok: false, error: "enqueue failed" });
            }
            return json(202, pushPayload);
        }
        if (req.method === "POST" && url.pathname.startsWith("/inbox/")) {
            const fpB64 = url.pathname.slice("/inbox/".length);
            const body = new Uint8Array(await req.arrayBuffer());
            if (body.length !== 72)
                return json(400, { ok: false, error: "bad proof payload" });
            const ts = new DataView(body.buffer, body.byteOffset, 8).getBigUint64(0, true);
            const nowS = BigInt(Math.floor(Date.now() / 1000));
            if (ts > nowS + BigInt(AUTH_SKEW_S) || ts < nowS - BigInt(AUTH_SKEW_S))
                return json(403, { ok: false, error: "timestamp out of window" });
            let fp;
            try {
                fp = b64urlDecode(fpB64);
            }
            catch {
                return json(400, { ok: false, error: "bad request" });
            }
            if (fp.length !== 8)
                return json(400, { ok: false, error: "bad request" });
            if (!await authorize(env, fp, body))
                return json(403, { ok: false, error: "unauthorized" });
            const id = env.NBX_FP.idFromName(fpB64);
            const stub = env.NBX_FP.get(id);
            const resp = await stub.fetch("https://do/pop");
            const payload = await resp.json();
            if (payload.popped_bytes === undefined && payload.envelopes) {
                let freed = 0;
                for (const e of payload.envelopes)
                    freed += Math.floor(e.length * 3 / 4);
                payload.popped_bytes = freed;
            }
            if ((payload.popped_bytes ?? 0) > 0) {
                const rel = new Uint8Array(28);
                rel.set(fp, 0);
                new DataView(rel.buffer).setUint32(8, payload.popped_bytes, true);
                if (payload.release_id) {
                    const rid = payload.release_id.replace(/-/g, "");
                    for (let i = 0; i < 16; i++)
                        rel[12 + i] = parseInt(rid.slice(i * 2, i * 2 + 2), 16);
                }
                let released = false;
                for (let attempt = 0; attempt < 3 && !released; attempt++) {
                    try {
                        const rr = await env.NBX_REGISTRY.get(env.NBX_REGISTRY.idFromName("registry"))
                            .fetch("https://do/recipient_release", { method: "POST", body: rel });
                        released = rr.ok;
                    }
                    catch { }
                }
                if (!released)
                    return json(503, { ok: false, error: "release unavailable, retry" });
                if (payload.release_id) {
                    const ackBytes = new Uint8Array(16).map((_, i) => rel[12 + i]);
                    await stub.fetch("https://do/pop_ack", {
                        method: "POST", body: ackBytes,
                    });
                }
            }
            return json(200, payload);
        }
        return json(404, { ok: false, error: "not found" });
    },
};
