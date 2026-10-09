const TTL_MS = 7 * 86400 * 1000;
const MAX_PER_FP = 256;
const MAX_REGISTERED = 10000;
const SEND_QUOTA_WINDOW_MS = 3600 * 1000;
const SEND_QUOTA_MAX = 600;
const MAX_ACTIVE_RECIPIENTS = 50000;
const MAX_TOTAL_QUEUED_BYTES = 512 * 1024 * 1024;
const RECIPIENT_DECAY_MS = 7 * 86400 * 1000;
const MAGIC_MSG = new Uint8Array([0x4e, 0x42, 0x58, 0x4d, 0x53, 0x47, 0x01, 0x00]);
function b64urlEncode(buf) {
    let s = "";
    for (const c of buf)
        s += String.fromCharCode(c);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
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
function json(status, obj) {
    return new Response(JSON.stringify(obj), {
        status,
        headers: { "Content-Type": "application/json" },
    });
}
export class NbxFpDurableObject {
    state;
    constructor(state, _env) {
        this.state = state;
    }
    async gc() {
        const q = ((await this.state.storage.get("q")) ?? [])
            .filter((e) => Date.now() - e.at < TTL_MS);
        await this.state.storage.put("q", q);
        const p = await this.state.storage.get("pending");
        if (p && Date.now() - p.at > TTL_MS)
            await this.state.storage.delete("pending");
    }
    async fetch(req) {
        const path = new URL(req.url).pathname;
        if (req.method === "PUT" && path === "/pubkey") {
            const pubRaw = new Uint8Array(await req.arrayBuffer());
            if (pubRaw.length !== 32)
                return json(400, { ok: false, error: "bad pubkey length" });
            const existing = await this.state.storage.get("pubkey");
            if (existing) {
                const old = b64urlEncode(existing);
                const neu = b64urlEncode(pubRaw);
                if (old !== neu)
                    return json(409, { ok: false, error: "fingerprint already bound to another key" });
                return json(200, { ok: true });
            }
            await this.state.storage.put("pubkey", pubRaw);
            return json(200, { ok: true });
        }
        if (req.method === "POST" && path === "/send_quota") {
            const now = Date.now();
            const times = ((await this.state.storage.get("send_times")) ?? [])
                .filter((t) => now - t < SEND_QUOTA_WINDOW_MS);
            if (times.length >= SEND_QUOTA_MAX)
                return json(429, { ok: false, error: "sender quota exceeded" });
            times.push(now);
            await this.state.storage.put("send_times", times);
            return json(200, { ok: true });
        }
        if (req.method === "GET" && path === "/pubkey") {
            const pub = await this.state.storage.get("pubkey");
            if (!pub)
                return new Response("not found", { status: 404 });
            return new Response(pub, {
                status: 200,
                headers: { "Content-Type": "application/octet-stream" },
            });
        }
        if (req.method === "POST" && path === "/push") {
            await this.gc();
            const blob = new Uint8Array(await req.arrayBuffer());
            if (blob.length < 48)
                return json(400, { ok: false, error: "bad envelope" });
            for (let i = 0; i < 8; i++)
                if (blob[i] !== MAGIC_MSG[i])
                    return json(400, { ok: false, error: "bad envelope" });
            const q = (await this.state.storage.get("q")) ?? [];
            q.push({ at: Date.now(), env: b64urlEncode(blob) });
            const evicted = q.length > MAX_PER_FP ? q.slice(0, q.length - MAX_PER_FP) : [];
            const trimmed = evicted.length ? q.slice(evicted.length) : q;
            await this.state.storage.put("q", trimmed);
            let evictedBytes = 0;
            for (const e of evicted) {
                evictedBytes += Math.floor(e.env.length * 3 / 4);
            }
            const msgId = b64urlEncode(blob.slice(28, 44));
            return json(202, { ok: true, msg_id: msgId, evicted_bytes: evictedBytes });
        }
        if (req.method === "GET" && path === "/pop") {
            await this.gc();
            const pend = await this.state.storage.get("pending");
            if (pend) {
                let pb = 0;
                for (const e of pend.q)
                    pb += Math.floor(e.env.length * 3 / 4);
                return json(200, { ok: true, envelopes: pend.q.map((e) => e.env),
                    popped_bytes: pb, release_id: pend.release_id });
            }
            const q = (await this.state.storage.get("q")) ?? [];
            if (!q.length)
                return json(200, { ok: true, envelopes: [], popped_bytes: 0, release_id: null });
            const releaseId = crypto.randomUUID();
            let popped = 0;
            for (const e of q)
                popped += Math.floor(e.env.length * 3 / 4);
            await this.state.storage.put("pending", { release_id: releaseId, at: Date.now(), q });
            await this.state.storage.put("q", []);
            return json(200, { ok: true, envelopes: q.map((e) => e.env),
                popped_bytes: popped, release_id: releaseId });
        }
        if (req.method === "POST" && path === "/pop_ack") {
            const raw = new Uint8Array(await req.arrayBuffer());
            if (raw.length !== 16)
                return json(400, { ok: false, error: "bad ack payload" });
            const hex = [...raw].map((b) => b.toString(16).padStart(2, "0")).join("");
            const expect = hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" + hex.slice(12, 16)
                + "-" + hex.slice(16, 20) + "-" + hex.slice(20);
            const p = await this.state.storage.get("pending");
            if (p && p.release_id === expect)
                await this.state.storage.delete("pending");
            return json(200, { ok: true });
        }
        return json(404, { ok: false, error: "not found" });
    }
}
export class RegistryDo {
    state;
    constructor(state, _env) {
        this.state = state;
    }
    async fetch(req) {
        const path = new URL(req.url).pathname;
        if (req.method === "POST" && path === "/claim") {
            const fp = new Uint8Array(await req.arrayBuffer()).toString();
            const existing = await this.state.storage.get("fp:" + fp);
            if (existing)
                return json(200, { ok: true, existing: true });
            const count = (await this.state.storage.get("count")) ?? 0;
            if (count >= MAX_REGISTERED)
                return json(429, { ok: false, error: "registration quota exhausted" });
            await this.state.storage.put("fp:" + fp, 1);
            await this.state.storage.put("count", count + 1);
            return json(200, { ok: true, existing: false });
        }
        if (req.method === "POST" && path === "/recipient_admit") {
            const body = new Uint8Array(await req.arrayBuffer());
            if (body.length !== 12)
                return json(400, { ok: false, error: "bad admit payload" });
            const fp = new Uint8Array(body.slice(0, 8)).toString();
            const envLen = new DataView(body.buffer, body.byteOffset + 8, 4).getUint32(0, true);
            const existing = await this.state.storage.get("rcp:" + fp);
            if (existing !== undefined) {
                const total = ((await this.state.storage.get("total_bytes")) ?? 0) + envLen;
                if (total > MAX_TOTAL_QUEUED_BYTES)
                    return json(429, { ok: false, error: "global queue budget exceeded" });
                await this.state.storage.put("total_bytes", total);
                await this.state.storage.put("rcp:" + fp, existing + envLen);
                await this.state.storage.put("rcp_at:" + fp, Date.now());
                return json(200, { ok: true });
            }
            const count = (await this.state.storage.get("recip_count")) ?? 0;
            if (count >= MAX_ACTIVE_RECIPIENTS)
                return json(429, { ok: false, error: "recipient budget exhausted" });
            const total0 = ((await this.state.storage.get("total_bytes")) ?? 0) + envLen;
            if (total0 > MAX_TOTAL_QUEUED_BYTES)
                return json(429, { ok: false, error: "global queue budget exceeded" });
            await this.state.storage.put("recip_count", count + 1);
            await this.state.storage.put("total_bytes", total0);
            await this.state.storage.put("rcp:" + fp, envLen);
            await this.state.storage.put("rcp_at:" + fp, Date.now());
            if (!(await this.state.storage.getAlarm())) {
                await this.state.storage.setAlarm(Date.now() + RECIPIENT_DECAY_CHECK_MS);
            }
            return json(200, { ok: true, new: true });
        }
        if (req.method === "POST" && path === "/recipient_release") {
            const body = new Uint8Array(await req.arrayBuffer());
            if (body.length !== 12 && body.length !== 28)
                return json(400, { ok: false, error: "bad release payload" });
            const fp = new Uint8Array(body.slice(0, 8)).toString();
            const freed = new DataView(body.buffer, body.byteOffset + 8, 4).getUint32(0, true);
            if (body.length === 28) {
                const rid = b64urlEncode(new Uint8Array(body.slice(12, 28)));
                const dupKey = "rel:" + fp + ":" + rid;
                if (await this.state.storage.get(dupKey))
                    return json(200, { ok: true, dup: true });
                await this.state.storage.put(dupKey, 1);
            }
            const cur = await this.state.storage.get("rcp:" + fp);
            if (cur !== undefined) {
                const total = Math.max(0, ((await this.state.storage.get("total_bytes")) ?? 0) - freed);
                const left = Math.max(0, cur - freed);
                await this.state.storage.put("total_bytes", total);
                if (left === 0) {
                    await this.state.storage.delete("rcp:" + fp);
                    await this.state.storage.delete("rcp_at:" + fp);
                    const count = (await this.state.storage.get("recip_count")) ?? 0;
                    await this.state.storage.put("recip_count", Math.max(0, count - 1));
                }
                else {
                    await this.state.storage.put("rcp:" + fp, left);
                }
            }
            return json(200, { ok: true });
        }
        if (req.method === "POST" && path === "/decay") {
            const now = Date.now();
            let count = (await this.state.storage.get("recip_count")) ?? 0;
            let total = (await this.state.storage.get("total_bytes")) ?? 0;
            const dels = [];
            const atMap = await this.state.storage.list({ prefix: "rcp_at:" });
            atMap.forEach((v, k) => {
                if (now - v > RECIPIENT_DECAY_MS)
                    dels.push(k);
            });
            for (const k of dels) {
                const fp = k.slice("rcp_at:".length);
                const bytes = (await this.state.storage.get("rcp:" + fp)) ?? 0;
                total -= bytes;
                count -= 1;
                await this.state.storage.delete("rcp_at:" + fp);
                await this.state.storage.delete("rcp:" + fp);
                const dups = await this.state.storage.list({ prefix: "rel:" + fp + ":" });
                for (const dk of dups.keys())
                    await this.state.storage.delete(dk);
            }
            if (dels.length) {
                await this.state.storage.put("recip_count", Math.max(0, count));
                await this.state.storage.put("total_bytes", Math.max(0, total));
            }
            return json(200, { ok: true, decayed: dels.length });
        }
        if (req.method === "GET" && path === "/stats") {
            return json(200, {
                ok: true,
                registered: (await this.state.storage.get("count")) ?? 0,
                recip_count: (await this.state.storage.get("recip_count")) ?? 0,
                total_bytes: (await this.state.storage.get("total_bytes")) ?? 0,
            });
        }
        if (req.method === "POST" && path === "/relay_sign") {
            const body = new Uint8Array(await req.arrayBuffer());
            if (body.length !== 16)
                return json(400, { ok: false, error: "bad sign payload" });
            const clientFp = body.slice(0, 8);
            const ts = body.slice(8, 16);
            let seed = await this.state.storage.get("relay_seed");
            if (!seed || seed.length !== 32) {
                const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
                const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
                seed = pkcs8.slice(pkcs8.length - 32);
                const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
                await this.state.storage.put("relay_seed", seed);
                await this.state.storage.put("relay_pub", rawPub);
            }
            const pubRaw = (await this.state.storage.get("relay_pub"));
            const priv = await crypto.subtle.importKey("pkcs8", ed25519SeedToPkcs8(seed), { name: "Ed25519" }, false, ["sign"]);
            const msg = concat(new TextEncoder().encode(RELAY_AUTH_INFO), clientFp, pubRaw, ts);
            const sig = await crypto.subtle.sign({ name: "Ed25519" }, priv, msg);
            return json(200, {
                ok: true,
                relay_pub: b64urlEncode(pubRaw),
                relay_sig: b64urlEncode(new Uint8Array(sig)),
            });
        }
        return json(404, { ok: false, error: "not found" });
    }
    async alarm() {
        const count = (await this.state.storage.get("recip_count")) ?? 0;
        if (count > 0) {
            const req = new Request("https://do/decay", { method: "POST" });
            await this.fetch(req);
        }
        await this.state.storage.setAlarm(Date.now() + RECIPIENT_DECAY_CHECK_MS);
    }
}
const RELAY_AUTH_INFO = "nbx-relay-server-auth-v1";
const RECIPIENT_DECAY_CHECK_MS = 86400 * 1000;
function ed25519SeedToPkcs8(seed) {
    const pkcs8 = new Uint8Array(48);
    pkcs8.set([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b,
        0x65, 0x70, 0x04, 0x22, 0x04, 0x20], 0);
    pkcs8.set(seed, 16);
    return pkcs8;
}
