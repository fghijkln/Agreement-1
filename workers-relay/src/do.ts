const TTL_MS = 7 * 86400 * 1000;
const MAX_PER_FP = 256;
const MAX_REGISTERED = 10000;
const SEND_QUOTA_WINDOW_MS = 3600 * 1000;
const SEND_QUOTA_MAX = 600;
const MAX_ACTIVE_RECIPIENTS = 50000;
const MAX_TOTAL_QUEUED_BYTES = 512 * 1024 * 1024;
const RECIPIENT_DECAY_MS = 7 * 86400 * 1000;
const MAX_RELEASE_EVENT_AGE_MS = 90 * 86400 * 1000;
const MAGIC_MSG = new Uint8Array([0x4e, 0x42, 0x58, 0x4d, 0x53, 0x47, 0x01, 0x00]);
function b64urlEncode(buf) {
    let s = "";
    for (const c of buf)
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
function json(status, obj) {
    return new Response(JSON.stringify(obj), {
        status,
        headers: { "Content-Type": "application/json" },
    });
}
function uuidBytes(uuid) {
    const hex = uuid.replace(/-/g, "");
    if (!/^[0-9a-f]{32}$/i.test(hex))
        throw new Error("bad UUID");
    return Uint8Array.from({ length: 16 }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16));
}
function bytesUuid(bytes) {
    const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    return hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" + hex.slice(12, 16)
        + "-" + hex.slice(16, 20) + "-" + hex.slice(20);
}
function releaseGroups(entries) {
    const totals = new Map();
    for (const entry of entries) {
        if (!entry.generation)
            continue;
        totals.set(entry.generation, (totals.get(entry.generation) ?? 0) + Math.floor(entry.env.length * 3 / 4));
    }
    return [...totals].map(([generation, bytes]) => ({ generation, bytes }));
}
async function nextGenerationEpoch(txn) {
    const next = ((await txn.get("generation_epoch")) ?? 0) + 1;
    await txn.put("generation_epoch", next);
    return next;
}
async function scheduleNextAlarm(txn, q, outbox, pending: { at: number } | null = null, now = Date.now()) {
    let next = Infinity;
    for (const entry of q)
        next = Math.min(next, entry.at + TTL_MS);
    if (pending)
        next = Math.min(next, pending.at + TTL_MS);
    for (const event of outbox)
        if (event.retry_at !== undefined)
            next = Math.min(next, event.retry_at);
    if (Number.isFinite(next))
        await txn.setAlarm(Math.max(next, now + 1000));
    else
        await txn.deleteAlarm();
}
export class NbxFpDurableObject {
    state;
    env;
    constructor(state, env) {
        this.state = state;
        this.env = env;
    }
    async gc(fallbackGeneration = null, resetGeneration = false, generationEpoch: number | null = null) {
        const accepted = await this.state.storage.transaction(async (txn) => {
            const now = Date.now();
            let q = (await txn.get("q")) ?? [];
            let replacingEpoch = false;
            if (fallbackGeneration) {
                if (generationEpoch === null || !Number.isSafeInteger(generationEpoch) || generationEpoch < 1) {
                    return false;
                }
                const queueGeneration = await txn.get("queue_generation");
                const queueEpoch = (await txn.get("queue_generation_epoch")) ?? 0;
                if (generationEpoch < queueEpoch
                    || (generationEpoch === queueEpoch && queueGeneration && queueGeneration !== fallbackGeneration)) {
                    return false;
                }
                replacingEpoch = generationEpoch > queueEpoch;
                q = (resetGeneration && (replacingEpoch || queueGeneration !== fallbackGeneration))
                    || (replacingEpoch && queueGeneration && queueGeneration !== fallbackGeneration)
                    ? q.filter((e) => e.generation === fallbackGeneration)
                    : q.map((e) => e.generation ? e : { ...e, generation: fallbackGeneration });
                await txn.put("queue_generation", fallbackGeneration);
                await txn.put("queue_generation_epoch", generationEpoch);
            }
            const expired = q.filter((e) => now - e.at >= TTL_MS);
            const live = q.filter((e) => now - e.at < TTL_MS);
            let outbox = ((await txn.get("release_outbox")) ?? [])
                .map((event) => Number.isSafeInteger(event.created_at) ? event : { ...event, created_at: now });
            for (const group of releaseGroups(expired)) {
                const first = expired.find((e) => e.generation === group.generation);
                const fp = b64urlDecode(first.env).slice(20, 28);
                outbox.push({ fp: [...fp], generation: group.generation, bytes: group.bytes,
                    release_id: crypto.randomUUID(), created_at: now, retry_at: now + 60_000 });
            }
            let pending = await txn.get("pending");
            if (pending && fallbackGeneration) {
                const hasOtherGeneration = (pending.generation && pending.generation !== fallbackGeneration)
                    || pending.q.some((e) => e.generation && e.generation !== fallbackGeneration);
                const hasUntagged = pending.q.some((e) => !e.generation);
                if (hasOtherGeneration || (replacingEpoch && resetGeneration && hasUntagged)) {
                    await txn.delete("pending");
                    pending = null;
                }
                else {
                    pending = { ...pending, generation: fallbackGeneration, generation_epoch: generationEpoch,
                        q: pending.q.map((e) => e.generation ? e : { ...e, generation: fallbackGeneration }) };
                    await txn.put("pending", pending);
                }
            }
            const pendingExpired = pending && now - pending.at > TTL_MS;
            if (pendingExpired) {
                for (const group of releaseGroups(pending.q)) {
                    const first = pending.q.find((e) => e.generation === group.generation);
                    const fp = b64urlDecode(first.env).slice(20, 28);
                    outbox.push({ fp: [...fp], generation: group.generation, bytes: group.bytes,
                        release_id: pending.release_id ?? crypto.randomUUID(),
                        created_at: pending.release_at ?? pending.at ?? now, retry_at: now + 60_000 });
                }
                await txn.delete("pending");
            }
            else if (pending)
                await txn.put("pending", pending);
            outbox = outbox.filter((event) => !Number.isSafeInteger(event.created_at)
                || now - event.created_at < MAX_RELEASE_EVENT_AGE_MS);
            await txn.put("q", live);
            await txn.put("release_outbox", outbox);
            await scheduleNextAlarm(txn, live, outbox, pendingExpired ? null : pending, now);
            return true;
        });
        if (!accepted)
            return false;
        await this.flushReleaseOutbox();
        return true;
    }
    async flushReleaseOutbox() {
        const events = (await this.state.storage.get("release_outbox")) ?? [];
        for (const event of events) {
            const hasCreatedAt = Number.isSafeInteger(event.created_at) && event.created_at > 0;
            const body = new Uint8Array(event.generation ? (hasCreatedAt ? 52 : 44) : 28);
            body.set(new Uint8Array(event.fp), 0);
            new DataView(body.buffer).setUint32(8, event.bytes, true);
            if (event.generation)
                body.set(uuidBytes(event.generation), 12);
            const rid = uuidBytes(event.release_id);
            for (let i = 0; i < 16; i++)
                body[(event.generation ? 28 : 12) + i] = rid[i];
            if (event.generation && hasCreatedAt)
                new DataView(body.buffer).setBigUint64(44, BigInt(event.created_at), true);
            let released = false;
            for (let attempt = 0; attempt < 3 && !released; attempt++) {
                try {
                    const registry = this.env.NBX_REGISTRY.get(this.env.NBX_REGISTRY.idFromName("registry"));
                    const resp = await registry.fetch("https://do/recipient_release", {
                        method: "POST", body,
                    });
                    released = resp.ok;
                }
                catch { }
            }
            if (released) {
                await this.state.storage.transaction(async (txn) => {
                    const current = (await txn.get("release_outbox")) ?? [];
                    await txn.put("release_outbox", current.filter((e) => e.release_id !== event.release_id
                        || e.generation !== event.generation || e.fp.toString() !== event.fp.toString()));
                });
            }
            else {
                await this.state.storage.transaction(async (txn) => {
                    const current = (await txn.get("release_outbox")) ?? [];
                    await txn.put("release_outbox", current.map((e) => e.release_id === event.release_id
                        && e.generation === event.generation && e.fp.toString() === event.fp.toString()
                        ? { ...e, retry_at: Date.now() + 60_000 } : e));
                });
            }
        }
        await this.state.storage.transaction(async (txn) => {
            const q = (await txn.get("q")) ?? [];
            const remaining = (await txn.get("release_outbox")) ?? [];
            const pending = await txn.get("pending");
            await scheduleNextAlarm(txn, q, remaining, pending);
        });
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
            const blob = new Uint8Array(await req.arrayBuffer());
            if (blob.length < 48)
                return json(400, { ok: false, error: "bad envelope" });
            for (let i = 0; i < 8; i++)
                if (blob[i] !== MAGIC_MSG[i])
                    return json(400, { ok: false, error: "bad envelope" });
            const generation = req.headers.get("x-recipient-generation");
            if (!generation || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(generation))
                return json(400, { ok: false, error: "missing recipient generation" });
            const generationEpochText = req.headers.get("x-recipient-generation-epoch");
            const generationEpoch = Number(generationEpochText);
            if (!generationEpochText || !Number.isSafeInteger(generationEpoch) || generationEpoch < 1)
                return json(400, { ok: false, error: "missing recipient generation epoch" });
            const resetGeneration = req.headers.get("x-recipient-reset") === "true";
            if (!await this.gc(generation, resetGeneration, generationEpoch))
                return json(409, { ok: false, error: "stale recipient generation" });
            let evictedBytes = 0;
            const accepted = await this.state.storage.transaction(async (txn) => {
                const currentEpoch = (await txn.get("queue_generation_epoch")) ?? 0;
                const currentGeneration = await txn.get("queue_generation");
                if (currentEpoch !== generationEpoch || currentGeneration !== generation)
                    return false;
                const q = (await txn.get("q")) ?? [];
                q.push({ at: Date.now(), env: b64urlEncode(blob), generation });
                const evicted = q.length > MAX_PER_FP ? q.slice(0, q.length - MAX_PER_FP) : [];
                const trimmed = evicted.length ? q.slice(evicted.length) : q;
                for (const e of evicted)
                    evictedBytes += Math.floor(e.env.length * 3 / 4);
                await txn.put("q", trimmed);
                if (evictedBytes > 0) {
                    const outbox = (await txn.get("release_outbox")) ?? [];
                    const now = Date.now();
                    for (const group of releaseGroups(evicted)) {
                        const first = evicted.find((e) => e.generation === group.generation);
                        const fp = b64urlDecode(first.env).slice(20, 28);
                        outbox.push({ fp: [...fp], generation: group.generation, bytes: group.bytes,
                            release_id: crypto.randomUUID(), created_at: now, retry_at: now + 60_000 });
                    }
                    await txn.put("release_outbox", outbox);
                }
                const outbox = (await txn.get("release_outbox")) ?? [];
                const pending = await txn.get("pending");
                await scheduleNextAlarm(txn, trimmed, outbox, pending);
                return true;
            });
            if (!accepted)
                return json(409, { ok: false, error: "stale recipient generation" });
            await this.flushReleaseOutbox();
            const msgId = b64urlEncode(blob.slice(28, 44));
            return json(202, { ok: true, msg_id: msgId, evicted_bytes: evictedBytes });
        }
        if (req.method === "GET" && path === "/pop") {
            const generation = req.headers.get("x-recipient-generation");
            const generationEpochText = req.headers.get("x-recipient-generation-epoch");
            const generationEpoch = Number(generationEpochText);
            const resetGeneration = req.headers.get("x-recipient-reset") === "true";
            if (generation && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(generation))
                return json(400, { ok: false, error: "bad recipient generation" });
            if (generation && (!generationEpochText || !Number.isSafeInteger(generationEpoch) || generationEpoch < 1))
                return json(400, { ok: false, error: "bad recipient generation epoch" });
            const accepted = generation
                ? await this.gc(generation, resetGeneration, generationEpoch)
                : await this.gc();
            if (!accepted)
                return json(409, { ok: false, error: "stale recipient generation" });
            const popResult = await this.state.storage.transaction(async (txn) => {
                if (generation) {
                    const currentEpoch = (await txn.get("queue_generation_epoch")) ?? 0;
                    const currentGeneration = await txn.get("queue_generation");
                    if (currentEpoch !== generationEpoch || currentGeneration !== generation)
                        return { stale: true, pending: null };
                }
                let pending = await txn.get("pending");
                if (pending && generation) {
                    const hasOtherGeneration = (pending.generation && pending.generation !== generation)
                        || pending.q.some((e) => e.generation && e.generation !== generation);
                    if (hasOtherGeneration) {
                        await txn.delete("pending");
                        pending = null;
                    }
                    else {
                        pending = { ...pending, generation, generation_epoch: generationEpoch,
                            q: pending.q.map((e) => e.generation ? e : { ...e, generation }) };
                        await txn.put("pending", pending);
                    }
                }
                if (pending)
                    return { stale: false, pending };
                const q = (await txn.get("q")) ?? [];
                if (!q.length)
                    return { stale: false, pending: null };
                const releaseAt = Date.now();
                const queueGeneration = generation ?? await txn.get("queue_generation") ?? null;
                const queueEpoch = generation ? generationEpoch : (await txn.get("queue_generation_epoch")) ?? null;
                const pendingRecord = { release_id: crypto.randomUUID(), at: releaseAt, release_at: releaseAt,
                    generation: queueGeneration, generation_epoch: queueEpoch, q };
                await txn.put("pending", pendingRecord);
                await txn.put("q", []);
                const outbox = (await txn.get("release_outbox")) ?? [];
                await scheduleNextAlarm(txn, [], outbox, pendingRecord);
                return { stale: false, pending: pendingRecord };
            });
            if (popResult.stale)
                return json(409, { ok: false, error: "stale recipient generation" });
            const created = popResult.pending;
            if (!created)
                return json(200, { ok: true, envelopes: [], popped_bytes: 0, release_id: null,
                    release_at: null, release_events: [] });
            let popped = 0;
            for (const e of created.q)
                popped += Math.floor(e.env.length * 3 / 4);
            return json(200, { ok: true, envelopes: created.q.map((e) => e.env),
                popped_bytes: popped, release_id: created.release_id, release_at: created.release_at ?? created.at,
                release_events: releaseGroups(created.q) });
        }
        if (req.method === "POST" && path === "/pop_ack") {
            const raw = new Uint8Array(await req.arrayBuffer());
            if (raw.length !== 16)
                return json(400, { ok: false, error: "bad ack payload" });
            const hex = [...raw].map((b) => b.toString(16).padStart(2, "0")).join("");
            const expect = hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" + hex.slice(12, 16)
                + "-" + hex.slice(16, 20) + "-" + hex.slice(20);
            await this.state.storage.transaction(async (txn) => {
                const p = await txn.get("pending");
                if (p && p.release_id === expect)
                    await txn.delete("pending");
                const q = (await txn.get("q")) ?? [];
                const outbox = (await txn.get("release_outbox")) ?? [];
                await scheduleNextAlarm(txn, q, outbox, p && p.release_id !== expect ? p : null);
            });
            return json(200, { ok: true });
        }
        return json(404, { ok: false, error: "not found" });
    }
    async alarm() {
        await this.gc();
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
            const result = await this.state.storage.transaction(async (txn) => {
                const existing = await txn.get("rcp:" + fp);
                if (existing !== undefined) {
                    const total = ((await txn.get("total_bytes")) ?? 0) + envLen;
                    if (total > MAX_TOTAL_QUEUED_BYTES)
                        return { status: 429, body: { ok: false, error: "global queue budget exceeded" } };
                    let generation = await txn.get("rcp_gen:" + fp);
                    if (!generation) {
                        generation = crypto.randomUUID();
                        await txn.put("rcp_gen:" + fp, generation);
                        await txn.put("rcp_gen_reset:" + fp, 0);
                    }
                    let generationEpoch = await txn.get("rcp_gen_epoch:" + fp);
                    if (!generationEpoch) {
                        generationEpoch = await nextGenerationEpoch(txn);
                        await txn.put("rcp_gen_epoch:" + fp, generationEpoch);
                    }
                    const resetGeneration = (await txn.get("rcp_gen_reset:" + fp)) === 1;
                    await txn.put("total_bytes", total);
                    await txn.put("rcp:" + fp, existing + envLen);
                    await txn.put("rcp_at:" + fp, Date.now());
                    return { status: 200, body: { ok: true, existing: true, generation,
                        generation_epoch: generationEpoch, reset_generation: resetGeneration } };
                }
                const count = (await txn.get("recip_count")) ?? 0;
                if (count >= MAX_ACTIVE_RECIPIENTS)
                    return { status: 429, body: { ok: false, error: "recipient budget exhausted" } };
                const total = ((await txn.get("total_bytes")) ?? 0) + envLen;
                if (total > MAX_TOTAL_QUEUED_BYTES)
                    return { status: 429, body: { ok: false, error: "global queue budget exceeded" } };
                const generation = crypto.randomUUID();
                const generationEpoch = await nextGenerationEpoch(txn);
                await txn.put("recip_count", count + 1);
                await txn.put("total_bytes", total);
                await txn.put("rcp:" + fp, envLen);
                await txn.put("rcp_at:" + fp, Date.now());
                await txn.put("rcp_gen:" + fp, generation);
                await txn.put("rcp_gen_reset:" + fp, 1);
                await txn.put("rcp_gen_epoch:" + fp, generationEpoch);
                if (!(await txn.getAlarm()))
                    await txn.setAlarm(Date.now() + RECIPIENT_DECAY_CHECK_MS);
                return { status: 200, body: { ok: true, new: true, generation,
                    generation_epoch: generationEpoch, reset_generation: true } };
            });
            return json(result.status, result.body);
        }
        if (req.method === "POST" && path === "/recipient_generation") {
            const body = new Uint8Array(await req.arrayBuffer());
            if (body.length !== 8)
                return json(400, { ok: false, error: "bad fingerprint" });
            const fp = body.toString();
            const generation = await this.state.storage.transaction(async (txn) => {
                if (await txn.get("rcp:" + fp) === undefined)
                    return null;
                let current = await txn.get("rcp_gen:" + fp);
                if (!current) {
                    current = crypto.randomUUID();
                    await txn.put("rcp_gen:" + fp, current);
                    await txn.put("rcp_gen_reset:" + fp, 0);
                }
                let generationEpoch = await txn.get("rcp_gen_epoch:" + fp);
                if (!generationEpoch) {
                    generationEpoch = await nextGenerationEpoch(txn);
                    await txn.put("rcp_gen_epoch:" + fp, generationEpoch);
                }
                return { generation: current, generation_epoch: generationEpoch,
                    reset_generation: (await txn.get("rcp_gen_reset:" + fp)) === 1 };
            });
            return json(200, { ok: true, ...generation });
        }
        if (req.method === "POST" && path === "/recipient_release") {
            const body = new Uint8Array(await req.arrayBuffer());
            if (body.length !== 28 && body.length !== 44 && body.length !== 52)
                return json(400, { ok: false, error: "bad release payload" });
            const fp = new Uint8Array(body.slice(0, 8)).toString();
            const freed = new DataView(body.buffer, body.byteOffset + 8, 4).getUint32(0, true);
            const generation = body.length >= 44 ? bytesUuid(body.slice(12, 28)) : null;
            const releaseId = body.length >= 44 ? b64urlEncode(body.slice(28, 44))
                : body.length === 28 ? b64urlEncode(body.slice(12, 28)) : null;
            const now = Date.now();
            const eventCreatedAt = body.length === 52
                ? Number(new DataView(body.buffer, body.byteOffset + 44, 8).getBigUint64(0, true)) : null;
            if (eventCreatedAt !== null) {
                if (!Number.isSafeInteger(eventCreatedAt) || eventCreatedAt > now + 5 * 60_000)
                    return json(400, { ok: false, error: "bad release timestamp" });
                if (now - eventCreatedAt >= MAX_RELEASE_EVENT_AGE_MS)
                    return json(200, { ok: true, stale: true, expired: true });
            }
            const dupKey = releaseId
                ? "rel:" + fp + ":" + (generation ?? "legacy") + ":" + releaseId : null;
            const result = await this.state.storage.transaction(async (txn) => {
                const activeGeneration = await txn.get("rcp_gen:" + fp);
                if (generation ? activeGeneration !== generation : activeGeneration !== undefined) {
                    return "stale";
                }
                const existingMarker = dupKey ? await txn.get(dupKey) : undefined;
                if (existingMarker) {
                    if (eventCreatedAt !== null && existingMarker?.version !== 2)
                        await txn.put(dupKey, { version: 2, created_at: eventCreatedAt });
                    return "duplicate";
                }
                if (generation && eventCreatedAt === null)
                    return "missing_timestamp";
                if (generation && eventCreatedAt !== null) {
                    const markers = await txn.list({ prefix: "rel:" + fp + ":" + generation + ":" });
                    const expiredKeys = [...markers.entries()]
                        .filter(([, value]) => value?.version === 2
                            && now - value.created_at >= MAX_RELEASE_EVENT_AGE_MS)
                        .map(([key]) => key);
                    if (expiredKeys.length)
                        await txn.delete(expiredKeys);
                }
                if (dupKey)
                    await txn.put(dupKey, eventCreatedAt === null ? 1 : { version: 2, created_at: eventCreatedAt });
                const cur = await txn.get("rcp:" + fp);
                if (cur !== undefined) {
                    const debited = Math.min(cur, freed);
                    const total = Math.max(0, ((await txn.get("total_bytes")) ?? 0) - debited);
                    const left = cur - debited;
                    await txn.put("total_bytes", total);
                    if (left === 0) {
                        await txn.delete("rcp:" + fp);
                        await txn.delete("rcp_at:" + fp);
                        await txn.delete("rcp_gen:" + fp);
                        await txn.delete("rcp_gen_reset:" + fp);
                        await txn.delete("rcp_gen_epoch:" + fp);
                        const count = (await txn.get("recip_count")) ?? 0;
                        await txn.put("recip_count", Math.max(0, count - 1));
                        const duplicates = await txn.list({ prefix: "rel:" + fp + ":" });
                        if (duplicates.size)
                            await txn.delete([...duplicates.keys()]);
                    }
                    else {
                        await txn.put("rcp:" + fp, left);
                    }
                }
                return "released";
            });
            if (result === "stale")
                return json(200, { ok: true, stale: true });
            if (result === "missing_timestamp")
                return json(400, { ok: false, error: "release timestamp required" });
            if (result === "duplicate")
                return json(200, { ok: true, dup: true });
            return json(200, { ok: true });
        }
        if (req.method === "POST" && path === "/decay") {
            const now = Date.now();
            const atMap = await this.state.storage.list({ prefix: "rcp_at:" });
            const decayed = await this.state.storage.transaction(async (txn) => {
                let count = (await txn.get("recip_count")) ?? 0;
                let total = (await txn.get("total_bytes")) ?? 0;
                let removed = 0;
                for (const key of atMap.keys()) {
                    const observedAt = await txn.get(key);
                    if (observedAt === undefined || now - observedAt <= RECIPIENT_DECAY_MS)
                        continue;
                    const fp = key.slice("rcp_at:".length);
                    const bytes = await txn.get("rcp:" + fp);
                    if (bytes !== undefined) {
                        total = Math.max(0, total - bytes);
                        count = Math.max(0, count - 1);
                    }
                    await txn.delete("rcp_at:" + fp);
                    await txn.delete("rcp:" + fp);
                    await txn.delete("rcp_gen:" + fp);
                    await txn.delete("rcp_gen_reset:" + fp);
                    await txn.delete("rcp_gen_epoch:" + fp);
                    const duplicates = await txn.list({ prefix: "rel:" + fp + ":" });
                    if (duplicates.size)
                        await txn.delete([...duplicates.keys()]);
                    removed++;
                }
                if (removed) {
                    await txn.put("recip_count", count);
                    await txn.put("total_bytes", total);
                }
                return removed;
            });
            return json(200, { ok: true, decayed });
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
