import { env, runDurableObjectAlarm, runInDurableObject, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const TTL_MS = 7 * 86400 * 1000;
const MAX_PER_FP = 256;
const ENV_LEN = 100;
const MAGIC = new Uint8Array([0x4e, 0x42, 0x58, 0x4d, 0x53, 0x47, 0x01, 0x00]);
const AUTH_INFO = "nbx-relay-auth-v1";
const DELIVERY_INFO = "nbx-relay-delivery-v2";
const b64u = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const concat = (...parts) => {
    const result = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        result.set(part, offset);
        offset += part.length;
    }
    return result;
};
function timestamp() {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, BigInt(Math.floor(Date.now() / 1000)), true);
    return bytes;
}
async function sign(privateKey, data) {
    return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, data));
}
async function testKeys() {
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    return { pub: concat(crypto.getRandomValues(new Uint8Array(32)), publicKey), privateKey: pair.privateKey };
}
async function fingerprint(keys) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", keys.pub)).slice(0, 8);
}
async function authBody(keys) {
    const ts = timestamp();
    return concat(keys.pub, ts, await sign(keys.privateKey,
        concat(new TextEncoder().encode(AUTH_INFO), keys.pub, ts)));
}
async function authProof(keys, fp) {
    const ts = timestamp();
    return concat(ts, await sign(keys.privateKey,
        concat(new TextEncoder().encode(AUTH_INFO), fp, ts)));
}
async function deliveryProof(keys, envelope) {
    const ts = timestamp();
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", envelope));
    return concat(ts, await sign(keys.privateKey,
        concat(new TextEncoder().encode(DELIVERY_INFO), digest, ts)));
}
function packMessage(senderFp, recipientFp, sequence) {
    const body = new Uint8Array([sequence & 0xff, (sequence >>> 8) & 0xff]);
    const header = new Uint8Array(48);
    header.set(MAGIC, 0);
    header[8] = 1;
    header[9] = 1;
    header.set(senderFp, 12);
    header.set(recipientFp, 20);
    for (let i = 0; i < 4; i++)
        header[28 + i] = (sequence >>> (i * 8)) & 0xff;
    new DataView(header.buffer).setUint32(44, body.length, true);
    return concat(header, body);
}
function bytesToUuidBytes(uuid) {
    const hex = uuid.replace(/-/g, "");
    return Uint8Array.from({ length: 16 }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16));
}
const recipientGenerations = new Map();
function envBlob(fp, sequence = 0) {
    const blob = new Uint8Array(ENV_LEN);
    blob.set(MAGIC, 0);
    blob[8] = 1;
    blob[9] = 1;
    blob.set(fp, 20);
    for (let i = 0; i < 4; i++)
        blob[28 + i] = (sequence >>> (i * 8)) & 0xff;
    return blob;
}
function registryStub() {
    return env.NBX_REGISTRY.get(env.NBX_REGISTRY.idFromName("registry"));
}
function fpDo(fp) {
    return env.NBX_FP.get(env.NBX_FP.idFromName(b64u(fp)));
}
function admitBody(fp, bytes) {
    const body = new Uint8Array(12);
    body.set(fp, 0);
    new DataView(body.buffer).setUint32(8, bytes, true);
    return body;
}
function releaseBody(fp, bytes, releaseId, createdAt = Date.now()) {
    const generation = recipientGenerations.get(fp.toString())?.generation;
    if (!generation)
        throw new Error("missing test recipient generation");
    const body = new Uint8Array(52);
    body.set(fp, 0);
    new DataView(body.buffer).setUint32(8, bytes, true);
    body.set(bytesToUuidBytes(generation), 12);
    body.set(bytesToUuidBytes(releaseId), 28);
    new DataView(body.buffer).setBigUint64(44, BigInt(createdAt), true);
    return body;
}
function pushRequest(fp, blob, isNew, recipient = recipientGenerations.get(fp.toString())) {
    if (!recipient?.generation || !recipient.generationEpoch)
        throw new Error("missing test recipient generation");
    return {
        method: "POST",
        headers: {
            "x-recipient-generation": recipient.generation,
            "x-recipient-generation-epoch": String(recipient.generationEpoch),
            "x-recipient-reset": String(isNew),
        },
        body: blob,
    };
}
function popRequest(fp) {
    const recipient = recipientGenerations.get(fp.toString());
    if (!recipient?.generation || !recipient.generationEpoch)
        throw new Error("missing test recipient generation");
    return popRequestFor(recipient);
}
function popRequestFor(recipient) {
    if (!recipient?.generation || !recipient.generationEpoch)
        throw new Error("missing test recipient generation");
    return { headers: {
        "x-recipient-generation": recipient.generation,
        "x-recipient-generation-epoch": String(recipient.generationEpoch),
        "x-recipient-reset": String(recipient.isNew),
    } };
}
async function stats() {
    return await (await registryStub().fetch("https://do/stats")).json();
}
async function admit(fp, bytes) {
    const response = await registryStub().fetch("https://do/recipient_admit", {
        method: "POST", body: admitBody(fp, bytes),
    });
    const payload = await response.clone().json();
    if (payload.generation)
        recipientGenerations.set(fp.toString(), {
            generation: payload.generation,
            generationEpoch: payload.generation_epoch,
            isNew: payload.reset_generation === true,
        });
    return response;
}

describe("R2-16: Durable Object 账本 GC 与稳定退账事件", () => {
    it("GC 过期队列和过期 pending 时释放 Registry 字节与名额", async () => {
        const before = await stats();
        const fp = crypto.getRandomValues(new Uint8Array(8));
        const stub = fpDo(fp);
        expect((await admit(fp, ENV_LEN)).status).toBe(200);
        expect((await stub.fetch("https://do/push", pushRequest(fp, envBlob(fp), true))).status).toBe(202);
        await runInDurableObject(stub, async (_instance, state) => {
            const q = await state.storage.get("q");
            q[0].at = Date.now() - TTL_MS - 1;
            await state.storage.put("q", q);
        });
        const expiredQueuePop = await (await stub.fetch("https://do/pop", popRequest(fp))).json();
        expect(expiredQueuePop.envelopes).toHaveLength(0);
        let after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes);
        expect(after.recip_count).toBe(before.recip_count);

        const fpPending = crypto.getRandomValues(new Uint8Array(8));
        const pendingStub = fpDo(fpPending);
        expect((await admit(fpPending, ENV_LEN)).status).toBe(200);
        expect((await pendingStub.fetch("https://do/push", pushRequest(fpPending, envBlob(fpPending), true))).status).toBe(202);
        const pendingPop = await (await pendingStub.fetch("https://do/pop", popRequest(fpPending))).json();
        expect(pendingPop.envelopes).toHaveLength(1);
        await runInDurableObject(pendingStub, async (_instance, state) => {
            const pending = await state.storage.get("pending");
            pending.at = Date.now() - TTL_MS - 1;
            await state.storage.put("pending", pending);
        });
        const expiredPendingPop = await (await pendingStub.fetch("https://do/pop", popRequest(fpPending))).json();
        expect(expiredPendingPop.envelopes).toHaveLength(0);
        after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes);
        expect(after.recip_count).toBe(before.recip_count);
    });

    it("活动账本下将 legacy pending 绑定到已确认代次，release_events 非空后才可 ack", async () => {
        const before = await stats();
        const fp = crypto.getRandomValues(new Uint8Array(8));
        const stub = fpDo(fp);
        expect((await admit(fp, ENV_LEN)).status).toBe(200);
        const recipient = { ...recipientGenerations.get(fp.toString()), isNew: false };
        await runInDurableObject(registryStub(), async (_instance, state) => {
            await state.storage.put("rcp_gen_reset:" + fp.toString(), 0);
        });
        await runInDurableObject(stub, async (_instance, state) => {
            await state.storage.put("pending", {
                release_id: crypto.randomUUID(), at: Date.now(),
                q: [{ at: Date.now(), env: b64u(envBlob(fp)) }],
            });
        });

        const pop = await (await stub.fetch("https://do/pop", popRequestFor(recipient))).json();
        expect(pop.envelopes).toHaveLength(1);
        expect(pop.release_events).toEqual([{ generation: recipient.generation, bytes: ENV_LEN }]);
        const normalized = await runInDurableObject(stub, async (_instance, state) => state.storage.get("pending"));
        expect(normalized.generation).toBe(recipient.generation);
        expect(normalized.generation_epoch).toBe(recipient.generationEpoch);
        expect(normalized.q[0].generation).toBe(recipient.generation);

        await registryStub().fetch("https://do/recipient_release", {
            method: "POST", body: releaseBody(fp, pop.popped_bytes, pop.release_id, pop.release_at),
        });
        await stub.fetch("https://do/pop_ack", {
            method: "POST", body: bytesToUuidBytes(pop.release_id),
        });
        const after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes);
        expect(after.recip_count).toBe(before.recip_count);
    });

    it("decay 后迟到旧 push/pop 返回 409，旧 pending 不得遮蔽新队列", async () => {
        const before = await stats();
        const fp = crypto.getRandomValues(new Uint8Array(8));
        const stub = fpDo(fp);
        expect((await admit(fp, ENV_LEN)).status).toBe(200);
        const oldRecipient = { ...recipientGenerations.get(fp.toString()) };
        expect((await stub.fetch("https://do/push", pushRequest(fp, envBlob(fp, 0), true))).status).toBe(202);
        const oldPending = await (await stub.fetch("https://do/pop", popRequest(fp))).json();
        expect(oldPending.envelopes).toHaveLength(1);

        await runInDurableObject(registryStub(), async (_instance, state) => {
            await state.storage.put("rcp_at:" + fp.toString(), Date.now() - 8 * 86400 * 1000);
        });
        const decay = await (await registryStub().fetch("https://do/decay", { method: "POST" })).json();
        expect(decay.decayed).toBeGreaterThanOrEqual(1);

        expect((await admit(fp, ENV_LEN)).status).toBe(200);
        const firstNewRecipient = { ...recipientGenerations.get(fp.toString()) };
        expect(firstNewRecipient.generation).not.toBe(oldRecipient.generation);
        expect(firstNewRecipient.generationEpoch).toBeGreaterThan(oldRecipient.generationEpoch);
        expect(recipientGenerations.get(fp.toString()).isNew).toBe(true);
        expect((await admit(fp, ENV_LEN)).status).toBe(200);
        expect(recipientGenerations.get(fp.toString()).generation).toBe(firstNewRecipient.generation);
        expect(recipientGenerations.get(fp.toString()).generationEpoch).toBe(firstNewRecipient.generationEpoch);
        expect(recipientGenerations.get(fp.toString()).isNew).toBe(true);

        // Pause both old requests after gc accepts their tokens; commit the new epoch before their queue txns.
        const racedRequests = await runInDurableObject(stub, async (instance) => {
            const doInstance = instance as unknown as {
                gc: (generation: string, reset: boolean, epoch: number) => Promise<boolean>;
                fetch: (request: Request) => Promise<Response>;
            };
            const originalGc = doInstance.gc.bind(doInstance);
            let signalFirstOldGc!: () => void;
            const firstOldGcPassed = new Promise<void>((resolve) => { signalFirstOldGc = resolve; });
            let signalSecondOldGc!: () => void;
            const secondOldGcPassed = new Promise<void>((resolve) => { signalSecondOldGc = resolve; });
            let resumeOldRequests!: () => void;
            const resume = new Promise<void>((resolve) => { resumeOldRequests = resolve; });
            let oldGcCalls = 0;
            doInstance.gc = async (generation, reset, epoch) => {
                const ok = await originalGc(generation, reset, epoch);
                if (epoch === oldRecipient.generationEpoch && oldGcCalls < 2) {
                    oldGcCalls++;
                    if (oldGcCalls === 1)
                        signalFirstOldGc();
                    if (oldGcCalls === 2)
                        signalSecondOldGc();
                    await resume;
                }
                return ok;
            };
            const oldPushPromise = doInstance.fetch(new Request("https://do/push",
                pushRequest(fp, envBlob(fp, 3), true, oldRecipient)));
            await firstOldGcPassed;
            const oldPopPromise = doInstance.fetch(new Request("https://do/pop", popRequestFor(oldRecipient)));
            await secondOldGcPassed;
            let newStatus: number;
            try {
                newStatus = (await doInstance.fetch(new Request("https://do/push",
                    pushRequest(fp, envBlob(fp, 2), true)))).status;
            }
            finally {
                resumeOldRequests();
            }
            const [oldPushResponse, oldPopResponse] = await Promise.all([oldPushPromise, oldPopPromise]);
            doInstance.gc = originalGc;
            return { oldPushStatus: oldPushResponse.status, oldPopStatus: oldPopResponse.status, newStatus };
        });
        expect(racedRequests.newStatus).toBe(202);
        expect(racedRequests.oldPushStatus).toBe(409);
        expect(racedRequests.oldPopStatus).toBe(409);
        const pendingAfterReset = await runInDurableObject(stub, async (_instance, state) => state.storage.get("pending"));
        expect(pendingAfterReset).toBeUndefined();
        expect((await stub.fetch("https://do/push", pushRequest(fp, envBlob(fp, 1), true))).status).toBe(202);
        const queue = await runInDurableObject(stub, async (_instance, state) => state.storage.get("q"));
        expect(queue).toHaveLength(2);
        expect(queue.every((entry) => entry.generation === firstNewRecipient.generation)).toBe(true);

        const pop = await (await stub.fetch("https://do/pop", popRequest(fp))).json();
        expect(pop.envelopes).toHaveLength(2);
        await registryStub().fetch("https://do/recipient_release", {
            method: "POST", body: releaseBody(fp, pop.popped_bytes, pop.release_id, pop.release_at),
        });
        await stub.fetch("https://do/pop_ack", {
            method: "POST", body: bytesToUuidBytes(pop.release_id),
        });
        const after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes);
        expect(after.recip_count).toBe(before.recip_count);
    });

    it("容量淘汰遇到 Registry 已提交但响应丢失时，重试复用同一 release_id", async () => {
        const before = await stats();
        const fp = crypto.getRandomValues(new Uint8Array(8));
        const stub = fpDo(fp);
        expect((await admit(fp, (MAX_PER_FP + 1) * ENV_LEN)).status).toBe(200);
        await runInDurableObject(stub, async (_instance, state) => {
            await state.storage.put("q", Array.from({ length: MAX_PER_FP }, (_, i) => ({
                at: Date.now(), env: b64u(envBlob(fp, i)), generation: recipientGenerations.get(fp.toString()).generation,
            })));
        });

        const result = await runInDurableObject(stub, async (instance, _state) => {
            const doInstance = instance as unknown as {
                env: { NBX_REGISTRY: { get: (id: unknown) => unknown; idFromName: (name: string) => unknown } };
                fetch: (request: Request) => Promise<Response>;
            };
            const namespace = doInstance.env.NBX_REGISTRY as unknown as {
                get: (id: unknown) => { fetch: (url: string, init?: RequestInit) => Promise<Response> };
                idFromName: (name: string) => unknown;
            };
            const originalGet = namespace.get.bind(namespace);
            const releaseBodies: Uint8Array[] = [];
            namespace.get = (id) => {
                const target = originalGet(id);
                return new Proxy(target, {
                    get(real, property, receiver) {
                        if (property === "fetch") {
                            return async (url, init) => {
                                if (String(url).includes("/recipient_release")) {
                                    releaseBodies.push(new Uint8Array(init.body));
                                    const committed = await real.fetch(url, init);
                                    if (releaseBodies.length === 1)
                                        throw new Error("simulated lost Registry response after commit");
                                    return committed;
                                }
                                return real.fetch(url, init);
                            };
                        }
                        return Reflect.get(real, property, receiver);
                    },
                });
            };
            try {
                const response = await doInstance.fetch(new Request("https://do/push",
                    pushRequest(fp, envBlob(fp, MAX_PER_FP), true)));
                return { status: response.status, releaseBodies };
            }
            finally {
                namespace.get = originalGet;
            }
        });
        expect(result.status).toBe(202);
        expect(result.releaseBodies).toHaveLength(2);
        expect(result.releaseBodies[0]).toHaveLength(52);
        expect(b64u(result.releaseBodies[0])).toBe(b64u(result.releaseBodies[1]));
        let after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes + MAX_PER_FP * ENV_LEN);
        expect(after.recip_count).toBe(before.recip_count + 1);

        const pop = await (await stub.fetch("https://do/pop", popRequest(fp))).json();
        expect(pop.envelopes).toHaveLength(MAX_PER_FP);
        await registryStub().fetch("https://do/recipient_release", {
            method: "POST", body: releaseBody(fp, pop.popped_bytes, pop.release_id, pop.release_at),
        });
        await stub.fetch("https://do/pop_ack", {
            method: "POST", body: bytesToUuidBytes(pop.release_id),
        });
        after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes);
        expect(after.recip_count).toBe(before.recip_count);
    });

    it("旧 outbox 缺 created_at 时首次 GC 补迁移时间并发送 52B release", async () => {
        const before = await stats();
        const fp = crypto.getRandomValues(new Uint8Array(8));
        const stub = fpDo(fp);
        expect((await admit(fp, 100)).status).toBe(200);
        const recipient = recipientGenerations.get(fp.toString());
        const releaseId = crypto.randomUUID();
        const migrationStartedAt = Date.now();
        await runInDurableObject(stub, async (_instance, state) => {
            await state.storage.put("release_outbox", [{
                fp: [...fp], generation: recipient.generation, bytes: 25,
                release_id: releaseId, retry_at: Date.now() + 60_000,
            }]);
        });

        const migrated = await runInDurableObject(stub, async (instance, state) => {
            const doInstance = instance as unknown as {
                env: { NBX_REGISTRY: { get: (id: unknown) => unknown; idFromName: (name: string) => unknown } };
                fetch: (request: Request) => Promise<Response>;
            };
            const namespace = doInstance.env.NBX_REGISTRY as unknown as {
                get: (id: unknown) => { fetch: (url: string, init?: RequestInit) => Promise<Response> };
                idFromName: (name: string) => unknown;
            };
            const originalGet = namespace.get.bind(namespace);
            const releaseBodies: Uint8Array[] = [];
            namespace.get = (id) => {
                const target = originalGet(id);
                return new Proxy(target, {
                    get(real, property, receiver) {
                        if (property === "fetch") {
                            return async (url, init) => {
                                if (String(url).includes("/recipient_release"))
                                    releaseBodies.push(new Uint8Array(init.body));
                                return real.fetch(url, init);
                            };
                        }
                        return Reflect.get(real, property, receiver);
                    },
                });
            };
            let status: number;
            try {
                status = (await doInstance.fetch(new Request("https://do/pop", popRequest(fp)))).status;
            }
            finally {
                namespace.get = originalGet;
            }
            return { status, releaseBodies, outbox: await state.storage.get("release_outbox") };
        });
        expect(migrated.status).toBe(200);
        expect(migrated.releaseBodies).toHaveLength(1);
        expect(migrated.releaseBodies[0]).toHaveLength(52);
        const migratedAt = Number(new DataView(migrated.releaseBodies[0].buffer,
            migrated.releaseBodies[0].byteOffset, 52).getBigUint64(44, true));
        expect(migratedAt).toBeGreaterThanOrEqual(migrationStartedAt);
        expect(migratedAt).toBeLessThanOrEqual(Date.now());
        expect(migrated.outbox).toHaveLength(0);
        const after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes + 75);
        expect(after.recip_count).toBe(before.recip_count + 1);
    });

    it("提交 outbox 后即使 flush 前中断，三次释放失败后 alarm 仍可恢复并只退账一次", async () => {
        const before = await stats();
        const fp = crypto.getRandomValues(new Uint8Array(8));
        const stub = fpDo(fp);
        expect((await admit(fp, (MAX_PER_FP + 1) * ENV_LEN)).status).toBe(200);
        await runInDurableObject(stub, async (_instance, state) => {
            await state.storage.put("q", Array.from({ length: MAX_PER_FP }, (_, i) => ({
                at: Date.now(), env: b64u(envBlob(fp, i)), generation: recipientGenerations.get(fp.toString()).generation,
            })));
        });

        const interrupted = await runInDurableObject(stub, async (instance, state) => {
            const doInstance = instance as unknown as {
                flushReleaseOutbox: () => Promise<void>;
                fetch: (request: Request) => Promise<Response>;
            };
            const originalFlush = doInstance.flushReleaseOutbox;
            let flushCalls = 0;
            let failedBeforeFlush = false;
            doInstance.flushReleaseOutbox = async () => {
                flushCalls++;
                if (flushCalls === 2)
                    throw new Error("simulated interruption before outbox flush");
                return originalFlush.call(doInstance);
            };
            try {
                await doInstance.fetch(new Request("https://do/push",
                    pushRequest(fp, envBlob(fp, MAX_PER_FP), true)));
            }
            catch {
                failedBeforeFlush = true;
            }
            finally {
                doInstance.flushReleaseOutbox = originalFlush;
            }
            return {
                failedBeforeFlush,
                flushCalls,
                outbox: await state.storage.get("release_outbox"),
                alarm: await state.storage.getAlarm(),
            };
        });
        expect(interrupted.failedBeforeFlush).toBe(true);
        expect(interrupted.flushCalls).toBe(2);
        expect(interrupted.outbox).toHaveLength(1);
        expect(interrupted.alarm).not.toBeNull();

        let releaseAttempts = 0;
        const failedAlarm = await runInDurableObject(stub, async (instance, state) => {
            const doInstance = instance as unknown as {
                env: { NBX_REGISTRY: { get: (id: unknown) => unknown; idFromName: (name: string) => unknown } };
                alarm: () => Promise<void>;
            };
            const namespace = doInstance.env.NBX_REGISTRY as unknown as {
                get: (id: unknown) => { fetch: (url: string, init?: RequestInit) => Promise<Response> };
                idFromName: (name: string) => unknown;
            };
            const originalGet = namespace.get.bind(namespace);
            namespace.get = (id) => {
                const target = originalGet(id);
                return new Proxy(target, {
                    get(real, property, receiver) {
                        if (property === "fetch") {
                            return async (url, init) => {
                                if (String(url).includes("/recipient_release")) {
                                    releaseAttempts++;
                                    throw new Error("simulated Registry outage");
                                }
                                return real.fetch(url, init);
                            };
                        }
                        return Reflect.get(real, property, receiver);
                    },
                });
            };
            try {
                await doInstance.alarm();
            }
            finally {
                namespace.get = originalGet;
            }
            return {
                outbox: await state.storage.get("release_outbox"),
                alarm: await state.storage.getAlarm(),
            };
        });
        expect(releaseAttempts).toBe(3);
        expect(failedAlarm.outbox).toHaveLength(1);
        expect(failedAlarm.alarm).not.toBeNull();
        let after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes + (MAX_PER_FP + 1) * ENV_LEN);

        expect(await runDurableObjectAlarm(stub)).toBe(true);
        const recovered = await runInDurableObject(stub, async (_instance, state) => ({
            outbox: await state.storage.get("release_outbox"),
            alarm: await state.storage.getAlarm(),
        }));
        expect(recovered.outbox).toHaveLength(0);
        expect(recovered.alarm).not.toBeNull();
        after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes + MAX_PER_FP * ENV_LEN);
        expect(after.recip_count).toBe(before.recip_count + 1);

        const pop = await (await stub.fetch("https://do/pop", popRequest(fp))).json();
        await registryStub().fetch("https://do/recipient_release", {
            method: "POST", body: releaseBody(fp, pop.popped_bytes, pop.release_id, pop.release_at),
        });
        await stub.fetch("https://do/pop_ack", {
            method: "POST", body: bytesToUuidBytes(pop.release_id),
        });
        const clearedAlarm = await runInDurableObject(stub, (_instance, state) => state.storage.getAlarm());
        expect(clearedAlarm).toBeNull();
        after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes);
        expect(after.recip_count).toBe(before.recip_count);
    });

    it("普通无淘汰入队也安排 TTL GC，分批到期后 alarm 连续退账并重设下一最早期限", async () => {
        const before = await stats();
        const fp = crypto.getRandomValues(new Uint8Array(8));
        const stub = fpDo(fp);
        expect((await admit(fp, 2 * ENV_LEN)).status).toBe(200);
        const generation = recipientGenerations.get(fp.toString()).generation;
        expect((await stub.fetch("https://do/push", pushRequest(fp, envBlob(fp, 1), true))).status).toBe(202);
        const firstAlarm = await runInDurableObject(stub, (_instance, state) => state.storage.getAlarm());
        expect(firstAlarm).not.toBeNull();

        await runInDurableObject(stub, async (_instance, state) => {
            const q = await state.storage.get("q");
            q[0].at = Date.now() - TTL_MS + 45_000;
            await state.storage.put("q", q);
        });
        expect((await stub.fetch("https://do/push", pushRequest(fp, envBlob(fp, 2), false))).status).toBe(202);
        let scheduled = await runInDurableObject(stub, (_instance, state) => state.storage.getAlarm());
        expect(scheduled).not.toBeNull();
        expect(scheduled).toBeLessThan(Date.now() + 90_000);

        await runInDurableObject(stub, async (_instance, state) => {
            const q = await state.storage.get("q");
            expect(q).toHaveLength(2);
            expect(q[0].generation).toBe(generation);
            q[0].at = Date.now() - TTL_MS - 1;
            await state.storage.put("q", q);
        });
        expect(await runDurableObjectAlarm(stub)).toBe(true);
        let after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes + ENV_LEN);
        expect(after.recip_count).toBe(before.recip_count + 1);
        const nextBatch = await runInDurableObject(stub, async (_instance, state) => ({
            q: await state.storage.get("q"), alarm: await state.storage.getAlarm(),
        }));
        expect(nextBatch.q).toHaveLength(1);
        expect(nextBatch.alarm).not.toBeNull();
        expect(nextBatch.alarm).toBeGreaterThan(Date.now() + TTL_MS - 10_000);

        await runInDurableObject(stub, async (_instance, state) => {
            const q = await state.storage.get("q");
            q[0].at = Date.now() - TTL_MS - 1;
            await state.storage.put("q", q);
        });
        expect(await runDurableObjectAlarm(stub)).toBe(true);
        const finalState = await runInDurableObject(stub, async (_instance, state) => ({
            q: await state.storage.get("q"), alarm: await state.storage.getAlarm(),
        }));
        expect(finalState.q).toHaveLength(0);
        expect(finalState.alarm).toBeNull();
        after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes);
        expect(after.recip_count).toBe(before.recip_count);
    });

    it("90 天未完成的 release outbox 停止重试并清除 alarm，不再迟到扣账", async () => {
        const before = await stats();
        const fp = crypto.getRandomValues(new Uint8Array(8));
        const stub = fpDo(fp);
        expect((await admit(fp, ENV_LEN)).status).toBe(200);
        const recipient = { ...recipientGenerations.get(fp.toString()) };
        const expiredAt = Date.now() - 90 * 86400 * 1000 - 1;
        await runInDurableObject(stub, async (_instance, state) => {
            await state.storage.put("release_outbox", [{
                fp: [...fp], generation: recipient.generation, bytes: ENV_LEN,
                release_id: crypto.randomUUID(), created_at: expiredAt, retry_at: expiredAt,
            }]);
            await state.storage.setAlarm(expiredAt);
        });

        const pop = await (await stub.fetch("https://do/pop", popRequest(fp))).json();
        expect(pop.envelopes).toHaveLength(0);
        const state = await runInDurableObject(stub, async (_instance, storage) => ({
            outbox: await storage.storage.get("release_outbox"),
            alarm: await storage.storage.getAlarm(),
        }));
        expect(state.outbox).toHaveLength(0);
        expect(state.alarm).toBeNull();
        const after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes + ENV_LEN);
        expect(after.recip_count).toBe(before.recip_count + 1);
    });

    it("真实 /envelope 容量淘汰后 /inbox 只保留 256 条且账本归零", async () => {
        const before = await stats();
        const bob = await testKeys();
        const alice = await testKeys();
        const bobFp = await fingerprint(bob);
        const aliceFp = await fingerprint(alice);
        expect((await SELF.fetch("https://example.com/auth", {
            method: "POST", body: await authBody(bob),
        })).status).toBe(200);
        expect((await SELF.fetch("https://example.com/auth", {
            method: "POST", body: await authBody(alice),
        })).status).toBe(200);

        const messageLength = 50;
        for (let i = 0; i < MAX_PER_FP + 1; i++) {
            const envelope = packMessage(aliceFp, bobFp, i);
            const response = await SELF.fetch("https://example.com/envelope", {
                method: "POST", body: concat(envelope, await deliveryProof(alice, envelope)),
            });
            expect(response.status).toBe(202);
        }
        let after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes + MAX_PER_FP * messageLength);
        expect(after.recip_count).toBe(before.recip_count + 1);

        const inbox = await SELF.fetch("https://example.com/inbox/" + b64u(bobFp), {
            method: "POST", body: await authProof(bob, bobFp),
        });
        expect(inbox.status).toBe(200);
        const payload = await inbox.json();
        expect(payload.envelopes).toHaveLength(MAX_PER_FP);
        expect(payload.popped_bytes).toBe(MAX_PER_FP * messageLength);
        after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes);
        expect(after.recip_count).toBe(before.recip_count);
    }, 60_000);
});
