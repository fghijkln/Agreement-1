import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
function registryStub() {
    const id = env.NBX_REGISTRY.idFromName("registry");
    return env.NBX_REGISTRY.get(id);
}
const generations = new Map();
const MAX_RELEASE_AGE_MS = 90 * 86400 * 1000;
async function admit(fp, envLen) {
    const body = new Uint8Array(12);
    body.set(fp, 0);
    new DataView(body.buffer).setUint32(8, envLen, true);
    const response = await registryStub().fetch("https://do/recipient_admit", { method: "POST", body: body });
    const payload = await response.clone().json();
    if (payload.generation)
        generations.set(fp.toString(), payload.generation);
    return response;
}
async function release(fp, freed) {
    return registryStub().fetch("https://do/recipient_release", {
        method: "POST", body: releaseWithId(fp, freed, crypto.randomUUID(), generations.get(fp.toString())),
    });
}
function uuidBytes(uuid) {
    const hex = uuid.replace(/-/g, "");
    return Uint8Array.from({ length: 16 }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16));
}
function releaseWithId(fp, freed, releaseId, generation, createdAt = Date.now()) {
    const body = new Uint8Array(52);
    body.set(fp, 0);
    new DataView(body.buffer).setUint32(8, freed, true);
    body.set(uuidBytes(generation), 12);
    body.set(uuidBytes(releaseId), 28);
    new DataView(body.buffer).setBigUint64(44, BigInt(createdAt), true);
    return body;
}
function b64u(bytes) {
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function stats() {
    const r = await registryStub().fetch("https://do/stats");
    return r.json();
}
describe("RegistryDo accounting (R2-11/R2-12)", () => {
    it("R2-11: admit then release-to-zero frees the recipient slot", async () => {
        const fp = new Uint8Array(8).fill(1);
        const before = (await stats()).recip_count;
        let r = await admit(fp, 100);
        expect(r.status).toBe(200);
        expect((await stats()).recip_count).toBe(before + 1);
        r = await release(fp, 100);
        expect(r.status).toBe(200);
        expect((await stats()).recip_count).toBe(before);
    });
    it("R2-11: repeated admit/release cycles do not leak slots", async () => {
        const before = (await stats()).recip_count;
        for (let i = 0; i < 20; i++) {
            const fp = new Uint8Array(8).fill(i + 40);
            await admit(fp, 50);
            await release(fp, 50);
        }
        expect((await stats()).recip_count).toBe(before);
    });
    it("R2-11: partial release keeps the slot (queue not empty)", async () => {
        const fp = new Uint8Array(8).fill(9);
        await admit(fp, 300);
        const afterAdmit = (await stats()).recip_count;
        await release(fp, 100);
        expect((await stats()).recip_count).toBe(afterAdmit);
        await release(fp, 200);
        expect((await stats()).recip_count).toBe(afterAdmit - 1);
    });
    it("R2-12: re-admit refreshes activity timestamp", async () => {
        const fp = new Uint8Array(8).fill(7);
        await admit(fp, 64);
        const id = env.NBX_REGISTRY.idFromName("registry");
        const stub = env.NBX_REGISTRY.get(id);
        const t1 = await runInDurableObject(stub, async (_inst, state) => {
            return state.storage.get("rcp_at:" + new Uint8Array(8).fill(7).toString());
        });
        await admit(fp, 64);
        const t2 = await runInDurableObject(stub, async (_inst, state) => {
            return state.storage.get("rcp_at:" + new Uint8Array(8).fill(7).toString());
        });
        expect(t2).toBeGreaterThanOrEqual(t1);
        expect(t2).toBeDefined();
    });
    it("R2-12: decay removes only stale entries, keeps active ones", async () => {
        const active = new Uint8Array(8).fill(21);
        const stale = new Uint8Array(8).fill(22);
        await admit(active, 64);
        await admit(stale, 64);
        const id = env.NBX_REGISTRY.idFromName("registry");
        const stub = env.NBX_REGISTRY.get(id);
        await runInDurableObject(stub, async (_inst, state) => {
            const k = "rcp_at:" + new Uint8Array(8).fill(22).toString();
            await state.storage.put(k, Date.now() - 8 * 86400 * 1000);
        });
        const r = await stub.fetch("https://do/decay", { method: "POST" });
        const body = await r.json();
        expect(body.decayed).toBeGreaterThanOrEqual(1);
        const activeLeft = await runInDurableObject(stub, async (_inst, state) => {
            return state.storage.get("rcp:" + new Uint8Array(8).fill(21).toString());
        });
        expect(activeLeft).toBeDefined();
    });
    it("R2-12: alarm is scheduled for decay", async () => {
        const fp = new Uint8Array(8).fill(31);
        await admit(fp, 64);
        const id = env.NBX_REGISTRY.idFromName("registry");
        const stub = env.NBX_REGISTRY.get(id);
        const alarm = await runInDurableObject(stub, async (_inst, state) => {
            return state.storage.getAlarm();
        });
        expect(alarm).not.toBeNull();
    });
    it("52B release 中途失败会回滚去重标记和账本，重试只扣一次", async () => {
        const fp = crypto.getRandomValues(new Uint8Array(8));
        const releaseId = crypto.randomUUID();
        const before = await stats();
        expect((await admit(fp, 100)).status).toBe(200);
        const generation = generations.get(fp.toString());
        const body = releaseWithId(fp, 50, releaseId, generation);
        const fpKey = fp.toString();
        const dupKey = "rel:" + fpKey + ":" + generation + ":" + b64u(body.slice(28, 44));
        const stub = registryStub();

        const interrupted = await runInDurableObject(stub, async (instance, state) => {
            const originalTransaction = state.storage.transaction.bind(state.storage);
            let injected = false;
            state.storage.transaction = async (callback) => originalTransaction(async (txn) => {
                const originalPut = txn.put.bind(txn);
                const wrapped = new Proxy(txn, {
                    get(target, property, receiver) {
                        if (property === "put") {
                            return async (key, value, options) => {
                                const result = await originalPut(key, value, options);
                                if (key === "total_bytes" && !injected) {
                                    injected = true;
                                    throw new Error("simulated failure after total_bytes write");
                                }
                                return result;
                            };
                        }
                        const value = Reflect.get(target, property, target);
                        return typeof value === "function" ? value.bind(target) : value;
                    },
                });
                return callback(wrapped);
            });
            let failed = false;
            try {
                await instance.fetch(new Request("https://do/recipient_release", {
                    method: "POST", body,
                }));
            }
            catch {
                failed = true;
            }
            state.storage.transaction = originalTransaction;
            return {
                injected,
                failed,
                duplicateMarker: await state.storage.get(dupKey),
                recipientBytes: await state.storage.get("rcp:" + fpKey),
            };
        });
        expect(interrupted.injected).toBe(true);
        expect(interrupted.failed).toBe(true);
        expect(interrupted.duplicateMarker).toBeUndefined();
        expect(interrupted.recipientBytes).toBe(100);
        let after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes + 100);
        expect(after.recip_count).toBe(before.recip_count + 1);

        const retry = await stub.fetch("https://do/recipient_release", { method: "POST", body });
        expect(retry.status).toBe(200);
        after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes + 50);
        expect(after.recip_count).toBe(before.recip_count + 1);
        const duplicate = await (await stub.fetch("https://do/recipient_release", { method: "POST", body })).json();
        expect(duplicate.dup).toBe(true);
        after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes + 50);
        expect(after.recip_count).toBe(before.recip_count + 1);
        await release(fp, 50);
        after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes);
        expect(after.recip_count).toBe(before.recip_count);
    });
    it("首次无时间戳 44B 和无 ID 12B release 不得扣账，已有 marker 的 44B 重试仍可确认", async () => {
        const fp = crypto.getRandomValues(new Uint8Array(8));
        const before = await stats();
        expect((await admit(fp, 100)).status).toBe(200);
        const generation = generations.get(fp.toString());
        const releaseId = crypto.randomUUID();
        const modern = releaseWithId(fp, 10, releaseId, generation);
        const legacy44 = modern.slice(0, 44);
        const idless12 = modern.slice(0, 12);
        expect(legacy44).toHaveLength(44);

        const stub = registryStub();
        expect((await stub.fetch("https://do/recipient_release", { method: "POST", body: idless12 })).status).toBe(400);
        const firstLegacy = await stub.fetch("https://do/recipient_release", { method: "POST", body: legacy44 });
        expect(firstLegacy.status).toBe(400);
        expect((await stats()).total_bytes).toBe(before.total_bytes + 100);

        expect((await stub.fetch("https://do/recipient_release", { method: "POST", body: modern })).status).toBe(200);
        const retry = await (await stub.fetch("https://do/recipient_release", {
            method: "POST", body: legacy44,
        })).json();
        expect(retry.dup).toBe(true);
        expect((await stats()).total_bytes).toBe(before.total_bytes + 90);
        expect((await release(fp, 90)).status).toBe(200);
        const after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes);
        expect(after.recip_count).toBe(before.recip_count);
    });
    it("decay 后重 admit 生成新账本代次，迟到旧 release 不触碰新账本", async () => {
        const fp = crypto.getRandomValues(new Uint8Array(8));
        const before = await stats();
        expect((await admit(fp, 200)).status).toBe(200);
        const oldGeneration = generations.get(fp.toString());
        const oldReleaseId = crypto.randomUUID();
        const oldRelease = releaseWithId(fp, 100, oldReleaseId, oldGeneration);
        expect((await registryStub().fetch("https://do/recipient_release", {
            method: "POST", body: oldRelease,
        })).status).toBe(200);

        const fpKey = fp.toString();
        const oldMarker = "rel:" + fpKey + ":" + oldGeneration + ":" + b64u(oldRelease.slice(28, 44));
        const stub = registryStub();
        await runInDurableObject(stub, async (_instance, state) => {
            await state.storage.put("rcp_at:" + fpKey, Date.now() - 8 * 86400 * 1000);
        });
        const decay = await (await stub.fetch("https://do/decay", { method: "POST" })).json();
        expect(decay.decayed).toBeGreaterThanOrEqual(1);
        const markerAfterDecay = await runInDurableObject(stub, async (_instance, state) => ({
            marker: await state.storage.get(oldMarker),
            generation: await state.storage.get("rcp_gen:" + fpKey),
        }));
        expect(markerAfterDecay.marker).toBeUndefined();
        expect(markerAfterDecay.generation).toBeUndefined();

        expect((await admit(fp, 50)).status).toBe(200);
        const newGeneration = generations.get(fp.toString());
        expect(newGeneration).not.toBe(oldGeneration);
        const beforeReplay = await stats();
        expect(beforeReplay.total_bytes).toBe(before.total_bytes + 50);
        const replay = await (await stub.fetch("https://do/recipient_release", {
            method: "POST", body: oldRelease,
        })).json();
        expect(replay.stale).toBe(true);
        const afterReplay = await stats();
        expect(afterReplay.total_bytes).toBe(before.total_bytes + 50);
        expect(afterReplay.recip_count).toBe(before.recip_count + 1);
        expect(await (await stub.fetch("https://do/recipient_release", {
            method: "POST", body: releaseWithId(fp, 50, crypto.randomUUID(), newGeneration),
        })).ok).toBe(true);
        const final = await stats();
        expect(final.total_bytes).toBe(before.total_bytes);
        expect(final.recip_count).toBe(before.recip_count);
    });
    it("90 天后 release 标记可清理，但同样过期的事件不会扣当前账本", async () => {
        const fp = crypto.getRandomValues(new Uint8Array(8));
        const before = await stats();
        expect((await admit(fp, 100)).status).toBe(200);
        const generation = generations.get(fp.toString());
        const stub = registryStub();
        const firstId = crypto.randomUUID();
        const firstBody = releaseWithId(fp, 10, firstId, generation);
        expect((await stub.fetch("https://do/recipient_release", {
            method: "POST", body: firstBody,
        })).ok).toBe(true);
        const markerKey = "rel:" + fp.toString() + ":" + generation + ":" + b64u(firstBody.slice(28, 44));
        const expiredAt = Date.now() - MAX_RELEASE_AGE_MS - 1;
        await runInDurableObject(stub, async (_instance, state) => {
            await state.storage.put(markerKey, { version: 2, created_at: expiredAt });
        });

        const expired = await (await stub.fetch("https://do/recipient_release", {
            method: "POST",
            body: releaseWithId(fp, 70, crypto.randomUUID(), generation, expiredAt),
        })).json();
        expect(expired.stale).toBe(true);
        expect(expired.expired).toBe(true);
        let after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes + 90);

        const nextBody = releaseWithId(fp, 10, crypto.randomUUID(), generation);
        expect((await stub.fetch("https://do/recipient_release", {
            method: "POST", body: nextBody,
        })).ok).toBe(true);
        const markers = await runInDurableObject(stub, async (_instance, state) => ({
            expired: await state.storage.get(markerKey),
            current: await state.storage.get("rel:" + fp.toString() + ":" + generation + ":"
                + b64u(nextBody.slice(28, 44))),
        }));
        expect(markers.expired).toBeUndefined();
        expect(markers.current.version).toBe(2);
        after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes + 80);
        await release(fp, 80);
        after = await stats();
        expect(after.total_bytes).toBe(before.total_bytes);
    });
});
