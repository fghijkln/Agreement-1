import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
const MAX_PER_FP = 256;
function registryStub() {
    return env.NBX_REGISTRY.get(env.NBX_REGISTRY.idFromName("registry"));
}
function fpDo(fp) {
    const id = env.NBX_FP.idFromName(btoa(String.fromCharCode(...fp)));
    return env.NBX_FP.get(id);
}
function admitBody(fp, envLen) {
    const b = new Uint8Array(12);
    b.set(fp, 0);
    new DataView(b.buffer).setUint32(8, envLen, true);
    return b;
}
function uuidBytes(uuid) {
    const hex = uuid.replace(/-/g, "");
    return Uint8Array.from({ length: 16 }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16));
}
function relBody(fp, freed, generation, releaseId, createdAt = Date.now()) {
    const b = new Uint8Array(52);
    b.set(fp, 0);
    new DataView(b.buffer).setUint32(8, freed, true);
    b.set(uuidBytes(generation), 12);
    b.set(uuidBytes(releaseId), 28);
    new DataView(b.buffer).setBigUint64(44, BigInt(createdAt), true);
    return b;
}
function envBlob(n, fp) {
    const b = new Uint8Array(n);
    b.set([0x4e, 0x42, 0x58, 0x4d, 0x53, 0x47, 0x01, 0x00], 0);
    b.set(fp, 20);
    return b;
}
async function stats() {
    const r = await registryStub().fetch("https://do/stats");
    return (await r.json());
}
describe("R2-13 eviction 退账", () => {
    it("满队列再投 100 条: DO 恒 256 条, 自动释放淘汰账本, pop 清零后名额释放", async () => {
        const fp = [1, 2, 3, 4, 5, 6, 7, 8];
        const ENV_LEN = 100;
        const reg = registryStub();
        const stub = fpDo(fp);
        const before = await stats();
        let latestAdmission;
        for (let i = 0; i < MAX_PER_FP; i++) {
            const r = await reg.fetch("https://do/recipient_admit", {
                method: "POST", body: admitBody(fp, ENV_LEN),
            });
            expect(r.status).toBe(200);
            const admission = await r.json();
            latestAdmission = admission;
            const pr = await stub.fetch("https://do/push", {
                method: "POST",
                headers: {
                    "x-recipient-generation": admission.generation,
                    "x-recipient-generation-epoch": String(admission.generation_epoch),
                    "x-recipient-reset": String(admission.reset_generation === true),
                },
                body: envBlob(ENV_LEN, fp),
            });
            expect(pr.status).toBe(202);
        }
        for (let i = 0; i < 100; i++) {
            const r = await reg.fetch("https://do/recipient_admit", {
                method: "POST", body: admitBody(fp, ENV_LEN),
            });
            expect(r.status).toBe(200);
            const admission = await r.json();
            latestAdmission = admission;
            const pr = await stub.fetch("https://do/push", {
                method: "POST",
                headers: {
                    "x-recipient-generation": admission.generation,
                    "x-recipient-generation-epoch": String(admission.generation_epoch),
                    "x-recipient-reset": String(admission.reset_generation === true),
                },
                body: envBlob(ENV_LEN, fp),
            });
            expect(pr.status).toBe(202);
            const pj = (await pr.json());
            expect(pj.evicted_bytes).toBe(ENV_LEN);
        }
        const pop = (await (await stub.fetch("https://do/pop", { headers: {
            "x-recipient-generation": latestAdmission.generation,
            "x-recipient-generation-epoch": String(latestAdmission.generation_epoch),
            "x-recipient-reset": String(latestAdmission.reset_generation === true),
        } })).json());
        expect(pop.envelopes.length).toBe(MAX_PER_FP);
        expect(pop.popped_bytes).toBe(MAX_PER_FP * ENV_LEN);
        expect(pop.release_events).toHaveLength(1);
        await reg.fetch("https://do/recipient_release", {
            method: "POST", body: relBody(fp, pop.release_events[0].bytes,
                pop.release_events[0].generation, pop.release_id, pop.release_at),
        });
        const after = await stats();
        expect(after.recip_count).toBe(before.recip_count);
        expect(after.total_bytes).toBe(before.total_bytes);
    });
});
