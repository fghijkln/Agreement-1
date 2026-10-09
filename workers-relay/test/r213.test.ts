import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
const MAX_PER_FP = 256;
function registryStub() {
    return env.NBX_REGISTRY.get(env.NBX_REGISTRY.idFromName("registry-r213"));
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
function relBody(fp, freed) {
    const b = new Uint8Array(12);
    b.set(fp, 0);
    new DataView(b.buffer).setUint32(8, freed, true);
    return b;
}
function envBlob(n) {
    const b = new Uint8Array(n);
    b.set([0x4e, 0x42, 0x58, 0x4d, 0x53, 0x47, 0x01, 0x00], 0);
    return b;
}
async function stats() {
    const r = await registryStub().fetch("https://do/stats");
    return (await r.json());
}
describe("R2-13 eviction 退账", () => {
    it("满队列再投 100 条: DO 恒 256 条, Registry 账本不虚胀, pop 清零后名额释放", async () => {
        const fp = [1, 2, 3, 4, 5, 6, 7, 8];
        const ENV_LEN = 100;
        const reg = registryStub();
        const stub = fpDo(fp);
        const before = await stats();
        for (let i = 0; i < MAX_PER_FP; i++) {
            const r = await reg.fetch("https://do/recipient_admit", {
                method: "POST", body: admitBody(fp, ENV_LEN),
            });
            expect(r.status).toBe(200);
            const pr = await stub.fetch("https://do/push", {
                method: "POST", body: envBlob(ENV_LEN),
            });
            expect(pr.status).toBe(202);
        }
        for (let i = 0; i < 100; i++) {
            const r = await reg.fetch("https://do/recipient_admit", {
                method: "POST", body: admitBody(fp, ENV_LEN),
            });
            expect(r.status).toBe(200);
            const pr = await stub.fetch("https://do/push", {
                method: "POST", body: envBlob(ENV_LEN),
            });
            expect(pr.status).toBe(202);
            const pj = (await pr.json());
            expect(pj.evicted_bytes).toBe(ENV_LEN);
            await reg.fetch("https://do/recipient_release", {
                method: "POST", body: relBody(fp, pj.evicted_bytes),
            });
        }
        const pop = (await (await stub.fetch("https://do/pop")).json());
        expect(pop.envelopes.length).toBe(MAX_PER_FP);
        expect(pop.popped_bytes).toBe(MAX_PER_FP * ENV_LEN);
        await reg.fetch("https://do/recipient_release", {
            method: "POST", body: relBody(fp, pop.popped_bytes),
        });
        const after = await stats();
        expect(after.recip_count).toBe(before.recip_count);
        expect(after.total_bytes).toBe(before.total_bytes);
    });
});
