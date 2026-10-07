// R2-13 回归: 队列 eviction 必须退账, 账本 == 真实队列字节。
// 风格对齐 registry.test.ts: 直接走 DO stub fetch, 用 /stats 观测账本。
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const MAX_PER_FP = 256;   // 必须与 src/do.ts 常量一致

function registryStub(): DurableObjectStub {
  return env.NBX_REGISTRY.get(env.NBX_REGISTRY.idFromName("registry-r213"));
}

function fpDo(fp: number[]): DurableObjectStub {
  const id = env.NBX_FP.idFromName(btoa(String.fromCharCode(...fp)));
  return env.NBX_FP.get(id);
}

function admitBody(fp: number[], envLen: number): Uint8Array {
  const b = new Uint8Array(12);
  b.set(fp, 0);
  new DataView(b.buffer).setUint32(8, envLen, true);
  return b;
}

function relBody(fp: number[], freed: number): Uint8Array {
  const b = new Uint8Array(12);
  b.set(fp, 0);
  new DataView(b.buffer).setUint32(8, freed, true);
  return b;
}

function envBlob(n: number): Uint8Array {
  const b = new Uint8Array(n);
  b.set([0x4e, 0x42, 0x58, 0x4d, 0x53, 0x47, 0x01, 0x00], 0);   // MAGIC_MSG ("NBXMSG\x01\x00")
  return b;
}

async function stats() {
  const r = await registryStub().fetch("https://do/stats");
  return (await r.json()) as { registered: number; recip_count: number; total_bytes: number };
}

describe("R2-13 eviction 退账", () => {
  it("满队列再投 100 条: DO 恒 256 条, Registry 账本不虚胀, pop 清零后名额释放", async () => {
    const fp = [1, 2, 3, 4, 5, 6, 7, 8];
    const ENV_LEN = 100;
    const reg = registryStub();
    const stub = fpDo(fp);
    const before = await stats();

    // 填满 256 条
    for (let i = 0; i < MAX_PER_FP; i++) {
      const r = await reg.fetch("https://do/recipient_admit", {
        method: "POST", body: admitBody(fp, ENV_LEN) as unknown as BodyInit,
      });
      expect(r.status).toBe(200);
      const pr = await stub.fetch("https://do/push", {
        method: "POST", body: envBlob(ENV_LEN) as unknown as BodyInit,
      });
      expect(pr.status).toBe(202);
    }

    // 再投 100 条: 每条淘汰 1 条旧信封 → admit+ENV_LEN, release(evicted)-ENV_LEN → 账本净 0
    for (let i = 0; i < 100; i++) {
      const r = await reg.fetch("https://do/recipient_admit", {
        method: "POST", body: admitBody(fp, ENV_LEN) as unknown as BodyInit,
      });
      expect(r.status).toBe(200);
      const pr = await stub.fetch("https://do/push", {
        method: "POST", body: envBlob(ENV_LEN) as unknown as BodyInit,
      });
      expect(pr.status).toBe(202);
      const pj = (await pr.json()) as { evicted_bytes?: number };
      expect(pj.evicted_bytes).toBe(ENV_LEN);   // 恰好淘汰 1 条
      await reg.fetch("https://do/recipient_release", {
        method: "POST", body: relBody(fp, pj.evicted_bytes!) as unknown as BodyInit,
      });
    }

    // 真实队列仍只有 256 条, 字节 = 256 * ENV_LEN
    const pop = (await (await stub.fetch("https://do/pop")).json()) as { envelopes: string[]; popped_bytes: number };
    expect(pop.envelopes.length).toBe(MAX_PER_FP);
    expect(pop.popped_bytes).toBe(MAX_PER_FP * ENV_LEN);

    // pop 后按 popped_bytes 退账 → 该收件人账目清零 → 名额释放, 全局账归位
    await reg.fetch("https://do/recipient_release", {
      method: "POST", body: relBody(fp, pop.popped_bytes) as unknown as BodyInit,
    });
    const after = await stats();
    expect(after.recip_count).toBe(before.recip_count);
    expect(after.total_bytes).toBe(before.total_bytes);
  });
});
