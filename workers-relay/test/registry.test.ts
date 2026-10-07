// R2-11/R2-12 回归: RegistryDo 账本(名额回收 / rcp_at 刷新 / decay / alarm)。
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";

function registryStub(): DurableObjectStub {
  const id = env.NBX_REGISTRY.idFromName("registry");
  return env.NBX_REGISTRY.get(id);
}

async function admit(fp: Uint8Array, envLen: number): Promise<Response> {
  const body = new Uint8Array(12);
  body.set(fp, 0);
  new DataView(body.buffer).setUint32(8, envLen, true);
  return registryStub().fetch("https://do/recipient_admit", { method: "POST", body: body as unknown as BodyInit });
}

async function release(fp: Uint8Array, freed: number): Promise<Response> {
  const body = new Uint8Array(12);
  body.set(fp, 0);
  new DataView(body.buffer).setUint32(8, freed, true);
  return registryStub().fetch("https://do/recipient_release", { method: "POST", body: body as unknown as BodyInit });
}

async function stats(): Promise<{ recip_count: number; total_bytes: number }> {
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

    // 取空 → 账目清零 → 名额释放
    r = await release(fp, 100);
    expect(r.status).toBe(200);
    expect((await stats()).recip_count).toBe(before);
  });

  it("R2-11: repeated admit/release cycles do not leak slots", async () => {
    const before = (await stats()).recip_count;
    for (let i = 0; i < 20; i++) {
      const fp = new Uint8Array(8).fill(i + 40);
      await admit(fp, 50);
      await release(fp, 50);            // 每个都是"一次性收件人"
    }
    expect((await stats()).recip_count).toBe(before);   // 无泄漏
  });

  it("R2-11: partial release keeps the slot (queue not empty)", async () => {
    const fp = new Uint8Array(8).fill(9);
    await admit(fp, 300);
    const afterAdmit = (await stats()).recip_count;
    await release(fp, 100);             // 还有 200 字节在队列
    expect((await stats()).recip_count).toBe(afterAdmit);   // 名额仍在
    await release(fp, 200);             // 清零
    expect((await stats()).recip_count).toBe(afterAdmit - 1);
  });

  it("R2-12: re-admit refreshes activity timestamp", async () => {
    const fp = new Uint8Array(8).fill(7);
    await admit(fp, 64);
    const id = env.NBX_REGISTRY.idFromName("registry");
    const stub = env.NBX_REGISTRY.get(id);
    const t1 = await runInDurableObject(stub, async (_inst, state) => {
      return state.storage.get<number>("rcp_at:" + new Uint8Array(8).fill(7).toString());
    });
    // 稍后再投一封, 时间戳应 >= t1
    await admit(fp, 64);
    const t2 = await runInDurableObject(stub, async (_inst, state) => {
      return state.storage.get<number>("rcp_at:" + new Uint8Array(8).fill(7).toString());
    });
    expect(t2).toBeGreaterThanOrEqual(t1 as number);
    expect(t2).toBeDefined();
  });

  it("R2-12: decay removes only stale entries, keeps active ones", async () => {
    const active = new Uint8Array(8).fill(21);
    const stale = new Uint8Array(8).fill(22);
    await admit(active, 64);
    await admit(stale, 64);
    const id = env.NBX_REGISTRY.idFromName("registry");
    const stub = env.NBX_REGISTRY.get(id);
    // 把 stale 的 rcp_at 改成 8 天前
    await runInDurableObject(stub, async (_inst, state) => {
      const k = "rcp_at:" + new Uint8Array(8).fill(22).toString();
      await state.storage.put(k, Date.now() - 8 * 86400 * 1000);
    });
    const r = await stub.fetch("https://do/decay", { method: "POST" });
    const body = await r.json() as { decayed: number };
    expect(body.decayed).toBeGreaterThanOrEqual(1);
    // active 仍在
    const activeLeft = await runInDurableObject(stub, async (_inst, state) => {
      return state.storage.get("rcp:" + new Uint8Array(8).fill(21).toString());
    });
    expect(activeLeft).toBeDefined();
  });

  it("R2-11: alarm is scheduled for decay", async () => {
    const fp = new Uint8Array(8).fill(31);
    await admit(fp, 64);
    const id = env.NBX_REGISTRY.idFromName("registry");
    const stub = env.NBX_REGISTRY.get(id);
    const alarm = await runInDurableObject(stub, async (_inst, state) => {
      return state.storage.getAlarm();
    });
    expect(alarm).not.toBeNull();
  });
});
