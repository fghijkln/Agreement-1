/**
 * NBX 中继 — Cloudflare Workers 版（Durable Object 存储）。
 *
 * 与 Python 版（nbx/relay.py）协议一致：
 *   POST /envelope      投递信封（明文头 + 加密体，服务器不解密）
 *   POST /auth          TOFU 公钥登记（pub_material(64) + ts + sig，fp 服务器计算）
 *   POST /inbox/<fp>    取信（body = ts + sig，取走即清；audit R-04 不走 URL）
 *   GET  /health        存活探测
 *
 * 存储：每页一个 Durable Object（强一致 + alarms 做 TTL 清理）。
 * 信封按接收方指纹分桶；队列上限/TTL 与 Python 版同参数。
 *
 * 端点不可见数据：正文、文件名、时间戳（全在加密体内）。
 */
import { NbxFpDurableObject, RegistryDo } from "./do";

export { NbxFpDurableObject, RegistryDo };

const TTL_MS = 7 * 86400 * 1000;        // 信封保存 7 天
const MAX_PER_FP = 256;                  // 每指纹队列上限
const MAX_ENVELOPE = 1 << 20;            // 单信封 1 MiB
const AUTH_SKEW_S = 300;                 // 时间窗 ±300s
const AUTH_INFO = "nbx-relay-auth-v1";
const DELIVERY_INFO = "nbx-relay-delivery-v2";   // R2-02: 投递签名域分隔

function b64urlEncode(buf: ArrayBuffer | Uint8Array): string {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (const c of b) s += String.fromCharCode(c);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function concat(...arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

const MAGIC_MSG = new Uint8Array([0x4e, 0x42, 0x58, 0x4d, 0x53, 0x47, 0x01, 0x00]);
const HEADER_SIZE = 48;

/** 解析明文头（nbx/message.py 48B 布局）。返回 null 表示不合法。 */
function parseHeader(blob: Uint8Array):
  { ptype: number; senderFp: Uint8Array; recvFp: Uint8Array; msgId: Uint8Array; body: Uint8Array } | null {
  if (blob.length < HEADER_SIZE) return null;
  for (let i = 0; i < 8; i++) if (blob[i] !== MAGIC_MSG[i]) return null;
  const ver = blob[8];
  if (ver !== 1) return null;
  const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  const bodyLen = dv.getUint32(44, true);
  if (blob.length !== HEADER_SIZE + bodyLen) return null;
  return {
    ptype: blob[9],
    senderFp: blob.slice(12, 20),
    recvFp: blob.slice(20, 28),
    msgId: blob.slice(28, 44),
    body: blob.slice(HEADER_SIZE),
  };
}

/** WebCrypto Ed25519 验签。 */
async function ed25519Verify(pubRaw: Uint8Array,
                             sig: Uint8Array, data: Uint8Array): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "raw", pubRaw as BufferSource,
    { name: "Ed25519" } as AlgorithmIdentifier,
    false, ["verify"]);
  return crypto.subtle.verify(
    { name: "Ed25519" } as AlgorithmIdentifier,
    key, sig as BufferSource, data as BufferSource);
}

/** 取信授权: proof = ts(8 LE) || sig(64)，sig = Ed25519_sign(AUTH_INFO || fp || ts)。 */
async function authorize(env: Env, fp: Uint8Array, proof: Uint8Array): Promise<boolean> {
  if (proof.length !== 72) return false;
  const ts = new DataView(proof.buffer, 0, 8).getBigUint64(0, true);
  const nowS = BigInt(Math.floor(Date.now() / 1000));
  if (ts > nowS + BigInt(AUTH_SKEW_S) || ts < nowS - BigInt(AUTH_SKEW_S)) return false;
  const pub = await env.NBX_FP.idFromName(b64urlEncode(fp))
  const stub = env.NBX_FP.get(pub);
  const resp = await stub.fetch("https://do/pubkey");
  if (!resp.ok) return false;             // 未登记
  const pubRaw = new Uint8Array(await resp.arrayBuffer());
  if (pubRaw.length !== 32) return false;
  const msg = concat(new TextEncoder().encode(AUTH_INFO), fp, proof.slice(0, 8));
  return ed25519Verify(pubRaw, proof.slice(8), msg);
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const json = (status: number, obj: unknown) =>
      new Response(JSON.stringify(obj), {
        status,
        headers: { "Content-Type": "application/json" },
      });

    if (url.pathname === "/health") return json(200, { ok: true });

    if (req.method === "POST" && url.pathname === "/auth") {
      // body = pub_material(64) || ts(8) || sig(64)
      // sig = Ed25519_sign(AUTH_INFO || pub_material || ts)
      // 安全（audit R-03）：fp 由服务器从 pub_material 计算，客户端不自报地址
      const body = new Uint8Array(await req.arrayBuffer());
      if (body.length !== 64 + 8 + 64) return json(400, { ok: false, error: "bad auth payload" });
      const pubMaterial = body.slice(0, 64);
      const tsBytes = body.slice(64, 72);
      const sig = body.slice(72, 136);
      const ts = new DataView(tsBytes.buffer, tsBytes.byteOffset, 8).getBigUint64(0, true);
      const nowS = BigInt(Math.floor(Date.now() / 1000));
      if (ts > nowS + BigInt(AUTH_SKEW_S) || ts < nowS - BigInt(AUTH_SKEW_S))
        return json(400, { ok: false, error: "timestamp out of window" });
      const edPub = pubMaterial.slice(32, 64);
      const ok = await ed25519Verify(
        edPub, sig,
        concat(new TextEncoder().encode(AUTH_INFO), pubMaterial, tsBytes));
      if (!ok) return json(403, { ok: false, error: "bad signature" });
      const fp = new Uint8Array(
        await crypto.subtle.digest("SHA-256", pubMaterial as BufferSource)).slice(0, 8);
      // audit R-10: 全局登记闸门 —— 无限造身份会创建无限 DO 实例。
      // REGISTRY DO（单例 idFromName("registry")）对新 fp 做计数上限；
      // 已登记的 fp 重放 AUTH 不占新名额（fp 已在 set 里则直接放行）。
      {
        const regStub = env.NBX_REGISTRY.get(env.NBX_REGISTRY.idFromName("registry"));
        const regResp = await regStub.fetch("https://registry/claim", {
          method: "POST", body: b64urlEncode(fp),
        });
        if (!regResp.ok) return json(429, { ok: false, error: "registration quota exhausted" });
      }
      // audit R2-01: 中继身份证明 —— 向 RegistryDo（单例，持有中继签名密钥）
      // 请求对 (client_fp, ts) 的签名，随 relay_pub 一并返回。客户端
      // TOFU-pin relay_pub 后可密码学认证"对面确实是这台中继"。
      let relayPubB64 = "", relaySigB64 = "";
      {
        const regStub = env.NBX_REGISTRY.get(env.NBX_REGISTRY.idFromName("registry"));
        const idResp = await regStub.fetch("https://registry/relay_sign", {
          method: "POST",
          body: concat(fp, tsBytes.slice(0)) as BodyInit,
        });
        if (idResp.ok) {
          const idObj = await idResp.json() as { relay_pub: string; relay_sig: string };
          relayPubB64 = idObj.relay_pub;
          relaySigB64 = idObj.relay_sig;
        }
      }
      const id = env.NBX_FP.idFromName(b64urlEncode(fp));
      const stub = env.NBX_FP.get(id);
      const resp = await stub.fetch("https://do/pubkey", {
        method: "PUT", body: edPub as BodyInit,
      });
      if (resp.status === 409) return json(409, { ok: false, error: "fingerprint already bound to another key" });
      return json(200, { ok: true, fp: b64urlEncode(fp),
                         relay_pub: relayPubB64, relay_sig: relaySigB64 });
    }

    if (req.method === "POST" && url.pathname === "/envelope") {
      // audit R-06：信封末尾必须附投递签名 (ts(8)+sig(64))，
      // sig = Ed25519_sign(AUTH_INFO || 明文头(48B) || ts)，发送者须先 AUTH 登记。
      // 否则任何知道 recv_fp 的人都能匿名灌满队列挤掉合法消息。
      const body = new Uint8Array(await req.arrayBuffer());
      if (body.length > MAX_ENVELOPE) return json(400, { ok: false, error: "envelope too large" });
      if (body.length < 48 + 72) return json(400, { ok: false, error: "missing sender proof" });
      const envLen = body.length - 72;
      const hdr = parseHeader(body.slice(0, envLen));
      if (!hdr) return json(400, { ok: false, error: "bad envelope" });
      if (hdr.ptype === 0) return json(400, { ok: false, error: "invalid ptype" });
      if (b64urlEncode(hdr.senderFp) === b64urlEncode(hdr.recvFp))
        return json(400, { ok: false, error: "self-addressed" });
      // R-06 + R2-02: 验证发送者签名（发送者须已 AUTH 登记）。
      // R2-02: 签名绑定完整信封 SHA256(头+密文) —— 只签 header 时可被
      // 拿合法 proof 换掉密文再投（绕过去重 + 毁掉合法消息）。
      {
        const senderFpB64 = b64urlEncode(hdr.senderFp);
        const senderId = env.NBX_FP.idFromName(senderFpB64);
        const senderStub = env.NBX_FP.get(senderId);
        const pubResp = await senderStub.fetch("https://do/pubkey");
        if (!pubResp.ok) return json(403, { ok: false, error: "sender not registered (auth first)" });
        const senderEd = new Uint8Array(await pubResp.arrayBuffer());
        if (senderEd.length !== 32) return json(403, { ok: false, error: "sender not registered" });
        const tsBytes = body.slice(envLen, envLen + 8);
        const sigBytes = body.slice(envLen + 8);
        const ts = new DataView(tsBytes.buffer, tsBytes.byteOffset, 8).getBigUint64(0, true);
        const nowS = BigInt(Math.floor(Date.now() / 1000));
        if (ts > nowS + BigInt(AUTH_SKEW_S) || ts < nowS - BigInt(AUTH_SKEW_S))
          return json(403, { ok: false, error: "sender proof timestamp out of window" });
        const envDigest = new Uint8Array(
          await crypto.subtle.digest("SHA-256", body.slice(0, envLen) as BufferSource));
        const msgBytes = concat(new TextEncoder().encode(DELIVERY_INFO), envDigest, tsBytes);
        if (!await ed25519Verify(senderEd, sigBytes, msgBytes))
          return json(403, { ok: false, error: "bad sender proof" });
        // audit R-10: per-sender 投递配额 —— 认证发送者也不能高频灌信封
        const quotaResp = await senderStub.fetch("https://do/send_quota", { method: "POST" });
        if (!quotaResp.ok) return json(429, { ok: false, error: "sender quota exceeded" });
      }
      // audit R2-08: 收件人维度准入 —— sender quota 限速不限规模，
      // 伪造 recv_fp 可无限建 DO。入队前过 RegistryDo 的收件人/字节预算。
      {
        const admit = new Uint8Array(12);
        admit.set(hdr.recvFp, 0);
        new DataView(admit.buffer).setUint32(8, envLen, true);
        const regStub = env.NBX_REGISTRY.get(env.NBX_REGISTRY.idFromName("registry"));
        const admitResp = await regStub.fetch("https://do/recipient_admit", {
          method: "POST", body: admit as BodyInit,
        });
        if (!admitResp.ok) {
          const err = await admitResp.json() as { error?: string };
          return json(429, { ok: false, error: err.error ?? "recipient admission denied" });
        }
      }
      // 入队存裸信封（不带投递签名后缀），收件方无需感知。
      // audit R2-13: admit 与 push 是两个成功点, 必须事务性对齐——
      // push 失败要退掉 admit 刚记的账; push 的队列淘汰(eviction)
      // 也要按被淘汰字节数退账, 否则 Registry 账本虚胀(phantom
      // accounting), 可被反复投递满队列收件人吃空全局预算。
      const id = env.NBX_FP.idFromName(b64urlEncode(hdr.recvFp));
      const stub = env.NBX_FP.get(id);
      const resp = await stub.fetch("https://do/push", {
        method: "POST", body: body.slice(0, envLen) as BodyInit,
      });
      const pushPayload = await resp.json() as { ok?: boolean; evicted_bytes?: number };
      const regStub = env.NBX_REGISTRY.get(env.NBX_REGISTRY.idFromName("registry"));
      if (resp.status === 202 && pushPayload.ok) {
        const evicted = pushPayload.evicted_bytes ?? 0;
        if (evicted > 0) {
          const rel = new Uint8Array(12);
          rel.set(hdr.recvFp, 0);
          new DataView(rel.buffer).setUint32(8, evicted, true);
          await regStub.fetch("https://do/recipient_release", {
            method: "POST", body: rel as BodyInit,
          });
        }
      } else {
        // push 失败: 退掉 admit 记入的账(补偿事务), 不留残留。
        const rel = new Uint8Array(12);
        rel.set(hdr.recvFp, 0);
        new DataView(rel.buffer).setUint32(8, envLen, true);
        await regStub.fetch("https://do/recipient_release", {
          method: "POST", body: rel as BodyInit,
        });
        return json(400, { ok: false, error: "enqueue failed" });
      }
      return json(202, pushPayload);
    }

    if (req.method === "POST" && url.pathname.startsWith("/inbox/")) {
      // 安全（audit R-04）：proof 走 POST body，不进 URL/访问日志。
      // body = ts(8 LE) || sig(64)，sig = Ed25519_sign(AUTH_INFO || fp || ts)
      const fpB64 = url.pathname.slice("/inbox/".length);
      const body = new Uint8Array(await req.arrayBuffer());
      if (body.length !== 72) return json(400, { ok: false, error: "bad proof payload" });
      const ts = new DataView(body.buffer, body.byteOffset, 8).getBigUint64(0, true);
      const nowS = BigInt(Math.floor(Date.now() / 1000));
      if (ts > nowS + BigInt(AUTH_SKEW_S) || ts < nowS - BigInt(AUTH_SKEW_S))
        return json(403, { ok: false, error: "timestamp out of window" });
      let fp: Uint8Array;
      try {
        fp = b64urlDecode(fpB64);
      } catch {
        return json(400, { ok: false, error: "bad request" });
      }
      if (fp.length !== 8) return json(400, { ok: false, error: "bad request" });
      if (!await authorize(env, fp, body)) return json(403, { ok: false, error: "unauthorized" });
      const id = env.NBX_FP.idFromName(fpB64);
      const stub = env.NBX_FP.get(id);
      const resp = await stub.fetch("https://do/pop");
      const payload = await resp.json() as { ok: boolean; envelopes?: string[]; popped_bytes?: number };
      // audit R2-08: pop 走信封后归还字节账（信封离开队列）。
      // audit R2-13: 退账口径 = DO 端精确统计的原始字节数(popped_bytes),
      // 与 admit/eviction 记账口径一致。
      // audit R2-14: 计算 popped_bytes(fallback, 仅兼容旧 DO 格式)与
      // 释放账本是两件独立的事, 必须拆开——此前 release 被错误地包进
      // "popped_bytes === undefined" 分支, 而新 DO 恒返回 popped_bytes,
      // 生产 /inbox 取信路径永远不退账(total_bytes/recip_count 永久
      // 泄漏)。现在: 无论 popped_bytes 来自 DO 还是 fallback, 只要
      // >0 就必须 release。
      if (payload.popped_bytes === undefined && payload.envelopes) {
        let freed = 0;
        for (const e of payload.envelopes) freed += Math.floor(e.length * 3 / 4);
        payload.popped_bytes = freed;
      }
      if ((payload.popped_bytes ?? 0) > 0) {
        const rel = new Uint8Array(12);
        rel.set(fp, 0);
        new DataView(rel.buffer).setUint32(8, payload.popped_bytes!, true);
        const regStub = env.NBX_REGISTRY.get(env.NBX_REGISTRY.idFromName("registry"));
        await regStub.fetch("https://do/recipient_release", {
          method: "POST", body: rel as BodyInit,
        });
      }
      return json(200, payload);
    }

    return json(404, { ok: false, error: "not found" });
  },
};

export interface Env {
  NBX_FP: DurableObjectNamespace;
  NBX_REGISTRY: DurableObjectNamespace;   // audit R-10: 全局登记闸门
}
