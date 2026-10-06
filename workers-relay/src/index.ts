/**
 * NBX 中继 — Cloudflare Workers 版（Durable Object 存储）。
 *
 * 与 Python 版（nbx/relay.py）协议一致：
 *   POST /envelope      投递信封（明文头 + 加密体，服务器不解密）
 *   POST /auth          TOFU 公钥登记（fp + ts + ed_pub + sig）
 *   GET  /inbox/<fp>    取信（?proof= ts+sig，取走即清）
 *   GET  /health        存活探测
 *
 * 存储：每页一个 Durable Object（强一致 + alarms 做 TTL 清理）。
 * 信封按接收方指纹分桶；队列上限/TTL 与 Python 版同参数。
 *
 * 端点不可见数据：正文、文件名、时间戳（全在加密体内）。
 */
import { NbxFpDurableObject } from "./do";

export { NbxFpDurableObject };

const TTL_MS = 7 * 86400 * 1000;        // 信封保存 7 天
const MAX_PER_FP = 256;                  // 每指纹队列上限
const MAX_ENVELOPE = 1 << 20;            // 单信封 1 MiB
const AUTH_SKEW_S = 300;                 // 时间窗 ±300s
const AUTH_INFO = "nbx-relay-auth-v1";

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
      const body = new Uint8Array(await req.arrayBuffer());
      if (body.length !== 8 + 8 + 32 + 64) return json(400, { ok: false, error: "bad auth payload" });
      const fp = body.slice(0, 8);
      const tsBytes = body.slice(8, 16);
      const pubRaw = body.slice(16, 48);
      const sig = body.slice(48, 112);
      const ts = new DataView(tsBytes.buffer, 0, 8).getBigUint64(0, true);
      const nowS = BigInt(Math.floor(Date.now() / 1000));
      if (ts > nowS + BigInt(AUTH_SKEW_S) || ts < nowS - BigInt(AUTH_SKEW_S))
        return json(400, { ok: false, error: "timestamp out of window" });
      const ok = await ed25519Verify(
        pubRaw, sig,
        concat(new TextEncoder().encode(AUTH_INFO), fp, tsBytes));
      if (!ok) return json(403, { ok: false, error: "bad signature" });
      const id = env.NBX_FP.idFromName(b64urlEncode(fp));
      const stub = env.NBX_FP.get(id);
      const resp = await stub.fetch("https://do/pubkey", {
        method: "PUT", body: pubRaw as BodyInit,
      });
      if (resp.status === 409) return json(409, { ok: false, error: "fingerprint already bound to another key" });
      return json(200, { ok: true });
    }

    if (req.method === "POST" && url.pathname === "/envelope") {
      const body = new Uint8Array(await req.arrayBuffer());
      if (body.length > MAX_ENVELOPE) return json(400, { ok: false, error: "envelope too large" });
      const hdr = parseHeader(body);
      if (!hdr) return json(400, { ok: false, error: "bad envelope" });
      if (hdr.ptype === 0) return json(400, { ok: false, error: "invalid ptype" });
      if (b64urlEncode(hdr.senderFp) === b64urlEncode(hdr.recvFp))
        return json(400, { ok: false, error: "self-addressed" });
      const id = env.NBX_FP.idFromName(b64urlEncode(hdr.recvFp));
      const stub = env.NBX_FP.get(id);
      const resp = await stub.fetch("https://do/push", {
        method: "POST", body: body as BodyInit,
      });
      return json(resp.status === 202 ? 202 : 400, await resp.json());
    }

    if (req.method === "GET" && url.pathname.startsWith("/inbox/")) {
      const fpB64 = url.pathname.slice("/inbox/".length);
      const proofB64 = url.searchParams.get("proof") ?? "";
      let fp: Uint8Array, proof: Uint8Array;
      try {
        fp = b64urlDecode(fpB64);
        proof = proofB64 ? b64urlDecode(proofB64) : new Uint8Array(0);
      } catch {
        return json(400, { ok: false, error: "bad request" });
      }
      if (fp.length !== 8) return json(400, { ok: false, error: "bad request" });
      if (!await authorize(env, fp, proof)) return json(403, { ok: false, error: "unauthorized" });
      const id = env.NBX_FP.idFromName(fpB64);
      const stub = env.NBX_FP.get(id);
      const resp = await stub.fetch("https://do/pop");
      return json(200, await resp.json());
    }

    return json(404, { ok: false, error: "not found" });
  },
};

export interface Env {
  NBX_FP: DurableObjectNamespace;
}
