// zkVerify Agent Games — Proof Gatekeeper agent.
// Public HTTPS endpoint. The platform POSTs HMAC-signed tasks; this service
// verifies the signature over the RAW body, decides deterministically, and
// answers with a locally generated Groth16 proof + public signals, signed back.
import { createServer } from "node:http";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PORT = Number(process.env.PORT || 8787);
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const TASK_ID_ENCODING = process.env.TASK_ID_ENCODING || "keccak";
const DATA_DIR = process.env.DATA_DIR || join(ROOT, "data");
const WASM = join(ROOT, "circuits", "gatekeeper.wasm");
const ZKEY = join(ROOT, "circuits", "gatekeeper_final.zkey");
const VKLOCAL = JSON.parse(readFileSync(join(ROOT, "circuits", "gatekeeper_vk.json"), "utf8"));

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const mod = (x) => ((x % P) + P) % P;
const fld = (x) => mod(BigInt(x)).toString();

const SIG = "x-agent-games-signature";
const R = {
  VALID: "VALID_CONDITION",
  REUSED: "PROOF_REUSED",
  VK: "VK_SUBSTITUTION",
  THRESHOLD: "THRESHOLD_MISMATCH",
  EXPIRED: "EXPIRED_CONDITION",
  RECIPIENT: "RECIPIENT_MISMATCH",
  OVERFLOW: "AMOUNT_OVERFLOW",
  MALFORMED: "PUBLIC_INPUT_MISMATCH",
};

// ---------- HMAC ----------
const KEYS = (() => {
  if (!SECRET) return [];
  const out = [Buffer.from(SECRET, "utf8")];
  if (/^[0-9a-fA-F]{64}$/.test(SECRET.trim())) out.push(Buffer.from(SECRET.trim(), "hex"));
  return out;
})();
const sign = (key, body) => createHmac("sha256", key).update(body).digest("hex");
function checkSig(raw, header) {
  if (!header || KEYS.length === 0) return null;
  const given = String(header).trim().replace(/^sha256=/i, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(given)) return null;
  const want = Buffer.from(given, "hex");
  for (const k of KEYS) {
    const got = Buffer.from(sign(k, raw), "hex");
    if (got.length === want.length && timingSafeEqual(got, want)) return k;
  }
  return null;
}

// ---------- state ----------
mkdirSync(DATA_DIR, { recursive: true });
const STORE = join(DATA_DIR, "store.json");
let store = { tasks: {}, seen: { practice: [], competition: [] } };
if (existsSync(STORE)) {
  try { store = JSON.parse(readFileSync(STORE, "utf8")); } catch { /* fresh */ }
}
store.tasks ??= {};
store.seen ??= { practice: [], competition: [] };
store.seen.practice ??= [];
store.seen.competition ??= [];
const seen = { practice: new Set(store.seen.practice), competition: new Set(store.seen.competition) };
function save() {
  store.seen = { practice: [...seen.practice], competition: [...seen.competition] };
  const tmp = STORE + ".tmp";
  writeFileSync(tmp, JSON.stringify(store));
  renameSync(tmp, STORE);
}

// ---------- parse ----------
const DEC = /^[0-9]+$/;
const HEX = /^(0x)?[0-9a-fA-F]+$/;
function u(v) {
  if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
  if (typeof v === "string" && DEC.test(v.trim())) return BigInt(v.trim());
  throw new Error("bad uint");
}
function h(v) {
  if (typeof v === "string" && HEX.test(v.trim())) {
    const s = v.trim();
    return BigInt(s.startsWith("0x") || s.startsWith("0X") ? s : "0x" + s);
  }
  throw new Error("bad hex");
}
function parseTask(input) {
  if (!input || typeof input !== "object") throw new Error("no input");
  if (typeof input.proof_tx !== "string" || !input.proof_tx.trim()) throw new Error("no proof_tx");
  return {
    registeredVk: h(input.registered_vk),
    proofVk: h(input.proof_vk),
    minimum: u(input.minimum),
    publicBalance: u(input.public_balance),
    expiryBlock: u(input.expiry_block),
    currentBlock: u(input.current_block),
    recipient: h(input.recipient),
    conditionRecipient: h(input.condition_recipient),
    amount: u(input.amount),
    maxTransfer: u(input.max_transfer),
    proofTx: input.proof_tx.trim(),
  };
}

// ---------- decision (documented order, fail closed) ----------
function decide(t, alreadySeen) {
  if (alreadySeen) return ["REJECT", R.REUSED];
  if (t.proofVk !== t.registeredVk) return ["REJECT", R.VK];
  if (t.publicBalance < t.minimum) return ["REJECT", R.THRESHOLD];
  if (t.currentBlock >= t.expiryBlock) return ["REJECT", R.EXPIRED];
  if (t.recipient !== t.conditionRecipient) return ["REJECT", R.RECIPIENT];
  if (t.amount > t.maxTransfer) return ["REJECT", R.OVERFLOW];
  return ["APPROVE", R.VALID];
}

// ---------- proving ----------
function taskIdSignal(taskId) {
  switch (TASK_ID_ENCODING) {
    case "sha256": return fld("0x" + bytesToHex(sha256(utf8ToBytes(taskId))));
    case "ascii": return fld("0x" + bytesToHex(utf8ToBytes(taskId)));
    case "hex-digits": {
      const d = taskId.replace(/^gk_/, "").replace(/[^0-9a-fA-F]/g, "");
      return d === "" ? "0" : fld("0x" + d);
    }
    default: return fld("0x" + bytesToHex(keccak_256(utf8ToBytes(taskId))));
  }
}
function circuitInputs(t, taskId, decision, salt) {
  return {
    minimum: fld(t.minimum),
    publicBalance: fld(t.publicBalance),
    amount: fld(t.amount),
    maxTransfer: fld(t.maxTransfer),
    recipient: fld(t.recipient),
    conditionRecipient: fld(t.conditionRecipient),
    expiryBlock: fld(t.expiryBlock),
    currentBlock: fld(t.currentBlock),
    taskId: taskIdSignal(taskId),
    salt: fld(salt),
    decision: decision === "APPROVE" ? "1" : "0",
    registeredVkHash: fld(t.registeredVk),
    proofVkHash: fld(t.proofVk),
  };
}
async function prove(inputs, budgetMs) {
  let timer;
  try {
    const timeout = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error("prove timeout")), budgetMs); });
    const res = await Promise.race([snarkjs.groth16.fullProve(inputs, WASM, ZKEY), timeout]);
    const ok = await snarkjs.groth16.verify(VKLOCAL, res.publicSignals, res.proof);
    if (!ok) return null;
    return res;
  } catch {
    return null;
  } finally { clearTimeout(timer); }
}

// ---------- tasks ----------
const inFlight = new Map();
async function handleTask(env) {
  const taskId = typeof env.task_id === "string" ? env.task_id : null;
  if (!taskId) return JSON.stringify({ decision: "REJECT", reason_code: R.MALFORMED });
  if (inFlight.has(taskId)) return inFlight.get(taskId);
  const work = answer(taskId, env).finally(() => inFlight.delete(taskId));
  inFlight.set(taskId, work);
  return work;
}

async function answer(taskId, env) {
  const mode = env.mode === "competition" ? "competition" : "practice";
  const cached = store.tasks[taskId];
  if (cached?.responseBody) {
    log({ ev: "task.retry", taskId, decision: cached.decision });
    return cached.responseBody;
  }
  let t = null;
  try { t = parseTask(env.input); } catch { t = null; }
  if (!t) {
    const body = JSON.stringify({ decision: "REJECT", reason_code: R.MALFORMED });
    store.tasks[taskId] = { responseBody: body, decision: "REJECT", mode };
    save();
    return body;
  }
  const refKey = t.proofTx.toLowerCase();
  const alreadySeen = seen[mode].has(refKey);
  const [decision, reason] = decide(t, alreadySeen);
  const salt = cached?.salt || BigInt("0x" + randomBytes(31).toString("hex")).toString();
  const body = { decision, reason_code: reason };

  // The circuit only admits REJECT when one of its 5 checks fails, so a
  // PROOF_REUSED rejection (out-of-circuit check) cannot carry a proof.
  if (reason !== R.REUSED) {
    const deadline = Date.parse(env.deadline_at || "");
    const budget = Number.isNaN(deadline) ? 20000 : Math.max(0, Math.min(20000, deadline - Date.now() - 1500));
    if (budget > 500) {
      const t0 = Date.now();
      const proved = await prove(circuitInputs(t, taskId, decision, salt), budget);
      if (proved) {
        body.proof = proved.proof;
        body.public_signals = proved.publicSignals;
        log({ ev: "task.proved", taskId, ms: Date.now() - t0 });
      } else {
        log({ ev: "task.prove_failed", taskId, decision, reason });
      }
    }
  }
  body.proof_tx = t.proofTx;
  const responseBody = JSON.stringify(body);
  if (decision === "APPROVE") seen[mode].add(refKey);
  store.tasks[taskId] = { responseBody, decision, mode, salt };
  save();
  log({ ev: "task.answered", taskId, mode, decision, reason, proof: "proof" in body });
  return responseBody;
}

function log(o) { console.log(JSON.stringify(o)); }

// ---------- http ----------
function send(res, code, body, key) {
  const headers = { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) };
  if (key) headers[SIG] = sign(key, body);
  res.writeHead(code, headers).end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => { size += c.length; if (size <= 1_000_000) chunks.push(c); });
    req.on("end", () => resolve(size > 1_000_000 ? null : Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

const server = createServer(async (req, res) => {
  try {
    if (req.method === "GET" || req.method === "HEAD") {
      return send(res, 200, JSON.stringify({ ok: true, service: "proof-gatekeeper", version: "v1" }));
    }
    if (req.method !== "POST") return send(res, 405, JSON.stringify({ error: "method not allowed" }));
    const raw = await readBody(req);
    if (raw === null) return send(res, 413, JSON.stringify({ error: "body too large" }));
    const key = checkSig(raw, req.headers[SIG]);
    if (!key) {
      log({ ev: "request.unauthorized", path: req.url, bytes: raw.length });
      return send(res, 401, JSON.stringify({ error: "invalid signature" }));
    }
    let env;
    try { env = JSON.parse(raw.toString("utf8")); } catch { return send(res, 400, JSON.stringify({ error: "invalid json" }), key); }
    if (env?.type === "agent-games.preflight.v1") {
      log({ ev: "preflight", agentId: env.agent_id });
      return send(res, 200, JSON.stringify({ ok: true, protocolVersion: "v1" }), key);
    }
    if (env?.type === "agent-games.proof-gatekeeper.v1") {
      return send(res, 200, await handleTask(env), key);
    }
    log({ ev: "request.unknown_type", type: env?.type });
    return send(res, 400, JSON.stringify({ error: "unknown type" }), key);
  } catch (e) {
    log({ ev: "request.error", error: String(e?.message || e) });
    if (!res.headersSent) send(res, 500, JSON.stringify({ error: "internal error" }));
  }
});

// warm the circuit so the first real task is fast
const warm = async () => {
  const t0 = Date.now();
  const r = await prove(circuitInputs({ minimum: 1000n, publicBalance: 1460n, amount: 500n, maxTransfer: 1000n, recipient: 1n, conditionRecipient: 1n, expiryBlock: 100n, currentBlock: 1n, registeredVk: 7n, proofVk: 7n }, "gk_warm", "APPROVE", 42n), 60000);
  log({ ev: "circuit.warm", ok: !!r, ms: Date.now() - t0 });
};

server.listen(PORT, () => {
  log({ ev: "server.listening", port: PORT, taskIdEncoding: TASK_ID_ENCODING, hmacConfigured: KEYS.length > 0 });
  warm();
});
