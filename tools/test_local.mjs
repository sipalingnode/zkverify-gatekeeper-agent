// Local test harness: replays signed envelopes against the running agent.
// Usage: node tools/test_local.mjs <base_url> [hmac_secret]
import { createHmac } from "node:crypto";

const BASE = process.argv[2] || "http://127.0.0.1:8787";
const SECRET = process.argv[3] || process.env.AGENT_GAMES_HMAC_SECRET || "test-secret-123";
const KEY = Buffer.from(SECRET, "utf8");

const H = (body) => createHmac("sha256", KEY).update(body).digest("hex");

async function post(obj) {
  const body = JSON.stringify(obj);
  const r = await fetch(BASE, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": H(body) },
    body,
  });
  const text = await r.text();
  const sig = r.headers.get("x-agent-games-signature");
  const sigOK = sig === H(text);
  return { code: r.status, sigOK, body: text, json: (() => { try { return JSON.parse(text); } catch { return null; } })() };
}

const now = Date.now();
const iso = (ms) => new Date(ms).toISOString();
const deadline = iso(now + 60000);

const baseInput = {
  registered_vk: "0x7d3a00000000000000000000000000000000000000000000000000000000f291",
  proof_vk: "0x7d3a00000000000000000000000000000000000000000000000000000000f291",
  minimum: "1000",
  public_balance: "1460",
  expiry_block: 8430000,
  current_block: 8420000,
  recipient: "0xDe42000000000000000000000000000000000001",
  condition_recipient: "0xDe42000000000000000000000000000000000001",
  amount: "500",
  max_transfer: "1000",
  proof_tx: "0xa80000000000000000000000000000000000000000000000000000000000002c",
};

const cases = [
  ["preflight", { type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: iso(now), nonce: "abc123" }],
  ["valid", { type: "agent-games.proof-gatekeeper.v1", task_id: "gk_t1", mode: "practice", issued_at: iso(now), deadline_at: deadline, input: baseInput }],
  ["vk_sub", { type: "agent-games.proof-gatekeeper.v1", task_id: "gk_t2", mode: "practice", issued_at: iso(now), deadline_at: deadline, input: { ...baseInput, proof_vk: "0x13aa0000000000000000000000000000000000000000000000000000000000aa", proof_tx: "0xbb01" } }],
  ["threshold", { type: "agent-games.proof-gatekeeper.v1", task_id: "gk_t3", mode: "practice", issued_at: iso(now), deadline_at: deadline, input: { ...baseInput, public_balance: "900", proof_tx: "0xbb02" } }],
  ["expired", { type: "agent-games.proof-gatekeeper.v1", task_id: "gk_t4", mode: "practice", issued_at: iso(now), deadline_at: deadline, input: { ...baseInput, current_block: 8430000, proof_tx: "0xbb03" } }],
  ["recipient", { type: "agent-games.proof-gatekeeper.v1", task_id: "gk_t5", mode: "practice", issued_at: iso(now), deadline_at: deadline, input: { ...baseInput, recipient: "0xBeef000000000000000000000000000000000002", proof_tx: "0xbb04" } }],
  ["overflow", { type: "agent-games.proof-gatekeeper.v1", task_id: "gk_t6", mode: "practice", issued_at: iso(now), deadline_at: deadline, input: { ...baseInput, amount: "1001", proof_tx: "0xbb05" } }],
  ["reused", { type: "agent-games.proof-gatekeeper.v1", task_id: "gk_t7", mode: "practice", issued_at: iso(now), deadline_at: deadline, input: baseInput }],
];

for (const [name, obj] of cases) {
  const t0 = Date.now();
  const r = await post(obj);
  const j = r.json || {};
  console.log(
    name.padEnd(10),
    String(r.code).padEnd(4),
    "sig=" + (r.sigOK ? "ok" : "BAD"),
    "decision=" + (j.decision ?? j.ok),
    "reason=" + (j.reason_code ?? j.protocolVersion ?? "-"),
    "proof=" + (j.proof ? "yes" : "no"),
    "signals=" + (Array.isArray(j.public_signals) ? j.public_signals.length : 0),
    (Date.now() - t0) + "ms"
  );
}

// bad signature must be rejected
const bad = await fetch(BASE, { method: "POST", headers: { "content-type": "application/json", "x-agent-games-signature": "0".repeat(64) }, body: "{}" });
console.log("badsig".padEnd(10), bad.status, "(expect 401)");
