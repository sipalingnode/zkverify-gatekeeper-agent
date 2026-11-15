// Tes turn Steal the VFY: kirim envelope ter-sign ke agent lokal.
import { createHmac, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";

const BASE = process.argv[2] || "http://127.0.0.1:8787/agent";
const SECRET = (process.env.AGENT_GAMES_HMAC_SECRET || readFileSync(".env", "utf8").match(/AGENT_GAMES_HMAC_SECRET=(.+)/)[1]).trim();

const body = {
  protocolVersion: "v1",
  eventId: "steal-the-vfy",
  mode: "practice",
  matchId: randomUUID(),
  turn: 1,
  issuedAt: new Date().toISOString(),
  deadlineAt: new Date(Date.now() + 30000).toISOString(),
  state: { selfBalance: "95", opponentBalance: "105", selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
  resolverVersion: "v1",
  nonce: randomUUID(),
};

const raw = JSON.stringify(body);
const sig = createHmac("sha256", SECRET).update(raw).digest("hex");

const r = await fetch(BASE, {
  method: "POST",
  headers: { "content-type": "application/json", "x-agent-games-signature": sig },
  body: raw,
});
const text = await r.text();
console.log("status", r.status);
try {
  const j = JSON.parse(text);
  console.log(JSON.stringify({
    action: j.action,
    circuitVersion: j.policyProof?.circuitVersion,
    hasProof: !!j.policyProof?.proof,
    publicSignals: j.policyProof?.public_signals?.length,
    publicInputsHashMatch: !!j.policyProof?.publicInputsHash,
    idempotencyKey: j.idempotencyKey,
    respSig: !!r.headers.get("x-agent-games-signature"),
  }, null, 1));
} catch { console.log(text.slice(0, 400)); }
