// Steal the VFY — policy proof untuk circuit vfy-policy (9 public signals).
// Strategy: EXTRACT 10 selama lawan punya saldo, HOLD kalau lawan habis.
import * as snarkjs from "snarkjs";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { buildPoseidon } from "circomlibjs";
import { keccak_256 } from "@noble/hashes/sha3.js";

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const WASM = new URL("../circuits/vfy-policy.wasm", import.meta.url).pathname;
const ZKEY = new URL("../circuits/vfy-policy_final.zkey", import.meta.url).pathname;
const SALT_FILE = new URL("../.strategy-salt", import.meta.url).pathname;

export const ACTION_CODE = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n };
const CIRCUIT_VERSION = "v1";
const VERSION_CODE = 1n;
const EXTRACT_CAP = 10n;
// strategyParams [10,0,0,0,0,0,0,0]: prove EXTRACT 10 while opponent has balance, HOLD at zero
const PARAMS = [10n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];

let poseidon = null;
let commitment = null;
let salt = null;

function loadSalt() {
  if (existsSync(SALT_FILE)) return BigInt("0x" + readFileSync(SALT_FILE, "utf8").trim()) % P;
  const s = BigInt("0x" + randomBytes(31).toString("hex")) % P;
  writeFileSync(SALT_FILE, s.toString(16) + "\n", { mode: 0o600 });
  return s;
}

export async function initStrategy() {
  if (commitment !== null) return commitment;
  poseidon = await buildPoseidon();
  salt = loadSalt();
  commitment = BigInt(poseidon.F.toString(poseidon([...PARAMS, salt])));
  return commitment;
}

export function getCommitment() { return commitment; }

/** Deterministic action from game state. EXTRACT at cap is never worse in the resolver matrix. */
export function chooseAction(state) {
  const opp = BigInt(state?.opponentBalance ?? 0);
  if (opp <= 0n) return { type: "HOLD" };
  return { type: "EXTRACT", amount: Number(EXTRACT_CAP) };
}

function word(v) {
  const n = BigInt(v);
  const out = new Uint8Array(32);
  let x = n;
  for (let i = 31; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}
const hex = (b) => "0x" + [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

export function publicInputsHash({ commitment, matchId, turn, selfBalance, opponentBalance, action }) {
  const fields = [
    commitment,
    "0x" + String(matchId).replace(/-/g, ""),
    turn, selfBalance, opponentBalance,
    ACTION_CODE[action.type],
    action.type === "EXTRACT" ? action.amount : 0,
    VERSION_CODE,
  ].map(word);
  const buf = new Uint8Array(fields.length * 32);
  fields.forEach((w, i) => buf.set(w, i * 32));
  return hex(keccak_256(buf));
}

/** Deterministic per-turn idempotency key: retry same turn reuses it. */
export function idempotencyKey(matchId, turn) {
  const h = keccak_256(new TextEncoder().encode(`steal-the-vfy:${matchId}:${turn}`));
  h[6] = (h[6] & 0x0f) | 0x50;
  h[8] = (h[8] & 0x3f) | 0x80;
  const s = [...h.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20, 32)}`;
}

/** Groth16 proof over the policy circuit. Returns { proof, publicSignals } or null. */
export async function provePolicy(input, budgetMs = 25000) {
  const work = snarkjs.groth16.fullProve(input, WASM, ZKEY);
  const timer = new Promise((_, rej) => setTimeout(() => rej(new Error("prove timeout")), budgetMs));
  try {
    const { proof, publicSignals } = await Promise.race([work, timer]);
    return { proof, publicSignals };
  } catch {
    return null;
  }
}

/** Build the turn response the platform expects. */
export async function buildTurnResponse(env, registeredCommitment, budgetMs = 25000) {
  const action = chooseAction(env.state);
  const matchId = env.matchId;
  const turn = env.turn;
  const selfBalance = BigInt(env.state?.selfBalance ?? 0);
  const opponentBalance = BigInt(env.state?.opponentBalance ?? 0);
  const commit = env.strategyCommitment?.hash ?? registeredCommitment ?? commitment;

  const circuitInput = {
    commitment: BigInt(commit).toString(),
    matchId: BigInt("0x" + String(matchId).replace(/-/g, "")).toString(),
    turnNumber: String(turn),
    selfBalance: selfBalance.toString(),
    opponentBalance: opponentBalance.toString(),
    action: ACTION_CODE[action.type].toString(),
    amount: action.type === "EXTRACT" ? String(action.amount) : "0",
    circuitVersion: VERSION_CODE.toString(),
    salt: salt.toString(),
    strategyParams: PARAMS.map(String),
  };

  const policyProof = { circuitVersion: CIRCUIT_VERSION };
  if (commit) {
    policyProof.publicInputsHash = publicInputsHash({
      commitment: commit, matchId, turn, selfBalance, opponentBalance, action,
    });
  }

  const proved = await provePolicy(circuitInput, budgetMs);
  if (proved) {
    policyProof.proof = proved.proof;
    policyProof.public_signals = proved.publicSignals;
  }

  return {
    protocolVersion: "v1",
    matchId,
    turn,
    // amount must be omitted entirely for HOLD/FORTIFY — the schema rejects even 0
    action: action.type === "EXTRACT" ? { type: "EXTRACT", amount: action.amount } : { type: action.type },
    policyProof,
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: idempotencyKey(matchId, turn),
  };
}

export const isVfyTurn = (b) => b && b.eventId === "steal-the-vfy" && b.matchId !== undefined && b.turn !== undefined;
