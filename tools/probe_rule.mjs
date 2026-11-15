// Probe the gatekeeper circuit rule: which decisions are provable?
import * as snarkjs from "snarkjs";
import { readFileSync } from "node:fs";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const mod = (x) => ((x % P) + P) % P;
const f = (x) => mod(BigInt(x)).toString();

const WASM = "circuits/gatekeeper.wasm";
const ZKEY = "circuits/gatekeeper_final.zkey";
const VK = JSON.parse(readFileSync("circuits/gatekeeper_vk.json", "utf8"));

const base = {
  minimum: 1000n,
  publicBalance: 1460n,
  amount: 500n,
  maxTransfer: 1000n,
  recipient: 0xde42n,
  conditionRecipient: 0xde42n,
  expiryBlock: 8430000n,
  currentBlock: 8420000n,
  registeredVkHash: 0x7dn,
  proofVkHash: 0x7dn,
};

function inputs(over, decision) {
  const b = { ...base, ...over };
  return {
    minimum: f(b.minimum),
    publicBalance: f(b.publicBalance),
    amount: f(b.amount),
    maxTransfer: f(b.maxTransfer),
    recipient: f(b.recipient),
    conditionRecipient: f(b.conditionRecipient),
    expiryBlock: f(b.expiryBlock),
    currentBlock: f(b.currentBlock),
    taskId: f("0x" + bytesToHex(keccak_256(utf8ToBytes("gk_probe_1")))),
    salt: f(123456789n),
    decision: decision === "APPROVE" ? "1" : "0",
    registeredVkHash: f(b.registeredVkHash),
    proofVkHash: f(b.proofVkHash),
  };
}

const cases = [
  ["VALID", {}, "APPROVE"],
  ["VALID_butREJECT", {}, "REJECT"],
  ["VK_SUB", { proofVkHash: 0x13n }, "REJECT"],
  ["VK_SUB_APPROVE", { proofVkHash: 0x13n }, "APPROVE"],
  ["THRESHOLD", { publicBalance: 900n }, "REJECT"],
  ["THRESHOLD_APPROVE", { publicBalance: 900n }, "APPROVE"],
  ["EXPIRED", { currentBlock: 8430000n }, "REJECT"],
  ["EXPIRED_APPROVE", { currentBlock: 8430000n }, "APPROVE"],
  ["RECIPIENT", { recipient: 0xbeefn }, "REJECT"],
  ["RECIPIENT_APPROVE", { recipient: 0xbeefn }, "APPROVE"],
  ["AMOUNT", { amount: 1001n }, "REJECT"],
  ["AMOUNT_APPROVE", { amount: 1001n }, "APPROVE"],
];

const t0 = Date.now();
for (const [name, over, decision] of cases) {
  const t = Date.now();
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs(over, decision), WASM, ZKEY);
    const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
    console.log(name.padEnd(20), decision.padEnd(8), "proofOK=" + ok, "signals=" + publicSignals.join(","), (Date.now() - t) + "ms");
  } catch (e) {
    console.log(name.padEnd(20), decision.padEnd(8), "FAIL:", String(e.message || e).slice(0, 90));
  }
}
console.log("total", Date.now() - t0, "ms");
