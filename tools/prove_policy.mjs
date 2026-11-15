// Tes lengkap circuit vfy-policy: witness + Groth16 proof + cek public signals.
import * as snarkjs from "snarkjs";
import { readFileSync, writeFileSync } from "node:fs";
import { buildPoseidon } from "circomlibjs";

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const WASM = "circuits/vfy-policy.wasm";
const ZKEY = "circuits/vfy-policy_final.zkey";

// strategy: EXTRACT 10 whenever opponent has balance, HOLD at zero
const params = [10n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
const salt = BigInt("0x" + readFileSync(".strategy-salt", "utf8").trim()) % P;

const poseidon = await buildPoseidon();
const commitment = BigInt(poseidon.F.toString(poseidon([...params, salt])));
console.log("commitment:", commitment.toString());

const matchId = "0x" + "9f4e1b2a".repeat(8);
const input = {
  commitment: commitment.toString(),
  matchId: BigInt(matchId).toString(),
  turnNumber: "3",
  selfBalance: "95",
  opponentBalance: "105",
  action: "2",        // EXTRACT
  amount: "10",
  circuitVersion: "1",
  salt: salt.toString(),
  strategyParams: params.map(String),
};

try {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  console.log("PROOF OK, publicSignals:", publicSignals.length);
  console.log(JSON.stringify(publicSignals, null, 1));
  writeFileSync("/tmp/vfy_proof.json", JSON.stringify({ proof, publicSignals }, null, 1));

  const vk = JSON.parse(readFileSync("circuits/vfy_vk.json", "utf8"));
  const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
  console.log("VERIFY:", ok);
} catch (err) {
  console.log("FAIL:", String(err.message || err).slice(0, 500));
}
