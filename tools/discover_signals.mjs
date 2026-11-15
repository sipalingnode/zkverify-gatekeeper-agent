import fs from "fs";
const buf = fs.readFileSync("circuits/vfy-policy.wasm");
const mod = await WebAssembly.compile(buf);
const inst = await WebAssembly.instantiate(mod, {
  runtime: { exceptionHandler: () => {}, printErrorMessage: () => {}, writeBufferMessage: () => {}, showSharedRWMemory: () => {} },
});
const e = inst.exports; e.init(1);
const U64 = BigInt(2) ** BigInt(64);
function fnvHash(str) {
  let h = BigInt("0xCBF29CE484222325");
  for (let i = 0; i < str.length; i++) { h ^= BigInt(str.charCodeAt(i)); h *= BigInt(0x100000001B3); h %= U64; }
  let s = h.toString(16); return "0".repeat(16 - s.length) + s;
}
function sizeOf(n) {
  const h = fnvHash(n);
  try { return e.getInputSignalSize(parseInt(h.slice(0,8),16), parseInt(h.slice(8,16),16)); } catch { return -1; }
}

const bases = ["strategy","policy","params","strategyParams","policyParams","paramsStrategy",
  "rules","rule","plan","plays","playbook","config","settings","weights","weight","thresholds",
  "paramsArr","paramArr","strategyArr","policyArr","strategyVec","values","vals","limits","caps","bounds"];
const suffix = ["", "s", "Arr", "Array", "Vec", "List", "Values", "Params"];
const cands = new Set();
for (const b of bases) {
  for (const s of suffix) cands.add(b + s);
  cands.add(b.charAt(0).toUpperCase() + b.slice(1));
}
for (const w of `strategy_params policy_params strategyParameters policyParameters
strategyParamsHash paramsHash strategyHash policyHash
configParams ruleParams
`.trim().split(/\s+/)) cands.add(w);

const out = {};
for (const c of [...cands]) { const n = sizeOf(c); if (n > 0) out[c] = n; }
console.log("FOUND:", JSON.stringify(out, null, 1));
