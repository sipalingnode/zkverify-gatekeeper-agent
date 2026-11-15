// Oracle instan: getInputSignalSize(hMSB,hLSB) dengan fnvHash 64-bit yang benar.
import fs from "fs";

const buf = fs.readFileSync("circuits/vfy-policy.wasm");
const mod = await WebAssembly.compile(buf);
const inst = await WebAssembly.instantiate(mod, {
  runtime: {
    exceptionHandler: () => {},
    printErrorMessage: () => {},
    writeBufferMessage: () => {},
    showSharedRWMemory: () => {},
  },
});
const e = inst.exports;
e.init(1);

const U64 = BigInt(2) ** BigInt(64);

export function fnvHash(str) {
  let hash = BigInt("0xCBF29CE484222325");
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str.charCodeAt(i));
    hash *= BigInt(0x100000001B3);
    hash %= U64;
  }
  let s = hash.toString(16);
  s = "0".repeat(16 - s.length) + s;
  return s;
}

export function sizeOf(name) {
  const h = fnvHash(name);
  const hMSB = parseInt(h.slice(0, 8), 16);
  const hLSB = parseInt(h.slice(8, 16), 16);
  try {
    return e.getInputSignalSize(hMSB, hLSB);
  } catch {
    return -1;
  }
}

console.log("getInputSize", e.getInputSize());
console.log("commitment:", sizeOf("commitment"), "| salt:", sizeOf("salt"), "| bogus:", sizeOf("zzz_bogus"));
