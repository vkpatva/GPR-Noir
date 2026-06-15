// verify.ts -- bb verify + decode the disclosed fields directly from public_inputs.
//
// Public inputs layout (140 field elements):
//   [  0.. 31] a_compressed      [ 32.. 63] r_compressed
//   [ 64.. 95] msg_hash          [ 96..127] k_be
//   [128..133] disclosed_mask    [134..139] disclosed_values
//
// Usage:
//   node scripts/verify.ts 001100
//   node scripts/verify.ts 001100 --against 110000   # cross-check (acceptance #6)

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { encodeStringToField, FIELD_MODULUS, NUM_FIELDS, SCHEMA } from "./lib/gpr.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const args = process.argv.slice(2);
const maskLabel = args.find((a) => !a.startsWith("--"));
if (!maskLabel) {
  console.error("usage: node scripts/verify.ts <maskLabel> [--against <otherMaskLabel>]");
  process.exit(1);
}
const againstIdx = args.indexOf("--against");
const againstLabel = againstIdx >= 0 ? args[againstIdx + 1] : maskLabel;

const proofDir = join(root, "target", "proofs", maskLabel);
const inputsDir = join(root, "target", "proofs", againstLabel);
for (const [label, dir] of [[maskLabel, proofDir], [againstLabel, inputsDir]] as const) {
  if (!existsSync(dir)) {
    console.error(`No proof found for "${label}" (${dir}). Run prove.ts first.`);
    process.exit(1);
  }
}

function decodePublicInputs(path: string): { mask: bigint[]; values: bigint[] } {
  const buf = new Uint8Array(readFileSync(path));
  const fe: bigint[] = [];
  for (let i = 0; i < buf.length; i += 32) {
    let v = 0n;
    for (let j = 0; j < 32; j++) v = (v << 8n) | BigInt(buf[i + j]);
    fe.push(v);
  }
  const tail = fe.slice(-2 * NUM_FIELDS);
  return { mask: tail.slice(0, NUM_FIELDS), values: tail.slice(NUM_FIELDS) };
}

const crossCheck = againstLabel !== maskLabel;
if (crossCheck) {
  console.log(`Cross-check: verifying proof "${maskLabel}" against public inputs of "${againstLabel}"`);
}

let verified = false;
try {
  execFileSync(
    "bb",
    ["verify", "-p", join(proofDir, "proof"), "-i", join(inputsDir, "public_inputs"), "-k", join(proofDir, "vk")],
    { cwd: root, stdio: "inherit" },
  );
  verified = true;
} catch {
  verified = false;
}

console.log(`\nResult: ${verified ? "VALID ✅" : "INVALID ❌"}`);

if (verified) {
  const { mask, values } = decodePublicInputs(join(inputsDir, "public_inputs"));

  const discl = JSON.parse(readFileSync(join(inputsDir, "disclosure.json"), "utf8"));
  const discloseByName: Record<string, string | number> = {};
  for (const r of discl.revealed ?? []) discloseByName[r.name] = r.disclose;

  console.log("\nDisclosed fields (decoded from public inputs):");
  let any = false;
  for (let i = 0; i < NUM_FIELDS; i++) {
    if (mask[i] !== 1n) continue;
    any = true;
    const f = SCHEMA[i];
    const d = discloseByName[f.name];
    if (f.type === "string") {
      // re-hash the revealed plaintext off-circuit and confirm it matches the field element
      const ok = typeof d === "string" && encodeStringToField(d) === values[i];
      console.log(`  ${f.name.padEnd(18)} (string) = "${d}"   [${ok ? "✓ re-hash matches" : "✗ RE-HASH MISMATCH"}]`);
    } else if (f.type === "hash") {
      // the disclosed digest must reduce to the committed field element
      const ok = typeof d === "string" && BigInt("0x" + d) % FIELD_MODULUS === values[i];
      console.log(`  ${f.name.padEnd(18)} (hash)   = SHA256 ${d}   [${ok ? "✓ digest matches" : "✗ DIGEST MISMATCH"}]`);
    } else {
      console.log(`  ${f.name.padEnd(18)} (number) = ${values[i]}`);
    }
  }
  if (!any) console.log("  (none)");
  console.log("\nAll other fields remain hidden inside the proof.");
}

process.exit(verified ? 0 : 1);
