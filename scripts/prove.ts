// prove.ts -- build Prover.toml for a chosen disclosure mask, run nargo execute + bb prove.
//
// Usage:
//   node scripts/prove.ts                 # default mask 0,0,1,1,0,0
//   node scripts/prove.ts 0,0,1,1,0,0
//   node scripts/prove.ts 0,0,1,1,0,0 --tamper-field 2=19990101   # acceptance #4
//   node scripts/prove.ts 0,0,1,1,0,0 --tamper-value 3=99999999   # acceptance #5

import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  fromHex,
  NUM_FIELDS,
  renderProverToml,
  SCHEMA,
} from "./lib/gpr.ts";
import { deriveProverCrypto } from "./lib/ed25519.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const dataDir = join(root, "sample-data");

const args = process.argv.slice(2);
const positional = args.filter((a) => !a.startsWith("--"));
const flags = new Map<string, string>();
for (const a of args.filter((x) => x.startsWith("--"))) {
  const [k, v] = a.replace(/^--/, "").split("=");
  flags.set(k, v ?? args[args.indexOf(a) + 1] ?? "");
}

function parseMask(s: string | undefined): bigint[] {
  if (!s) return SCHEMA.map((f) => (f.name === "eventDate" || f.name === "accessionNumber" ? 1n : 0n));
  const parts = s.includes(",") ? s.split(",") : s.split("");
  if (parts.length !== NUM_FIELDS) throw new Error(`mask must have ${NUM_FIELDS} entries`);
  return parts.map((p) => {
    const n = BigInt(p.trim());
    if (n !== 0n && n !== 1n) throw new Error(`mask entries must be 0 or 1`);
    return n;
  });
}

const mask = parseMask(positional[0]);
const maskLabel = mask.map((m) => m.toString()).join("");

const g = JSON.parse(readFileSync(join(dataDir, "gpr.json"), "utf8"));
const fields = g.fields.map((x: string) => BigInt(x)) as bigint[];

// crypto inputs are derived from the (unchanged) signature
const crypto = deriveProverCrypto(fromHex(g.publicKey), fromHex(g.signature), fromHex(g.msgHash));

// optional tampering (acceptance #4: corrupt a private field -> hash mismatch)
const tamperField = flags.get("tamper-field");
if (tamperField) {
  const [i, v] = tamperField.split("=");
  fields[Number(i)] = BigInt(v);
  console.log(`[tamper] private fields[${i}] overwritten with ${v}`);
}

const disclosedValues = mask.map((m, i) => (m === 1n ? fields[i] : 0n));

// optional tampering (acceptance #5: claim a wrong disclosed value)
const tamperValue = flags.get("tamper-value");
if (tamperValue) {
  const [i, v] = tamperValue.split("=");
  disclosedValues[Number(i)] = BigInt(v);
  console.log(`[tamper] disclosed_values[${i}] overwritten with ${v}`);
}

writeFileSync(
  join(root, "Prover.toml"),
  renderProverToml({
    fields,
    sBe: crypto.sBe,
    aX: crypto.aX,
    aY: crypto.aY,
    rX: crypto.rX,
    rY: crypto.rY,
    aCompressed: crypto.aCompressed,
    rCompressed: crypto.rCompressed,
    msgHash: fromHex(g.msgHash),
    kBe: crypto.kBe,
    disclosedMask: mask,
    disclosedValues,
  }),
);
console.log(`Prover.toml written (mask = [${maskLabel.split("").join(",")}])`);

const witnessName = "noir_gpr_ed25519";
try {
  process.stdout.write(execFileSync("nargo", ["execute", witnessName], { cwd: root, encoding: "utf8" }));
} catch (e: any) {
  console.error("\nnargo execute FAILED (constraint unsatisfiable):");
  console.error(e.stdout || e.message);
  process.exit(1);
}

const outDir = join(root, "target", "proofs", maskLabel);
mkdirSync(outDir, { recursive: true });
console.log("Running bb prove (Ed25519 in-circuit verification is heavy -- this can take a while)...");
execFileSync(
  "bb",
  [
    "prove",
    "-b", join(root, "target", `${witnessName}.json`),
    "-w", join(root, "target", `${witnessName}.gz`),
    "-o", outDir,
    "--write_vk",
  ],
  { cwd: root, stdio: "inherit" },
);

// Record what each revealed field discloses (the off-circuit channel the verifier checks):
//   number -> the value, string -> the plaintext (re-hashed), hash -> the digest hex.
const revealed = SCHEMA.map((f, i) => ({
  name: f.name,
  type: f.type,
  fieldElement: disclosedValues[i].toString(),
  disclose: f.type === "number" ? Number(g.disclose?.[f.name] ?? disclosedValues[i]) : (g.disclose?.[f.name] ?? null),
})).filter((_, i) => mask[i] === 1n);

writeFileSync(
  join(outDir, "disclosure.json"),
  JSON.stringify(
    { mask: mask.map(String), disclosedValues: disclosedValues.map(String), revealed },
    null,
    2,
  ) + "\n",
);

console.log(`\nProof artifacts written to ${outDir}`);
console.log(`Verify with:  node scripts/verify.ts ${maskLabel}`);
