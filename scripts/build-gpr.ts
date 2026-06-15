// build-gpr.ts -- build a sample GPR row (strings + numbers) from the schema, Ed25519-sign
// its canonical hash, self-check in pure JS, and write sample-data/gpr.json.

import { sha256 } from "@noble/hashes/sha2";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  canonicalSerialize,
  encodeRow,
  FIELD_NAMES,
  fromHex,
  type PlainValue,
  SCHEMA,
  toHex,
} from "./lib/gpr.ts";
import { deriveProverCrypto, sign } from "./lib/ed25519.ts";

const here = dirname(fileURLToPath(import.meta.url));
const dataDir = join(here, "..", "sample-data");

const key = JSON.parse(readFileSync(join(dataDir, "issuer-key.json"), "utf8"));
const priv = fromHex(key.privateKey);
const pub = fromHex(key.publicKey);

// contentHash is computed at build time from REAL content. Point CONTENT_FILE at any file
// (text or binary); its SHA256 becomes the contentHash field. A default is created if missing.
const contentPath = process.env.CONTENT_FILE ?? join(dataDir, "content.txt");
if (!existsSync(contentPath)) {
  writeFileSync(contentPath, "GPR sample document content — replace with the real blob.\n");
}
const content = new Uint8Array(readFileSync(contentPath)); // raw bytes, so binary files work too

const row: Record<string, PlainValue> = {
  contentHash: content, // hashed to SHA256(content) by the "hash" field type
  institution: "Mass General Hospital",
  eventDate: 20260615,
  accessionNumber: "ACC-2024-0091",
  subjectPerson: "Jane Q. Doe",
  classificationId: 2,
};

const { fields, disclose } = encodeRow(row);

const rowBytes = canonicalSerialize(fields);
const msgHash = sha256(rowBytes);
const signature = sign(msgHash, priv);

// ACCEPTANCE #1: independent JS verification of the Ed25519 equation (no Noir).
deriveProverCrypto(pub, signature, msgHash);

const out = {
  scheme: "ed25519",
  schema: SCHEMA,
  // disclosable representation per field (number, plaintext string, or 32-byte digest hex)
  disclose: Object.fromEntries(FIELD_NAMES.map((n, i) => [n, disclose[i]])),
  fields: fields.map((f) => f.toString()),
  canonicalRowHex: toHex(rowBytes),
  msgHash: toHex(msgHash),
  signature: toHex(signature),
  publicKey: toHex(pub),
};
const outPath = join(dataDir, "gpr.json");
writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n");

console.log(`Sample GPR built and signed (Ed25519) -> ${outPath}`);
console.log(`  JS signature self-check ([S]B == R + [k]A): PASS`);
console.log(`  contentHash computed from ${contentPath} (${content.length} bytes)`);
console.log(`  msgHash = ${out.msgHash}`);
for (const f of SCHEMA) {
  const i = FIELD_NAMES.indexOf(f.name);
  const d = disclose[i];
  const note =
    f.type === "hash" ? `SHA256(content) = ${d}` : f.type === "string" ? `"${d}" -> ${fields[i]}` : `${d}`;
  console.log(`  ${f.name.padEnd(18)} (${f.type.padEnd(6)}) = ${note}`);
}
