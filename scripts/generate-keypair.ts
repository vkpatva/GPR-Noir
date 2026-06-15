// generate-keypair.ts -- Ed25519 issuer keypair.

import { writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { generateKeypair } from "./lib/ed25519.ts";
import { toHex } from "./lib/gpr.ts";

const here = dirname(fileURLToPath(import.meta.url));
const dataDir = join(here, "..", "sample-data");
const outPath = join(dataDir, "issuer-key.json");

const kp = generateKeypair();
mkdirSync(dataDir, { recursive: true });
writeFileSync(
  outPath,
  JSON.stringify(
    {
      scheme: "ed25519",
      privateKey: toHex(kp.privateKey),
      publicKey: toHex(kp.publicKey),
    },
    null,
    2,
  ) + "\n",
);

console.log(`Ed25519 issuer keypair written to ${outPath}`);
console.log(`  publicKey = ${toHex(kp.publicKey)}`);
