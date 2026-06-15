// Shared definitions for the Ed25519 GPR selective-disclosure demo.
//
// SCHEMA is the single source of truth. Every field is one BN254 `Field` element serialized
// UNIFORMLY as 32 big-endian bytes (matching src/main.nr). Numbers encode as themselves;
// strings are SHA256-hashed into the field, revealed by disclosing the field element + the
// plaintext, which the verifier re-hashes off-circuit.

import { sha256 } from "@noble/hashes/sha2";

export const FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Field types:
//   "number" - the integer value itself (must be < BN254 modulus).
//   "string" - SHA256(utf8(value)) mod p. Discloses the plaintext; verifier re-hashes it.
//   "hash"   - the value is raw CONTENT (text/bytes); the field stores SHA256(content) mod p.
//              Discloses the 32-byte digest (NOT the content); verifier checks digest mod p.
//              Use this for "hash of a document/blob computed at build time".
export type FieldType = "number" | "string" | "hash";
export interface SchemaField {
  name: string;
  type: FieldType;
}

// ---- THE SCHEMA (edit here + NUM_FIELDS in src/main.nr to change the row shape) --------
export const SCHEMA: SchemaField[] = [
  { name: "contentHash", type: "hash" }, // SHA256 of real content, computed at build time
  { name: "institution", type: "string" },
  { name: "eventDate", type: "number" },
  { name: "accessionNumber", type: "string" },
  { name: "subjectPerson", type: "string" },
  { name: "classificationId", type: "number" },
];

export const NUM_FIELDS = SCHEMA.length;
export const FIELD_NAMES = SCHEMA.map((f) => f.name);
export const FIELD_BYTES = 32;
export const ROW_BYTES = NUM_FIELDS * FIELD_BYTES;

export type PlainValue = string | number | bigint | Uint8Array;

/** Interpret a byte array as a big-endian integer reduced into the BN254 field. */
export function bytesToFieldMod(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v % FIELD_MODULUS;
}

/** "string" fields: SHA256(utf8(s)) reduced into the field. */
export function encodeStringToField(s: string): bigint {
  return bytesToFieldMod(sha256(new TextEncoder().encode(s)));
}

/** "hash" fields: SHA256 of real content -> { field element, 32-byte digest hex }. */
export function hashContent(content: string | Uint8Array): { field: bigint; digestHex: string } {
  const bytes = typeof content === "string" ? new TextEncoder().encode(content) : content;
  const digest = sha256(bytes);
  return { field: bytesToFieldMod(digest), digestHex: toHex(digest) };
}

export function encodeValue(value: PlainValue, type: FieldType): bigint {
  if (type === "string") {
    if (typeof value !== "string") throw new Error(`string field needs a string`);
    return encodeStringToField(value);
  }
  if (type === "hash") {
    if (typeof value !== "string") throw new Error(`hash field needs content as a string`);
    return hashContent(value).field;
  }
  const v = BigInt(value);
  if (v < 0n || v >= FIELD_MODULUS) throw new Error(`number field out of range: ${value}`);
  return v;
}

/**
 * Encode a full plaintext row (keyed by schema name) into field elements.
 * `disclose[i]` is the value recorded for disclosure of field i:
 *   number -> the number, string -> the plaintext, hash -> the 32-byte digest hex.
 */
export function encodeRow(row: Record<string, PlainValue>): {
  fields: bigint[];
  disclose: (string | number)[];
} {
  const fields: bigint[] = [];
  const disclose: (string | number)[] = [];
  for (const f of SCHEMA) {
    if (!(f.name in row)) throw new Error(`missing field "${f.name}" in row`);
    const value = row[f.name];
    if (f.type === "hash") {
      const { field, digestHex } = hashContent(value as string | Uint8Array);
      fields.push(field);
      disclose.push(digestHex);
    } else if (f.type === "string") {
      fields.push(encodeValue(value, "string"));
      disclose.push(value as string);
    } else {
      fields.push(encodeValue(value, "number"));
      disclose.push(Number(value));
    }
  }
  return { fields, disclose };
}

function writeBigUintBE(out: Uint8Array, value: bigint, offset: number, width: number): void {
  if (value < 0n) throw new Error(`negative field value: ${value}`);
  if (value >= 1n << BigInt(width * 8)) throw new Error(`value ${value} does not fit in ${width} bytes`);
  let v = value;
  for (let i = width - 1; i >= 0; i--) {
    out[offset + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

export function canonicalSerialize(fields: bigint[]): Uint8Array {
  if (fields.length !== NUM_FIELDS) throw new Error(`expected ${NUM_FIELDS} fields`);
  const out = new Uint8Array(ROW_BYTES);
  for (let i = 0; i < NUM_FIELDS; i++) {
    if (fields[i] >= FIELD_MODULUS) throw new Error(`field[${i}] exceeds BN254 modulus`);
    writeBigUintBE(out, fields[i], i * FIELD_BYTES, FIELD_BYTES);
  }
  return out;
}

export function gprMsgHash(fields: bigint[]): Uint8Array {
  return sha256(canonicalSerialize(fields));
}

// ---- byte / bigint helpers (Ed25519-specific) ------------------------------

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToNumberLE(b: Uint8Array): bigint {
  let v = 0n;
  for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  return v;
}

export function toBE32(v: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error(`value does not fit in 32 bytes: ${v}`);
  return out;
}

// ---- Prover.toml rendering --------------------------------------------------

function tomlByteArray(bytes: Uint8Array): string {
  return "[" + Array.from(bytes).map((b) => `"${b}"`).join(", ") + "]";
}
function tomlFieldArray(values: bigint[]): string {
  return "[" + values.map((v) => `"${v.toString()}"`).join(", ") + "]";
}

export interface ProverInputs {
  fields: bigint[];
  sBe: Uint8Array;
  aX: Uint8Array;
  aY: Uint8Array;
  rX: Uint8Array;
  rY: Uint8Array;
  aCompressed: Uint8Array;
  rCompressed: Uint8Array;
  msgHash: Uint8Array;
  kBe: Uint8Array;
  disclosedMask: bigint[];
  disclosedValues: bigint[];
}

export function renderProverToml(inp: ProverInputs): string {
  return [
    `fields = ${tomlFieldArray(inp.fields)}`,
    `s_be = ${tomlByteArray(inp.sBe)}`,
    `a_x = ${tomlByteArray(inp.aX)}`,
    `a_y = ${tomlByteArray(inp.aY)}`,
    `r_x = ${tomlByteArray(inp.rX)}`,
    `r_y = ${tomlByteArray(inp.rY)}`,
    `a_compressed = ${tomlByteArray(inp.aCompressed)}`,
    `r_compressed = ${tomlByteArray(inp.rCompressed)}`,
    `msg_hash = ${tomlByteArray(inp.msgHash)}`,
    `k_be = ${tomlByteArray(inp.kBe)}`,
    `disclosed_mask = ${tomlFieldArray(inp.disclosedMask)}`,
    `disclosed_values = ${tomlFieldArray(inp.disclosedValues)}`,
    "",
  ].join("\n");
}
