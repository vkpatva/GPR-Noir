# Noir GPR Selective Disclosure (Ed25519)

Zero-knowledge **selective disclosure** over a normally-signed GPR (GAMI Proof Record) row.

A GPR row is signed **once, as a whole**, with a single **Ed25519** signature — no per-field
salts, no commitments, no Merkle tree, just one ordinary signature. At proof time the holder
chooses, freshly, which subset of fields to reveal and proves in zero-knowledge:

> "I hold a row `R` and a valid issuer Ed25519 signature over its canonical hash, and `R`
> contains these specific field values — without revealing anything else in `R`."

The full row and the signature are **private** inputs; the issuer public key, the signed hash,
and the disclosure request (mask + claimed values) are **public** inputs.

Ed25519 has no turnkey verifier in Noir, so the **Edwards-curve verification is implemented from
scratch** here: the group law (`src/curve.nr`) is hand-written over
[`noir-bignum`](https://github.com/noir-lang/noir-bignum)'s `ED25519_Fq` field and validated
against `@noble/curves` test vectors (`nargo test`).

## How verification works (and the one trade-off)

Ed25519 (RFC 8032) verifies a signature `(R, S)` on message `M` under public key `A` by
checking, on the edwards25519 curve:

```
[S]·B == R + [k]·A        where   k = SHA512(R ‖ A ‖ M) mod L
```

There are two layers: what the **circuit** proves, and what the **verifier** then checks.

### What the circuit enforces (`src/main.nr`)

Over a private row + signature, all of these must hold at once — if any fails, no proof exists:

1. **Re-hash the row:** `SHA256(canonical_serialize(fields)) == msg_hash` — binds the hidden row
   to the exact bytes the issuer signed.
2. **Validate the points:** the witness coordinates of `A` and `R` are on-curve **and**
   recompress to the public `a_compressed` / `r_compressed`, so the witness can't swap in a
   different point (this sidesteps in-circuit `sqrt` decompression).
3. **Check the signature:** the curve equation `[S]·B == R + [k]·A`, via the from-scratch group law.
4. **Enforce disclosures:** `mask[i] * (fields[i] - disclosed_values[i]) == 0` — revealed fields
   must equal the claimed value; hidden fields stay unconstrained.

So a valid proof means: *a genuinely issuer-signed row exists with those disclosed values, and
nothing else leaks.*

### What the verifier does

The verifier already holds the issuer key `A`, the signed hash `msg_hash`, and `R` (out of
band). It runs `bb verify` on the proof + public inputs, and `verify.ts` reads the disclosed
values straight from the public inputs.

### The trade-off — the SHA-512 challenge `k` is computed off-circuit

Computing `k` would mean running **SHA-512 + a 512-bit reduction inside the circuit**, very
expensive on top of the already-heavy curve math. Instead, because `R`, `A`, and `msg_hash` are
**all public**, the **verifier recomputes `k` itself** and passes it in as a public input; the
circuit only checks the curve equation.

This stays sound — the prover can't fake `k`, and the chain holds end-to-end:

- in-circuit `SHA256(fields) == msg_hash` binds the row to the message `M`,
- the verifier derives `k` from the public `R, A, M`,
- the in-circuit equation binds `S, R, A, k` together.

Privacy is unchanged: the row stays private, only `msg_hash` is public.

> A **fully in-circuit SHA-512** (so `k` is recomputed inside the proof too) is the natural next
> step — it just costs a lot more gates.

## Schema (dynamic, strings + numbers)

The row shape is data-driven from a single `SCHEMA` in `scripts/lib/gpr.ts`, and every field
is one BN254 `Field` element serialized **uniformly as 32 big-endian bytes** (so the canonical
layout is just `NUM_FIELDS * 32` bytes — the circuit serialization is a simple loop).

```ts
export const SCHEMA = [
  { name: "contentHash",      type: "hash" },     // SHA256 of real content, computed at build
  { name: "institution",      type: "string" },
  { name: "eventDate",        type: "number" },   // e.g. 20260615
  { name: "accessionNumber",  type: "string" },   // e.g. "ACC-2024-0091"
  { name: "subjectPerson",    type: "string" },
  { name: "classificationId", type: "number" },
];
```

Three field types, all reduced to one 32-byte field element:

- **number** — the integer itself (must be `< BN254 modulus`). Discloses the value directly.
- **string** — `SHA256(utf8(value)) mod p`; the circuit only sees the field element. Revealing
  it discloses the **plaintext**, and `verify.ts` **re-hashes it off-circuit** to confirm it
  matches (`✓ re-hash matches`), then prints the readable string.
- **hash** — the value is **real content** (text or binary bytes); the field stores
  `SHA256(content) mod p`, computed **at build time**. `build-gpr.ts` reads the content from a
  file (`sample-data/content.txt`, or set `CONTENT_FILE=/path`), so `contentHash` is a genuine
  digest of an actual document, never a hardcoded constant. Revealing it discloses the **32-byte
  digest** (not the content); `verify.ts` confirms the digest reduces to the committed field
  element (`✓ digest matches`).

### Changing a value (no recompile)

To change what a field holds — a different `eventDate`, a new `accessionNumber`, or new
document content — you do **not** touch the circuit:

1. Edit the value in the `row` object in `scripts/build-gpr.ts` (or edit `sample-data/content.txt`
   for `contentHash`).
2. Re-run the build + proof:
   ```bash
   node scripts/build-gpr.ts      # re-encodes + re-signs the row
   node scripts/prove.ts 0,0,1,1,0,0
   node scripts/verify.ts 001100
   ```

### Adding a new field to the schema (recompile)

Adding a field changes the circuit, so it needs a recompile and produces a new verification
key. Worked example — add a `physician` string field:

1. **Add it to `SCHEMA`** in `scripts/lib/gpr.ts` (pick `number`, `string`, or `hash`):
   ```ts
   export const SCHEMA = [
     { name: "contentHash",      type: "hash" },
     { name: "institution",      type: "string" },
     { name: "eventDate",        type: "number" },
     { name: "accessionNumber",  type: "string" },
     { name: "subjectPerson",    type: "string" },
     { name: "classificationId", type: "number" },
     { name: "physician",        type: "string" },   // ← new field
   ];
   ```

2. **Bump `NUM_FIELDS`** in `src/main.nr` to the new count so the circuit array sizes match:
   ```rust
   global NUM_FIELDS: u32 = 7;   // was 6
   ```

3. **Provide its value** in the `row` object in `scripts/build-gpr.ts`:
   ```ts
   const row = {
     // ...existing fields...
     physician: "Dr. Alice Chen",
   };
   ```

4. **Recompile the circuit** (regenerates the ACIR + a new verification key):
   ```bash
   nargo compile
   ```

5. **Rebuild, prove, verify** — the disclosure mask now has one entry per field (7 here). For
   example, to additionally reveal `physician` (the last field):
   ```bash
   node scripts/build-gpr.ts
   node scripts/prove.ts 0,0,1,1,0,0,1   # 7 entries; reveal eventDate, accessionNumber, physician
   node scripts/verify.ts 0011001
   ```

Notes:
- `NUM_FIELDS` in `src/main.nr` **must** equal `SCHEMA.length`; if they differ, `nargo execute`
  fails on an input-shape mismatch.
- The mask length and the public-inputs count follow `NUM_FIELDS` automatically — `verify.ts`
  decodes the disclosure from the tail of `public_inputs`, so no change is needed there.
- A new field count means a new circuit and a new `vk`; previously generated proofs no longer
  verify against it.

## Cost

| | |
|---|---|
| signature verify | from-scratch edwards25519 group law over noir-bignum |
| circuit size | **~837k gates** (two in-circuit scalar mults) |
| proving time | tens of seconds (machine-dependent) |
| memory | ~2 GiB |

The cost is dominated by the two in-circuit scalar multiplications (`[S]·B`, `[k]·A`), each a
256-step double-and-add of complete Edwards additions. A windowed/precomputed-base
multiplication would cut this substantially — left as future work.

## Layout

```
GPR-Noir/
  Nargo.toml            # deps: vendored bignum (path) + sha256 (git)
  vendor/bignum/        # noir-bignum v0.10.0, vendored with the poseidon dep removed (see below)
  src/
    curve.nr            # from-scratch edwards25519 group law (+ @noble test vectors)
    main.nr             # the Ed25519 GPR disclosure circuit
  scripts/
    lib/gpr.ts          # schema, canonical serialization, Prover.toml rendering
    lib/ed25519.ts      # @noble keygen/sign + derive circuit inputs (with JS self-check)
    generate-keypair.ts build-gpr.ts prove.ts verify.ts
  sample-data/
  README.md
```

### Why bignum is vendored

`noir-bignum` v0.10.0 pins `poseidon` v0.3.0, whose `poseidon2_permutation` arity is
incompatible with `nargo 1.0.0-beta.19`. bignum only uses poseidon inside `derive_from_seed`
(unused here), so `vendor/bignum` is a copy with the poseidon dependency removed and that one
function stubbed. Everything we rely on — field add/sub/mul, `from_be_bytes`/`to_be_bytes` —
is untouched. If a poseidon release catches up to the compiler, switch back to the upstream
git dependency and delete `vendor/`.

## Prerequisites

- `nargo` (tested `1.0.0-beta.19`), `bb` (tested `4.0.0-nightly`, UltraHonk)
- Node ≥ 22 (native TypeScript; tested `v23.9.0`)

## Run it

```bash
npm install
nargo test                      # validate the from-scratch curve against @noble vectors

node scripts/generate-keypair.ts
node scripts/build-gpr.ts        # build + Ed25519-sign a row (JS self-check of [S]B==R+[k]A)
node scripts/prove.ts 0,0,1,1,0,0   # reveal eventDate + accessionNumber (slow: ~837k gates)
node scripts/verify.ts 001100
```

The mask is six `0/1` entries (comma list or 6-char binary), one per schema field.

## Generated files (nothing is pre-committed)

The repo intentionally ships **no keypair, no `Prover.toml`, no witness, and no proofs** — they
are all produced by running the steps above. The Ed25519 private key in particular must never be
committed, so it is gitignored. Here is every artifact, where it comes from, and its git status:

| File | Created by | Contains | Git |
|------|-----------|----------|-----|
| `sample-data/issuer-key.json` | `generate-keypair.ts` | Ed25519 **private + public** key (hex) | **gitignored** (secret) |
| `sample-data/content.txt` | you (or a default is created) | the real content whose SHA256 becomes `contentHash` | up to you |
| `sample-data/gpr.json` | `build-gpr.ts` | row `fields`, per-field `disclose` reps, `msgHash`, `signature`, **public key only** | committed (sample, no secret) |
| `Prover.toml` | `prove.ts` | the full witness inputs for one disclosure: private `fields`, `s_be`, the decompressed point coords `a_x/a_y/r_x/r_y`, and public `a_compressed`, `r_compressed`, `msg_hash`, `k_be`, `disclosed_mask`, `disclosed_values` | **gitignored** (regenerated per run) |
| `target/noir_gpr_ed25519.json` | `nargo compile` | compiled ACIR circuit | build artifact |
| `target/noir_gpr_ed25519.gz` | `nargo execute` (via `prove.ts`) | the **solved witness** (binary field elements) | **gitignored** |
| `target/proofs/<mask>/proof` | `bb prove` | the zk proof | **gitignored** |
| `target/proofs/<mask>/public_inputs` | `bb prove` | 140 public field elements (keys, `msg_hash`, `k`, mask, disclosed values) | **gitignored** |
| `target/proofs/<mask>/vk` | `bb prove --write_vk` | verification key | **gitignored** |
| `target/proofs/<mask>/disclosure.json` | `prove.ts` | human-readable record of what was revealed | **gitignored** |

So a fresh clone has only `gpr.json`. Run `generate-keypair.ts` → `build-gpr.ts` → `prove.ts`
to materialize the key, witness inputs, witness, and proof. To inspect the witness inputs for a
given disclosure, open the generated `Prover.toml`; to inspect the solved witness you must
`nargo execute` (the `.gz` is binary, not human-readable).

## Acceptance checks

```bash
node scripts/prove.ts 0,0,1,1,0,0 --tamper-field 2=19990101   # tamper a private field -> hash mismatch, execute fails
node scripts/prove.ts 0,0,1,1,0,0 --tamper-value 3=99999999   # claim a wrong disclosed value -> assertion fails
node scripts/prove.ts 1,1,0,0,0,0                             # build a second disclosure
node scripts/verify.ts 001100 --against 110000               # verify a proof against a different disclosure -> INVALID
```

The disclosed values are decoded directly from the proof's `public_inputs` (layout documented
in `scripts/verify.ts`).
