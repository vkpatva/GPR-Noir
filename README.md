# Noir GPR Selective Disclosure (Ed25519)

Zero-knowledge **selective disclosure** over a normally-signed GPR (GAMI Proof Record) row.

A GPR row is signed **once, as a whole**, with a single **Ed25519** signature — no per-field
salts, no commitments, no Merkle tree, just one ordinary signature. The **same institute** that
issued the row later chooses, at proof time, which subset of fields to reveal and proves in
zero-knowledge to **any verifier**:

> "We hold a row `R` and a valid Ed25519 signature over its canonical hash, and `R`
> contains these specific field values — without revealing anything else in `R`."

The full row and the signature are **private** inputs; the institute public key, the signed hash,
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

### End-to-end flow

The institute both **signs** the GPR row and **generates** the zk proof. The verifier can be
anyone — a regulator, partner lab, patient portal, etc. — who receives the proof and checks it
without seeing the hidden fields.

```
  Institute (issuer + prover)                         Anyone (verifier)
  ───────────────────────────                         ─────────────────
    │                                                       │
    │  build GPR row, Ed25519-sign it                       │
    │────────────┐                                          │
    │            │                                          │
    │◄───────────┘                                          │
    │                                                       │
    │  pick disclosure mask (full row stays private)        │
    │  nargo execute + bb prove                             │
    │────────────┐                                          │
    │            │                                          │
    │◄───────────┘                                          │
    │                                                       │
    │  zk proof + public_inputs                             │
    ├──────────────────────────────────────────────────────►│
    │                                                       │  recompute k
    │                                                       │  bb verify
    │                                                       │  read disclosed fields
    │                                                       │
```

### In-circuit vs off-circuit

```
  PRIVATE WITNESS                 IN-CIRCUIT (src/main.nr)              PUBLIC INPUTS
  (hidden in the proof)           ────────────────────────              (in the proof)
  ───────────────

  fields  ─────────────────────►  (1) SHA256(serialize) == msg_hash ──► msg_hash
  a_x, a_y,                       (2) check_point: A and R are         a_compressed
  r_x, r_y  ───────────────────►     on-curve and match compressed  ──► r_compressed
  s_be  ───────────────────────►  (3) [S]*B == R + [k]*A  ◄────────── k_be
  fields + mask  ──────────────►  (4) mask*(field-disclosed)==0  ───► disclosed_mask
                                                                       disclosed_values


                                  OFF-CIRCUIT (verify.ts + bb)
                                  ────────────────────────────
                                  k = SHA512(R || A || msg_hash) mod L
                                  bb verify (SNARK check)
                                  decode + re-hash disclosed strings
```

**What the symbols mean**

| Symbol | Role | Plain English |
|--------|------|---------------|
| `fields` | private | The full GPR row (all schema fields as field elements). Never leaves the proof. |
| `msg_hash` | public | `SHA256` of the canonical row bytes — this is what the institute signed (`M` in Ed25519). |
| `A` / `a_compressed` | public | The institute's **Ed25519 public key** (32-byte compressed point). Identifies who signed the row. |
| `R` / `r_compressed` | public | The **nonce point** from the signature (first 32 bytes of the 64-byte Ed25519 sig). Not the GPR row `R`. |
| `a_x`, `a_y` | private | Affine **x** and **y** coordinates of public key `A`, decompressed off-circuit. The circuit checks they lie on the curve and recompress to `a_compressed`. |
| `r_x`, `r_y` | private | Affine **x** and **y** coordinates of nonce point `R`, same validation as above. Avoids doing `sqrt` decompression inside the circuit. |
| `S` / `s_be` | private | The **signature scalar** (second 32 bytes of the Ed25519 sig), big-endian in the witness. Used in `[S]*B`. |
| `k` / `k_be` | public | The Ed25519 challenge `SHA512(R ‖ A ‖ msg_hash) mod L`. Recomputed by the verifier (see trade-off below) and passed in; the circuit checks the curve equation with it. |
| `disclosed_mask` | public | One `0` or `1` per schema field — `1` means "reveal this field". |
| `disclosed_values` | public | The claimed value for each field; only enforced where `mask[i] == 1`. |
| `B` | (constant) | The Ed25519 base point; fixed in `curve.nr`, not an input. |

In short: the institute keeps the **full row** and **raw signature parts** private; the verifier
only sees the **public key**, **signed hash**, **signature points** (`A`, `R`), **challenge** `k`,
and whichever **field values the mask selects**.

### What the circuit enforces (`src/main.nr`)

Over a private row + signature, all of these must hold at once — if any fails, no proof exists:

1. **Re-hash the row:** `SHA256(canonical_serialize(fields)) == msg_hash` — binds the hidden row
   to the exact bytes the institute signed.
2. **Validate the points:** the witness coordinates of `A` and `R` are on-curve **and**
   recompress to the public `a_compressed` / `r_compressed`, so the witness can't swap in a
   different point (this sidesteps in-circuit `sqrt` decompression).
3. **Check the signature:** the curve equation `[S]·B == R + [k]·A`, via the from-scratch group law.
4. **Enforce disclosures:** `mask[i] * (fields[i] - disclosed_values[i]) == 0` — revealed fields
   must equal the claimed value; hidden fields stay unconstrained.

So a valid proof means: *a genuinely institute-signed row exists with those disclosed values, and
nothing else leaks.*

### What the verifier does

Anyone with the proof file, `public_inputs`, and verification key can verify — no access to the
institute's private key or full row is needed. They should already know (or trust out-of-band)
which institute public key `A` signed the record. `verify.ts` runs `bb verify`, then reads the
disclosed values straight from `public_inputs`.

### What gets revealed (and how the verifier reconfirms)

The proof **never leaks hidden fields**. Revelation is entirely explicit: the institute picks the
mask when it runs `prove.ts`. Only fields with `mask[i] = 1` are written into `public_inputs`;
everything else stays in the private witness and is never published.

**Reveal nothing** (`mask = 0,0,0,0,0,0`) is valid. The disclosure constraint
`mask[i] * (fields[i] - disclosed_values[i]) == 0` is vacuous when every mask bit is `0`, so the
proof only shows *"a genuinely institute-signed GPR row exists"* (via `msg_hash` + Ed25519) without
exposing any field content.

**What the institute sends the verifier**

| Artifact | Required? | Purpose |
|----------|-----------|---------|
| `proof` | yes | the zk-SNARK |
| `public_inputs` | yes | issuer key, `msg_hash`, `k`, mask, disclosed field elements (bundled with the proof) |
| `disclosure.json` | recommended | human-readable labels for strings/hashes (written by `prove.ts` alongside the proof) |
| `vk` | yes | verification key (`target/proofs/<mask>/vk`) |

Hidden fields are never sent. The institute does **not** need to share plaintext for fields the
mask left at `0`.

**Example** — mask `001100` reveals `eventDate` and `accessionNumber` only:

| Field | In `public_inputs`? | Human-readable form |
|-------|---------------------|---------------------|
| `eventDate` (number) | yes — `20260615` directly | verifier reads the integer from the proof |
| `accessionNumber` (string) | yes — but only as `SHA256(utf8) mod p` | institute must also share `"ACC-2024-0091"` (in `disclosure.json` or any channel) |
| `subjectPerson`, etc. | no — mask is `0` | not shared, not in the proof |

**How the verifier reconfirms disclosed values**

There are two layers — one cryptographic, one human-readable:

1. **`bb verify` (the real guarantee)** — confirms that every `disclosed_values[i]` where
   `mask[i] = 1` really equals `fields[i]` in the hidden signed row. The verifier never sees
   `fields` directly; the SNARK math guarantees the public commitments match the signed row.
   A wrong claimed value fails at prove time (`--tamper-value` acceptance check).

2. **`verify.ts` decode + re-hash (human-readable check)** — after `bb verify` passes, reads
   field elements from `public_inputs` and maps them back to readable form:
   - **number** — value is already in the proof; nothing extra to share.
   - **string** — takes the plaintext the institute shared, re-hashes it, and checks
     `encodeStringToField(plaintext) == disclosed_values[i]` (`✓ re-hash matches`).
   - **hash** — takes the digest hex the institute shared and checks it reduces to the field
     element (`✓ digest matches`).

`disclosure.json` is a convenience sidecar for display — the cryptographic truth is always in
`public_inputs`. If the institute lies about a string in `disclosure.json`, the re-hash check
fails. If they lie in `public_inputs`, `bb verify` fails.

```
Institute picks mask  →  only those fields enter public_inputs
Institute shares proof + public_inputs + (for strings) the plaintext
Verifier: bb verify   →  "committed values match a signed row"
Verifier: re-hash     →  "plaintext they gave me matches the commitment"
```

### The trade-off — the SHA-512 challenge `k` is computed off-circuit

Computing `k` would mean running **SHA-512 + a 512-bit reduction inside the circuit**, very
expensive on top of the already-heavy curve math. Instead, because `R`, `A`, and `msg_hash` are
**all public**, the **verifier recomputes `k` itself** and passes it in as a public input; the
circuit only checks the curve equation.

This stays sound — the prover can't fake `k`, and the chain holds end-to-end:

```
  private fields ──(1) SHA256 in-circuit──► msg_hash (public)
                                                    │
           r_compressed (public) ───────────────────┤
           a_compressed (public) ───────────────────┤
                                                    ▼
                              k_be (public) ◄── SHA512 mod L off-circuit
                                                    │
  private s_be ─────────────────────────────────────┤
                                                    ▼
                              (3) [S]*B == R + [k]*A  in-circuit  ──► valid signature

  private fields ──(4) disclosure in-circuit──► only masked values public
```

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
