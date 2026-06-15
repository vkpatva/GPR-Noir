// Selective disclosure over a normally-signed GPR row -- Ed25519 variant.
//
// Same idea as the secp256k1 circuit (../GPR): a GPR row is signed ONCE as a whole, and
// at proof time the holder reveals a chosen subset of fields in zero-knowledge. The only
// difference is the signature scheme: here the issuer signs with Ed25519 (RFC 8032), and
// the Edwards-curve verification equation is checked in-circuit using a from-scratch group
// law (see curve.nr) over noir-bignum's ED25519_Fq field.
//
// TRUST-MODEL NOTE -- the SHA-512 challenge is computed off-circuit:
//   Ed25519 verifies  [S]*B == R + [k]*A   with  k = SHA512(R || A || M) mod L.
//   R, A and M (= msg_hash) are ALL public here, so the verifier recomputes `k` itself and
//   passes it in as a public input. This keeps the privacy property identical to the
//   secp256k1 circuit (the row `fields` stay private; only msg_hash is public) while
//   avoiding an in-circuit SHA-512 + 512-bit mod-L reduction. A fully in-circuit SHA-512
//   variant is a documented further step. The chain of soundness is:
//     fields --SHA256--> msg_hash (in-circuit)  ==  M used by verifier to derive k
//     k --(public)-->  binds R, A, M            (verifier recomputes from public data)
//     [S]B == R + [k]A                          (in-circuit Edwards equation)
//
// Canonical row serialization: each field -> 32 big-endian bytes, NUM_FIELDS * 32 total
// (must match scripts/lib/gpr.ts -> canonicalSerialize).

mod curve;

use bignum::BigNum;
use curve::{Fq, Point};

// Data-driven schema: every field is one Field element serialized uniformly as 32 BE bytes.
// Strings are hashed to a field element off-circuit (see scripts/lib/gpr.ts). To change the
// field count, edit NUM_FIELDS here and SCHEMA in scripts/lib/gpr.ts (recompile + new VK).
global NUM_FIELDS: u32 = 6;
global FIELD_BYTES: u32 = 32;
global ROW_BYTES: u32 = NUM_FIELDS * FIELD_BYTES;

fn bytes_eq(a: [u8; 32], b: [u8; 32]) -> bool {
    let mut ok = true;
    for i in 0..32 {
        ok = ok & (a[i] == b[i]);
    }
    ok
}

// Verify that affine point (x_be, pt) is on the curve and that its Ed25519 compressed
// encoding equals `compressed`: 32 little-endian bytes of y, with bit 255 set to lsb(x).
fn check_point(x_be: [u8; 32], y_be: [u8; 32], compressed: [u8; 32]) -> Point {
    let x = Fq::from_be_bytes(x_be);
    let y = Fq::from_be_bytes(y_be);
    Point::assert_on_curve(x, y);

    let mut y_le = y.to_le_bytes();
    let x_lsb = x_be[31] & 1; // parity of x
    y_le[31] = y_le[31] | (x_lsb << 7);
    assert(bytes_eq(y_le, compressed), "compressed point encoding mismatch");

    Point::from_affine(x, y)
}

fn main(
    // PRIVATE: the full row, the signature scalar S, and the decompressed point
    // coordinates (witness hints, validated on-curve + against the compressed encodings).
    fields: [Field; NUM_FIELDS],
    s_be: [u8; 32],
    a_x: [u8; 32],
    a_y: [u8; 32],
    r_x: [u8; 32],
    r_y: [u8; 32],
    // PUBLIC: issuer key A, signature nonce R, the signed hash, the SHA-512 challenge k
    // (recomputed by the verifier from R, A, msg_hash), and the disclosure request.
    a_compressed: pub [u8; 32],
    r_compressed: pub [u8; 32],
    msg_hash: pub [u8; 32],
    k_be: pub [u8; 32],
    disclosed_mask: pub [Field; NUM_FIELDS],
    disclosed_values: pub [Field; NUM_FIELDS],
) {
    // 1. Recompute the canonical serialization and bind its SHA256 to msg_hash (32B/field).
    let mut msg: [u8; ROW_BYTES] = [0; ROW_BYTES];
    for j in 0..NUM_FIELDS {
        let fb: [u8; 32] = fields[j].to_be_bytes::<32>();
        for k in 0..FIELD_BYTES {
            msg[j * FIELD_BYTES + k] = fb[k];
        }
    }
    let computed = sha256::sha256_var(msg, ROW_BYTES);
    assert(computed == msg_hash, "hash mismatch: fields do not match signed msg_hash");

    // 2. Validate the decompressed pubkey A and nonce R against their public encodings.
    let a_point = check_point(a_x, a_y, a_compressed);
    let r_point = check_point(r_x, r_y, r_compressed);

    // 3. Ed25519 verification equation: [S]*B == R + [k]*A.
    let lhs = curve::base_point().mul(s_be);
    let rhs = r_point.add(a_point.mul(k_be));
    assert(lhs.eq(rhs), "invalid Ed25519 signature");

    // 4. Enforce disclosures: mask[i] * (fields[i] - disclosed_values[i]) == 0.
    for i in 0..NUM_FIELDS {
        assert(
            disclosed_mask[i] * (fields[i] - disclosed_values[i]) == 0,
            "disclosed value does not match field",
        );
    }
}
