// Ed25519 (RFC 8032) helpers built on @noble/curves: keygen, signing, and derivation of
// the circuit's witness/public inputs from a standard 64-byte signature.

import { ed25519 } from "@noble/curves/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { bytesToNumberLE, toBE32, toHex } from "./gpr.ts";

const L = ed25519.CURVE.n; // group order

export interface Keypair {
  privateKey: Uint8Array;
  publicKey: Uint8Array; // 32B compressed
}

export function generateKeypair(): Keypair {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/** Sign a 32-byte message (here: the GPR msg_hash). Returns the 64-byte signature. */
export function sign(msg: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return ed25519.sign(msg, privateKey);
}

export interface ProverCrypto {
  sBe: Uint8Array;
  aX: Uint8Array;
  aY: Uint8Array;
  rX: Uint8Array;
  rY: Uint8Array;
  aCompressed: Uint8Array;
  rCompressed: Uint8Array;
  kBe: Uint8Array;
}

/**
 * Decompose a signature into the circuit inputs and verify the Ed25519 equation
 * [S]*B == R + [k]*A in JS (k = SHA512(R||A||M) mod L, little-endian reduced per RFC 8032).
 * Throws if the equation does not hold -- this is the no-Noir signing self-check.
 */
export function deriveProverCrypto(
  publicKey: Uint8Array,
  signature: Uint8Array,
  msg: Uint8Array,
): ProverCrypto {
  const rCompressed = signature.slice(0, 32);
  const sBytesLE = signature.slice(32, 64);
  const S = bytesToNumberLE(sBytesLE);

  // k = SHA512(R || A || M) as little-endian integer, mod L
  const hramInput = new Uint8Array([...rCompressed, ...publicKey, ...msg]);
  const k = bytesToNumberLE(sha512(hramInput)) % L;

  // decompress points to affine coordinates
  const Ap = ed25519.ExtendedPoint.fromHex(toHex(publicKey));
  const Rp = ed25519.ExtendedPoint.fromHex(toHex(rCompressed));
  const aAff = Ap.toAffine();
  const rAff = Rp.toAffine();

  // self-check the verification equation in pure JS
  const lhs = ed25519.ExtendedPoint.BASE.multiply(S);
  const rhs = Rp.add(Ap.multiply(k));
  if (!lhs.equals(rhs)) {
    throw new Error("Ed25519 JS self-check FAILED: [S]B != R + [k]A");
  }

  return {
    sBe: toBE32(S),
    aX: toBE32(aAff.x),
    aY: toBE32(aAff.y),
    rX: toBE32(rAff.x),
    rY: toBE32(rAff.y),
    aCompressed: publicKey,
    rCompressed,
    kBe: toBE32(k),
  };
}
