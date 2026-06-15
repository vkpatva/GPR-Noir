// edwards25519 group law, implemented from scratch over noir-bignum's ED25519_Fq
// (the base field, integers mod 2^255 - 19).
//
// Curve:  -x^2 + y^2 = 1 + d x^2 y^2     (twisted Edwards, a = -1)
// d is non-square mod p, so the unified addition formula below is COMPLETE: it is
// correct for all inputs including P == Q and the identity, so a single `add` doubles
// too and there are no exceptional cases to special-case.
//
// Points are held in extended coordinates (X : Y : Z : T) with x = X/Z, y = Y/Z,
// T = XY/Z, which lets addition avoid per-step field inversions.

use bignum::fields::ed25519Fq::ED25519_Fq;
use bignum::BigNum;

pub type Fq = ED25519_Fq;

// d   = -121665 / 121666 mod p     (curve constant)
pub fn d_const() -> Fq {
    Fq::from_be_bytes([
        82, 3, 108, 238, 43, 111, 254, 115, 140, 199, 64, 121, 119, 121, 232, 152, 0, 112,
        10, 77, 65, 65, 216, 171, 117, 235, 77, 202, 19, 89, 120, 163,
    ])
}

// 2d, the constant used inside the addition formula
fn d2_const() -> Fq {
    Fq::from_be_bytes([
        36, 6, 217, 220, 86, 223, 252, 231, 25, 142, 128, 242, 238, 243, 209, 48, 0, 224,
        20, 154, 130, 131, 177, 86, 235, 214, 155, 148, 38, 178, 241, 89,
    ])
}

fn one() -> Fq {
    let mut b = [0; 32];
    b[31] = 1;
    Fq::from_be_bytes(b)
}

fn zero() -> Fq {
    Fq::from_be_bytes([0; 32])
}

// Base point B of edwards25519.
pub fn base_point() -> Point {
    let bx = Fq::from_be_bytes([
        33, 105, 54, 211, 205, 110, 83, 254, 192, 164, 226, 49, 253, 214, 220, 92, 105, 44,
        199, 96, 149, 37, 167, 178, 201, 86, 45, 96, 143, 37, 213, 26,
    ]);
    let by = Fq::from_be_bytes([
        102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
        102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 88,
    ]);
    Point::from_affine(bx, by)
}

pub struct Point {
    x: Fq,
    y: Fq,
    z: Fq,
    t: Fq,
}

impl Point {
    pub fn identity() -> Self {
        // neutral element (x, y) = (0, 1)
        Self { x: zero(), y: one(), z: one(), t: zero() }
    }

    pub fn from_affine(x: Fq, y: Fq) -> Self {
        Self { x, y, z: one(), t: x * y }
    }

    // Complete unified addition (Hisil-Wong-Carter-Dawson, a = -1).
    pub fn add(self, q: Self) -> Self {
        let a = (self.y - self.x) * (q.y - q.x);
        let b = (self.y + self.x) * (q.y + q.x);
        let c = (self.t * d2_const()) * q.t;
        let dd = self.z * (q.z + q.z); // 2 * Z1 * Z2
        let e = b - a;
        let f = dd - c;
        let g = dd + c;
        let h = b + a;
        Self { x: e * f, y: g * h, t: e * h, z: f * g }
    }

    // Scalar multiplication via MSB-first double-and-add.
    // `scalar_be` is the scalar in big-endian bytes; 256 bits are processed.
    pub fn mul(self, scalar_be: [u8; 32]) -> Self {
        let mut acc = Point::identity();
        for byte_i in 0..32 {
            let byte = scalar_be[byte_i];
            for bit_i in 0..8 {
                acc = acc.add(acc); // double
                let bit = (byte >> (7 - bit_i)) & 1;
                let sum = acc.add(self);
                acc = if bit == 1 { sum } else { acc };
            }
        }
        acc
    }

    // Projective equality: (X1/Z1, Y1/Z1) == (X2/Z2, Y2/Z2)
    // checked as X1*Z2 == X2*Z1 and Y1*Z2 == Y2*Z1 (no inversions).
    pub fn eq(self, q: Self) -> bool {
        let x_ok = (self.x * q.z) == (q.x * self.z);
        let y_ok = (self.y * q.z) == (q.y * self.z);
        x_ok & y_ok
    }

    // Assert the affine point (x, y) satisfies the curve equation.
    pub fn assert_on_curve(x: Fq, y: Fq) {
        let xx = x * x;
        let yy = y * y;
        let lhs = yy - xx; // -x^2 + y^2
        let rhs = one() + (d_const() * (xx * yy));
        assert(lhs == rhs, "point not on edwards25519");
    }
}

#[test]
fn test_scalar_mul_matches_noble() {
    // Vector from @noble/curves: [12345] * B
    let mut s = [0; 32];
    s[30] = 48;
    s[31] = 57; // 12345 = 0x3039
    let got = base_point().mul(s);
    let expected = Point::from_affine(
        Fq::from_be_bytes([
            27, 217, 197, 21, 193, 239, 99, 101, 124, 89, 104, 47, 3, 15, 82, 121, 143, 128,
            235, 254, 59, 230, 7, 187, 204, 60, 165, 29, 208, 222, 88, 21,
        ]),
        Fq::from_be_bytes([
            1, 160, 41, 215, 228, 175, 62, 28, 250, 46, 239, 149, 199, 79, 221, 57, 156, 154,
            200, 211, 206, 250, 156, 135, 173, 51, 151, 71, 248, 98, 79, 239,
        ]),
    );
    assert(got.eq(expected));
}

#[test]
fn test_on_curve_base() {
    let bp = base_point();
    Point::assert_on_curve(bp.x, bp.y);
}
