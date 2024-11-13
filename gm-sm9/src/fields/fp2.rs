use crate::fields::fp::{fp_from_hex, Fp};
use crate::fields::FieldElement;
use crate::u256::U256;

const SM9_FP2_ZERO: [U256; 2] = [[0, 0, 0, 0], [0, 0, 0, 0]];
const SM9_FP2_ONE: [U256; 2] = [[1, 0, 0, 0], [0, 0, 0, 0]];
const SM9_FP2_U: [U256; 2] = [[0, 0, 0, 0], [1, 0, 0, 0]];
const SM9_FP2_5U: [U256; 2] = [[0, 0, 0, 0], [5, 0, 0, 0]];
const SM9_FP2_MONT_5U: [U256; 2] = [
    [0, 0, 0, 0],
    [
        0xb9f2c1e8c8c71995,
        0x125df8f246a377fc,
        0x25e650d049188d1c,
        0x43fffffed866f63,
    ],
];

#[derive(Debug, Copy, Clone)]
pub struct Fp2 {
    pub(crate) c0: Fp,
    pub(crate) c1: Fp,
}

impl PartialEq for Fp2 {
    fn eq(&self, other: &Self) -> bool {
        self.c0.eq(&other.c0) && self.c1.eq(&other.c1)
    }
}

impl Eq for Fp2 {}

impl FieldElement for Fp2 {
    fn zero() -> Self {
        Fp2 {
            c0: Fp::zero(),
            c1: Fp::zero(),
        }
    }

    fn one() -> Self {
        Fp2 {
            c0: Fp::one(),
            c1: Fp::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    fn fp_sqr(&self) -> Self {
        let mut r0 = Fp::zero();
        let mut r1 = Fp::zero();
        let mut t0 = Fp::zero();
        let mut t1 = Fp::zero();

        r1 = self.c0.fp_mul(&self.c1);

        // r0 = (a0 + a1) * (a0 - 2a1) + a0 * a1
        t0 = self.c0.fp_add(&self.c1);
        t1 = self.c1.fp_double();
        t1 = self.c0.fp_sub(&t1);

        r0 = t0.fp_mul(&t1);
        r0 = r0.fp_add(&r1);

        // r1 = 2 * a0 * a1
        r1 = r1.fp_double();

        Self { c0: r0, c1: r1 }
    }

    fn fp_double(&self) -> Self {
        Fp2 {
            c0: self.c0.fp_double(),
            c1: self.c1.fp_double(),
        }
    }

    fn fp_triple(&self) -> Self {
        Fp2 {
            c0: self.c0.fp_triple(),
            c1: self.c1.fp_triple(),
        }
    }

    fn fp_add(&self, rhs: &Self) -> Self {
        Fp2 {
            c0: self.c0.fp_add(&rhs.c0),
            c1: self.c1.fp_add(&rhs.c1),
        }
    }

    fn fp_sub(&self, rhs: &Self) -> Self {
        Fp2 {
            c0: self.c0.fp_sub(&rhs.c0),
            c1: self.c1.fp_sub(&rhs.c1),
        }
    }

    fn fp_mul(&self, rhs: &Self) -> Self {
        let mut r0 = Fp::zero();
        let mut r1 = Fp::zero();
        let mut t = Fp::zero();

        r0 = self.c0.fp_add(&self.c1);
        t = rhs.c0.fp_add(&rhs.c1);
        r1 = t.fp_mul(&r0);

        // r0 = a0 * b0 - 2 * a1 * b1
        r0 = self.c0.fp_mul(&rhs.c0);
        t = self.c1.fp_mul(&rhs.c1);

        // r1 = (a0 + a1) * (b0 + b1) - a0 * b0 - a1 * b1
        r1 = r1.fp_sub(&r0);
        r1 = r1.fp_sub(&t);

        t = t.fp_double();
        r0 = r0.fp_sub(&t);

        Self { c0: r0, c1: r1 }
    }

    fn fp_neg(&self) -> Self {
        Fp2 {
            c0: self.c0.fp_neg(),
            c1: self.c1.fp_neg(),
        }
    }

    fn fp_div2(&self) -> Self {
        Fp2 {
            c0: self.c0.fp_div2(),
            c1: self.c1.fp_div2(),
        }
    }

    fn fp_inv(&self) -> Self {
        let mut r: Fp2 = Fp2::zero();

        let mut k = Fp::zero();
        let mut t = Fp::zero();

        let mut r0 = Fp::zero();
        let mut r1 = Fp::zero();

        if self.c0.is_zero() {
            // r0 = 0
            // r1 = -(2 * a1)^-1
            r1 = self.c1.fp_double();
            r1 = self.c1.fp_inv();
            r1 = r1.fp_neg();
        } else if self.c1.is_zero() {
            // r1 = 0
            // r0 = a0^-1
            r0 = self.c0.fp_inv();
        } else {
            // k = (a[0]^2 + 2 * a[1]^2)^-1
            k = self.c0.fp_sqr();
            t = self.c1.fp_sqr();
            t = t.fp_double();
            k = k.fp_add(&t);
            k = k.fp_inv();

            // r[0] = a[0] * k
            r0 = self.c0.fp_mul(&k);

            // r[1] = -a[1] * k
            r1 = self.c1.fp_mul(&k);
            r1 = r1.fp_neg();
        }
        r.c0 = r0;
        r.c1 = r1;
        r
    }
}

impl Fp2 {
    pub(crate) fn div(&self, rhs: &Self) -> Self {
        let t = rhs.fp_inv();
        self.fp_mul(&t)
    }

    pub(crate) fn conjugate(&self) -> Self {
        let r0 = self.c0;
        let r1 = self.c1.fp_neg();
        Self { c0: r0, c1: r1 }
    }

    pub(crate) fn a_mul_u(&self) -> Self {
        let mut r0 = Fp::zero();
        let mut a0 = Fp::zero();
        let mut a1 = Fp::zero();

        a0 = self.c0;
        a1 = self.c1;

        // r0 = -2 * a1
        r0 = a1.fp_double();
        r0 = r0.fp_neg();

        //r1 = a0
        Self { c0: r0, c1: a0 }
    }

    pub(crate) fn mul_u(&self, rhs: &Self) -> Self {
        let mut r0 = Fp::zero();
        let mut r1 = Fp::zero();
        let mut t = Fp::zero();

        // r0 = -2 * (a0 * b1 + a1 * b0)
        r0 = self.c0.fp_mul(&rhs.c1);
        t = self.c1.fp_mul(&rhs.c0);
        r0 = r0.fp_add(&t);
        r0 = r0.fp_double();
        r0 = r0.fp_neg();

        // r1 = a0 * b0 - 2 * a1 * b1
        r1 = self.c0.fp_mul(&rhs.c0);
        t = self.c1.fp_mul(&rhs.c1);
        t = t.fp_double();
        r1 = r1.fp_sub(&t);

        Self { c0: r0, c1: r1 }
    }

    pub(crate) fn mul_fp(&self, k: &Fp) -> Self {
        Fp2 {
            c0: self.c0.fp_mul(k),
            c1: self.c1.fp_mul(k),
        }
    }

    pub(crate) fn sqr_u(&self) -> Self {
        let mut r: Fp2 = Fp2::zero();
        let mut r0 = Fp::zero();
        let mut r1 = Fp::zero();
        let mut t = Fp::zero();

        // r0 = -4 * a0 * a1
        r0 = self.c0.fp_mul(&self.c1);
        r0 = r0.fp_double();
        r0 = r0.fp_double();
        r0 = r0.fp_neg();

        // r1 = a0^2 - 2 * a1^2
        r1 = self.c0.fp_sqr();
        t = self.c1.fp_sqr();
        t = t.fp_double();
        r1 = r1.fp_sub(&t);

        r.c0 = r0;
        r.c1 = r1;
        r
    }

    pub fn from_hex(hex: [&str; 2]) -> Fp2 {
        Fp2 {
            c0: fp_from_hex(hex[0]),
            c1: fp_from_hex(hex[1]),
        }
    }
}

#[cfg(test)]
mod test_mod_operation {
    use crate::fields::fp::{fp_from_mont, fp_to_mont};
    use crate::fields::fp2::Fp2;
    use crate::fields::FieldElement;

    #[test]
    fn test_mod_op() {
        let mut a: Fp2 = Fp2 {
            c0: [
                0x6215BBA5C999A7C7,
                0x47EFBA98A71A0811,
                0x5F3170153D278FF2,
                0xA7CF28D519BE3DA6,
            ],
            c1: [
                0x856DC76B84EBEB96,
                0x0736A96FA347C8BD,
                0x66BA0D262CBEE6ED,
                0x17509B092E845C12,
            ],
        };

        let mut b: Fp2 = Fp2 {
            c0: [
                0x8F14D65696EA5E32,
                0x414D2177386A92DD,
                0x6CE843ED24A3B573,
                0x29DBA116152D1F78,
            ],
            c1: [
                0x0AB1B6791B94C408,
                0x1CE0711C5E392CFB,
                0xE48AFF4B41B56501,
                0x9F64080B3084F733,
            ],
        };

        a.c0 = fp_to_mont(&a.c0);
        a.c1 = fp_to_mont(&a.c1);

        b.c0 = fp_to_mont(&b.c0);
        b.c1 = fp_to_mont(&b.c1);

        let mut r = a.fp_add(&b);
        r.c0 = fp_from_mont(&r.c0);
        r.c1 = fp_from_mont(&r.c1);
        r.c0.reverse();
        r.c1.reverse();
        println!("fp_add ={:x?}", r); // [1b6ac9eb2c47b62c, f61608b26c3c7e20, 674a48c4c509ac13, bbaf6d47d32c07c], c1: [74a3145c65ac54, 7541612178e584a9, 2248740e70606dc, aaafe2bcbd2f6a21]
    }
}
