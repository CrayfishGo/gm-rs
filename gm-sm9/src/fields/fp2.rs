use crate::fields::fp::Fp;
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
}
