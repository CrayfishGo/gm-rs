use crate::fields::FieldElement;
use crate::fields::fp::Fp;

const SM9_FP2_ZERO: [[u64; 8]; 2] = [[0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0]];
const SM9_FP2_U: [[u64; 8]; 2] = [[0, 0, 0, 0, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0, 0, 0]];
const SM9_FP2_5U: [[u64; 8]; 2] = [[0, 0, 0, 0, 0, 0, 0, 0], [5, 0, 0, 0, 0, 0, 0, 0]];

#[derive(Debug, Copy, Clone)]
pub struct Fp2 {
    pub(crate) c0: Fp,
    pub(crate) c1: Fp,
}

impl PartialEq for Fp2 {
    fn eq(&self, other: &Self) -> bool {
        todo!()
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

    fn squared(&self) -> Self {
        let mut r: Fp2 = Fp2::zero();
        let mut r0 = Fp::zero();
        let mut r1 = Fp::zero();
        let mut t = Fp::zero();

        // r0 = a0^2 - 2 * a1^2
        r0 = self.c0.squared();
        t = self.c1.squared();
        t = t.double();
        r0 = r0.sub(&t);

        // r1 = 2 * a0 * a1
        r1 = self.c0.mul(&self.c1);
        r1 = r1.double();
        r.c0 = r0;
        r.c1 = r1;
        r
    }

    fn double(&self) -> Self {
        Fp2 {
            c0: self.c0.double(),
            c1: self.c1.double(),
        }
    }

    fn triple(&self) -> Self {
        Fp2 {
            c0: self.c0.triple(),
            c1: self.c1.triple(),
        }
    }

    fn add(&self, rhs: &Self) -> Self {
        Fp2 {
            c0: self.c0.add(&rhs.c0),
            c1: self.c1.add(&rhs.c1),
        }
    }

    fn sub(&self, rhs: &Self) -> Self {
        Fp2 {
            c0: self.c0.sub(&rhs.c0),
            c1: self.c1.sub(&rhs.c1),
        }
    }

    fn mul(&self, rhs: &Self) -> Self {
        let mut r = Fp2::zero();
        let mut r0 = Fp::zero();
        let mut r1 = Fp::zero();
        let mut t = Fp::zero();
        // r0 = a0 * b0 - 2 * a1 * b1
        r0 = self.c0.mul(&rhs.c0);
        t = self.c1.mul(&rhs.c1);
        t = t.double();
        r0 = r0.sub(&t);
        r.c0 = r0;

        // r1 = a0 * b1 + a1 * b0
        r1 = self.c0.mul(&rhs.c1);
        t = self.c1.mul(&rhs.c0);
        r1 = r1.add(&t);
        r.c1 = r1;
        r
    }

    fn neg(&self) -> Self {
        Fp2 {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
        }
    }

    fn div2(&self) -> Self {
        Fp2 {
            c0: self.c0.div2(),
            c1: self.c1.div2(),
        }
    }

    fn inverse(&self) -> Self {
        let mut r: Fp2 = Fp2::zero();

        let mut k = Fp::zero();
        let mut t = Fp::zero();

        let mut r0 = Fp::zero();
        let mut r1 = Fp::zero();

        if self.c0.is_zero() {
            // r0 = 0
            // r1 = -(2 * a1)^-1
            r1 = self.c1.double();
            r1 = self.c1.inverse();
            r1 = r1.neg();
        } else if self.c1.is_zero() {
            // r1 = 0
            // r0 = a0^-1
            r0 = self.c0.inverse();
        } else {
            // k = (a[0]^2 + 2 * a[1]^2)^-1
            k = self.c0.squared();
            t = self.c1.squared();
            t = t.double();
            k = k.add(&t);
            k = k.inverse();

            // r[0] = a[0] * k
            r0 = self.c0.mul(&k);

            // r[1] = -a[1] * k
            r1 = self.c1.mul(&k);
            r1 = r1.neg();
        }
        r.c0 = r0;
        r.c1 = r1;
        r
    }
}

impl Fp2 {
    pub(crate) fn div(&self, rhs: &Self) -> Self {
        let t = rhs.inverse();
        self.mul(&t)
    }

    pub(crate) fn mul_u(&self, rhs: &Self) -> Self {
        let mut r: Fp2 = Fp2::zero();
        let mut r0 = Fp::zero();
        let mut r1 = Fp::zero();
        let mut t = Fp::zero();

        // r0 = -2 * (a0 * b1 + a1 * b0)
        r0 = self.c0.mul(&rhs.c1);
        t = self.c1.mul(&rhs.c0);
        r0 = r0.add(&t);
        r0 = r0.double();
        r0 = r0.neg();
        r.c0 = r0;

        // r1 = a0 * b0 - 2 * a1 * b1
        r1 = self.c0.mul(&rhs.c0);
        t = self.c1.mul(&rhs.c1);
        t = t.double();
        r1 = r1.sub(&t);
        r.c1 = r1;
        r
    }

    pub(crate) fn mul_fp(&self, k: &Fp) -> Self {
        Fp2 {
            c0: self.c0.mul(k),
            c1: self.c1.mul(k),
        }
    }

    pub(crate) fn sqr_u(&self) -> Self {
        let mut r: Fp2 = Fp2::zero();
        let mut r0 = Fp::zero();
        let mut r1 = Fp::zero();
        let mut t = Fp::zero();

        // r0 = -4 * a0 * a1
        r0 = self.c0.mul(&self.c1);
        r0 = r0.double();
        r0 = r0.double();
        r0 = r0.neg();

        // r1 = a0^2 - 2 * a1^2
        r1 = self.c0.squared();
        t = self.c1.squared();
        t = t.double();
        r1 = r1.sub(&t);

        r.c0 = r0;
        r.c1 = r1;
        r
    }
}