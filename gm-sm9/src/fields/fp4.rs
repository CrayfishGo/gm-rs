use crate::fields::fp::Fp;
use crate::fields::fp2::Fp2;
use crate::fields::FieldElement;

#[derive(Debug, Copy, Clone)]
pub struct Fp4 {
    pub(crate) c0: Fp2,
    pub(crate) c1: Fp2,
}

impl Fp4 {
    pub(crate) fn fp_mul_fp(&self, k: &Fp) -> Fp4 {
        Self {
            c0: self.c0.fp_mul_fp(k),
            c1: self.c1.fp_mul_fp(k),
        }
    }

    pub(crate) fn fp_mul_fp2(&self, k: &Fp2) -> Fp4 {
        Self {
            c0: self.c0.fp_mul(k),
            c1: self.c1.fp_mul(k),
        }
    }
}

impl PartialEq for Fp4 {
    fn eq(&self, other: &Self) -> bool {
        self.c0.eq(&other.c0) && self.c1.eq(&other.c1)
    }
}

impl Eq for Fp4 {}

impl FieldElement for Fp4 {
    fn zero() -> Self {
        Fp4 {
            c0: Fp2::zero(),
            c1: Fp2::zero(),
        }
    }

    fn one() -> Self {
        Fp4 {
            c0: Fp2::one(),
            c1: Fp2::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    fn fp_sqr(&self) -> Self {
        let mut r0 = Fp2::zero();
        let mut r1 = Fp2::zero();
        let mut t = Fp2::zero();

        r1 = self.c0.fp_add(&self.c1);
        r1 = r1.fp_sqr();

        r0 = self.c0.fp_sqr();
        t = self.c1.fp_sqr();

        r1 = r1.fp_sub(&r0);
        r1 = r1.fp_sub(&t);

        t = t.a_mul_u();
        r0 = r0.fp_add(&t);

        Self { c0: r0, c1: r1 }
    }

    fn fp_double(&self) -> Self {
        Self {
            c0: self.c0.fp_double(),
            c1: self.c1.fp_double(),
        }
    }

    fn fp_triple(&self) -> Self {
        Self {
            c0: self.c0.fp_triple(),
            c1: self.c1.fp_triple(),
        }
    }

    fn fp_add(&self, rhs: &Self) -> Self {
        Self {
            c0: self.c0.fp_add(&rhs.c0),
            c1: self.c1.fp_add(&rhs.c1),
        }
    }

    fn fp_sub(&self, rhs: &Self) -> Self {
        Self {
            c0: self.c0.fp_sub(&rhs.c0),
            c1: self.c1.fp_sub(&rhs.c1),
        }
    }

    fn fp_mul(&self, rhs: &Self) -> Self {
        let mut r0 = Fp2::zero();
        let mut r1 = Fp2::zero();
        let mut t = Fp2::zero();

        r0 = self.c0.fp_add(&self.c1);
        t = rhs.c0.fp_add(&rhs.c1);
        r1 = t.fp_mul(&r0);

        r0 = self.c0.fp_mul(&rhs.c0);
        t = self.c1.fp_mul(&rhs.c1);

        r1 = r1.fp_sub(&r0);
        r1 = r1.fp_sub(&t);

        t = t.a_mul_u();
        r0 = r0.fp_add(&t);

        Self { c0: r0, c1: r1 }
    }

    fn fp_neg(&self) -> Self {
        Self {
            c0: self.c0.fp_neg(),
            c1: self.c1.fp_neg(),
        }
    }

    fn fp_div2(&self) -> Self {
        Self {
            c0: self.c0.fp_div2(),
            c1: self.c1.fp_div2(),
        }
    }

    fn fp_inv(&self) -> Self {
        let mut r0 = Fp2::zero();
        let mut r1 = Fp2::zero();
        let mut k = Fp2::zero();

        k = self.c1.sqr_u();
        r0 = self.c0.fp_sqr();
        k = k.fp_sub(&r0);
        k = k.fp_inv();

        r0 = self.c0.fp_mul(&k);
        r0 = r0.fp_neg();

        r1 = self.c1.fp_mul(&k);

        Self { c0: r0, c1: r1 }
    }

    fn to_bytes_be(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend_from_slice(self.c1.to_bytes_be().as_slice());
        bytes.extend_from_slice(self.c0.to_bytes_be().as_slice());
        bytes
    }
}

impl Fp4 {
    pub(crate) fn mont_one() -> Self {
        Fp4 {
            c0: Fp2 {
                c0: [
                    0x1a9064d81caeba83,
                    0xde0d6cb4e5851124,
                    0x29fc54b00a7138ba,
                    0x49bffffffd5c590e,
                ],
                c1: [0, 0, 0, 0],
            },
            c1: Fp2::zero(),
        }
    }

    pub(crate) fn fp_mul_v(&self, b: &Self) -> Self {
        let mut r0 = Fp2::zero();
        let mut r1 = Fp2::zero();
        let mut t = Fp2::zero();

        r0 = self.c0.fp_mul_u(&b.c1);
        t = self.c1.fp_mul_u(&b.c0);
        r0 = r0.fp_add(&t);

        r1 = self.c0.fp_mul(&b.c0);
        t = self.c1.fp_mul_u(&b.c1);
        r1 = r1.fp_add(&t);

        Self { c0: r0, c1: r1 }
    }

    pub(crate) fn a_mul_v(&self) -> Self {
        let mut r0 = Fp2::zero();
        let mut a0 = Fp2::zero();
        let mut a1 = Fp2::zero();

        a0 = self.c0;
        a1 = self.c1;

        //r1 = a0
        //r0 = a1 * u
        r0 = a1.a_mul_u();

        Self { c0: r0, c1: a0 }
    }

    pub(crate) fn conjugate(&self) -> Self {
        let r0 = self.c0;
        let r1 = self.c1.fp_neg();
        Self { c0: r0, c1: r1 }
    }

    pub(crate) fn sqr_v(&self) -> Self {
        let mut r0 = Fp2::zero();
        let mut r1 = Fp2::zero();
        let mut t = Fp2::zero();

        t = self.c0.fp_mul_u(&self.c1);
        r0 = t.fp_double();

        r1 = self.c0.fp_sqr();
        t = self.c1.sqr_u();
        r1 = r1.fp_add(&t);

        Self { c0: r0, c1: r1 }
    }
}
