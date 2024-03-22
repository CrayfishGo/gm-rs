use crate::fields::FieldElement;
use crate::fields::fp2::Fp2;
use crate::fields::fp::Fp;

#[derive(Debug, Copy, Clone)]
pub struct Fp4 {
    pub(crate) c0: Fp2,
    pub(crate) c1: Fp2,
}

impl PartialEq for Fp4 {
    fn eq(&self, other: &Self) -> bool {
        todo!()
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

    fn squared(&self) -> Self {
        let mut r0 = Fp2::zero();
        let mut r1 = Fp2::zero();
        let mut t = Fp2::zero();

        r0 = self.c0.squared();
        t = self.c1.sqr_u();
        r0 = r0.add(&t);

        r1 = self.c0.mul(&self.c1);
        r1 = r1.double();

        Self {
            c0: r0,
            c1: r1,
        }
    }

    fn double(&self) -> Self {
        Self {
            c0: self.c0.double(),
            c1: self.c1.double(),
        }
    }

    fn triple(&self) -> Self {
        Self {
            c0: self.c0.triple(),
            c1: self.c1.triple(),
        }
    }

    fn add(&self, rhs: &Self) -> Self {
        Self {
            c0: self.c0.add(&rhs.c0),
            c1: self.c1.add(&rhs.c1),
        }
    }

    fn sub(&self, rhs: &Self) -> Self {
        Self {
            c0: self.c0.sub(&rhs.c0),
            c1: self.c1.sub(&rhs.c1),
        }
    }

    fn mul(&self, rhs: &Self) -> Self {
        let mut r0 = Fp2::zero();
        let mut r1 = Fp2::zero();
        let mut t = Fp2::zero();

        r0 = self.c0.mul(&rhs.c0);
        t = self.c1.mul_u(&rhs.c1);
        r0 = r0.add(&t);

        r1 = self.c0.mul(&rhs.c1);
        t = self.c1.mul(&rhs.c0);
        r1 = r1.add(&t);

        Self {
            c0: r0,
            c1: r1,
        }
    }

    fn neg(&self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
        }
    }

    fn div2(&self) -> Self {
        Self {
            c0: self.c0.div2(),
            c1: self.c1.div2(),
        }
    }

    fn inverse(&self) -> Self {
        let mut r0 = Fp2::zero();
        let mut r1 = Fp2::zero();
        let mut k = Fp2::zero();

        k = self.c1.sqr_u();
        r0 = self.c0.squared();
        k = k.sub(&r0);
        k = k.inverse();
        r0 = self.c0.mul(&k);
        r0 = r0.neg();

        r1 = self.c1.mul(&k);

        Self {
            c0: r0,
            c1: r1,
        }
    }
}

impl Fp4 {
    pub(crate) fn mul_fp(&self, k: &Fp) -> Self {
        Self {
            c0: self.c0.mul_fp(k),
            c1: self.c1.mul_fp(k),
        }
    }

    pub(crate) fn mul_fp2(&self, k: &Fp2) -> Self {
        Self {
            c0: self.c0.mul(k),
            c1: self.c1.mul(k),
        }
    }

    pub(crate) fn mul_v(&self, b: &Self) -> Self {
        let mut r0 = Fp2::zero();
        let mut r1 = Fp2::zero();
        let mut t = Fp2::zero();

        r0 = self.c0.mul_u(&b.c1);
        t = self.c1.mul_u(&b.c0);
        r0 = r0.add(&t);

        r1 = self.c0.mul(&b.c0);
        t = self.c1.mul_u(&b.c1);
        r1 = r1.add(&t);

        Self {
            c0: r0,
            c1: r1,
        }
    }

    pub(crate) fn sqr_v(&self) -> Self {
        let mut r0 = Fp2::zero();
        let mut r1 = Fp2::zero();
        let mut t = Fp2::zero();

        t = self.c0.mul_u(&self.c1);
        r0 = t.double();

        r1 = self.c0.squared();
        t = self.c1.sqr_u();
        r1 = r1.add(&t);

        Self {
            c0: r0,
            c1: r1,
        }
    }
}