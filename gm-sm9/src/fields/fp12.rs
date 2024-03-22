use crate::fields::FieldElement;
use crate::fields::fp4::Fp4;

#[derive(Debug, Copy, Clone)]
pub struct Fp12 {
    pub(crate) c0: Fp4,
    pub(crate) c1: Fp4,
    pub(crate) c2: Fp4,
}

impl PartialEq for Fp12 {
    fn eq(&self, other: &Self) -> bool {
        todo!()
    }
}

impl Eq for Fp12 {}

impl FieldElement for Fp12 {
    fn zero() -> Self {
        Self {
            c0: Fp4::zero(),
            c1: Fp4::zero(),
            c2: Fp4::zero(),
        }
    }

    fn one() -> Self {
        Self {
            c0: Fp4::one(),
            c1: Fp4::zero(),
            c2: Fp4::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero() && self.c2.is_zero()
    }

    fn squared(&self) -> Self {
        todo!()
    }

    fn double(&self) -> Self {
        Self {
            c0: self.c0.double(),
            c1: self.c1.double(),
            c2: self.c2.double(),
        }
    }

    fn triple(&self) -> Self {
        let t = self.double();
        t.add(self)
    }

    fn add(&self, rhs: &Self) -> Self {
        Self {
            c0: self.c0.add(&rhs.c0),
            c1: self.c1.add(&rhs.c1),
            c2: self.c2.add(&rhs.c2),
        }
    }

    fn sub(&self, rhs: &Self) -> Self {
        Self {
            c0: self.c0.sub(&rhs.c0),
            c1: self.c1.sub(&rhs.c1),
            c2: self.c2.sub(&rhs.c2),
        }
    }

    fn mul(&self, rhs: &Self) -> Self {
        todo!()
    }

    fn neg(&self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
            c2: self.c2.neg(),
        }
    }

    fn div2(&self) -> Self {
        Self {
            c0: self.c0.div2(),
            c1: self.c1.div2(),
            c2: self.c2.div2(),
        }
    }

    fn inverse(&self) -> Self {
        todo!()
    }
}