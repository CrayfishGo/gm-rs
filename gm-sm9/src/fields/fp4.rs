use crate::fields::FieldElement;
use crate::fields::fp2::Fp2;

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
        todo!()
    }

    fn double(&self) -> Self {
        todo!()
    }

    fn triple(&self) -> Self {
        todo!()
    }

    fn add(&self, rhs: &Self) -> Self {
        todo!()
    }

    fn sub(&self, rhs: &Self) -> Self {
        todo!()
    }

    fn mul(&self, rhs: &Self) -> Self {
        todo!()
    }

    fn pow(&self, rhs: &[u64; 8]) -> Self {
        todo!()
    }

    fn neg(&self) -> Self {
        todo!()
    }

    fn div2(&self) -> Self {
        todo!()
    }

    fn inverse(&self) -> Self {
        todo!()
    }
}