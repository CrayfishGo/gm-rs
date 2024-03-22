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

impl FieldElement for Fp12{
    fn zero() -> Self {
        todo!()
    }

    fn one() -> Self {
        todo!()
    }

    fn is_zero(&self) -> bool {
        todo!()
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