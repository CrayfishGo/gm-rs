use std::fmt::Debug;
use std::ops::{Add, Mul, MulAssign, Neg, Sub};

pub mod fp;
pub(crate) mod fp12;
pub(crate) mod fp2;
pub(crate) mod fp4;
pub(crate) mod r#fn;

pub trait FieldElement: Sized + Copy + Clone + PartialEq + Eq + Debug {
    fn zero() -> Self;
    fn one() -> Self;
    fn is_zero(&self) -> bool;
    fn fp_sqr(&self) -> Self;
    fn fp_double(&self) -> Self;
    fn fp_triple(&self) -> Self;
    fn fp_add(&self, rhs: &Self) -> Self;
    fn fp_sub(&self, rhs: &Self) -> Self;
    fn fp_mul(&self, rhs: &Self) -> Self;
    fn fp_neg(&self) -> Self;
    fn fp_div2(&self) -> Self;
    fn fp_inv(&self) -> Self;
}
