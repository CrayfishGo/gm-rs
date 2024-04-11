use std::fmt::Debug;

pub mod fn64;
pub mod fp64;

pub trait FieldModOperation: Sized + Copy + Clone + PartialEq + Eq + Debug {
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
    fn to_byte_be(&self) -> Vec<u8>;
    fn from_byte_be(input: &[u8]) -> Self;
}
