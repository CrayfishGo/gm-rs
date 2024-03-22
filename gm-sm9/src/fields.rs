use std::fmt::Debug;
use std::ops::{Add, Mul, MulAssign, Neg, Sub};

mod fp;
mod fp2;
mod fp4;
mod fp12;


pub trait FieldElement:
Sized
+ Copy
+ Clone
+ PartialEq
+ Eq
+ Debug
{
    fn zero() -> Self;
    fn one() -> Self;
    fn is_zero(&self) -> bool;
    fn squared(&self) -> Self;
    fn double(&self) -> Self;
    fn triple(&self) -> Self;
    fn add(&self, rhs: &Self) -> Self;
    fn sub(&self, rhs: &Self) -> Self;
    fn mul(&self, rhs: &Self) -> Self;
    fn pow(&self, rhs: &[u64; 8]) -> Self;
    fn neg(&self) -> Self;
    fn div2(&self) -> Self;
    fn inverse(&self) -> Self;
}
