use crate::sm2::p256_ecc::P256C_PARAMS;
use crate::{
    forward_ref_ref_binop, forward_ref_val_binop, forward_val_ref_binop, forward_val_val_binop,
};
use core::fmt;
use core::ops::{Add, AddAssign};
use num_bigint::{BigUint, ParseBigIntError};
use num_integer::{div_rem, Integer};
use num_traits::{FromPrimitive, Num, One, ToPrimitive, Zero};
use std::cmp::Ordering;
use std::fmt::{Display, Formatter};
use std::hash;
use std::hash::Hash;
use std::ops::{Mul, Rem, Sub};

pub struct FieldElement {
    inner: BigUint,
}

impl FieldElement {
    #[inline]
    pub fn from_u32(n: u32) -> FieldElement {
        FieldElement {
            inner: BigUint::from_u32(n).unwrap(),
        }
    }

    #[inline]
    pub fn to_u32_digits(&self) -> Vec<u32> {
        self.inner.to_u32_digits()
    }

    #[inline]
    pub fn from_bytes_be(bytes: &[u8]) -> FieldElement {
        FieldElement {
            inner: BigUint::from_bytes_be(bytes),
        }
    }

    pub fn from_str_radix(s: &str, radix: u32) -> Result<FieldElement, ParseBigIntError> {
        let r = BigUint::from_str_radix(s, radix);
        match r {
            Ok(inner) => Ok(FieldElement { inner }),
            Err(e) => Err(e),
        }
    }

    #[inline]
    pub fn to_str_radix(&self, radix: u32) -> String {
        self.inner.to_str_radix(radix)
    }

    pub fn zero() -> FieldElement {
        FieldElement {
            inner: BigUint::zero(),
        }
    }

    pub fn one() -> FieldElement {
        FieldElement {
            inner: BigUint::one(),
        }
    }

    pub fn is_zero(&self) -> bool {
        self.inner.is_zero()
    }

    pub fn modpow(&self, exponent: &Self, modulus: &Self) -> Self {
        FieldElement {
            inner: self.inner.modpow(&exponent.inner, &modulus.inner),
        }
    }
}

impl Clone for FieldElement {
    #[inline]
    fn clone(&self) -> Self {
        FieldElement {
            inner: self.inner.clone(),
        }
    }

    #[inline]
    fn clone_from(&mut self, other: &Self) {
        self.inner.clone_from(&other.inner);
    }
}

impl hash::Hash for FieldElement {
    #[inline]
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.inner.hash(state)
    }
}

impl PartialEq for FieldElement {
    #[inline]
    fn eq(&self, other: &FieldElement) -> bool {
        self.inner == other.inner
    }
}
impl Eq for FieldElement {}

impl PartialOrd for FieldElement {
    #[inline]
    fn partial_cmp(&self, other: &FieldElement) -> Option<Ordering> {
        self.inner.partial_cmp(&other.inner)
    }
}

impl Ord for FieldElement {
    #[inline]
    fn cmp(&self, other: &FieldElement) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl From<BigUint> for FieldElement {
    fn from(n: BigUint) -> Self {
        Self { inner: n }
    }
}

forward_val_val_binop!(impl Add for FieldElement, add);
forward_ref_ref_binop!(impl Add for FieldElement, add);
forward_ref_val_binop!(impl Add for FieldElement, add);
impl<'a> Add<&'a FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(mut self, rhs: &FieldElement) -> Self::Output {
        self.inner = (self.inner + &rhs.inner) % &P256C_PARAMS.p.inner;
        self
    }
}

forward_val_val_binop!(impl Sub for FieldElement, sub);
forward_ref_ref_binop!(impl Sub for FieldElement, sub);
forward_ref_val_binop!(impl Sub for FieldElement, sub);
impl<'a> Sub<&'a FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(mut self, rhs: &'a FieldElement) -> Self::Output {
        let modulus = &P256C_PARAMS.p.inner;
        if self.inner >= rhs.inner {
            self.inner = (self.inner - &rhs.inner) % modulus;
        } else {
            // 负数取模
            let d = &rhs.inner - self.inner;
            let e = d.div_ceil(modulus);
            self.inner = e * modulus - d
        }
        self
    }
}

forward_val_val_binop!(impl Mul for FieldElement, mul);
forward_ref_ref_binop!(impl Mul for FieldElement, mul);
forward_ref_val_binop!(impl Mul for FieldElement, mul);
impl<'a> Mul<&'a FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(mut self, rhs: &'a FieldElement) -> Self::Output {
        self.inner = (self.inner * &rhs.inner) % &P256C_PARAMS.p.inner;
        self
    }
}

impl Add<u32> for FieldElement {
    type Output = FieldElement;

    fn add(mut self, rhs: u32) -> Self::Output {
        self.inner = (self.inner + rhs) % &P256C_PARAMS.p.inner;
        self
    }
}

impl Mul<u32> for FieldElement {
    type Output = FieldElement;

    fn mul(mut self, rhs: u32) -> Self::Output {
        self.inner = (self.inner * rhs) % &P256C_PARAMS.p.inner;
        self
    }
}

impl<'a> Mul<u32> for &'a FieldElement {
    type Output = FieldElement;

    fn mul(mut self, rhs: u32) -> Self::Output {
        let mut s = self.clone();
        s.inner = (&self.inner * rhs) % &P256C_PARAMS.p.inner;
        s
    }
}

forward_val_ref_binop!(impl Rem for FieldElement, rem);
forward_ref_val_binop!(impl Rem for FieldElement, rem);
impl Rem<FieldElement> for FieldElement {
    type Output = FieldElement;

    #[inline]
    fn rem(self, other: FieldElement) -> FieldElement {
        FieldElement {
            inner: self.inner % other.inner,
        }
    }
}

impl<'a, 'b> Rem<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    #[inline]
    fn rem(self, other: &FieldElement) -> FieldElement {
        FieldElement {
            inner: &self.inner % &other.inner,
        }
    }
}

impl Default for FieldElement {
    #[inline]
    fn default() -> FieldElement {
        FieldElement {
            inner: Zero::zero(),
        }
    }
}

impl fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad_integral(true, "", &self.to_str_radix(10))
    }
}

impl fmt::LowerHex for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad_integral(true, "0x", &self.to_str_radix(16))
    }
}

impl fmt::UpperHex for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = self.to_str_radix(16);
        s.make_ascii_uppercase();
        f.pad_integral(true, "0x", &s)
    }
}

impl fmt::Binary for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad_integral(true, "0b", &self.to_str_radix(2))
    }
}

impl fmt::Octal for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad_integral(true, "0o", &self.to_str_radix(8))
    }
}

#[cfg(test)]
mod test {
    use crate::sm2::field::FieldElement;
    use crate::sm2::p256_ecc::P256C_PARAMS;

    #[test]
    fn test_add() {}
}
