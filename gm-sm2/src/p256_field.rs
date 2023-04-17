use core::ops::Add;
use std::io::Cursor;
use std::ops::{Mul, Sub};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_bigint::BigUint;
use num_traits::Num;

use crate::{FeOperation, forward_ref_ref_binop, forward_ref_val_binop, forward_val_val_binop};
use crate::error::{Sm2Error, Sm2Result};
use crate::p256_ecc::P256C_PARAMS;

pub type Fe = [u32; 8];

pub trait Conversion {
    fn fe_to_bigunit(&self) -> BigUint;

    fn bigunit_fe(&self) -> Fe;
}

// p = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
// p = 2^256 − 2^224 − 2^96 + 2^32 − 1
pub const ECC_P: Fe = [
    0xffff_fffe,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0x0000_0000,
    0xffff_ffff,
    0xffff_ffff,
];

/// 素域Fp的域元素
///
/// 这里我们规定一个有限域Fp
///
/// * 取大质数p，则有限域中有p-1个有限元：0，1，2...p-1
/// * 域元素的加法是整数的模p加法，即若a,b ∈ Fp，则a+b = (a+b) mod p；
/// * 域元素的乘法是整数的模p乘法，即若a,b ∈ Fp，则a · b = (a · b) mod p
/// * 域元素的减法是整数的模p减法，即若a,b ∈ Fp，则a - b = (a - b) mod p
/// * Fp上的除法就是乘除数的乘法逆元`a÷b≡c(mod p)`，即 `a×b^(-1)≡c (mod p)`
/// * Fp的乘法单位元是整数1
/// * Fp的加法单位元是整数0
/// * Fp域上满足交换律，结合律，分配律
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct FieldElement {
    pub(crate) inner: Fe,
}

impl FieldElement {
    pub fn new(x: Fe) -> FieldElement {
        FieldElement { inner: x }
    }

    #[inline]
    pub fn from_slice(x: &[u32]) -> FieldElement {
        let mut arr: Fe = [0; 8];
        arr.copy_from_slice(&x[..]);
        FieldElement::new(arr)
    }

    #[inline]
    pub fn from_number(x: u64) -> FieldElement {
        let mut arr: Fe = [0; 8];
        arr[7] = (x & 0xffff_ffff) as u32;
        arr[6] = (x >> 32) as u32;
        FieldElement { inner: arr }
    }

    #[inline]
    pub fn to_bytes_be(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        for i in 0..8 {
            ret.write_u32::<BigEndian>(self.inner[i]).unwrap();
        }
        ret
    }

    #[inline]
    pub fn from_bytes_be(bytes: &[u8]) -> Sm2Result<FieldElement> {
        if bytes.len() != 32 {
            return Err(Sm2Error::InvalidFieldLen);
        }
        let mut elem = FieldElement::zero();
        let mut c = Cursor::new(bytes);
        for i in 0..8 {
            elem.inner[i] = c.read_u32::<BigEndian>().unwrap();
        }
        Ok(elem)
    }

    #[inline]
    pub fn to_biguint(&self) -> BigUint {
        let v = self.to_bytes_be();
        BigUint::from_bytes_be(&v[..])
    }

    #[inline]
    pub fn from_biguint(bi: &BigUint) -> Sm2Result<FieldElement> {
        let v = bi.to_bytes_be();
        let mut num_v = [0; 32];
        num_v[32 - v.len()..32].copy_from_slice(&v[..]);
        FieldElement::from_bytes_be(&num_v[..])
    }

    pub fn sqrt(&self) -> Sm2Result<FieldElement> {
        // p = 4 * u + 3
        // u = u + 1
        let u = BigUint::from_str_radix(
            "28948022302589062189105086303505223191562588497981047863605298483322421248000",
            10,
        )
        .unwrap();
        let y = self.modpow(&u);
        let z = &y.square();
        if z == self {
            Ok(y)
        } else {
            Err(Sm2Error::FieldSqrtError)
        }
    }

    #[inline]
    pub fn to_str_radix(&self, radix: u32) -> String {
        self.to_biguint().to_str_radix(radix)
    }

    pub fn zero() -> FieldElement {
        FieldElement::new([0; 8])
    }

    pub fn one() -> FieldElement {
        FieldElement::from_number(1)
    }

    pub fn is_even(&self) -> bool {
        self.inner[7] & 0x01 == 0
    }

    pub fn is_zero(&self) -> bool {
        self.inner == [0; 8]
    }

    pub fn is_one(&self) -> bool {
        self.inner[7] == 1
    }

    #[inline]
    pub fn square(&self) -> FieldElement {
        self * self
    }

    #[inline]
    pub fn double(&self) -> FieldElement {
        self + self
    }

    #[inline]
    pub fn modpow(&self, exponent: &BigUint) -> Self {
        let u = FieldElement::from_biguint(exponent).unwrap();
        let mut q0 = FieldElement::from_number(1);
        let mut q1 = *self;
        let mut i = 0;
        while i < 256 {
            let index = i as usize / 32;
            let bit = 31 - i as usize % 32;

            let sum = &q0 * &q1;
            if (u.inner[index] >> bit) & 0x01 == 0 {
                q1 = sum;
                q0 = q0.square();
            } else {
                q0 = sum;
                q1 = q1.square();
            }
            i += 1;
        }
        q0
    }

    // calculate x^(-1) mod p
    #[inline]
    pub fn modinv(&self) -> FieldElement {
        let ecc_p = &P256C_PARAMS.p;
        let ret = self.inner.inv(&ecc_p.inner);
        FieldElement::new(ret)
    }
}

forward_val_val_binop!(impl Add for FieldElement, add);
forward_ref_ref_binop!(impl Add for FieldElement, add);
forward_ref_val_binop!(impl Add for FieldElement, add);
impl<'a> Add<&'a FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(mut self, rhs: &FieldElement) -> Self::Output {
        self.inner = self.inner.mod_add(&rhs.inner, &ECC_P);
        self
    }
}

forward_val_val_binop!(impl Sub for FieldElement, sub);
forward_ref_ref_binop!(impl Sub for FieldElement, sub);
forward_ref_val_binop!(impl Sub for FieldElement, sub);
impl<'a> Sub<&'a FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(mut self, rhs: &'a FieldElement) -> Self::Output {
        self.inner = self.inner.mod_sub(&rhs.inner, &ECC_P);
        self
    }
}

forward_val_val_binop!(impl Mul for FieldElement, mul);
forward_ref_ref_binop!(impl Mul for FieldElement, mul);
forward_ref_val_binop!(impl Mul for FieldElement, mul);
impl<'a> Mul<&'a FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(mut self, rhs: &'a FieldElement) -> Self::Output {
        self.inner = self.inner.mod_mul(&rhs.inner, &ECC_P);
        self
    }
}

impl Default for FieldElement {
    #[inline]
    fn default() -> FieldElement {
        FieldElement {
            inner: [0; 8],
        }
    }
}


#[cfg(test)]
mod test_fe{
    use crate::p256_field::FieldElement;
    use crate::sm2::p256_field::FieldElement;

    #[test]
    fn test_mod_mul(){
        let a = FieldElement::new([
            764497930, 2477372445, 473039778, 1327312203, 3110691882, 1307193102, 2665428562, 967816337,
        ]);
        let b = FieldElement::new([
            2873589426, 3315627933, 3055686524, 325110103, 3264434653, 2512214348, 3018997295,
            3617546169,
        ]);

        let ret = a * b;
        println!("{:?}", ret)
    }

}
