use core::fmt;
use core::ops::Add;
use std::cmp::Ordering;
use std::fmt::Display;
use std::hash;
use std::io::Cursor;
use std::ops::{Mul, Sub};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_bigint::BigUint;
use num_traits::Num;

use crate::{
    forward_ref_ref_binop, forward_ref_val_binop, forward_val_val_binop,
};
use crate::sm2::error::{Sm2Error, Sm2Result};
use crate::sm2::p256_ecc::P256C_PARAMS;

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
#[derive(Copy)]
pub struct FieldElement {
    pub(crate) inner: [u32; 8],
}

impl FieldElement {
    pub fn new(x: [u32; 8]) -> FieldElement {
        FieldElement { inner: x }
    }

    pub fn from_slice(x: &[u32]) -> FieldElement {
        let mut arr: [u32; 8] = [0; 8];
        arr.copy_from_slice(&x[0..8]);
        FieldElement::new(arr)
    }

    #[inline]
    pub fn from_number(x: u64) -> FieldElement {
        let mut arr: [u32; 8] = [0; 8];
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
            let x = c.read_u32::<BigEndian>().unwrap();
            elem.inner[i] = x;
        }
        Ok(elem)
    }

    pub fn to_biguint(&self) -> BigUint {
        let v = self.to_bytes_be();
        BigUint::from_bytes_be(&v[..])
    }

    pub fn from_biguint(bi: &BigUint) -> Sm2Result<FieldElement> {
        let v = bi.to_bytes_be();
        let mut num_v = [0u8; 32];
        num_v[32 - v.len()..32].copy_from_slice(&v[..]);
        FieldElement::from_bytes_be(&num_v[..])
    }

    pub fn div2(&self, carry: u32) -> FieldElement {
        let mut ret = FieldElement::zero();
        let mut carry = carry;

        let mut i = 0;
        while i < 8 {
            ret.inner[i] = (carry << 31) + (self.inner[i] >> 1);
            carry = self.inner[i] & 0x01;

            i += 1;
        }
        ret
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

    pub fn square(&self) -> FieldElement {
        self.clone() * self.clone()
    }

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
    pub fn modinv(&self) -> FieldElement {
        let ecc_p = &P256C_PARAMS.p;
        let mut ru = *self;
        let mut rv = ecc_p.clone();
        let mut ra = FieldElement::from_number(1);
        let mut rc = FieldElement::zero();

        while !ru.is_zero() {
            if ru.is_even() {
                ru = ru.div2(0);
                if ra.is_even() {
                    ra = ra.div2(0);
                } else {
                    let (sum, car) = self.add_raw(&ra.inner, &ecc_p.inner);
                    ra = FieldElement::new(sum).div2(car);
                }
            }

            if rv.is_even() {
                rv = rv.div2(0);
                if rc.is_even() {
                    rc = rc.div2(0);
                } else {
                    let (sum, car) = self.add_raw(&rc.inner, &ecc_p.inner);
                    rc = FieldElement::new(sum).div2(car);
                }
            }

            if ru >= rv {
                ru = &ru - &rv;
                ra = &ra - &rc;
            } else {
                rv = &rv - &ru;
                rc = &rc - &ra;
            }
        }
        rc
    }
}

impl FieldElement {
    fn mod_sub_raw(&self, a: &[u32; 8], b: &[u32; 8], modulus: &[u32; 8]) -> [u32; 8] {
        let (modulus_complete, _) = self.sub_raw(&[0; 8], &modulus);
        let (raw_diff, borrow) = self.sub_raw(a, b);
        if borrow == 1 {
            let (diff, _borrow) = self.sub_raw(&raw_diff, &modulus_complete);
            diff
        } else {
            raw_diff
        }
    }

    fn sub_raw(&self, a: &[u32; 8], b: &[u32; 8]) -> ([u32; 8], u32) {
        let mut sum = [0; 8];
        let mut borrow: u32 = 0;
        let mut j = 0;
        while j < 8 {
            let i = 7 - j;
            let t_sum: i64 = i64::from(a[i]) - i64::from(b[i]) - i64::from(borrow);
            if t_sum < 0 {
                sum[i] = (t_sum + (1 << 32)) as u32;
                borrow = 1;
            } else {
                sum[i] = t_sum as u32;
                borrow = 0;
            }
            j += 1;
        }
        (sum, borrow)
    }

    fn mod_add_raw(&self, a: &[u32; 8], b: &[u32; 8], modulus: &[u32; 8]) -> [u32; 8] {
        let (raw_sum, carry) = self.add_raw(a, b);
        if carry == 1 || raw_sum >= *modulus {
            let (sum, _borrow) = self.sub_raw(&raw_sum, &modulus);
            sum
        } else {
            raw_sum
        }
    }

    fn add_raw(&self, a: &[u32; 8], b: &[u32; 8]) -> ([u32; 8], u32) {
        let mut sum = [0; 8];
        let mut carry: u32 = 0;

        let t_sum: u64 = u64::from(a[7]) + u64::from(b[7]) + u64::from(carry);
        sum[7] = (t_sum & 0xffff_ffff) as u32;
        carry = (t_sum >> 32) as u32;

        let t_sum: u64 = u64::from(a[6]) + u64::from(b[6]) + u64::from(carry);
        sum[6] = (t_sum & 0xffff_ffff) as u32;
        carry = (t_sum >> 32) as u32;

        let t_sum: u64 = u64::from(a[5]) + u64::from(b[5]) + u64::from(carry);
        sum[5] = (t_sum & 0xffff_ffff) as u32;
        carry = (t_sum >> 32) as u32;

        let t_sum: u64 = u64::from(a[4]) + u64::from(b[4]) + u64::from(carry);
        sum[4] = (t_sum & 0xffff_ffff) as u32;
        carry = (t_sum >> 32) as u32;

        let t_sum: u64 = u64::from(a[3]) + u64::from(b[3]) + u64::from(carry);
        sum[3] = (t_sum & 0xffff_ffff) as u32;
        carry = (t_sum >> 32) as u32;

        let t_sum: u64 = u64::from(a[2]) + u64::from(b[2]) + u64::from(carry);
        sum[2] = (t_sum & 0xffff_ffff) as u32;
        carry = (t_sum >> 32) as u32;

        let t_sum: u64 = u64::from(a[1]) + u64::from(b[1]) + u64::from(carry);
        sum[1] = (t_sum & 0xffff_ffff) as u32;
        carry = (t_sum >> 32) as u32;

        let t_sum: u64 = u64::from(a[0]) + u64::from(b[0]) + u64::from(carry);
        sum[0] = (t_sum & 0xffff_ffff) as u32;
        carry = (t_sum >> 32) as u32;

        (sum, carry)
    }

    fn mod_mul_raw(&self, a: &[u32; 8], b: &[u32; 8], modulus: &[u32; 8]) -> [u32; 8] {
        let raw_prod = self.mul_raw(a, b);
        self.fast_reduction(&raw_prod, &modulus)
    }

    fn mul_raw(&self, a: &[u32; 8], b: &[u32; 8]) -> [u32; 16] {
        let mut local: u64 = 0;
        let mut carry: u64 = 0;
        let mut ret: [u32; 16] = [0; 16];

        let mut ret_idx = 0;
        while ret_idx < 15 {
            let index = 15 - ret_idx;
            let mut a_idx = 0;
            while a_idx < 8 {
                if a_idx > ret_idx {
                    break;
                }
                let b_idx = ret_idx - a_idx;
                if b_idx < 8 {
                    let (hi, lo) = self.u32_mul(a[7 - a_idx], b[7 - b_idx]);
                    local += lo;
                    carry += hi;
                }

                a_idx += 1;
            }
            carry += local >> 32;
            local &= 0xffff_ffff;
            ret[index] = local as u32;
            local = carry;
            carry = 0;

            ret_idx += 1;
        }
        ret[0] = local as u32;
        ret
    }

    #[inline(always)]
    fn u32_mul(&self, a: u32, b: u32) -> (u64, u64) {
        let uv = u64::from(a) * u64::from(b);
        let u = uv >> 32;
        let v = uv & 0xffff_ffff;
        (u, v)
    }

    // a quick algorithm to reduce elements on SCA-256 field
    // Reference:
    // http://ieeexplore.ieee.org/document/7285166/ for details
    #[inline]
    fn fast_reduction(&self, input: &[u32; 16], modulus: &[u32; 8]) -> [u32; 8] {
        let mut rs: [[u32; 8]; 10] = [[0; 8]; 10];
        let mut rx: [u32; 16] = [0; 16];

        let mut i = 0;
        while i < 16 {
            rx[i] = input[15 - i];
            i += 1;
        }

        rs[0] = [rx[7], rx[6], rx[5], rx[4], rx[3], rx[2], rx[1], rx[0]];
        rs[1] = [rx[15], 0, 0, 0, 0, 0, rx[15], rx[14]];
        rs[2] = [rx[14], 0, 0, 0, 0, 0, rx[14], rx[13]];
        rs[3] = [rx[13], 0, 0, 0, 0, 0, 0, 0];
        rs[4] = [rx[12], 0, rx[15], rx[14], rx[13], 0, 0, rx[15]];
        rs[5] = [rx[15], rx[15], rx[14], rx[13], rx[12], 0, rx[11], rx[10]];
        rs[6] = [rx[11], rx[14], rx[13], rx[12], rx[11], 0, rx[10], rx[9]];
        rs[7] = [rx[10], rx[11], rx[10], rx[9], rx[8], 0, rx[13], rx[12]];
        rs[8] = [rx[9], 0, 0, rx[15], rx[14], 0, rx[9], rx[8]];
        rs[9] = [rx[8], 0, 0, 0, rx[15], 0, rx[12], rx[11]];

        let mut carry: i32 = 0;
        let mut sum = [0; 8];

        let (rt, rc) = self.add_raw(&sum, &rs[1]);
        sum = rt;
        carry += rc as i32;
        let (rt, rc) = self.add_raw(&sum, &rs[2]);
        sum = rt;
        carry += rc as i32;
        let (rt, rc) = self.add_raw(&sum, &rs[3]);
        sum = rt;
        carry += rc as i32;
        let (rt, rc) = self.add_raw(&sum, &rs[4]);
        sum = rt;
        carry += rc as i32;

        let (rt, rc) = self.add_raw(&sum, &sum);
        sum = rt;
        carry = carry * 2 + rc as i32;

        let (rt, rc) = self.add_raw(&sum, &rs[5]);
        sum = rt;
        carry += rc as i32;
        let (rt, rc) = self.add_raw(&sum, &rs[6]);
        sum = rt;
        carry += rc as i32;
        let (rt, rc) = self.add_raw(&sum, &rs[7]);
        sum = rt;
        carry += rc as i32;
        let (rt, rc) = self.add_raw(&sum, &rs[8]);
        sum = rt;
        carry += rc as i32;
        let (rt, rc) = self.add_raw(&sum, &rs[9]);
        sum = rt;
        carry += rc as i32;

        let mut part3 = [0; 8];
        let rt: u64 = u64::from(rx[8]) + u64::from(rx[9]) + u64::from(rx[13]) + u64::from(rx[14]);
        part3[5] = (rt & 0xffff_ffff) as u32;
        part3[4] = (rt >> 32) as u32;

        let (rt, rc) = self.add_raw(&sum, &rs[0]);
        sum = rt;
        carry += rc as i32;

        let (rt, rc) = self.sub_raw(&sum, &part3);
        sum = rt;
        carry -= rc as i32;

        while carry > 0 || sum >= *modulus {
            let (rs, rb) = self.sub_raw(&sum, modulus);
            sum = rs;
            carry -= rb as i32;
        }
        sum
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

forward_val_val_binop!(impl Add for FieldElement, add);
forward_ref_ref_binop!(impl Add for FieldElement, add);
forward_ref_val_binop!(impl Add for FieldElement, add);
impl<'a> Add<&'a FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(mut self, rhs: &FieldElement) -> Self::Output {
        self.inner = self.mod_add_raw(&self.inner, &rhs.inner, &P256C_PARAMS.p.inner);
        self
    }
}

forward_val_val_binop!(impl Sub for FieldElement, sub);
forward_ref_ref_binop!(impl Sub for FieldElement, sub);
forward_ref_val_binop!(impl Sub for FieldElement, sub);
impl<'a> Sub<&'a FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(mut self, rhs: &'a FieldElement) -> Self::Output {
        self.inner = self.mod_sub_raw(&self.inner, &rhs.inner, &P256C_PARAMS.p.inner);
        self
    }
}

forward_val_val_binop!(impl Mul for FieldElement, mul);
forward_ref_ref_binop!(impl Mul for FieldElement, mul);
forward_ref_val_binop!(impl Mul for FieldElement, mul);
impl<'a> Mul<&'a FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(mut self, rhs: &'a FieldElement) -> Self::Output {
        self.inner = self.mod_mul_raw(&self.inner, &rhs.inner, &P256C_PARAMS.p.inner);
        self
    }
}

impl Add<u64> for FieldElement {
    type Output = FieldElement;

    fn add(mut self, rhs: u64) -> Self::Output {
        self.inner = self.mod_add_raw(
            &self.inner,
            &FieldElement::from_number(rhs).inner,
            &P256C_PARAMS.p.inner,
        );
        self
    }
}

impl Mul<u64> for FieldElement {
    type Output = FieldElement;

    fn mul(mut self, rhs: u64) -> Self::Output {
        self.inner = self.mod_mul_raw(
            &self.inner,
            &FieldElement::from_number(rhs).inner,
            &P256C_PARAMS.p.inner,
        );
        self
    }
}

impl<'a> Mul<u64> for &'a FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: u64) -> Self::Output {
        let mut s = self.clone();
        s.inner = self.mod_mul_raw(
            &s.inner,
            &FieldElement::from_number(rhs).inner,
            &P256C_PARAMS.p.inner,
        );
        s
    }
}

impl Default for FieldElement {
    #[inline]
    fn default() -> FieldElement {
        FieldElement { inner: [0; 8] }
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
