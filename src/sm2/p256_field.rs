use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use core::fmt;
use core::ops::Add;
use std::cmp::Ordering;
use std::fmt::Display;
use std::hash;
use std::io::Cursor;
use std::ops::{Mul, Rem, Sub};

use num_bigint::{BigUint, ParseBigIntError};
use num_integer::Integer;
use num_traits::{FromPrimitive, Num, One, Zero};

use crate::sm2::error::{Sm2Error, Sm2Result};
use crate::sm2::p256_ecc::P256C_PARAMS;
use crate::{
    forward_ref_ref_binop, forward_ref_val_binop, forward_val_ref_binop, forward_val_val_binop,
};

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
    pub fn to_bytes_be(&self) -> Vec<u8> {
        self.inner.to_bytes_be()
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

    pub fn sqrt(&self) -> Sm2Result<FieldElement> {
        // p = 4 * u + 3
        // u = u + 1
        let u = FieldElement::from_str_radix(
            "28948022302589062189105086303505223191562588497981047863605298483322421248000",
            10,
        )
        .unwrap();
        let y = self.modpow(&u, &P256C_PARAMS.p);
        let z = &y * &y;
        if z == *self {
            Ok(y)
        } else {
            Err(Sm2Error::FieldSqrtError)
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
    pub fn inner(&self) -> &BigUint {
        &self.inner
    }

    // calculate x^(-1) mod p
    pub fn modinv(&self) -> FieldElement {
        let ecc_p = &P256C_PARAMS.p;
        self.modpow(&(ecc_p - FieldElement::from_u32(2)), ecc_p)
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
        // let a = from_biguint(&self.inner);
        // let b = from_biguint(&rhs.inner);
        // let p = from_biguint(&P256C_PARAMS.p.inner);
        // let r = mod_mul_raw(&a, &b, &p);
        // FieldElement {
        //     inner: to_bigunit(&r),
        // }
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

    fn mul(self, rhs: u32) -> Self::Output {
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

pub fn from_biguint(bi: &BigUint) -> [u32; 8] {
    let v = bi.to_bytes_be();
    let mut num_v = [0u8; 32];
    num_v[32 - v.len()..32].copy_from_slice(&v[..]);

    let mut elem = [0; 8];
    let mut c = Cursor::new(num_v);
    for i in 0..8 {
        let x = c.read_u32::<BigEndian>().unwrap();
        elem[i] = x;
    }
    elem
}

pub fn to_bigunit(value: &[u32; 8]) -> BigUint {
    let mut ret: Vec<u8> = Vec::new();
    for i in 0..8 {
        ret.write_u32::<BigEndian>(value[i]).unwrap();
    }
    BigUint::from_bytes_be(&ret[..])
}

pub fn mod_sub_raw(a: &[u32; 8], b: &[u32; 8], modulus: &[u32; 8]) -> [u32; 8] {
    let (modulus_complete, _) = sub_raw(&[0; 8], &modulus);
    let (raw_diff, borrow) = sub_raw(a, b);
    if borrow == 1 {
        let (diff, _borrow) = sub_raw(&raw_diff, &modulus_complete);
        diff
    } else {
        raw_diff
    }
}

fn sub_raw(a: &[u32; 8], b: &[u32; 8]) -> ([u32; 8], u32) {
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

pub fn mod_add_raw(a: &[u32; 8], b: &[u32; 8], modulus: &[u32; 8]) -> [u32; 8] {
    let (raw_sum, carry) = add_raw(a, b);
    if carry == 1 || raw_sum >= *modulus {
        let (sum, _borrow) = sub_raw(&raw_sum, &modulus);
        sum
    } else {
        raw_sum
    }
}

fn add_raw(a: &[u32; 8], b: &[u32; 8]) -> ([u32; 8], u32) {
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

pub fn mod_mul_raw(a: &[u32; 8], b: &[u32; 8], modulus: &[u32; 8]) -> [u32; 8] {
    let raw_prod = mul_raw(a, b);
    fast_reduction(&raw_prod, &modulus)
}

fn mul_raw(a: &[u32; 8], b: &[u32; 8]) -> [u32; 16] {
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
                let (hi, lo) = u32_mul(a[7 - a_idx], b[7 - b_idx]);
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
fn u32_mul(a: u32, b: u32) -> (u64, u64) {
    let uv = u64::from(a) * u64::from(b);
    let u = uv >> 32;
    let v = uv & 0xffff_ffff;
    (u, v)
}

// a quick algorithm to reduce elements on SCA-256 field
// Reference:
// http://ieeexplore.ieee.org/document/7285166/ for details
#[inline]
fn fast_reduction(input: &[u32; 16], modulus: &[u32; 8]) -> [u32; 8] {
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

    let (rt, rc) = add_raw(&sum, &rs[1]);
    sum = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&sum, &rs[2]);
    sum = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&sum, &rs[3]);
    sum = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&sum, &rs[4]);
    sum = rt;
    carry += rc as i32;

    let (rt, rc) = add_raw(&sum, &sum);
    sum = rt;
    carry = carry * 2 + rc as i32;

    let (rt, rc) = add_raw(&sum, &rs[5]);
    sum = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&sum, &rs[6]);
    sum = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&sum, &rs[7]);
    sum = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&sum, &rs[8]);
    sum = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&sum, &rs[9]);
    sum = rt;
    carry += rc as i32;

    let mut part3 = [0; 8];
    let rt: u64 = u64::from(rx[8]) + u64::from(rx[9]) + u64::from(rx[13]) + u64::from(rx[14]);
    part3[5] = (rt & 0xffff_ffff) as u32;
    part3[4] = (rt >> 32) as u32;

    let (rt, rc) = add_raw(&sum, &rs[0]);
    sum = rt;
    carry += rc as i32;

    let (rt, rc) = sub_raw(&sum, &part3);
    sum = rt;
    carry -= rc as i32;

    while carry > 0 || sum >= *modulus {
        let (rs, rb) = sub_raw(&sum, modulus);
        sum = rs;
        carry -= rb as i32;
    }
    sum
}
