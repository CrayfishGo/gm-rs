use std::borrow::ToOwned;
use std::{cmp::Ordering, ops::Mul};

use num_bigint::BigUint;
use num_traits::Num;

use crate::p256_field::BigUnit2Fe;

/// 蒙哥马利域
pub trait MontDomain {
    fn to_mont(&self) -> Self;
    fn from_mont(&self) -> Self;
}

pub const WORDS: usize = 8;

// pub const P: [u32; WORDS] = [
//     0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF,
// ];
// pub const RR_P: [u32; WORDS] = [
//     0x00000004, 0x00000002, 0x00000001, 0x00000001, 0x00000002, 0xffffffff, 0x00000002, 0x00000003,
// ];
//
// pub const P_INV_R_NEG: [u32; WORDS] = [
//     0xfffffffc, 0x00000001, 0xfffffffe, 0x00000000, 0xffffffff, 0x00000001, 0x00000000, 0x00000001,
// ];

pub const P: [u32; WORDS] = [
    0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE,
];
pub const RR_P: [u32; WORDS] = [
    0x00000003, 0x00000002, 0xffffffff, 0x00000002, 0x00000001, 0x00000001, 0x00000002, 0x00000004,
];

pub const P_INV_R_NEG: [u32; WORDS] = [
    0x00000001, 0x00000000, 0x00000001, 0xffffffff, 0x00000000, 0xfffffffe, 0x00000001, 0xfffffffc,
];

// pub const R: [u32; WORDS] = [
//     0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
// ];

// pub const P: [u32; WORDS] = [
//     0x00000001, 0xffffffff, 0xfffe5bfe, 0x53bda402, 0x09a1d805, 0x3339d808, 0x299d7d48, 0x73eda753,
// ];
// pub const RR_P: [u32; WORDS] = [
//     0xf3f29c6d, 0xc999e990, 0x87925c23, 0x2b6cedcb, 0x7254398f, 0x05d31496, 0x9f59ff11, 0x0748d9d9,
// ];

const MODULO: MontyBigNum = MontyBigNum::from_u32_slice_const(&P);

pub fn big_uint_mulmod(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
    a * b % m
}

#[derive(Eq, PartialEq, Ord, Copy, Clone, Debug)]
pub struct MontyBigNum {
    num: [u32; WORDS],
}

impl PartialOrd for MontyBigNum {
    fn partial_cmp(&self, other: &MontyBigNum) -> Option<Ordering> {
        for i in (0..WORDS).rev() {
            if self.num[i] > other.num[i] {
                return Some(Ordering::Greater);
            } else if self.num[i] < other.num[i] {
                return Some(Ordering::Less);
            }
        }
        Some(Ordering::Equal)
    }
}

impl MontyBigNum {
    pub const fn zero() -> Self {
        Self { num: [0; WORDS] }
    }

    pub const fn one() -> Self {
        let mut res = Self::zero();
        res.num[0] = 1;
        res
    }

    pub const fn from_u32_slice_const(v: &[u32; WORDS]) -> Self {
        Self { num: *v }
    }

    pub fn from_u32_slice(v: &[u32]) -> Self {
        let mut res = Self::zero();
        res.num.copy_from_slice(v);
        res
    }

    pub fn to_monty(&mut self) {
        *self = *self * MontyBigNum::from_u32_slice(&RR_P);
    }

    pub fn from_monty(&mut self) {
        *self = *self * MontyBigNum::one();
    }
}

fn bignum_sub(lhs: &mut MontyBigNum, rhs: &MontyBigNum) -> u32 {
    let mut borrow: u32 = 0;
    for i in 0..WORDS {
        let mut temp: u64 = lhs.num[i] as u64;
        let underflow = (temp == 0) && (rhs.num[i] > 0 || borrow != 0);
        if borrow != 0 {
            temp = temp.wrapping_sub(1);
        }
        borrow = (underflow || (temp < rhs.num[i] as u64)) as u32;
        if borrow != 0 {
            temp = temp.wrapping_add(1 << 33);
        }
        lhs.num[i] = (temp - rhs.num[i] as u64) as u32;
    }
    borrow
}

impl Mul for MontyBigNum {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let mut res = [0u32; WORDS + 2];
        // for i=0 to s-1
        for i in 0..WORDS {
            // C := 0
            let mut c = 0;
            // for j = 0 to s-1
            for j in 0..WORDS {
                // (C, S) := t[j] + a[j] * b[i] + C
                let mut cs = res[j] as u64;
                cs += self.num[j] as u64 * other.num[i] as u64;
                cs += c as u64;
                c = (cs >> 32) as u32;
                // t[j] := S
                res[j] = cs as u32;
            }
            // (C, S) := t[s] + C
            let cs = res[WORDS] as u64 + c as u64;
            // t[s] := S
            res[WORDS] = cs as u32;
            // t[s+1] := C
            res[WORDS + 1] = (cs >> 32) as u32;
            // m := t[0]*n'[0] mod W
            let m: u32 = (res[0] as u64 * P_INV_R_NEG[0] as u64) as u32;
            // (C, S) := t[0] + m*n[0]
            let mut cs = res[0] as u64 + m as u64 * P[0] as u64;
            c = (cs >> 32) as u32;
            // for j=1 to s-1
            for j in 1..WORDS {
                // (C, S) := t[j] + m*n[j] + C
                cs = res[j] as u64;
                cs += m as u64 * P[j] as u64;
                cs += c as u64;
                c = (cs >> 32) as u32;
                // t[j-1] := S
                res[j - 1] = cs as u32;
            }
            // (C, S) := t[s] + C
            cs = res[WORDS] as u64 + c as u64;
            // t[s-1] := S
            res[WORDS - 1] = cs as u32;
            // t[s] := t[s+1] + C
            res[WORDS] = res[WORDS + 1] + (cs >> 32) as u32;
        }
        let res_scalar = MontyBigNum::from_u32_slice(&res[0..WORDS]);
        let mut res_scalar_sub = res_scalar;
        let borrow = bignum_sub(&mut res_scalar_sub, &MODULO);
        if res[WORDS] != 0 || borrow == 0 {
            res_scalar_sub
        } else {
            res_scalar
        }
    }
}

#[cfg(test)]
mod test_mont {
    use num_bigint::BigUint;

    use crate::mont256::{big_uint_mulmod, MontyBigNum, P, RR_P};
    use crate::util::{fe32_to_fe64, fe64_to_fe32};

    #[test]
    fn test_mont_mul() {
        let a = BigUint::from_slice(&[
            0xffff_fffe,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            0x0000_0000,
            0xffff_ffff,
            0xffff_fffc,
        ]);
        let b = BigUint::from_slice(&[
            0x28e9_fa9e,
            0x9d9f_5e34,
            0x4d5a_9e4b,
            0xcf65_09a7,
            0xf397_89f5,
            0x15ab_8f92,
            0xddbc_bd41,
            0x4d94_0e93,
        ]);

        let fe32 = fe64_to_fe32(&[
            0x0000000000000001,
            0xffffffff00000001,
            0xfffffffe00000000,
            0xfffffffc00000001,
        ]);
        for x in fe32 {
            println!("{:x}", x);
        }
        println!("");
        let fe64 = fe32_to_fe64(&[
            0x00000001, 0x00000000, 0x00000001, 0xffffffff, 0x00000000, 0xfffffffe, 0x00000001,
            0xfffffffc,
        ]);

        for x in fe64 {
            println!("{:x}", x);
        }

        let m = BigUint::from_slice(&P);
        let res = big_uint_mulmod(&a, &b, &m);
        println!("==========普通模乘结果===========");
        println!("ret = {}", &res);
        println!("ret = {:?}", res.to_u32_digits());
        println!("==========普通模乘结果===========");

        let r2_mod = MontyBigNum::from_u32_slice(&RR_P);
        let one = MontyBigNum::one();

        // 进蒙哥马利域
        let a_monty = MontyBigNum::from_u32_slice(&a.to_u32_digits()) * r2_mod;
        let b_monty = MontyBigNum::from_u32_slice(&b.to_u32_digits()) * r2_mod;

        // 蒙哥马利模乘
        let res = a_monty * b_monty;

        // 出蒙哥马利
        let res = res * one;
        println!("==========蒙哥马利模乘结果===========");
        println!("ret = {:?}", BigUint::from_slice(&res.num));
        println!("ret = {:?}", res.num);
        println!("==========蒙哥马利模乘结果===========");

        ()
    }
}
