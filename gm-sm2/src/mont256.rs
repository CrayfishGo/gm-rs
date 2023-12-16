use std::{cmp::Ordering, ops::Mul};
use std::borrow::ToOwned;

use num_bigint::BigUint;
use num_traits::Num;

use crate::p256_field::{BigUnit2Fe, Fe};

/// 蒙哥马利域
pub trait MontDomain {
    fn to_mont(&self) -> Self;
    fn from_mont(&self) -> Self;
}

// pub const P: Fe = [
//     0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF,
// ];
// pub const RR_P: Fe = [
//     0x00000004, 0x00000002, 0x00000001, 0x00000001, 0x00000002, 0xffffffff, 0x00000002, 0x00000003,
// ];
//
// pub const P_INV_R_NEG: Fe = [
//     0xfffffffc, 0x00000001, 0xfffffffe, 0x00000000, 0xffffffff, 0x00000001, 0x00000000, 0x00000001,
// ];

pub const P: Fe = [
    0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE,
];

// 蒙哥马利域转化用参数，(r ^ 2)(mod p)
pub const RR_P: Fe = [
    0x00000003, 0x00000002, 0xffffffff, 0x00000002, 0x00000001, 0x00000001, 0x00000002, 0x00000004,
];

pub const P_INV_R_NEG: Fe = [
    0x00000001, 0x00000000, 0x00000001, 0xffffffff, 0x00000000, 0xfffffffe, 0x00000001, 0xfffffffc,
];

const MODULO: MontyBigNum = MontyBigNum::from_u32_slice_const(&P);

pub fn big_uint_mulmod(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
    a * b % m
}

#[derive(Eq, PartialEq, Ord, Copy, Clone, Debug)]
pub struct MontyBigNum {
    num: Fe,
}

impl PartialOrd for MontyBigNum {
    fn partial_cmp(&self, other: &MontyBigNum) -> Option<Ordering> {
        for i in (0..8).rev() {
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
        Self { num: [0; 8] }
    }

    pub const fn one() -> Self {
        let mut res = Self::zero();
        res.num[0] = 1;
        res
    }

    pub const fn from_u32_slice_const(v: &Fe) -> Self {
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
    for i in 0..8 {
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
        let mut res = [0u32; 10];
        // for i=0 to s-1
        for i in 0..8 {
            // C := 0
            let mut c = 0;
            // for j = 0 to s-1
            for j in 0..8 {
                // (C, S) := t[j] + a[j] * b[i] + C
                let mut cs = res[j] as u64;
                cs += self.num[j] as u64 * other.num[i] as u64;
                cs += c as u64;
                c = (cs >> 32) as u32;
                // t[j] := S
                res[j] = cs as u32;
            }
            // (C, S) := t[s] + C
            let cs = res[8] as u64 + c as u64;
            // t[s] := S
            res[8] = cs as u32;
            // t[s+1] := C
            res[8 + 1] = (cs >> 32) as u32;
            // m := t[0]*n'[0] mod W
            let m: u32 = (res[0] as u64 * P_INV_R_NEG[0] as u64) as u32;
            // (C, S) := t[0] + m*n[0]
            let mut cs = res[0] as u64 + m as u64 * P[0] as u64;
            c = (cs >> 32) as u32;
            // for j=1 to s-1
            for j in 1..8 {
                // (C, S) := t[j] + m*n[j] + C
                cs = res[j] as u64;
                cs += m as u64 * P[j] as u64;
                cs += c as u64;
                c = (cs >> 32) as u32;
                // t[j-1] := S
                res[j - 1] = cs as u32;
            }
            // (C, S) := t[s] + C
            cs = res[8] as u64 + c as u64;
            // t[s-1] := S
            res[8 - 1] = cs as u32;
            // t[s] := t[s+1] + C
            res[8] = res[8 + 1] + (cs >> 32) as u32;
        }
        let res_scalar = MontyBigNum::from_u32_slice(&res[0..8]);
        let mut res_scalar_sub = res_scalar;
        let borrow = bignum_sub(&mut res_scalar_sub, &MODULO);
        if res[8] != 0 || borrow == 0 {
            res_scalar_sub
        } else {
            res_scalar
        }
    }
}

#[cfg(test)]
mod test_mont {
    use num_bigint::BigUint;

    use crate::FeOperation;
    use crate::mont256::{big_uint_mulmod, MODULO, MontyBigNum, P, RR_P};

    #[test]
    fn test_mont_mul() {
        let a = BigUint::from_slice(&[
            0xffff_fffc,
            0xffff_ffff,
            0x0000_0000,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_fffe,
        ]);
        let b = BigUint::from_slice(&[
            0x4d94_0e93,
            0xddbc_bd41,
            0x15ab_8f92,
            0xf397_89f5,
            0xcf65_09a7,
            0x4d5a_9e4b,
            0x9d9f_5e34,
            0x28e9_fa9e,
        ]);

        let g_x = BigUint::from_slice(&[
            0x334c_74c7,
            0x715a_4589,
            0xf266_0be1,
            0x8fe3_0bbf,
            0x6a39_c994,
            0x5f99_0446,
            0x1f19_8119,
            0x32c4_ae2c,
        ]);
        let g_y = BigUint::from_slice(&[
            0x2139_f0a0,
            0x02df_32e5,
            0xc62a_4740,
            0xd0a9_877c,
            0x6b69_2153,
            0x59bd_cee3,
            0xf4f6_779c,
            0xbc37_36a2,
        ]);

        let n = BigUint::from_slice(&[
            0x39d54123,
            0x53bbf409,
            0x21c6052b,
            0x7203df6b,
            0xffffffff,
            0xffffffff,
            0xffffffff,
            0xfffffffe,
        ]);

        let m = BigUint::from_slice(&P);

        println!("mod sum = {:?}", ((&a + &b) % &m).to_u32_digits());
        println!(
            "mod sum2= {:?}",
            MontyBigNum::from_u32_slice(&a.to_u32_digits()).num.mod_add(
                &MontyBigNum::from_u32_slice(&b.to_u32_digits()).num,
                &MODULO.num
            )
        );
        println!("========================");
        println!("mod sub = {:?}", ((&a - &b) % &m).to_u32_digits());
        println!(
            "mod sub2= {:?}",
            MontyBigNum::from_u32_slice(&a.to_u32_digits()).num.mod_sub(
                &MontyBigNum::from_u32_slice(&b.to_u32_digits()).num,
                &MODULO.num
            )
        );
        println!("========================");

        let r2_mod = MontyBigNum::from_u32_slice(&RR_P);
        let one = MontyBigNum::one();
        // 进蒙哥马利域
        let a_monty = MontyBigNum::from_u32_slice(&a.to_u32_digits()) * r2_mod;
        let b_monty = MontyBigNum::from_u32_slice(&b.to_u32_digits()) * r2_mod;
        // 蒙哥马利模乘
        let res = a_monty * b_monty;
        // 出蒙哥马利域
        let res = res * one;
        println!("==========蒙哥马利模乘结果===========");
        println!("ret = {:?}", BigUint::from_slice(&res.num));
        println!("ret = {:?}", res.num);
        println!("==========蒙哥马利模乘结果===========");

        let res = big_uint_mulmod(&a, &b, &m);
        println!("==========普通模乘结果===========");
        println!("ret = {}", &res);
        println!("ret = {:?}", res.to_u32_digits());
        println!("==========普通模乘结果===========");

        ()
    }
}
