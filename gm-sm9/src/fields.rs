use crate::u256::{u256_add, u256_cmp, u256_from_be_bytes, u256_mul, u256_sub, SM9_ONE, U256};
use rand::RngCore;
use std::fmt::Debug;
use std::ops::{Add, Mul, MulAssign, Neg, Sub};

pub mod fp;
pub(crate) mod fp12;
pub(crate) mod fp2;
pub(crate) mod fp4;

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

/// 群的阶 N(t) = 36t^4 + 36t^3 + 18t^2 + 6t + 1
///
/// n =  B6400000 02A3A6F1 D603AB4F F58EC744 49F2934B 18EA8BEE E56EE19C D69ECF25
const SM9_N: U256 = [
    0xe56ee19cd69ecf25,
    0x49f2934b18ea8bee,
    0xd603ab4ff58ec744,
    0xb640000002a3a6f1,
];

/// 2^256 - n
const SM9_N_NEG: U256 = [
    0x1a911e63296130db,
    0xb60d6cb4e7157411,
    0x29fc54b00a7138bb,
    0x49bffffffd5c590e,
];

/// N - 1
pub const SM9_N_MINUS_ONE: U256 = [
    0xe56ee19cd69ecf24,
    0x49f2934b18ea8bee,
    0xd603ab4ff58ec744,
    0xb640000002a3a6f1,
];

/// N - 2
const SM9_N_MINUS_TWO: U256 = [
    0xe56ee19cd69ecf23,
    0x49f2934b18ea8bee,
    0xd603ab4ff58ec744,
    0xb640000002a3a6f1,
];

const SM9_N_BARRETT_MU: [u64; 5] = [
    0x74df4fd4dfc97c2f,
    0x9c95d85ec9c073b0,
    0x55f73aebdcd1312c,
    0x67980e0beb5759a6,
    0x1,
];

pub const SM9_Z256_N_MINUS_ONE_BARRETT_MU: [u64; 4] = [
    0x74df4fd4dfc97c31,
    0x9c95d85ec9c073b0,
    0x55f73aebdcd1312c,
    0x67980e0beb5759a6,
];

#[inline(always)]
pub fn fn_random_u256() -> U256 {
    let mut rng = rand::thread_rng();
    let mut buf: [u8; 32] = [0; 32];
    let mut ret;
    loop {
        rng.fill_bytes(&mut buf[..]);
        ret = u256_from_be_bytes(&buf);
        if ret < SM9_N_MINUS_ONE && ret != [0, 0, 0, 0] {
            break;
        }
    }
    ret
}

pub fn mod_n_add(a: &U256, b: &U256) -> U256 {
    let (r, c) = u256_add(a, b);
    if c {
        // a + b - n = (a + b - 2^256) + (2^256 - n)
        return u256_add(&r, &SM9_N_NEG).0;
    }
    if u256_cmp(&r, &SM9_N) >= 0 {
        return u256_sub(&r, &SM9_N).0;
    }
    r
}

pub fn mod_n_sub(a: &U256, b: &U256) -> U256 {
    let (mut r, c) = u256_sub(a, b);
    if c {
        r = u256_sub(&r, &SM9_N_NEG).0
    }
    r
}

#[inline(always)]
pub fn u320_mul(a: &[u64; 5], b: &[u64; 5]) -> [u64; 10] {
    let mut a_: [u64; 10] = [0; 10];
    let mut b_: [u64; 10] = [0; 10];
    let mut ret: [u64; 10] = [0; 10];
    let mut s: [u64; 20] = [0; 20];

    for i in 0..5 {
        a_[2 * i] = a[i] & 0xffffffff;
        b_[2 * i] = b[i] & 0xffffffff;
        a_[2 * i + 1] = a[i] >> 32;
        b_[2 * i + 1] = b[i] >> 32;
    }

    let mut u = 0;
    for i in 0..10 {
        u = 0;
        for j in 0..10 {
            u = s[i + j] + a_[i] * b_[j] + u;
            s[i + j] = u & 0xffffffff;
            u >>= 32;
        }
        s[i + 10] = u;
    }

    for i in 0..10 {
        ret[i] = (s[2 * i + 1] << 32) | s[2 * i];
    }
    ret
}

pub fn mod_n_mul(a: &U256, b: &U256) -> U256 {
    let mut r = [0, 0, 0, 0];

    let z = u256_mul(a, b);

    // (z // 2^192) = z[3-7]
    let z1: [u64; 5] = [z[3], z[4], z[5], z[6], z[7]];
    let h = u320_mul(&z1, &SM9_N_BARRETT_MU);

    // (h // 2^320) = h[5-9]
    let h1: [u64; 4] = [h[5], h[6], h[7], h[8]];
    let mut s = u256_mul(&h1, &SM9_N);

    s[4] += SM9_N[0] * h[9];

    let mut carry = 0;
    let (t0, overflow) = z[0].overflowing_sub(s[0]);
    r[0] = t0;
    carry = overflow as u64;

    let (t1, overflow) = z[1].overflowing_sub(carry);
    let (t1, overflow2) = t1.overflowing_sub(s[1]);
    r[1] = t1;
    carry = (overflow || overflow2) as u64;

    let (t2, overflow) = z[2].overflowing_sub(carry);
    let (t2, overflow2) = t2.overflowing_sub(s[2]);
    r[2] = t2;
    carry = (overflow || overflow2) as u64;

    let (t3, overflow) = z[3].overflowing_sub(carry);
    let (t3, overflow2) = t3.overflowing_sub(s[3]);
    r[3] = t3;
    carry = (overflow || overflow2) as u64;

    // s[4] holds the temporary value for r[4]
    let (t4, overflow) = z[4].overflowing_sub(carry);
    s[4] = t4.wrapping_sub(s[4]);

    if s[4] > 0 || u256_cmp(&r, &SM9_N) >= 0 {
        r = u256_sub(&r, &SM9_N).0;
    }
    r
}

pub fn mod_n_pow(a: &U256, e: &U256) -> U256 {
    let mut r = SM9_ONE;
    for i in (0..4).rev() {
        let mut w = e[i];
        for _ in 0..64 {
            r = mod_n_mul(&r, &r);
            if w & 0x8000000000000000 != 0 {
                r = mod_n_mul(&r, a);
            }
            w <<= 1;
        }
    }
    r
}

pub fn mod_n_inv(a: &U256) -> U256 {
    mod_n_pow(a, &SM9_N_MINUS_TWO)
}

pub fn mod_n_from_hash(ha: &[u8]) -> U256 {
    let mut h = SM9_ONE;
    let mut z: [u64; 5] = [0; 5];
    for i in 0..5 {
        z[4 - i] = getu64(&ha[8 * i..]);
    }

    let mut c = false;
    let mut t = 0_u64;
    let z1 = [z[3], z[4], 0, 0];
    let mut r = u256_mul(&z1, &SM9_Z256_N_MINUS_ONE_BARRETT_MU);

    r[4] += z[3];
    c = r[4] < z[3];
    t = z[4] + (c as u64);
    c = t < z[4];
    r[5] += t;
    c = r[5] < t;
    r[6] = u64::from(c);

    r = u256_mul(&[r[5], r[6], 0, 0], &SM9_N_MINUS_ONE);
    h = u256_sub(&[z[0], z[1], z[2], z[3]], &[r[0], r[1], r[2], r[3]]).0;
    h = mod_n_add(&h, &SM9_ONE);
    h
}

fn getu64(bytes: &[u8]) -> u64 {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[..8]);
    u64::from_be_bytes(arr)
}
