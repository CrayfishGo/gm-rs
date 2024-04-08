use rand::RngCore;

use crate::u256::{
    u256_add, u256_cmp, u256_from_be_bytes, u256_mul, u256_sub, u512_add, SM2_ONE, SM2_ZERO, U256,
};

pub(crate) const SM2_P: U256 = [
    0xffffffffffffffff,
    0xffffffff00000000,
    0xffffffffffffffff,
    0xfffffffeffffffff,
];

pub(crate) const SM2_P_MINUS_ONE: U256 = [
    0xfffffffffffffffe,
    0xffffffff00000000,
    0xffffffffffffffff,
    0xfffffffeffffffff,
];

pub(crate) const SM2_P_MINUS_TWO: U256 = [
    0xfffffffffffffffd,
    0xffffffff00000000,
    0xffffffffffffffff,
    0xfffffffeffffffff,
];

// p' * p = -1 mod 2^256

// p' = -p^(-1) mod 2^256
//    = fffffffc00000001fffffffe00000000ffffffff000000010000000000000001
// sage: -(IntegerModRing(2^256)(p))^-1
const SM2_P_PRIME: U256 = [
    0x0000000000000001,
    0xffffffff00000001,
    0xfffffffe00000000,
    0xfffffffc00000001,
];

// 2^512 (mod p)
const SM2_MODP_2E512: U256 = [
    0x0000000200000003,
    0x00000002ffffffff,
    0x0000000100000001,
    0x0000000400000002,
];

// (p+1)/4 = 3fffffffbfffffffffffffffffffffffffffffffc00000004000000000000000
const SM2_SQRT_EXP: U256 = [
    0x4000000000000000,
    0xffffffffc0000000,
    0xffffffffffffffff,
    0x3fffffffbfffffff,
];

const SM9_MODP_MONT_ONE: U256 = [1, (1 << 32) - 1, 0, 1 << 32];

#[inline(always)]
pub fn fp_random_u256() -> U256 {
    let mut rng = rand::thread_rng();
    let mut buf: [u8; 32] = [0; 32];
    let mut ret;
    loop {
        rng.fill_bytes(&mut buf[..]);
        ret = u256_from_be_bytes(&buf);
        if u256_cmp(&ret, &SM2_P_MINUS_ONE) < 0 && ret != [0, 0, 0, 0] {
            break;
        }
    }
    ret
}

pub(crate) fn fp_pow(a: &U256, e: &U256) -> U256 {
    let mut r = SM9_MODP_MONT_ONE;
    let mut w = 0u64;
    for i in (0..4).rev() {
        w = e[i];
        for _j in 0..64 {
            r = fp_sqr(&r);
            if w & 0x8000000000000000 != 0 {
                r = fp_mul(&r, a);
            }
            w <<= 1;
        }
    }
    r
}

pub(crate) fn to_mont(a: &U256) -> U256 {
    mont_mul(a, &SM2_MODP_2E512)
}

pub(crate) fn from_mont(a: &U256) -> U256 {
    mont_mul(a, &SM2_ONE)
}

pub(crate) fn mont_mul(a: &U256, b: &U256) -> U256 {
    let mut r = [0u64; 4];

    let mut z = [0u64; 8];
    let mut t = [0u64; 8];

    // z = a * b
    z = u256_mul(a, b);

    // t = low(z) * p'
    let z_low = [z[0], z[1], z[2], z[3]];
    let t1 = u256_mul(&z_low, &SM2_P_PRIME);
    t[0] = t1[0];
    t[1] = t1[1];
    t[2] = t1[2];
    t[3] = t1[3];

    // t = low(t) * p
    let t_low = [t[0], t[1], t[2], t[3]];
    t = u256_mul(&t_low, &SM2_P);

    // z = z + t
    let (sum, c) = u512_add(&z, &t);
    z = sum;

    // r = high(r)
    r = [z[4], z[5], z[6], z[7]];
    if c {
        r = u256_add(&r, &SM9_MODP_MONT_ONE).0;
    } else if u256_cmp(&r, &SM2_P) >= 0 {
        r = u256_sub(&r, &SM2_P).0
    }
    r
}

fn zero() -> U256 {
    SM2_ZERO
}

fn one() -> U256 {
    SM2_ONE
}

fn is_zero(a: &U256) -> bool {
    a == &SM2_ZERO
}

fn fp_sqr(a: &U256) -> U256 {
    fp_mul(a, a)
}

fn fp_double(a: &U256) -> U256 {
    fp_add(a, a)
}

fn fp_triple(a: &U256) -> U256 {
    let mut r = fp_double(a);
    r = fp_add(&r, a);
    r
}

fn fp_add(a: &U256, b: &U256) -> U256 {
    let (r, c) = u256_add(a, b);
    if c {
        let (diff, _borrow) = u256_add(&r, &SM9_MODP_MONT_ONE);
        return diff;
    }
    if u256_cmp(&r, &SM2_P) >= 0 {
        let (diff, _borrow) = u256_sub(&r, &SM2_P);
        return diff;
    }
    r
}

fn fp_sub(a: &U256, rhs: &U256) -> U256 {
    let (raw_diff, borrow) = u256_sub(&a, rhs);
    if borrow {
        let (diff, _borrow) = u256_sub(&raw_diff, &SM9_MODP_MONT_ONE);
        diff
    } else {
        raw_diff
    }
}

fn fp_mul(a: &U256, rhs: &U256) -> U256 {
    mont_mul(a, rhs)
}

fn fp_neg(a: &U256) -> U256 {
    if is_zero(a) {
        a.clone()
    } else {
        u256_sub(&SM2_P, a).0
    }
}

fn fp_div2(a: &U256) -> U256 {
    let mut r = a.clone();
    let mut c = 0;
    if r[0] & 0x01 == 1 {
        r = fp_add(a, &SM2_P);
        c = u64::from(u256_add(a, &SM2_P).1)
    } else {
        r[0] = a[0];
        r[1] = a[1];
        r[2] = a[2];
        r[3] = a[3];
    }
    r[0] = (r[0] >> 1) | ((r[1] & 1) << 63);
    r[1] = (r[1] >> 1) | ((r[2] & 1) << 63);
    r[2] = (r[2] >> 1) | ((r[3] & 1) << 63);
    r[3] = (r[3] >> 1) | ((c & 1) << 63);
    r
}

fn fp_inv(a: &U256) -> U256 {
    fp_pow(a, &SM2_P_MINUS_TWO)
}
