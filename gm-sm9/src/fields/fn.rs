use rand::RngCore;

use crate::u256::{SM9_ONE, sm9_u256_from_bytes, U256, u256_add, u256_mul, u256_sub};

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
const SM9_N_MINUS_ONE: U256 = [
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
    0x74df4fd4dfc97c2f, 0x9c95d85ec9c073b0, 0x55f73aebdcd1312c, 0x67980e0beb5759a6, 0x1
];


#[inline(always)]
pub fn fn_random_u256() -> U256 {
    let mut rng = rand::thread_rng();
    let mut buf: [u8; 32] = [0; 32];
    let mut ret;
    loop {
        rng.fill_bytes(&mut buf[..]);
        ret = sm9_u256_from_bytes(&buf);
        if ret < SM9_N_MINUS_ONE && ret != [0, 0, 0, 0] {
            break;
        }
    }
    ret
}

pub fn fn_add(a: &U256, b: &U256) -> U256 {
    let (r, c) = u256_add(a, b);
    if c {
        // a + b - n = (a + b - 2^256) + (2^256 - n)
        return u256_add(&r, &SM9_N_NEG).0;
    }
    if r >= SM9_N {
        return u256_sub(&r, &SM9_N).0;
    }
    r
}

pub fn fn_sub(a: &U256, b: &U256) -> U256 {
    let (mut r, c) = u256_sub(a, b);
    if c {
        r = u256_sub(&r, &SM9_N_NEG).0
    }
    r
}


#[inline(always)]
pub const fn u256_mul_5(a: &[u64; 5], b: &[u64; 5]) -> [u64; 10] {
    let mut local: u128 = 0;
    let mut carry: u128 = 0;
    let mut ret: [u64; 10] = [0; 10];
    let mut ret_idx = 0;
    while ret_idx < 9 {
        let index = 9 - ret_idx;
        let mut a_idx = 0;
        while a_idx < 5 {
            if a_idx > ret_idx {
                break;
            }
            let b_idx = ret_idx - a_idx;
            if b_idx < 5 {
                let (hi, lo) = {
                    let uv = (a[4 - a_idx] as u128) * (b[4 - b_idx] as u128);
                    let u = uv >> 64;
                    let v = uv & 0xffff_ffff_ffff_ffff;
                    (u, v)
                };
                local += lo;
                carry += hi;
            }
            a_idx += 1;
        }
        carry += local >> 64;
        local &= 0xffff_ffff_ffff_ffff;
        ret[index] = local as u64;
        local = carry;
        carry = 0;
        ret_idx += 1;
    }
    ret[0] = local as u64;
    ret
}

pub fn fn_mul(a: &U256, b: &U256) -> U256 {
    let mut r = [0, 0, 0, 0];

    let z = u256_mul(a, b);

    // (z // 2^192) = z[3-7]
    let z1: [u64; 5] = [z[3], z[4], z[5], z[6], z[7]];
    let h = u256_mul_5(&z1, &SM9_N_BARRETT_MU);

    // (h // 2^320) = h[6-9]
    let h1: [u64; 4] = [h[6], h[7], h[8], h[9]];
    let mut s = u256_mul(&h1, &SM9_N);

    s[4] += SM9_N[0] * h[9];

    let mut t = z[0] - s[0];
    let mut c = (t > z[0]) as u64;
    r[0] = t;

    t = z[1] - c;
    c = (t > z[1]) as u64;
    r[1] = t - s[1];
    c += (r[1] > t) as u64;

    t = z[2] - c;
    c = (t > z[2]) as u64;
    r[2] = t - s[2];
    c += (r[2] > t) as u64;

    t = z[3] - c;
    c = (t > z[3]) as u64;
    r[3] = t - s[3];
    c += (r[3] > t) as u64;

    t = z[4] - c;
    s[4] = t - s[4];

    if s[4] > 0 || r >= SM9_N {
        r = u256_sub(&r, &SM9_N).0;
    }
    r
}

pub fn fn_pow(a: &U256, e: &U256) -> U256 {
    let mut r = SM9_ONE;
    let mut w = 0u64;
    for i in (0..4).rev() {
        w = e[i];
        for j in 0..64 {
            r = fn_mul(&r, &r);
            if w & 0x8000000000000000 == 1 {
                r = fn_mul(&r, a);
            }
            w <<= 1;
        }
    }
    r
}

pub fn fn_inv(a: &U256) -> U256 {
    fn_pow(a, &SM9_N_MINUS_ONE)
}

pub fn fn_from_bytes(buf: &[u8; 32]) -> U256 {
    sm9_u256_from_bytes(buf)
}
