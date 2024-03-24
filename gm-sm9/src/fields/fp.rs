use crate::fields::FieldElement;
use crate::u256::{u256_add, u256_mul, u256_mul_low, u256_sub, u512_add, U256};

pub(crate) const SM9_ZERO: U256 = [0, 0, 0, 0];
pub(crate) const SM9_ONE: U256 = [1, 0, 0, 0];
pub(crate) const SM9_TWO: U256 = [2, 0, 0, 0];
pub(crate) const SM9_FIVE: U256 = [5, 0, 0, 0];

/// 本文使用256位的BN曲线。
///
/// 椭圆曲线方程：y2 = x3 + b
///
/// 参数 t: 60000000 0058F98A
///
/// 基域特征 q(t) = 36t^4 + 36t^3 + 24t^2 + 6t + 1
///
/// p =  B6400000 02A3A6F1 D603AB4F F58EC745 21F2934B 1A7AEEDB E56F9B27 E351457D
pub(crate) const SM9_P: U256 = [
    0xe56f9b27e351457d,
    0x21f2934b1a7aeedb,
    0xd603ab4ff58ec745,
    0xb640000002a3a6f1,
];

/// 群的阶 N(t) = 36t^4 + 36t^3 + 18t^2 + 6t + 1
///
/// n =  B6400000 02A3A6F1 D603AB4F F58EC744 49F2934B 18EA8BEE E56EE19C D69ECF25
const SM9_N: U256 = [
    0xe56ee19cd69ecf25,
    0x49f2934b18ea8bee,
    0xd603ab4ff58ec744,
    0xb640000002a3a6f1,
];

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

// p = b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d
// p' = -p^(-1) mod 2^256 = afd2bac5558a13b3966a4b291522b137181ae39613c8dbaf892bc42c2f2ee42b
// sage: -(IntegerModRing(2^256)(p))^-1
const SM9_P_PRIME: U256 = [
    0x892bc42c2f2ee42b,
    0x181ae39613c8dbaf,
    0x966a4b291522b137,
    0xafd2bac5558a13b3,
];

// mont params (mod p)
// mu = p^-1 mod 2^64 = 0x76d43bd3d0d11bd5
// 2^512 mod p = 0x2ea795a656f62fbde479b522d6706e7b88f8105fae1a5d3f27dea312b417e2d2
// mont(1) mod p = 2^256 mod p = 0x49bffffffd5c590e29fc54b00a7138bade0d6cb4e58511241a9064d81caeba83

const SM9_MODP_MU: u64 = 0x76d43bd3d0d11bd5_u64;
const SM9_MODP_2E512: U256 = [
    0x27dea312b417e2d2,
    0x88f8105fae1a5d3f,
    0xe479b522d6706e7b,
    0x2ea795a656f62fbd,
];
const SM9_MODP_MONT_ONE: U256 = [
    0x1a9064d81caeba83,
    0xde0d6cb4e5851124,
    0x29fc54b00a7138ba,
    0x49bffffffd5c590e,
];
const SM9_MODP_MONT_FIVE: U256 = [
    0xb9f2c1e8c8c71995,
    0x125df8f246a377fc,
    0x25e650d049188d1c,
    0x43fffffed866f63,
];

pub(crate) type Fp = U256;

pub(crate) fn pow(a: &Fp, e: &U256) -> Fp {
    let mut r = SM9_MODP_MONT_ONE;
    let mut w = 0u64;
    for i in (0..4).rev() {
        w = e[i];
        for j in 0..64 {
            r = r.fp_sqr();
            if w & 0x8000000000000000 == 1 {
                r = r.fp_mul(a);
            }
            w <<= 1;
        }
    }
    r
}

pub(crate) fn to_mont(a: &Fp) -> Fp {
    a.mont_mul(&SM9_MODP_2E512)
}

pub(crate) fn from_mont(a: &Fp) -> Fp {
    a.mont_mul(&SM9_ONE)
}

pub(crate) fn mont_mul(a: &Fp, b: &Fp) -> Fp {
    let mut r = [0u64; 4];

    let mut z = [0u64; 8];
    let mut t = [0u64; 8];

    // z = a * b
    z = u256_mul(a, b);

    // t = low(z) * p'
    let z_low = [z[0], z[1], z[2], z[3]];
    let t1 = u256_mul(&z_low, &SM9_P_PRIME);
    t[0] = t1[0];
    t[1] = t1[1];
    t[2] = t1[2];
    t[3] = t1[3];

    // t = low(t) * p
    let t_low = [t[0], t[1], t[2], t[3]];
    t = u256_mul(&t_low, &SM9_P);

    // z = z + t
    let (sum, c) = u512_add(&z, &t);
    z = sum;

    // r = high(r)
    r = [z[4], z[5], z[6], z[7]];
    if c {
        r = u256_add(&r, &SM9_MODP_MONT_ONE).0;
    } else if r >= SM9_P {
        r = u256_sub(&r, &SM9_P).0
    }
    r
}

impl FieldElement for Fp {
    fn zero() -> Self {
        SM9_ZERO
    }

    fn one() -> Self {
        SM9_ONE
    }

    fn is_zero(&self) -> bool {
        self[0] == 0
    }

    fn fp_sqr(&self) -> Self {
        self.fp_mul(self)
    }

    fn fp_double(&self) -> Self {
        self.fp_add(self)
    }

    fn fp_triple(&self) -> Self {
        self.fp_double().fp_add(self)
    }

    fn fp_add(&self, rhs: &Self) -> Self {
        let (r, c) = u256_add(self, rhs);
        if c {
            let (diff, _borrow) = u256_sub(&r, &SM9_P);
            diff
        } else {
            r
        }
    }

    fn fp_sub(&self, rhs: &Self) -> Self {
        let (raw_diff, borrow) = u256_sub(&self, rhs);
        if borrow {
            let (modulus_complete, _) = u256_sub(&[0; 4], &SM9_P);
            let (diff, _borrow) = u256_sub(&raw_diff, &modulus_complete);
            diff
        } else {
            raw_diff
        }
    }

    fn fp_mul(&self, rhs: &Self) -> Self {
        mont_mul(self, rhs)
    }

    fn fp_neg(&self) -> Self {
        if self.is_zero() {
            self.clone()
        } else {
            u256_sub(&SM9_P, self).0
        }
    }

    fn fp_div2(&self) -> Self {
        let mut r = self.clone();
        let mut c = 0;
        if r[0] & 0x01 == 1 {
            r = self.fp_add(&SM9_P);
            c = u64::from(u256_add(self, &SM9_P).1)
        } else {
            r[0] = self[0];
            r[1] = self[1];
            r[2] = self[2];
            r[3] = self[3];
        }
        r[0] = (r[0] >> 1) | ((r[1] & 1) << 63);
        r[1] = (r[1] >> 1) | ((r[2] & 1) << 63);
        r[2] = (r[2] >> 1) | ((r[3] & 1) << 63);
        r[3] = (r[3] >> 1) | ((c & 1) << 63);
        r
    }

    fn fp_inv(&self) -> Self {
        let e = u256_sub(&SM9_P, &SM9_TWO).0;
        pow(self, &e)
    }
}
