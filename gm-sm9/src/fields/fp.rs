use crate::algorithm::{sm9_bn_add, sm9_bn_sub};
use crate::fields::FieldElement;

pub(crate) const SM9_ZERO: [u64; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
pub(crate) const SM9_ONE: [u64; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
pub(crate) const SM9_TWO: [u64; 8] = [2, 0, 0, 0, 0, 0, 0, 0];
pub(crate) const SM9_FIVE: [u64; 8] = [5, 0, 0, 0, 0, 0, 0, 0];

/// 本文使用256位的BN曲线。
///
/// 椭圆曲线方程：y2 = x3 + b
///
/// 参数 t: 60000000 0058F98A
///
/// 基域特征 q(t) = 36t^4 + 36t^3 + 24t^2 + 6t + 1
///
/// p =  B6400000 02A3A6F1 D603AB4F F58EC745 21F2934B 1A7AEEDB E56F9B27 E351457D
pub(crate) const SM9_P: [u64; 8] = [
    0xe351457d, 0xe56f9b27, 0x1a7aeedb, 0x21f2934b, 0xf58ec745, 0xd603ab4f, 0x02a3a6f1, 0xb6400000
];

/// 群的阶 N(t) = 36t^4 + 36t^3 + 18t^2 + 6t + 1
/// n =  B6400000 02A3A6F1 D603AB4F F58EC744 49F2934B 18EA8BEE E56EE19C D69ECF25
const SM9_N: [u64; 8] = [
    0xd69ecf25, 0xe56ee19c, 0x18ea8bee, 0x49f2934b, 0xf58ec744, 0xd603ab4f, 0x02a3a6f1, 0xb6400000
];

/// P - 1
const SM9_P_MINUS_ONE: [u64; 8] = [
    0xe351457c, 0xe56f9b27, 0x1a7aeedb, 0x21f2934b, 0xf58ec745, 0xd603ab4f, 0x02a3a6f1, 0xb6400000
];

/// N - 1
const SM9_N_MINUS_ONE: [u64; 8] = [
    0xd69ecf24, 0xe56ee19c, 0x18ea8bee, 0x49f2934b, 0xf58ec744, 0xd603ab4f, 0x02a3a6f1, 0xb6400000
];

// mu_p = 2^512 // p = 167980e0beb5759a655f73aebdcd1312af2665f6d1e36081c71188f90d5c22146
const SM9_MU_P: [u64; 9] = [
    0xd5c22146, 0x71188f90, 0x1e36081c, 0xf2665f6d, 0xdcd1312a, 0x55f73aeb, 0xeb5759a6, 0x67980e0b, 0x00000001
];

// mu_n = 2^512 // n
const SM9_MU_N: [u64; 9] = [
    0xdfc97c2f, 0x74df4fd4, 0xc9c073b0, 0x9c95d85e, 0xdcd1312c, 0x55f73aeb, 0xeb5759a6, 0x67980e0b, 0x00000001
];

const SM9_MU_N_MINUS_ONE: [u64; 9] = [
    0xdfc97c31, 0x74df4fd4, 0xc9c073b0, 0x9c95d85e, 0xdcd1312c, 0x55f73aeb, 0xeb5759a6, 0x67980e0b, 0x00000001
];

pub(crate) type Fp = [u64; 8];

impl FieldElement for Fp {
    fn zero() -> Self {
        [0, 0, 0, 0, 0, 0, 0, 0]
    }

    fn one() -> Self {
        [1, 0, 0, 0, 0, 0, 0, 0]
    }

    fn is_zero(&self) -> bool {
        self[0] == 0
    }

    fn squared(&self) -> Self {
        self.mul(self)
    }

    fn double(&self) -> Self {
        self.add(self)
    }

    fn triple(&self) -> Self {
        self.double().add(self)
    }

    fn add(&self, rhs: &Self) -> Self {
        let raw_sum = sm9_bn_add(self, rhs);
        if raw_sum >= SM9_P {
            let sum = sm9_bn_sub(&raw_sum, &SM9_P);
            sum
        } else {
            raw_sum
        }
    }

    fn sub(&self, rhs: &Self) -> Self {
        if *self >= *rhs {
            sm9_bn_sub(self, rhs)
        } else {
            let r = sm9_bn_sub(&SM9_P, rhs);
            sm9_bn_add(&r, self)
        }
    }

    fn mul(&self, rhs: &Self) -> Self {
        let mut r = [0u64; 8];
        let mut s = [0u64; 18];
        let mut w = 0u64;

        for i in 0..8 {
            for j in 0..8 {
                w += s[i + j] + self[i] * rhs[j];
                s[i + j] = w & 0xffffffff;
                w >>= 32;
            }
            s[i + 8] = w;
        }

        let mut zh = [0u64; 9];
        let mut zl = [0u64; 9];
        let mut q = [0u64; 9];

        // zl = z mod (2^32)^9 = z[0..8]
        // zh = z // (2^32)^7 = z[7..15]
        for i in 0..9 {
            zl[i] = s[i];
            zh[i] = s[7 + i];
        }
        for i in 0..9 {
            s[i] = 0;
        }

        // q = zh * mu // (2^32)^9
        for i in 0..9 {
            w = 0;
            for j in 0..9 {
                w += s[i + j] + zh[i] * SM9_MU_P[j];
                s[i + j] = w & 0xffffffff;
                w >>= 32;
            }
            s[i + 9] = w;
        }

        //  q = q * p mod (2^32)^9
        for i in 0..8 {
            s[i] = 0;
        }
        w = 0;
        for j in 0..8 {
            w += s[j] + q[0] * SM9_P[j];
            s[j] = w & 0xffffffff;
            w >>= 32;
        }
        s[8] = w;
        for i in 1..9 {
            w = 0;
            let mut j = 0;
            while i + j < 9 {
                w += s[i + j] + q[i] * SM9_P[j];
                s[i + j] = w & 0xffffffff;
                w >>= 32;
                j += 1;
            }
        }
        for i in 0..9 {
            q[i] = s[i];
        }

        // r = zl - q (mod (2^32)^9)
        if zl > q {
            zl = crate::algorithm::sm9_barrett_bn_sub(&zl, &q);
        } else {
            let c = [0, 0, 0, 0, 0, 0, 0, 0, 0x100000000];
            q = crate::algorithm::sm9_barrett_bn_sub(&c, &q);
            zl = crate::algorithm::sm9_barrett_bn_add(&q, &zl);
        }

        for i in 0..8 {
            r[i] = zl[i];
        }
        r[7] += zl[8] << 32;

        // while r >= p do: r = r - p
        while r >= SM9_P {
            r = sm9_bn_sub(&r, &SM9_P);
        }
        r
    }

    fn pow(&self, rhs: &[u64; 8]) -> Self {
        assert!(rhs <= &SM9_ZERO);
        let mut r = [0u64; 8];
        let mut w = 0u32;
        let mut i = 7;
        loop {
            w = rhs[i] as u32;
            for _j in 0..32 {
                r = r.squared();
                if w & 0x80000000 == 1 {
                    r = r.mul(self);
                }
                w <<= 1;
            }
            if i == 0 {
                break;
            }
            i -= 1;
        }
        r
    }

    fn neg(&self) -> Self {
        if self.is_zero() {
            self.clone()
        } else {
            sm9_bn_sub(&SM9_P, self)
        }
    }

    fn div2(&self) -> Self {
        let mut r = self.clone();
        let mut i = 0;
        if r[0] & 0x01 == 1 {
            r = self.add(&SM9_P);
        }
        loop {
            r[i] = (r[i] >> 1) | ((r[i + 1] & 0x01) << 31);
            if i == 7 {
                break;
            }
            i += 1;
        }
        r[i] >>= 1;
        r
    }

    fn inverse(&self) -> Self {
        let e = sm9_bn_sub(&SM9_P, &SM9_TWO);
        self.pow(&e)
    }
}