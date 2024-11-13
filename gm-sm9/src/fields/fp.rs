use rand::RngCore;

use crate::fields::fp2::Fp2;
use crate::fields::FieldElement;
use crate::u256::{
    u256_add, u256_cmp, u256_from_be_bytes, u256_mul, u256_sub, u256_to_be_bytes, u512_add,
    SM9_ONE, SM9_ZERO, U256,
};

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

pub(crate) const SM9_P_MINUS_ONE: U256 = [
    0xe56f9b27e351457c,
    0x21f2934b1a7aeedb,
    0xd603ab4ff58ec745,
    0xb640000002a3a6f1,
];

/// e = p - 2 = b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457b
///
/// p - 2, used in a^(p-2) = a^-1
pub(crate) const SM9_P_MINUS_TWO: U256 = [
    0xe56f9b27e351457b,
    0x21f2934b1a7aeedb,
    0xd603ab4ff58ec745,
    0xb640000002a3a6f1,
];

/// p = b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d
///
/// p' = -p^(-1) mod 2^256 = afd2bac5558a13b3966a4b291522b137181ae39613c8dbaf892bc42c2f2ee42b
///
/// sage: -(IntegerModRing(2^256)(p))^-1
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

pub type Fp = U256;

#[inline(always)]
pub fn fp_random_u256() -> U256 {
    let mut rng = rand::thread_rng();
    let mut buf: [u8; 32] = [0; 32];
    let mut ret;
    loop {
        rng.fill_bytes(&mut buf[..]);
        ret = u256_from_be_bytes(&buf);
        if u256_cmp(&ret, &SM9_P_MINUS_ONE) < 0 && ret != [0, 0, 0, 0] {
            break;
        }
    }
    ret
}

pub(crate) fn fp_pow(a: &Fp, e: &U256) -> Fp {
    let mut r = SM9_MODP_MONT_ONE;
    let mut w = 0u64;
    for i in (0..4).rev() {
        w = e[i];
        for j in 0..64 {
            r = r.fp_sqr();
            if w & 0x8000000000000000 != 0 {
                r = r.fp_mul(a);
            }
            w <<= 1;
        }
    }
    r
}

pub fn fp_to_mont(a: &Fp) -> Fp {
    mont_mul(a, &SM9_MODP_2E512)
}

pub fn fp_from_mont(a: &Fp) -> Fp {
    mont_mul(a, &SM9_ONE)
}

pub fn fp_to_bytes(a: &Fp) -> Vec<u8> {
    let t = fp_from_mont(a);
    u256_to_be_bytes(&t)
}

pub(crate) fn fp_from_bytes(buf: &[u8; 32]) -> Fp {
    let mut t = u256_from_be_bytes(buf);
    t = fp_to_mont(&t);
    t
}

pub fn mont_mul(a: &Fp, b: &Fp) -> Fp {
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
    } else if u256_cmp(&r, &SM9_P) >= 0 {
        r = u256_sub(&r, &SM9_P).0
    }
    r
}

impl FieldElement for Fp {
    fn zero() -> Self {
        SM9_ZERO
    }

    fn one() -> Self {
        SM9_MODP_MONT_ONE
    }

    fn is_zero(&self) -> bool {
        self == &SM9_ZERO
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
            let (diff, _borrow) = u256_add(&r, &SM9_MODP_MONT_ONE);
            return diff;
        }
        if u256_cmp(&r, &SM9_P) >= 0 {
            let (diff, _borrow) = u256_sub(&r, &SM9_P);
            return diff;
        }
        r
    }

    fn fp_sub(&self, rhs: &Self) -> Self {
        let (raw_diff, borrow) = u256_sub(&self, rhs);
        if borrow {
            let (diff, _borrow) = u256_sub(&raw_diff, &SM9_MODP_MONT_ONE);
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
            let (sum, carry) = u256_add(self, &SM9_P);
            c = carry as u64;
            r = sum;
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
        fp_pow(self, &SM9_P_MINUS_TWO)
    }
}

pub fn fp_from_hex(hex: &str) -> Fp {
    fp_to_mont(&u256_from_be_bytes(&hex::decode(hex).unwrap()))
}

#[cfg(test)]
mod test_mod_operation {
    use crate::fields::fp::{fp_from_mont, fp_pow, fp_to_mont};
    use crate::fields::FieldElement;

    #[test]
    fn test_mod_op() {
        let mut a: [u64; 4] = [
            0x54806C11D8806141,
            0xF1DD2C190F5E93C4,
            0x597B6027B441A01F,
            0x85AEF3D078640C98,
        ];

        let mut b: [u64; 4] = [
            0x0E75C05FB4E3216D,
            0x1006E85F5CDFF073,
            0x1A7CE027B7A46F74,
            0x41E00A53DDA532DA,
        ];

        let p: [u64; 4] = [
            0xe56f9b27e351457d,
            0x21f2934b1a7aeedb,
            0xd603ab4ff58ec745,
            0xb640000002a3a6f1,
        ];

        let r = a.fp_add(&b);
        println!("fp_add ={:?}", &r); // [9045076647192182065, 16136820971490481499, 11381885983195088974, 1247213578799650944]

        let mut r = a.fp_sub(&b);
        r.reverse();
        println!("fp_sub ={:x?}", r); // 43cee97c9abed9be3efe7ffffc9d30abe1d643b9b27ea351460aabb2239d3fd4

        a = fp_to_mont(&a);
        b = fp_to_mont(&b);
        let mut r = a.fp_mul(&b);
        r = fp_from_mont(&r);
        r.reverse();
        println!("fp_mul ={:x?}", r); // 9e4d19bb5d94a47352e6f53f4116b2a71b16a1113dc789b26528ee19f46b72e0

        let mut r = a.fp_double();
        r = fp_from_mont(&r);
        r.reverse();
        println!("fp_dbl ={:x?}", r); // 551de7a0ee24723edcf314ff72f478fac1c7c4e7044238acc3913cfbcdaf7d05

        let mut r = a.fp_triple();
        r = fp_from_mont(&r);
        r.reverse();
        println!("fp_tri ={:x?}", r); // 248cdb7163e4d7e5606ac9d731a751d591b25db4f925dd9532a20de5c2de98c9

        let mut r = a.fp_div2();
        r = fp_from_mont(&r);
        r.reverse();
        println!("fp_div2 ={:x?}", r); // 9df779e83d83d9c517bf85bbd4e833b289e7dfb214ecc1501cf8039cdde8d35f

        let mut r = a.fp_neg();
        r = fp_from_mont(&r);
        r.reverse();
        println!("fp_neg ={:x?}", r); // 30910c2f8a3f9a597c884b28414d2725301567320b1c5b1790ef2f160ad0e43c

        let mut r = a.fp_sqr();
        r = fp_from_mont(&r);
        r.reverse();
        println!("fp_sqr ={:x?}", r); // 46dc2a5b8853234b341d9c57f9c4ca5709e95bbfef25356812e884e4f38cd0d6

        b = fp_from_mont(&b);
        let mut r = fp_pow(&a, &b);
        r = fp_from_mont(&r);
        r.reverse();
        println!("fp_pow ={:x?}", r);

        let mut r = a.fp_inv();
        r = fp_from_mont(&r);
        r.reverse();
        println!("fp_inv ={:x?}", r);
    }
}
