use rand::RngCore;

use crate::error::{Sm2Error, Sm2Result};
use crate::fields::FieldModOperation;
use crate::u256::{
    SM2_ONE, SM2_ZERO, U256, u256_add, u256_cmp, u256_from_be_bytes, u256_mul,
    u256_sub, u256_to_be_bytes, u512_add,
};

// 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff
pub const SM2_P: U256 = [
    0xffffffffffffffff,
    0xffffffff00000000,
    0xffffffffffffffff,
    0xfffffffeffffffff,
];

pub const SM2_P_MINUS_ONE: U256 = [
    0xfffffffffffffffe,
    0xffffffff00000000,
    0xffffffffffffffff,
    0xfffffffeffffffff,
];

pub const SM2_P_MINUS_TWO: U256 = [
    0xfffffffffffffffd,
    0xffffffff00000000,
    0xffffffffffffffff,
    0xfffffffeffffffff,
];

// p' = -p^(-1) mod 2^256
//    = fffffffc00000001fffffffe00000000ffffffff000000010000000000000001
// sage: -(IntegerModRing(2^256)(p))^-1
pub const SM2_P_PRIME: U256 = [
    0x0000000000000001,
    0xffffffff00000001,
    0xfffffffe00000000,
    0xfffffffc00000001,
];

// 2^512 (mod p)
pub const SM2_MODP_2E512: U256 = [
    0x0000000200000003,
    0x00000002ffffffff,
    0x0000000100000001,
    0x0000000400000002,
];

// (p+1)/4 = 3fffffffbfffffffffffffffffffffffffffffffc00000004000000000000000
pub const SM2_SQRT_EXP: U256 = [
    0x4000000000000000,
    0xffffffffc0000000,
    0xffffffffffffffff,
    0x3fffffffbfffffff,
];

pub const SM2_MODP_MONT_ONE: U256 = [1, (1 << 32) - 1, 0, 1 << 32];

// mont(b), b = 0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93
pub const SM2_MODP_MONT_B: U256 = [
    0x90d230632bc0dd42,
    0x71cf379ae9b537ab,
    0x527981505ea51c3c,
    0x240fe188ba20e2c8,
];

pub const SM2_MODP_MONT_A: U256 = [
    0xfffffffffffffffc,
    0xfffffffc00000003,
    0xffffffffffffffff,
    0xfffffffbffffffff,
];

// 0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7
pub const SM2_G_X: U256 = [
    0x715a4589334c74c7,
    0x8fe30bbff2660be1,
    0x5f9904466a39c994,
    0x32c4ae2c1f198119,
];

// 0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0
pub const SM2_G_Y: U256 = [
    0x02df32e52139f0a0,
    0xd0a9877cc62a4740,
    0x59bdcee36b692153,
    0xbc3736a2f4f6779c,
];

#[inline(always)]
pub fn random_u256() -> U256 {
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

pub fn fp_pow(a: &U256, e: &U256) -> U256 {
    let mut r = SM2_MODP_MONT_ONE;
    let mut w = 0u64;
    for i in (0..4).rev() {
        w = e[i];
        for _j in 0..64 {
            r = r.fp_sqr();
            if w & 0x8000000000000000 != 0 {
                r = r.fp_mul(a);
            }
            w <<= 1;
        }
    }
    r
}

pub(crate) fn fp_to_mont(a: &U256) -> U256 {
    mont_mul(a, &SM2_MODP_2E512)
}

pub(crate) fn fp_from_mont(a: &U256) -> U256 {
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
        r = u256_add(&r, &SM2_MODP_MONT_ONE).0;
    } else if u256_cmp(&r, &SM2_P) >= 0 {
        r = u256_sub(&r, &SM2_P).0
    }
    r
}

pub fn fp_sqrt(a: &U256) -> Sm2Result<U256> {
    let r = fp_pow(a, &SM2_SQRT_EXP);
    let a1 = r.fp_sqr();
    if u256_cmp(&a1, &a) != 0 {
        return Err(Sm2Error::FieldSqrtError);
    }
    Ok(r)
}

impl FieldModOperation for U256 {
    fn zero() -> Self {
        SM2_ZERO
    }

    fn one() -> Self {
        SM2_ONE
    }

    fn is_zero(&self) -> bool {
        self == &SM2_ZERO
    }

    fn fp_sqr(&self) -> Self {
        self.fp_mul(self)
    }

    fn fp_double(&self) -> Self {
        self.fp_add(self)
    }

    fn fp_triple(&self) -> Self {
        let mut r = self.fp_double();
        r = self.fp_add(&r);
        r
    }

    fn fp_add(&self, rhs: &Self) -> Self {
        let (r, c) = u256_add(self, rhs);
        if c {
            let (diff, _borrow) = u256_add(&r, &SM2_MODP_MONT_ONE);
            return diff;
        }
        if u256_cmp(&r, &SM2_P) >= 0 {
            let (diff, _borrow) = u256_sub(&r, &SM2_P);
            return diff;
        }
        r
    }

    fn fp_sub(&self, rhs: &Self) -> Self {
        let (raw_diff, borrow) = u256_sub(self, rhs);
        if borrow {
            let (diff, _borrow) = u256_sub(&raw_diff, &SM2_MODP_MONT_ONE);
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
            u256_sub(&SM2_P, self).0
        }
    }

    fn fp_div2(&self) -> Self {
        let mut r = self.clone();
        let mut c = 0;
        if r[0] & 0x01 == 1 {
            r = self.fp_add(&SM2_P);
            c = u64::from(u256_add(&self, &SM2_P).1)
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
        fp_pow(self, &SM2_P_MINUS_TWO)
    }

    fn to_byte_be(&self) -> Vec<u8> {
        u256_to_be_bytes(self)
    }

    fn from_byte_be(input: &[u8]) -> Self {
        u256_from_be_bytes(input)
    }
}
