use crate::u256::{
    SM2_ONE, U256, u256_add, u256_cmp, u256_mul, u256_sub, u512_add,
};

///
/// n =  0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123
pub const SM2_N: U256 = [
    0x53bbf40939d54123,
    0x7203df6b21c6052b,
    0xffffffffffffffff,
    0xfffffffeffffffff,
];

/// 2^256 - n  =   0x10000000000000000000000008dfc2094de39fad4ac440bf6c62abedd
pub const SM2_N_NEG: U256 = [
    0xac440bf6c62abedd,
    0x8dfc2094de39fad4,
    0x0000000000000000,
    0x0000000100000000,
];

/// N - 2
pub const SM2_N_MINUS_TWO: U256 = [
    0x53bbf40939d54121,
    0x7203df6b21c6052b,
    0xffffffffffffffff,
    0xfffffffeffffffff,
];

pub const SM2_N_PRIME: U256 = [
    0x327f9e8872350975,
    0xdf1e8d34fc8319a5,
    0x2b0068d3b08941d4,
    0x6f39132f82e4c7bc,
];

pub const SM2_MOD_N_2E512: U256 = [
    0x901192af7c114f20,
    0x3464504ade6fa2fa,
    0x620fc84c3affe0d4,
    0x1eb5e412a22b3d3b,
];

pub fn fn_add(a: &U256, b: &U256) -> U256 {
    let (r, c) = u256_add(a, b);
    if c {
        // a + b - n = (a + b - 2^256) + (2^256 - n)
        return u256_add(&r, &SM2_N_NEG).0;
    }
    if u256_cmp(&r, &SM2_N) >= 0 {
        return u256_sub(&r, &SM2_N).0;
    }
    r
}

pub fn fn_sub(a: &U256, b: &U256) -> U256 {
    let (mut r, c) = u256_sub(a, b);
    if c {
        r = u256_sub(&r, &SM2_N_NEG).0
    }
    r
}

pub fn to_mont(a: &U256) -> U256 {
    mont_mul(a, &SM2_MOD_N_2E512)
}

pub fn from_mont(a: &U256) -> U256 {
    mont_mul(a, &SM2_ONE)
}

pub fn fn_mul(a: &U256, b: &U256) -> U256 {
    let mont_a = to_mont(a);
    let mont_b = to_mont(b);
    let mut r = mont_mul(&mont_a, &mont_b);
    r = from_mont(&r);
    r
}

fn mont_mul(a: &U256, b: &U256) -> U256 {
    let mut r = [0u64; 4];
    let mut z = [0u64; 8];
    let mut t = [0u64; 8];

    // z = a * b
    z = u256_mul(a, b);

    // t = low(z) * n'
    let z_low = [z[0], z[1], z[2], z[3]];
    let t1 = u256_mul(&z_low, &SM2_N_PRIME);
    t[0] = t1[0];
    t[1] = t1[1];
    t[2] = t1[2];
    t[3] = t1[3];

    // t = low(t) * n
    let t_low = [t[0], t[1], t[2], t[3]];
    t = u256_mul(&t_low, &SM2_N);

    // z = z + t
    let (sum, c) = u512_add(&z, &t);
    z = sum;

    // r = high(r)
    r = [z[4], z[5], z[6], z[7]];
    if c {
        r = u256_add(&r, &SM2_N_NEG).0;
    } else if u256_cmp(&r, &SM2_N) >= 0 {
        r = u256_sub(&r, &SM2_N).0
    }
    r
}

pub fn fn_pow(a: &U256, e: &U256) -> U256 {
    let mont_a = to_mont(a);
    let mut r = SM2_N_NEG;
    let mut w = 0u64;
    for i in (0..4).rev() {
        w = e[i];
        for _j in 0..64 {
            r = mont_mul(&r, &r);
            if w & 0x8000000000000000 != 0 {
                r = mont_mul(&r, &mont_a);
            }
            w <<= 1;
        }
    }
    r = from_mont(&r);
    r
}

pub fn fn_inv(a: &U256) -> U256 {
    let mont_a = to_mont(a);
    let mut r = fn_pow(&mont_a, &SM2_N_MINUS_TWO);
    r = from_mont(&r);
    r
}

#[cfg(test)]
mod test_mod_operation {
    use num_bigint::BigUint;

    use crate::fields::fn64::fn_mul;

    #[test]
    fn test_mod_op() {
        let a: [u64; 4] = [
            0x715a4589334c74c7,
            0x8fe30bbff2660be1,
            0x5f9904466a39c994,
            0x32c4ae2c1f198119,
        ];

        let b: [u64; 4] = [
            0x02df32e52139f0a0,
            0xd0a9877cc62a4740,
            0x59bdcee36b692153,
            0xbc3736a2f4f6779c,
        ];

        let r = fn_mul(&a, &b);
        println!("{:x?}", r);

        let a1 = BigUint::from_bytes_be(
            &hex::decode("32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7")
                .unwrap(),
        );

        let b1 = BigUint::from_bytes_be(
            &hex::decode("bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0")
                .unwrap(),
        );

        let n1 = BigUint::from_bytes_be(
            &hex::decode("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123")
                .unwrap(),
        );

        let r = ((&a1 * &b1) % n1).to_u64_digits();
        println!("{:x?}", r);

    }
}
