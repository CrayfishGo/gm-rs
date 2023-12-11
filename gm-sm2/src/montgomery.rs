use std::ops::Neg;

use num_bigint::{BigInt, ExtendedGcd};
use num_traits::{One, Zero};

use crate::p256_ecc::P256C_PARAMS;

// 高位相减法  a % p
fn cus_mod(a: &BigInt, p: &BigInt) -> (BigInt, BigInt) {
    if a < &BigInt::zero() {
        let (c, r) = cus_mod(&a.neg(), p);
        return if !r.is_zero() {
            (c.neg() - BigInt::one(), p - r)
        } else {
            (c.neg(), BigInt::zero())
        };
    }

    if p > a {
        return (BigInt::zero(), a.clone());
    }

    let a_len = a.bits();
    let p_len = p.bits();

    let mut d_len = a_len - p_len;
    if d_len == 0 {
        return (BigInt::one(), a - p);
    }

    let mut c = BigInt::zero();
    let mut a = a.clone();
    loop {
        c = 2 * c;
        let mut a1 = &a >> (d_len);
        if a1 < *p {
            continue;
        }
        c = c + BigInt::one();
        let b1 = &a - (&a1 << (d_len));
        a1 = &a1 - p;
        a = (a1 << d_len) + b1;
        if d_len == 0 {
            break;
        }
        d_len -= 1;
    }
    return (c, a);
}

pub fn montgomery_mod(a: &BigInt, p: &BigInt) -> BigInt {
    let r = &P256C_PARAMS.rr;
    let (gcd, _x, y) = &r.clone().extended_gcd(p);
    assert_eq!(gcd, &BigInt::one());
    // let q = y.neg() % r;
    let (_, q) = cus_mod(&y.neg(), r);
    return redc(a * &P256C_PARAMS.rr_pp, p, r.clone(), q);
}

pub fn montgomery_mul_mod(a: &BigInt, b: &BigInt, p: &BigInt) -> BigInt {
    let r = &P256C_PARAMS.r;
    let q = &P256C_PARAMS.q;
    let ar = redc(a * &P256C_PARAMS.rr_pp, p, r.clone(), q.clone());
    let br = redc(b * &P256C_PARAMS.rr_pp, p, r.clone(), q.clone());
    let abr = redc(ar * br, p, r.clone(), q.clone());
    return redc(abr, p, r.clone(), q.clone());
}

fn redc(t: BigInt, p: &BigInt, r: BigInt, q: BigInt) -> BigInt {
    let r_len = r.bits() - 1;
    let r_mask = r - BigInt::one();
    let m = ((&t & &r_mask) * &q) & &r_mask;
    let t1 = (&t + &m * p) >> r_len;
    let ret = if t1 < *p { t1 } else { t1 - p };
    ret
}

#[cfg(test)]
mod test_mont {
    use crate::montgomery::{cus_mod, montgomery_mod, montgomery_mul_mod};
    use num_bigint::{BigInt, BigUint, Sign, ToBigInt};
    use num_traits::Num;

    #[test]
    fn test() {
        let p = BigUint::from_str_radix(
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
            16,
        )
        .unwrap()
        .to_bigint()
        .unwrap();

        let a = BigInt::from_slice(
            Sign::Plus,
            &[
                0xbc37_36a2,
                0xf4f6_779c,
                0x59bd_cee3,
                0x6b69_2153,
                0xd0a9_877c,
                0xc62a_4740,
                0x02df_32e5,
                0x2139_f0a0,
            ],
        );

        let b = BigInt::from_slice(
            Sign::Plus,
            &[
                0x32c4_ae2c,
                0x1f19_8119,
                0x5f99_0446,
                0x6a39_c994,
                0x8fe3_0bbf,
                0xf266_0be1,
                0x715a_4589,
                0x334c_74c7,
            ],
        );

        let ret0 = cus_mod(&p, &a);
        let ret1 = montgomery_mod(&(&a * &b), &p);
        let ret2 = montgomery_mul_mod(&a, &b, &p);
        let ret3 = (&a * &b) % &p;
        assert_eq!(ret0.1, &p % &a);
        assert_eq!(ret1, ret3);
        assert_eq!(ret2, ret3);
    }
}
