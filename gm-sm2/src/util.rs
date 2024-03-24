use byteorder::{BigEndian, WriteBytesExt};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::RngCore;

use gm_sm3::sm3_hash;

use crate::error::{Sm2Error, Sm2Result};
use crate::key::Sm2PublicKey;
use crate::p256_ecc::P256C_PARAMS;

pub(crate) const DEFAULT_ID: &'static str = "1234567812345678";

#[inline]
pub fn random_uint() -> BigUint {
    let n = &P256C_PARAMS.n;
    let mut rng = rand::thread_rng();
    let mut buf: [u8; 32] = [0; 32];
    let mut ret;
    loop {
        rng.fill_bytes(&mut buf[..]);
        ret = BigUint::from_bytes_be(&buf[..]);
        if ret < n - BigUint::one() && ret != BigUint::zero() {
            break;
        }
    }
    ret
}

/// compute ZA = H256(ENTLA ∥ IDA ∥ a ∥ b ∥ xG ∥ yG ∥ xA ∥ yA)
pub fn compute_za(id: &str, pk: &Sm2PublicKey) -> Sm2Result<[u8; 32]> {
    if !pk.is_valid() {
        return Err(Sm2Error::InvalidPublic);
    }
    let mut prepend: Vec<u8> = Vec::new();
    if id.len() * 8 > 65535 {
        return Err(Sm2Error::IdTooLong);
    }
    prepend
        .write_u16::<BigEndian>((id.len() * 8) as u16)
        .unwrap();
    for c in id.bytes() {
        prepend.push(c);
    }

    prepend.extend_from_slice(&P256C_PARAMS.a.to_bytes_be());
    prepend.extend_from_slice(&P256C_PARAMS.b.to_bytes_be());
    prepend.extend_from_slice(&P256C_PARAMS.g_point.x.to_bytes_be());
    prepend.extend_from_slice(&P256C_PARAMS.g_point.y.to_bytes_be());

    let pk_affine = pk.value().to_affine_point();
    prepend.extend_from_slice(&pk_affine.x.to_bytes_be());
    prepend.extend_from_slice(&pk_affine.y.to_bytes_be());

    Ok(sm3_hash(&prepend))
}

#[inline]
pub fn kdf(z: &[u8], klen: usize) -> Vec<u8> {
    let mut ct = 0x00000001u32;
    let bound = ((klen as f64) / 32.0).ceil() as u32;
    let mut h_a = Vec::new();
    for _i in 1..bound {
        let mut prepend = Vec::new();
        prepend.extend_from_slice(z);
        prepend.extend_from_slice(&ct.to_be_bytes());

        let h_a_i = sm3_hash(&prepend[..]);
        h_a.extend_from_slice(&h_a_i);
        ct += 1;
    }

    let mut prepend = Vec::new();
    prepend.extend_from_slice(z);
    prepend.extend_from_slice(&ct.to_be_bytes());

    let last = sm3_hash(&prepend[..]);
    if klen % 32 == 0 {
        h_a.extend_from_slice(&last);
    } else {
        h_a.extend_from_slice(&last[0..(klen % 32)]);
    }
    h_a
}

#[inline(always)]
pub const fn add_raw(a: &[u32; 8], b: &[u32; 8]) -> ([u32; 8], bool) {
    let mut sum = [0; 8];
    let mut carry = false;
    let mut i = 7;
    loop {
        let (t_sum, c) = {
            let (m, c1) = a[i].overflowing_add(b[i]);
            let (r, c2) = m.overflowing_add(carry as u32);
            (r & 0xffff_ffff, c1 || c2)
        };
        sum[i] = t_sum;
        carry = c;
        if i == 0 {
            break;
        }
        i -= 1;
    }
    (sum, carry)
}

#[inline(always)]
pub const fn add_raw_u64(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], bool) {
    let mut sum = [0; 4];
    let mut carry = false;
    let mut i = 3;
    loop {
        let (t_sum, c) = {
            let (m, c1) = a[i].overflowing_add(b[i]);
            let (r, c2) = m.overflowing_add(carry as u64);
            (r & 0xffff_ffff_ffff_ffff, c1 || c2)
        };
        sum[i] = t_sum;
        carry = c;
        if i == 0 {
            break;
        }
        i -= 1;
    }
    (sum, carry)
}

#[inline(always)]
pub const fn sub_raw_u64(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], bool) {
    let mut r = [0; 4];
    let mut borrow = false;
    let mut j = 0;
    loop {
        let i = 3 - j;
        let (diff, bor) = {
            let (a, b1) = a[i].overflowing_sub(borrow as u64);
            let (res, b2) = a.overflowing_sub(b[i]);
            (res, b1 || b2)
        };
        r[i] = diff;
        borrow = bor;
        if j == 3 {
            break;
        }
        j += 1;
    }
    (r, borrow)
}

#[inline(always)]
pub const fn sub_raw(a: &[u32; 8], b: &[u32; 8]) -> ([u32; 8], bool) {
    let mut r = [0; 8];
    let mut borrow = false;
    let mut j = 0;
    loop {
        let i = 7 - j;
        let (diff, bor) = {
            let (a, b1) = a[i].overflowing_sub(borrow as u32);
            let (res, b2) = a.overflowing_sub(b[i]);
            (res, b1 || b2)
        };
        r[i] = diff;
        borrow = bor;
        if j == 7 {
            break;
        }
        j += 1;
    }
    (r, borrow)
}

#[inline(always)]
pub const fn mul_raw(a: &[u32; 8], b: &[u32; 8]) -> [u32; 16] {
    let mut local: u64 = 0;
    let mut carry: u64 = 0;
    let mut ret: [u32; 16] = [0; 16];
    let mut ret_idx = 0;
    while ret_idx < 15 {
        let index = 15 - ret_idx;
        let mut a_idx = 0;
        while a_idx < 8 {
            if a_idx > ret_idx {
                break;
            }
            let b_idx = ret_idx - a_idx;
            if b_idx < 8 {
                let (hi, lo) = {
                    let uv = (a[7 - a_idx] as u64) * (b[7 - b_idx] as u64);
                    let u = uv >> 32;
                    let v = uv & 0xffff_ffff;
                    (u, v)
                };
                local += lo;
                carry += hi;
            }
            a_idx += 1;
        }
        carry += local >> 32;
        local &= 0xffff_ffff;
        ret[index] = local as u32;
        local = carry;
        carry = 0;
        ret_idx += 1;
    }
    ret[0] = local as u32;
    ret
}

#[inline(always)]
pub const fn mul_raw_u64(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut local: u128 = 0;
    let mut carry: u128 = 0;
    let mut ret: [u64; 8] = [0; 8];
    let mut ret_idx = 0;
    while ret_idx < 7 {
        let index = 7 - ret_idx;
        let mut a_idx = 0;
        while a_idx < 4 {
            if a_idx > ret_idx {
                break;
            }
            let b_idx = ret_idx - a_idx;
            if b_idx < 4 {
                let (hi, lo) = {
                    let uv = (a[3 - a_idx] as u128) * (b[3 - b_idx] as u128);
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

#[cfg(test)]
mod test_operation {
    use num_bigint::BigUint;
    use num_traits::Num;

    use crate::util::{add_raw_u64, mul_raw_u64, sub_raw_u64};

    #[test]
    fn test_raw_add_u64() {
        let a: [u64; 4] = [
            0xF9B7213BAF82D65B,
            0xEE265948D19C17AB,
            0xD2AAB97FD34EC120,
            0x3722755292130B08,
        ];

        let b: [u64; 4] = [
            0x54806C11D8806141,
            0xF1DD2C190F5E93C4,
            0x597B6027B441A01F,
            0x85AEF3D078640C98,
        ];

        let a1 = BigUint::from_str_radix(
            "F9B7213BAF82D65BEE265948D19C17ABD2AAB97FD34EC1203722755292130B08",
            16,
        )
            .unwrap();
        let b1 = BigUint::from_str_radix(
            "54806C11D8806141F1DD2C190F5E93C4597B6027B441A01F85AEF3D078640C98",
            16,
        )
            .unwrap();

        let (r, c) = add_raw_u64(&a, &b);
        println!("sum r={:?}", r);

        let mut sum = (&a1 + &b1).to_u64_digits();
        sum.reverse();
        println!("sum r={:?}", &sum[1..]);

        let (r, c) = sub_raw_u64(&a, &b);
        println!("sub r={:?}", r);

        let mut sub = (&a1 - &b1).to_u64_digits();
        sub.reverse();
        println!("sub r={:?}", sub.as_slice());

        let r = mul_raw_u64(&a, &b);
        println!("mul r={:?}", r);

        let mut mul = (&a1 * &b1).to_u64_digits();
        mul.reverse();
        println!("mul r={:?}", mul.as_slice());
    }
}
